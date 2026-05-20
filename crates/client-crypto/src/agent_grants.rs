use std::sync::atomic::{AtomicU64, Ordering};

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{
    PublicKey as X25519PublicKey, SharedSecret as X25519SharedSecret,
    StaticSecret as X25519StaticSecret,
};
use zeroize::Zeroize;

use worklist_client_core::{PublicError, PublicResult};

use crate::{
    KEY_SIZE, SealedBlobPayload, SymmetricKey, deserialize_complete_from_cbor, serialize_to_cbor,
    symmetric_key_from_bytes,
};

const HPKE_NONCE_SIZE: usize = 12;
const HPKE_MODE_BASE: u8 = 0x00;
const HPKE_KEM_CODEPOINT: u16 = 0x0020;
// Legacy Worklist envelopes accidentally used RFC 9180's P-256 KEM codepoint
// for the same X25519 key material. Keep this accept-on-read only; new seals
// must continue to use HPKE_KEM_CODEPOINT. This is not true P-256 HPKE support.
const HPKE_LEGACY_KEM_CODEPOINT: u16 = 0x0010;
const HPKE_KDF_CODEPOINT: u16 = 0x0001;
const HPKE_AEAD_CODEPOINT: u16 = 0x0003;
const HPKE_KEM_ID: [u8; 2] = HPKE_KEM_CODEPOINT.to_be_bytes();
const HPKE_LEGACY_KEM_ID: [u8; 2] = HPKE_LEGACY_KEM_CODEPOINT.to_be_bytes();
const HPKE_KDF_ID: [u8; 2] = HPKE_KDF_CODEPOINT.to_be_bytes();
const HPKE_AEAD_ID: [u8; 2] = HPKE_AEAD_CODEPOINT.to_be_bytes();

static LEGACY_AGENT_GRANT_HPKE_OPEN_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HpkeEnvelope {
    version: u8,
    suite: HpkeSuite,
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
struct HpkeSuite {
    kem: u16,
    kdf: u16,
    aead: u16,
    mode: u8,
}

impl HpkeSuite {
    const fn supported() -> Self {
        Self {
            kem: HPKE_KEM_CODEPOINT,
            kdf: HPKE_KDF_CODEPOINT,
            aead: HPKE_AEAD_CODEPOINT,
            mode: HPKE_MODE_BASE,
        }
    }

    const fn legacy() -> Self {
        Self {
            kem: HPKE_LEGACY_KEM_CODEPOINT,
            kdf: HPKE_KDF_CODEPOINT,
            aead: HPKE_AEAD_CODEPOINT,
            mode: HPKE_MODE_BASE,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HpkeSuiteKind {
    Current,
    Legacy,
}

pub fn encrypt_agent_work_list_key(
    recipient_public_key: &[u8],
    work_list_id: &uuid::Uuid,
    list_key: &SymmetricKey,
) -> PublicResult<SealedBlobPayload> {
    let recipient_public_key: [u8; KEY_SIZE] = recipient_public_key
        .try_into()
        .map_err(|_| PublicError::validation("agent recipient public key must be 32 bytes"))?;
    let recipient_public = X25519PublicKey::from(recipient_public_key);
    let ephemeral = X25519StaticSecret::random();
    let enc = X25519PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&recipient_public);
    let mut dh = ensure_contributory_shared_secret(&shared)?;
    let context = agent_grant_context(work_list_id);
    let shared_secret_result = hpke_dhkem_shared_secret(&dh, &enc, recipient_public.as_bytes());
    dh.zeroize();
    let mut shared_secret = shared_secret_result?;
    let key_schedule_result = hpke_key_schedule(&shared_secret, &context);
    shared_secret.zeroize();
    let (mut key, mut nonce) = key_schedule_result?;
    let ciphertext_result = hpke_seal(&key, &nonce, &context, list_key.as_bytes());
    key.zeroize();
    nonce.zeroize();
    let ciphertext = ciphertext_result?;
    let envelope = HpkeEnvelope {
        version: 1,
        suite: HpkeSuite::supported(),
        enc: enc.to_vec(),
        ciphertext,
    };
    let bytes = serialize_to_cbor(&envelope)?;
    Ok(SealedBlobPayload {
        base64: STANDARD_NO_PAD.encode(&bytes),
        bytes,
    })
}

pub fn decrypt_agent_work_list_key(
    recipient_private_key: &[u8],
    work_list_id: &uuid::Uuid,
    ciphertext: &[u8],
) -> PublicResult<SymmetricKey> {
    if recipient_private_key.len() != KEY_SIZE {
        return Err(PublicError::validation(
            "agent recipient private key must be 32 bytes",
        ));
    }

    let envelope: HpkeEnvelope = deserialize_complete_from_cbor(ciphertext)?;
    if envelope.version != 1 {
        return Err(PublicError::validation("unsupported agent grant version"));
    }
    let suite_kind = hpke_suite_kind(&envelope.suite)?;
    if envelope.enc.len() != KEY_SIZE {
        return Err(PublicError::validation("agent grant enc must be 32 bytes"));
    }
    let enc: [u8; KEY_SIZE] = envelope
        .enc
        .as_slice()
        .try_into()
        .map_err(|_| PublicError::validation("agent grant enc must be 32 bytes"))?;
    let mut recipient_private_key_bytes = [0u8; KEY_SIZE];
    recipient_private_key_bytes.copy_from_slice(recipient_private_key);
    let recipient_private = X25519StaticSecret::from(recipient_private_key_bytes);
    recipient_private_key_bytes.zeroize();
    let shared = recipient_private.diffie_hellman(&X25519PublicKey::from(enc));
    let mut dh = ensure_contributory_shared_secret(&shared)?;
    let recipient_public = X25519PublicKey::from(&recipient_private).to_bytes();
    let context = agent_grant_context(work_list_id);
    let key_schedule_result = match suite_kind {
        HpkeSuiteKind::Current => {
            let shared_secret_result = hpke_dhkem_shared_secret(&dh, &enc, &recipient_public);
            dh.zeroize();
            let mut shared_secret = shared_secret_result?;
            let key_schedule_result = hpke_key_schedule(&shared_secret, &context);
            shared_secret.zeroize();
            key_schedule_result
        }
        HpkeSuiteKind::Legacy => {
            let key_schedule_result =
                legacy_hpke_key_schedule(&dh, &enc, &recipient_public, &context);
            // The legacy schedule borrows raw DH. Zeroize immediately after
            // the schedule returns and before later fallible decrypt work.
            dh.zeroize();
            key_schedule_result
        }
    };
    let (mut key, mut nonce) = key_schedule_result?;
    let plaintext_result = hpke_open(&key, &nonce, &context, &envelope.ciphertext);
    key.zeroize();
    nonce.zeroize();
    let mut plaintext = plaintext_result?;
    let key_result = symmetric_key_from_bytes(&plaintext);
    plaintext.zeroize();
    if key_result.is_ok() && matches!(suite_kind, HpkeSuiteKind::Legacy) {
        record_legacy_agent_grant_hpke_open();
    }
    key_result
}

/// Successful legacy agent-grant HPKE opens observed in this process.
///
/// This is an observability hook for the KEM 0x0010 re-seal migration and lets
/// CLIs or embedding runtimes surface whether old envelopes are still read.
pub fn legacy_agent_grant_hpke_open_count() -> u64 {
    LEGACY_AGENT_GRANT_HPKE_OPEN_COUNT.load(Ordering::Relaxed)
}

fn record_legacy_agent_grant_hpke_open() {
    LEGACY_AGENT_GRANT_HPKE_OPEN_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn agent_grant_context(work_list_id: &uuid::Uuid) -> Vec<u8> {
    format!("worklist.agent.grant:{work_list_id}").into_bytes()
}

fn hpke_suite_kind(suite: &HpkeSuite) -> PublicResult<HpkeSuiteKind> {
    if *suite == HpkeSuite::supported() {
        return Ok(HpkeSuiteKind::Current);
    }
    if *suite == HpkeSuite::legacy() {
        return Ok(HpkeSuiteKind::Legacy);
    }

    Err(PublicError::validation(
        "agent grant uses an unsupported HPKE ciphersuite",
    ))
}

fn ensure_contributory_shared_secret(
    shared_secret: &X25519SharedSecret,
) -> PublicResult<[u8; KEY_SIZE]> {
    if !shared_secret.was_contributory() {
        return Err(PublicError::validation(
            "derived HPKE shared secret is invalid",
        ));
    }

    Ok(shared_secret.to_bytes())
}

fn hpke_dhkem_shared_secret(
    dh: &[u8; KEY_SIZE],
    enc: &[u8; KEY_SIZE],
    recipient_public: &[u8; KEY_SIZE],
) -> PublicResult<[u8; KEY_SIZE]> {
    // The CBOR envelope is Worklist-specific; the DHKEM and key schedule below
    // follow RFC 9180 base mode for DHKEM(X25519, HKDF-SHA256) + ChaCha20Poly1305.
    let suite_id = hpke_kem_suite_id();
    let mut eae_prk = hpke_labeled_extract_with_suite(&suite_id, None, b"eae_prk", dh)?;
    let mut kem_context = [enc.as_slice(), recipient_public.as_slice()].concat();
    let shared_secret_result = hpke_labeled_expand_with_suite::<KEY_SIZE>(
        &suite_id,
        &eae_prk,
        b"shared_secret",
        &kem_context,
    );
    eae_prk.zeroize();
    kem_context.zeroize();
    shared_secret_result
}

fn hpke_key_schedule(
    shared_secret: &[u8; KEY_SIZE],
    context: &[u8],
) -> PublicResult<([u8; KEY_SIZE], [u8; HPKE_NONCE_SIZE])> {
    let mut psk_id_hash = hpke_labeled_extract(None, b"psk_id_hash", &[])?;
    let info_hash_result = hpke_labeled_extract(None, b"info_hash", context);
    if info_hash_result.is_err() {
        psk_id_hash.zeroize();
    }
    let mut info_hash = info_hash_result?;
    let mut key_schedule_context = [
        [HPKE_MODE_BASE].as_slice(),
        psk_id_hash.as_slice(),
        info_hash.as_slice(),
    ]
    .concat();
    psk_id_hash.zeroize();
    info_hash.zeroize();

    let secret_result = hpke_labeled_extract(Some(shared_secret), b"secret", &[]);
    if secret_result.is_err() {
        key_schedule_context.zeroize();
    }
    let mut secret = secret_result?;

    let key_result = hpke_labeled_expand::<KEY_SIZE>(&secret, b"key", &key_schedule_context);
    if key_result.is_err() {
        secret.zeroize();
        key_schedule_context.zeroize();
    }
    let mut key = key_result?;

    let nonce_result =
        hpke_labeled_expand::<HPKE_NONCE_SIZE>(&secret, b"base_nonce", &key_schedule_context);
    secret.zeroize();
    key_schedule_context.zeroize();

    let nonce = match nonce_result {
        Ok(nonce) => nonce,
        Err(err) => {
            key.zeroize();
            return Err(err);
        }
    };
    Ok((key, nonce))
}

fn legacy_hpke_key_schedule(
    dh: &[u8; KEY_SIZE],
    enc: &[u8; KEY_SIZE],
    recipient_public: &[u8; KEY_SIZE],
    context: &[u8],
) -> PublicResult<([u8; KEY_SIZE], [u8; HPKE_NONCE_SIZE])> {
    // Legacy Worklist envelopes were not RFC 9180 DHKEM: they fed raw X25519
    // DH output into the HPKE labeled key schedule and bound
    // enc || recipient || info as context. Keep this only for old 0x0010
    // accept-on-read envelopes.
    let suite_id = legacy_hpke_suite_id();
    let mut kem_context = [enc.as_slice(), recipient_public.as_slice()].concat();
    let mut key_schedule_context =
        [[HPKE_MODE_BASE].as_slice(), kem_context.as_slice(), context].concat();
    kem_context.zeroize();

    let secret_result = hpke_labeled_extract_with_suite(&suite_id, None, b"secret", dh);
    if secret_result.is_err() {
        key_schedule_context.zeroize();
    }
    let mut secret = secret_result?;

    let key_result = hpke_labeled_expand_with_suite::<KEY_SIZE>(
        &suite_id,
        &secret,
        b"key",
        &key_schedule_context,
    );
    if key_result.is_err() {
        secret.zeroize();
        key_schedule_context.zeroize();
    }
    let mut key = key_result?;

    let nonce_result = hpke_labeled_expand_with_suite::<HPKE_NONCE_SIZE>(
        &suite_id,
        &secret,
        b"base_nonce",
        &key_schedule_context,
    );
    secret.zeroize();
    key_schedule_context.zeroize();

    let nonce = match nonce_result {
        Ok(nonce) => nonce,
        Err(err) => {
            key.zeroize();
            return Err(err);
        }
    };
    Ok((key, nonce))
}

fn hpke_labeled_extract(
    salt: Option<&[u8]>,
    label: &[u8],
    ikm: &[u8],
) -> PublicResult<[u8; KEY_SIZE]> {
    hpke_labeled_extract_with_suite(&hpke_suite_id(), salt, label, ikm)
}

fn hpke_labeled_extract_with_suite(
    suite_id: &[u8],
    salt: Option<&[u8]>,
    label: &[u8],
    ikm: &[u8],
) -> PublicResult<[u8; KEY_SIZE]> {
    let mut labeled_ikm = hpke_labeled_ikm(suite_id, label, ikm);
    let default_salt = [0u8; KEY_SIZE];
    let salt = salt.unwrap_or(&default_salt);
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(salt) {
        Ok(mac) => mac,
        Err(err) => {
            labeled_ikm.zeroize();
            return Err(PublicError::crypto(format!(
                "hpke extract init failed: {err}"
            )));
        }
    };
    mac.update(&labeled_ikm);
    labeled_ikm.zeroize();
    let mut prk = mac.finalize().into_bytes();
    let mut output = [0u8; KEY_SIZE];
    output.copy_from_slice(&prk);
    prk.zeroize();
    Ok(output)
}

fn hpke_labeled_expand<const N: usize>(
    prk: &[u8; KEY_SIZE],
    label: &[u8],
    info: &[u8],
) -> PublicResult<[u8; N]> {
    hpke_labeled_expand_with_suite(&hpke_suite_id(), prk, label, info)
}

fn hpke_labeled_expand_with_suite<const N: usize>(
    suite_id: &[u8],
    prk: &[u8; KEY_SIZE],
    label: &[u8],
    info: &[u8],
) -> PublicResult<[u8; N]> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|err| PublicError::crypto(format!("hpke prk init failed: {err}")))?;
    let mut labeled_info = hpke_labeled_info(suite_id, N as u16, label, info);
    let mut output = [0u8; N];
    let expand_result = hkdf.expand(&labeled_info, &mut output);
    labeled_info.zeroize();
    if let Err(err) = expand_result {
        output.zeroize();
        return Err(PublicError::crypto(format!("hpke expand failed: {err}")));
    }
    Ok(output)
}

fn hpke_labeled_ikm(suite_id: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
    [b"HPKE-v1".as_slice(), suite_id, label, ikm].concat()
}

fn hpke_labeled_info(suite_id: &[u8], length: u16, label: &[u8], info: &[u8]) -> Vec<u8> {
    [
        length.to_be_bytes().as_slice(),
        b"HPKE-v1".as_slice(),
        suite_id,
        label,
        info,
    ]
    .concat()
}

fn hpke_kem_suite_id() -> Vec<u8> {
    [b"KEM".as_slice(), HPKE_KEM_ID.as_slice()].concat()
}

fn hpke_suite_id() -> Vec<u8> {
    [
        b"HPKE".as_slice(),
        HPKE_KEM_ID.as_slice(),
        HPKE_KDF_ID.as_slice(),
        HPKE_AEAD_ID.as_slice(),
    ]
    .concat()
}

fn legacy_hpke_suite_id() -> Vec<u8> {
    [
        b"HPKE".as_slice(),
        HPKE_LEGACY_KEM_ID.as_slice(),
        HPKE_KDF_ID.as_slice(),
        HPKE_AEAD_ID.as_slice(),
    ]
    .concat()
}

fn hpke_seal(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; HPKE_NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> PublicResult<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut buffer = plaintext.to_vec();
    let tag = match cipher.encrypt_in_place_detached(nonce.into(), aad, &mut buffer) {
        Ok(tag) => tag,
        Err(_) => {
            buffer.zeroize();
            return Err(PublicError::crypto("hpke encrypt failed"));
        }
    };
    buffer.extend_from_slice(&tag);
    Ok(buffer)
}

fn hpke_open(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; HPKE_NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> PublicResult<Vec<u8>> {
    if ciphertext.len() < 16 {
        return Err(PublicError::validation(
            "agent grant ciphertext is truncated",
        ));
    }
    let split = ciphertext.len() - 16;
    let (message, tag_bytes) = ciphertext.split_at(split);
    let mut buffer = message.to_vec();
    let cipher = ChaCha20Poly1305::new(key.into());
    if cipher
        .decrypt_in_place_detached(nonce.into(), aad, &mut buffer, tag_bytes.into())
        .is_err()
    {
        buffer.zeroize();
        return Err(PublicError::crypto("hpke decrypt failed"));
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deserialize_from_cbor;

    #[test]
    fn encrypt_agent_work_list_key_round_trips() {
        let work_list_id = uuid::Uuid::now_v7();
        let list_key = SymmetricKey::new([0x42; KEY_SIZE]);
        let recipient_private = X25519StaticSecret::random();
        let recipient_public = X25519PublicKey::from(&recipient_private);

        let sealed =
            encrypt_agent_work_list_key(recipient_public.as_bytes(), &work_list_id, &list_key)
                .expect("encrypt agent grant");
        let envelope: HpkeEnvelope =
            deserialize_from_cbor(&sealed.bytes).expect("decode agent grant envelope");
        assert_eq!(envelope.suite, HpkeSuite::supported());
        let decrypted = decrypt_agent_work_list_key(
            &recipient_private.to_bytes(),
            &work_list_id,
            &sealed.bytes,
        )
        .expect("decrypt agent grant");

        assert_eq!(decrypted, list_key);
    }

    #[test]
    fn decrypt_agent_work_list_key_accepts_legacy_hpke_suite() {
        let work_list_id =
            uuid::Uuid::parse_str("018f2a22-5f8c-7b2a-9e49-2f9b76153c11").expect("work list id");
        let list_key = SymmetricKey::new([0x42; KEY_SIZE]);
        let recipient_private_key = hex_array::<KEY_SIZE>(
            "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
        );
        // Frozen vector for the Rust CBOR envelope shape using the legacy
        // Worklist schedule from commit 012e0aa: KEM 0x0010 with X25519 key
        // material and direct DH-to-key-schedule derivation.
        let sealed = hex_bytes(
            "a46776657273696f6e01657375697465a4636b656d10636b646601646165616403\
             646d6f64650063656e6358201afa08d3dec047a643885163f1180476fa7ddb54\
             c6a8029ea33f95796bf2ac4a6a636970686572746578745830a96f2d9e590d\
             86ddb9446ac350e03aa0f66884d76cb094f0b37438436b9da36027e3106a8d\
             d8982ee20cf1195736576b",
        );

        let before_count = legacy_agent_grant_hpke_open_count();
        let decrypted = decrypt_agent_work_list_key(&recipient_private_key, &work_list_id, &sealed)
            .expect("decrypt legacy agent grant");

        assert_eq!(decrypted, list_key);
        assert_eq!(legacy_agent_grant_hpke_open_count(), before_count + 1);
    }

    #[test]
    fn decrypt_agent_work_list_key_validates_private_key_length_before_ciphertext() {
        let work_list_id = uuid::Uuid::now_v7();
        let recipient_private_key = vec![0x33; KEY_SIZE - 1];

        let err = decrypt_agent_work_list_key(&recipient_private_key, &work_list_id, b"not cbor")
            .expect_err("private key length should be validated first");

        assert_validation_error(err, "agent recipient private key must be 32 bytes");
    }

    #[test]
    fn decrypt_agent_work_list_key_rejects_trailing_cbor_bytes() {
        let work_list_id = uuid::Uuid::now_v7();
        let recipient_private = X25519StaticSecret::random();
        let recipient_public = X25519PublicKey::from(&recipient_private);
        let list_key = SymmetricKey::new([0x42; KEY_SIZE]);
        let mut ciphertext =
            encrypt_agent_work_list_key(recipient_public.as_bytes(), &work_list_id, &list_key)
                .expect("encrypt agent grant")
                .bytes;
        ciphertext.push(0);

        let err =
            decrypt_agent_work_list_key(&recipient_private.to_bytes(), &work_list_id, &ciphertext)
                .expect_err("trailing CBOR data should be rejected");

        assert_validation_error(err, "CBOR payload contains trailing bytes");
    }

    #[test]
    fn hpke_labeled_extract_returns_raw_hkdf_extract_prk() {
        let suite_id = hpke_suite_id();
        let salt = [0xa0; KEY_SIZE];
        let ikm = [0xb1; KEY_SIZE];
        let labeled_ikm = [
            b"HPKE-v1".as_slice(),
            suite_id.as_slice(),
            b"secret".as_slice(),
            ikm.as_slice(),
        ]
        .concat();
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&salt).expect("hmac should accept sha256 salt");
        mac.update(&labeled_ikm);
        let expected = mac.finalize().into_bytes();

        let actual = hpke_labeled_extract_with_suite(&suite_id, Some(&salt), b"secret", &ikm)
            .expect("labeled extract");

        assert_eq!(actual.as_slice(), &expected[..]);
    }

    #[test]
    fn hpke_base_mode_matches_rfc9180_x25519_chacha20poly1305_vector() {
        let sender_private_key = hex_array::<KEY_SIZE>(
            "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
        );
        let enc = hex_array::<KEY_SIZE>(
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
        );
        let recipient_public_key = hex_array::<KEY_SIZE>(
            "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
        );
        let expected_shared_secret = hex_array::<KEY_SIZE>(
            "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
        );
        let info = hex_bytes("4f6465206f6e2061204772656369616e2055726e");
        let expected_key = hex_array::<KEY_SIZE>(
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
        );
        let expected_base_nonce = hex_array::<HPKE_NONCE_SIZE>("5c4d98150661b848853b547f");
        let plaintext = hex_bytes("4265617574792069732074727574682c20747275746820626561757479");
        let aad = hex_bytes("436f756e742d30");
        let expected_ciphertext = hex_bytes(
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db\
             21993c62ce81883d2dd1b51a28",
        );

        assert_eq!(HpkeSuite::supported().kem, 32);
        assert_eq!(hpke_kem_suite_id(), b"KEM\x00\x20".to_vec());
        assert_eq!(hpke_suite_id(), b"HPKE\x00\x20\x00\x01\x00\x03".to_vec());

        let sender_private = X25519StaticSecret::from(sender_private_key);
        assert_eq!(X25519PublicKey::from(&sender_private).to_bytes(), enc);
        let shared = sender_private.diffie_hellman(&X25519PublicKey::from(recipient_public_key));
        let dh = ensure_contributory_shared_secret(&shared).expect("contributory dh");

        let shared_secret =
            hpke_dhkem_shared_secret(&dh, &enc, &recipient_public_key).expect("shared secret");
        assert_eq!(shared_secret, expected_shared_secret);

        let (key, base_nonce) = hpke_key_schedule(&shared_secret, &info).expect("key schedule");
        assert_eq!(key, expected_key);
        assert_eq!(base_nonce, expected_base_nonce);

        let ciphertext = hpke_seal(&key, &base_nonce, &aad, &plaintext).expect("seal plaintext");
        assert_eq!(ciphertext, expected_ciphertext);
        let decrypted = hpke_open(&key, &base_nonce, &aad, &ciphertext).expect("open ciphertext");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_agent_work_list_key_rejects_non_contributory_recipient_public_key() {
        let work_list_id = uuid::Uuid::now_v7();
        let list_key = SymmetricKey::new([0x42; KEY_SIZE]);

        let err = encrypt_agent_work_list_key(&[0; KEY_SIZE], &work_list_id, &list_key)
            .expect_err("all-zero recipient public key should be rejected");

        assert_invalid_hpke_shared_secret(err);
    }

    #[test]
    fn decrypt_agent_work_list_key_rejects_non_contributory_encapsulated_key() {
        let work_list_id = uuid::Uuid::now_v7();
        let recipient_private_key = [0x33; KEY_SIZE];
        let envelope = HpkeEnvelope {
            version: 1,
            suite: HpkeSuite::supported(),
            enc: vec![0; KEY_SIZE],
            ciphertext: vec![0; 16],
        };
        let ciphertext = serialize_to_cbor(&envelope).expect("serialize agent grant envelope");

        let err = decrypt_agent_work_list_key(&recipient_private_key, &work_list_id, &ciphertext)
            .expect_err("all-zero encapsulated key should be rejected");

        assert_invalid_hpke_shared_secret(err);
    }

    #[test]
    fn decrypt_agent_work_list_key_rejects_unsupported_hpke_suite() {
        let work_list_id = uuid::Uuid::now_v7();
        let recipient_private_key = [0x33; KEY_SIZE];
        let mut suite = HpkeSuite::supported();
        suite.aead = 0xffff;
        let envelope = HpkeEnvelope {
            version: 1,
            suite,
            enc: vec![0x44; KEY_SIZE],
            ciphertext: vec![0; 16],
        };
        let ciphertext = serialize_to_cbor(&envelope).expect("serialize agent grant envelope");

        let err = decrypt_agent_work_list_key(&recipient_private_key, &work_list_id, &ciphertext)
            .expect_err("unsupported ciphersuite should be rejected");

        assert_validation_error(err, "agent grant uses an unsupported HPKE ciphersuite");
    }

    #[test]
    fn hpke_dhkem_shared_secret_binds_kem_context() {
        let dh = [0x11; KEY_SIZE];
        let enc = [0x22; KEY_SIZE];
        let other_enc = [0x23; KEY_SIZE];
        let recipient_public = [0x33; KEY_SIZE];
        let other_recipient_public = [0x34; KEY_SIZE];

        let baseline =
            hpke_dhkem_shared_secret(&dh, &enc, &recipient_public).expect("baseline secret");
        let changed_enc =
            hpke_dhkem_shared_secret(&dh, &other_enc, &recipient_public).expect("enc secret");
        let changed_recipient =
            hpke_dhkem_shared_secret(&dh, &enc, &other_recipient_public).expect("recipient secret");

        assert_ne!(baseline, changed_enc);
        assert_ne!(baseline, changed_recipient);
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex_bytes(value);
        assert_eq!(bytes.len(), N);
        let mut output = [0u8; N];
        output.copy_from_slice(&bytes);
        output
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        let compact: String = value.chars().filter(|char| !char.is_whitespace()).collect();
        assert_eq!(compact.len() % 2, 0);
        compact
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let byte = std::str::from_utf8(pair).expect("hex byte should be utf8");
                u8::from_str_radix(byte, 16).expect("hex byte should parse")
            })
            .collect()
    }

    fn assert_invalid_hpke_shared_secret(err: PublicError) {
        assert_validation_error(err, "derived HPKE shared secret is invalid");
    }

    fn assert_validation_error(err: PublicError, expected: &str) {
        match err {
            PublicError::Validation(message) => {
                assert_eq!(message, expected);
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }
}
