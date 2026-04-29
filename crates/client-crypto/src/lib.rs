#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::{fmt::Debug, io::Cursor};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInPlace};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use strong_box::{Key as StrongBoxKey, StaticStrongBox, StrongBox};
use x25519_dalek::{
    PublicKey as X25519PublicKey, SharedSecret as X25519SharedSecret,
    StaticSecret as X25519StaticSecret,
};
use zeroize::Zeroize;

use worklist_client_core::{PublicError, PublicResult};

pub const USER_DATA_KEY_CONTEXT: &[u8] = b"worklist.user.data_key";
pub const WORK_LIST_PAYLOAD_CONTEXT: &[u8] = b"worklist.work_list.v1";
pub const WORK_LIST_MEMBERSHIP_CONTEXT: &[u8] = b"worklist.membership";
pub const TASK_PAYLOAD_CONTEXT: &[u8] = b"worklist.task.v1";
pub const COMMENT_PAYLOAD_CONTEXT: &[u8] = b"worklist.comment.v1";
pub const ATTACHMENT_BLOB_CONTEXT: &[u8] = b"worklist.attachment.blob.v1";
pub const ATTACHMENT_REF_CONTEXT: &[u8] = b"worklist.attachment.ref.v1";
pub const ATTACHMENT_BLOB_CONTEXT_LABEL: &str = "worklist.attachment.blob.v1";
pub const ATTACHMENT_BLOB_REF_VERSION: u8 = 1;
pub const DATA_KEY_SALT_BYTES: usize = 32;
pub const KEY_SIZE: usize = 32;
const HPKE_NONCE_SIZE: usize = 12;
const HPKE_MODE_BASE: u8 = 0x00;
const HPKE_KEM_CODEPOINT: u16 = 0x0020;
const HPKE_KDF_CODEPOINT: u16 = 0x0001;
const HPKE_AEAD_CODEPOINT: u16 = 0x0003;
const HPKE_KEM_ID: [u8; 2] = HPKE_KEM_CODEPOINT.to_be_bytes();
const HPKE_KDF_ID: [u8; 2] = HPKE_KDF_CODEPOINT.to_be_bytes();
const HPKE_AEAD_ID: [u8; 2] = HPKE_AEAD_CODEPOINT.to_be_bytes();

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoCapability {
    DataKeyUnwrap,
    WorkListKeyDecrypt,
    PayloadSeal,
    PayloadProof,
}

impl CryptoCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataKeyUnwrap => "data_key_unwrap",
            Self::WorkListKeyDecrypt => "work_list_key_decrypt",
            Self::PayloadSeal => "payload_seal",
            Self::PayloadProof => "payload_proof",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymmetricKey([u8; KEY_SIZE]);

impl SymmetricKey {
    pub fn new(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> PublicResult<Self> {
        symmetric_key_from_bytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    fn to_strong_box_key(&self) -> StrongBoxKey {
        StrongBoxKey::from(Box::new(self.0))
    }
}

#[derive(Clone, Default)]
pub struct KeyDerivationService {
    argon2: Argon2<'static>,
}

impl KeyDerivationService {
    pub fn new() -> Self {
        let params = Params::new(64 * 1024, 3, 1, None).expect("frontend-compatible argon2 params");
        Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    pub fn derive_master_key(
        &self,
        secret: impl AsRef<[u8]>,
        salt: &[u8],
    ) -> PublicResult<SymmetricKey> {
        if salt.len() < 8 {
            return Err(PublicError::validation("salt must be at least 8 bytes"));
        }

        let mut output = [0u8; KEY_SIZE];
        let derivation_result = self
            .argon2
            .hash_password_into(secret.as_ref(), salt, &mut output);
        if let Err(err) = derivation_result {
            output.zeroize();
            return Err(PublicError::crypto(format!(
                "argon2id derivation failed: {err}"
            )));
        }

        let key = SymmetricKey::new(output);
        output.zeroize();
        Ok(key)
    }
}

#[derive(Clone, Debug)]
pub struct StrongBoxKeyRing {
    encryption: SymmetricKey,
    history: Vec<SymmetricKey>,
}

impl StrongBoxKeyRing {
    pub fn new(current: SymmetricKey) -> Self {
        Self {
            encryption: current,
            history: Vec::new(),
        }
    }

    pub fn strong_box(&self) -> StaticStrongBox {
        let enc = self.encryption.to_strong_box_key();
        let mut dec_keys: Vec<StrongBoxKey> = Vec::with_capacity(self.history.len() + 1);
        dec_keys.push(self.encryption.to_strong_box_key());
        dec_keys.extend(self.history.iter().map(SymmetricKey::to_strong_box_key));
        StaticStrongBox::new(enc, dec_keys)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedPayload {
    pub version: u8,
    pub ciphertext: Vec<u8>,
}

impl SealedPayload {
    pub const CURRENT_VERSION: u8 = 1;

    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            ciphertext,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> PublicResult<Self> {
        deserialize_from_cbor(bytes)
    }

    pub fn to_bytes(&self) -> PublicResult<Vec<u8>> {
        serialize_to_cbor(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlobPayload {
    pub bytes: Vec<u8>,
    pub base64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentBlobRef {
    pub version: u8,
    pub object_key: String,
    pub ciphertext_bytes: u64,
    pub file_key: Vec<u8>,
    #[serde(default = "default_attachment_blob_context_label")]
    pub enc_context: String,
}

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
}

pub type FlexibleValue = strong_box::ciborium::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPayloadEnvelope {
    pub kind: String,
    pub version: u8,
    pub body: TaskPayloadBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPayloadBody {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_text: Option<TaskPayloadRichText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checklist: Option<Vec<ChecklistItemPayload>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<FlexibleValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<FlexibleValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_meta: Option<FlexibleValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence_state: Option<FlexibleValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPayloadRichText {
    pub format: String,
    pub version: u8,
    pub blocks: Vec<RichTextBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichTextBlock {
    #[serde(rename = "type")]
    pub block_type: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentPayloadEnvelope {
    pub kind: String,
    pub version: u8,
    pub body: CommentPayloadBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommentPayloadBody {
    pub content: TaskPayloadRichText,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<FlexibleValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_meta: Option<FlexibleValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistItemPayload {
    pub id: String,
    pub title: String,
    pub is_done: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee_user_ids: Option<Vec<String>>,
}

pub fn derive_child_key(
    parent: &SymmetricKey,
    purpose: impl AsRef<[u8]>,
) -> PublicResult<SymmetricKey> {
    let mut okm = [0u8; KEY_SIZE];
    let hkdf = Hkdf::<Sha256>::new(None, parent.as_bytes());
    let expand_result = hkdf.expand(purpose.as_ref(), &mut okm);
    if let Err(err) = expand_result {
        okm.zeroize();
        return Err(PublicError::crypto(format!("hkdf expansion failed: {err}")));
    }

    let key = SymmetricKey::new(okm);
    okm.zeroize();
    Ok(key)
}

pub fn derive_work_list_key(
    data_key: &SymmetricKey,
    work_list_id: &uuid::Uuid,
) -> PublicResult<SymmetricKey> {
    derive_child_key(data_key, format!("worklist:{work_list_id}"))
}

pub fn derive_payload_binding_key(list_key: &SymmetricKey) -> PublicResult<SymmetricKey> {
    derive_child_key(list_key, "member:payload-binding")
}

pub fn decrypt_user_data_key(
    password: &str,
    data_key_ciphertext_b64: &str,
) -> PublicResult<SymmetricKey> {
    let bytes = decode_base64(data_key_ciphertext_b64)?;
    let payload = SealedPayload::from_bytes(&bytes)?;
    ensure_payload_version(payload.version)?;

    if payload.ciphertext.len() <= DATA_KEY_SALT_BYTES {
        return Err(PublicError::validation("data key payload is truncated"));
    }

    let (salt, sealed) = payload.ciphertext.split_at(DATA_KEY_SALT_BYTES);
    let key_derivation = KeyDerivationService::new();
    let wrapping_key = key_derivation.derive_master_key(password.as_bytes(), salt)?;

    let strong_box = StrongBoxKeyRing::new(wrapping_key).strong_box();
    let mut data_key = strong_box
        .decrypt(sealed, USER_DATA_KEY_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt data key: {err}")))?;

    let key_result = symmetric_key_from_bytes(&data_key);
    data_key.zeroize();
    key_result
}

pub fn decrypt_work_list_key(
    data_key: &SymmetricKey,
    work_list_key_ciphertext: &[u8],
) -> PublicResult<SymmetricKey> {
    let mut plaintext = decrypt_sealed_bytes(
        data_key,
        work_list_key_ciphertext,
        WORK_LIST_MEMBERSHIP_CONTEXT,
        "failed to decrypt work list key",
    )?;
    let key_bytes_result = decode_work_list_key_bytes(&plaintext);
    plaintext.zeroize();

    let mut key_bytes = key_bytes_result?;
    let key_result = symmetric_key_from_bytes(&key_bytes);
    key_bytes.zeroize();
    key_result
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

    let envelope: HpkeEnvelope = deserialize_from_cbor(ciphertext)?;
    if envelope.version != 1 {
        return Err(PublicError::validation("unsupported agent grant version"));
    }
    ensure_supported_hpke_suite(&envelope.suite)?;
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
    let shared_secret_result = hpke_dhkem_shared_secret(&dh, &enc, &recipient_public);
    dh.zeroize();
    let mut shared_secret = shared_secret_result?;
    let key_schedule_result = hpke_key_schedule(&shared_secret, &context);
    shared_secret.zeroize();
    let (mut key, mut nonce) = key_schedule_result?;
    let plaintext_result = hpke_open(&key, &nonce, &context, &envelope.ciphertext);
    key.zeroize();
    nonce.zeroize();
    let mut plaintext = plaintext_result?;
    let key_result = symmetric_key_from_bytes(&plaintext);
    plaintext.zeroize();
    key_result
}

pub fn decrypt_work_list_payload<T: DeserializeOwned>(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<T> {
    decrypt_sealed_payload(
        list_key,
        payload_ciphertext,
        WORK_LIST_PAYLOAD_CONTEXT,
        "failed to decrypt payload",
    )
}

fn agent_grant_context(work_list_id: &uuid::Uuid) -> Vec<u8> {
    format!("worklist.agent.grant:{work_list_id}").into_bytes()
}

fn ensure_supported_hpke_suite(suite: &HpkeSuite) -> PublicResult<()> {
    if *suite != HpkeSuite::supported() {
        return Err(PublicError::validation(
            "agent grant uses an unsupported HPKE ciphersuite",
        ));
    }

    Ok(())
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

pub fn decrypt_task_payload(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<TaskPayloadEnvelope> {
    decrypt_sealed_payload(
        list_key,
        payload_ciphertext,
        TASK_PAYLOAD_CONTEXT,
        "failed to decrypt task payload",
    )
}

pub fn decrypt_comment_payload(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<CommentPayloadEnvelope> {
    decrypt_sealed_payload(
        list_key,
        payload_ciphertext,
        COMMENT_PAYLOAD_CONTEXT,
        "failed to decrypt comment payload",
    )
}

pub fn decode_attachment_blob_key(
    list_key: &SymmetricKey,
    blob_key: &[u8],
) -> PublicResult<AttachmentBlobRef> {
    let plaintext = decrypt_sealed_bytes(
        list_key,
        blob_key,
        ATTACHMENT_REF_CONTEXT,
        "failed to decrypt attachment reference",
    )?;
    let blob_ref_value: FlexibleValue = deserialize_from_cbor(&plaintext).map_err(|err| {
        PublicError::validation(format!(
            "failed to deserialize attachment reference payload: {err}"
        ))
    })?;
    validate_attachment_blob_ref(parse_attachment_blob_ref(blob_ref_value)?)
}

pub fn decrypt_attachment_bytes(
    ciphertext: &[u8],
    file_key: &[u8],
    enc_context: Option<&str>,
) -> PublicResult<Vec<u8>> {
    let file_key = symmetric_key_from_bytes(file_key)?;
    let context = enc_context.unwrap_or(ATTACHMENT_BLOB_CONTEXT_LABEL);
    decrypt_raw_attachment_bytes(&file_key, ciphertext, context.as_bytes()).or_else(|raw_err| {
        decrypt_sealed_bytes(
            &file_key,
            ciphertext,
            context.as_bytes(),
            "failed to decrypt attachment bytes",
        )
        .map_err(|sealed_err| {
            PublicError::crypto(format!(
                "failed to decrypt attachment bytes as raw StrongBox ciphertext ({raw_err}); also failed wrapped payload fallback ({sealed_err})"
            ))
        })
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TextValuePayload {
    value: String,
}

pub fn decrypt_text_value(payload_ciphertext: &[u8]) -> PublicResult<String> {
    let sealed = SealedPayload::from_bytes(payload_ciphertext)?;
    ensure_payload_version(sealed.version)?;
    let payload: TextValuePayload = deserialize_from_cbor(&sealed.ciphertext)?;
    Ok(payload.value)
}

pub fn flexible_value_to_json(value: FlexibleValue) -> serde_json::Value {
    match value {
        FlexibleValue::Integer(value) => integer_to_json_value(value),
        FlexibleValue::Bytes(bytes) => {
            serde_json::Value::Array(bytes.into_iter().map(serde_json::Value::from).collect())
        }
        FlexibleValue::Float(value) => serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .unwrap_or_else(|| serde_json::Value::String(value.to_string())),
        FlexibleValue::Text(value) => serde_json::Value::String(value),
        FlexibleValue::Bool(value) => serde_json::Value::Bool(value),
        FlexibleValue::Null => serde_json::Value::Null,
        FlexibleValue::Tag(tag, value) => serde_json::json!({
            "tag": tag,
            "value": flexible_value_to_json(*value),
        }),
        FlexibleValue::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(flexible_value_to_json).collect())
        }
        FlexibleValue::Map(entries) => serde_json::Value::Object(
            entries
                .into_iter()
                .map(|(key, value)| {
                    (
                        flexible_map_key_to_string(key),
                        flexible_value_to_json(value),
                    )
                })
                .collect(),
        ),
        other => serde_json::Value::String(format!("{other:?}")),
    }
}

pub fn json_value_to_flexible(value: serde_json::Value) -> FlexibleValue {
    match value {
        serde_json::Value::Null => FlexibleValue::Null,
        serde_json::Value::Bool(value) => FlexibleValue::Bool(value),
        serde_json::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                FlexibleValue::Integer(value.into())
            } else if let Some(value) = value.as_u64() {
                FlexibleValue::Integer(value.into())
            } else {
                FlexibleValue::Float(
                    value
                        .as_f64()
                        .expect("serde_json number should deserialize as f64"),
                )
            }
        }
        serde_json::Value::String(value) => FlexibleValue::Text(value),
        serde_json::Value::Array(values) => {
            FlexibleValue::Array(values.into_iter().map(json_value_to_flexible).collect())
        }
        serde_json::Value::Object(values) => FlexibleValue::Map(
            values
                .into_iter()
                .map(|(key, value)| (FlexibleValue::Text(key), json_value_to_flexible(value)))
                .collect(),
        ),
    }
}

pub fn build_task_payload_envelope(body: TaskPayloadBody, version: u8) -> TaskPayloadEnvelope {
    TaskPayloadEnvelope {
        kind: "task".to_string(),
        version,
        body,
    }
}

fn integer_to_json_value(value: strong_box::ciborium::value::Integer) -> serde_json::Value {
    let value = i128::from(value);
    if let Ok(value) = i64::try_from(value) {
        return serde_json::Value::from(value);
    }
    if let Ok(value) = u64::try_from(value) {
        return serde_json::Value::from(value);
    }

    serde_json::Value::String(value.to_string())
}

fn flexible_map_key_to_string(value: FlexibleValue) -> String {
    match value {
        FlexibleValue::Text(value) => value,
        other => flexible_value_to_json(other).to_string(),
    }
}

fn default_attachment_blob_context_label() -> String {
    ATTACHMENT_BLOB_CONTEXT_LABEL.to_string()
}

fn parse_attachment_blob_ref(value: FlexibleValue) -> PublicResult<AttachmentBlobRef> {
    let json = flexible_value_to_json(value);
    let version = parse_attachment_blob_ref_version(&json)?;
    let object_key = parse_attachment_blob_ref_object_key(&json)?;
    let ciphertext_bytes =
        parse_required_attachment_blob_ref_u64(&json, &["ciphertext_bytes", "ciphertextBytes"])?;
    let file_key = parse_attachment_blob_ref_file_key(&json)?;
    let enc_context =
        parse_optional_attachment_blob_ref_text(&json, &["enc_context", "encContext"])
            .unwrap_or_else(default_attachment_blob_context_label);

    Ok(AttachmentBlobRef {
        version,
        object_key,
        ciphertext_bytes,
        file_key,
        enc_context,
    })
}

fn parse_attachment_blob_ref_version(value: &serde_json::Value) -> PublicResult<u8> {
    let version = parse_required_attachment_blob_ref_u64(value, &["version"])?;
    u8::try_from(version).map_err(|_| {
        PublicError::validation(format!(
            "attachment reference version {version} does not fit in u8"
        ))
    })
}

fn parse_attachment_blob_ref_object_key(value: &serde_json::Value) -> PublicResult<String> {
    parse_required_attachment_blob_ref_text(value, &["object_key", "objectKey"]).or_else(|_| {
        extract_attachment_blob_ref_nested_object_key(value)
            .ok_or_else(|| PublicError::validation("attachment reference object key is required"))
    })
}

fn parse_attachment_blob_ref_file_key(value: &serde_json::Value) -> PublicResult<Vec<u8>> {
    parse_required_attachment_blob_ref_bytes(value, &["file_key", "fileKey"]).or_else(|_| {
        find_attachment_blob_ref_value(value, &["file_key", "fileKey"])
            .and_then(extract_attachment_blob_ref_nested_file_key)
            .ok_or_else(|| PublicError::validation("attachment reference file key is required"))
    })
}

fn parse_required_attachment_blob_ref_text(
    value: &serde_json::Value,
    field_names: &[&str],
) -> PublicResult<String> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_text)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            PublicError::validation(format!(
                "attachment reference {} is required",
                field_names[0]
            ))
        })
}

fn parse_optional_attachment_blob_ref_text(
    value: &serde_json::Value,
    field_names: &[&str],
) -> Option<String> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_text)
        .filter(|value| !value.trim().is_empty())
}

fn parse_required_attachment_blob_ref_u64(
    value: &serde_json::Value,
    field_names: &[&str],
) -> PublicResult<u64> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_u64)
        .ok_or_else(|| {
            PublicError::validation(format!(
                "attachment reference {} is required",
                field_names[0]
            ))
        })
}

fn parse_required_attachment_blob_ref_bytes(
    value: &serde_json::Value,
    field_names: &[&str],
) -> PublicResult<Vec<u8>> {
    find_attachment_blob_ref_value(value, field_names)
        .and_then(extract_attachment_blob_ref_bytes)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PublicError::validation(format!(
                "attachment reference {} is required",
                field_names[0]
            ))
        })
}

fn find_attachment_blob_ref_value<'a>(
    value: &'a serde_json::Value,
    field_names: &[&str],
) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(entries) => {
            for field_name in field_names {
                if let Some(value) = entries.get(*field_name) {
                    return Some(value);
                }
            }
            entries
                .values()
                .find_map(|value| find_attachment_blob_ref_value(value, field_names))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_attachment_blob_ref_value(value, field_names)),
        _ => None,
    }
}

fn extract_attachment_blob_ref_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Array(values) => {
            let bytes = json_array_to_bytes(values)?;
            String::from_utf8(bytes).ok()
        }
        serde_json::Value::Object(_) => extract_attachment_blob_ref_nested_object_key(value),
        _ => None,
    }
}

fn extract_attachment_blob_ref_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(value) => value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok())),
        serde_json::Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn extract_attachment_blob_ref_bytes(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Array(values) => json_array_to_bytes(values),
        serde_json::Value::String(value) => decode_base64(value).ok(),
        serde_json::Value::Object(_) => extract_attachment_blob_ref_nested_file_key(value),
        _ => None,
    }
}

fn extract_attachment_blob_ref_nested_object_key(value: &serde_json::Value) -> Option<String> {
    find_attachment_blob_ref_value(value, &["object_key", "objectKey", "key", "path", "value"])
        .and_then(extract_attachment_blob_ref_text)
}

fn extract_attachment_blob_ref_nested_file_key(value: &serde_json::Value) -> Option<Vec<u8>> {
    find_attachment_blob_ref_value(value, &["file_key", "fileKey", "bytes", "data", "value"])
        .and_then(extract_attachment_blob_ref_bytes)
}

fn json_array_to_bytes(values: &[serde_json::Value]) -> Option<Vec<u8>> {
    values
        .iter()
        .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect()
}

fn validate_attachment_blob_ref(blob_ref: AttachmentBlobRef) -> PublicResult<AttachmentBlobRef> {
    if blob_ref.version != ATTACHMENT_BLOB_REF_VERSION {
        return Err(PublicError::validation(format!(
            "unsupported attachment reference version {}",
            blob_ref.version
        )));
    }
    if blob_ref.object_key.trim().is_empty() {
        return Err(PublicError::validation(
            "attachment reference object key cannot be empty",
        ));
    }
    if blob_ref.ciphertext_bytes == 0 {
        return Err(PublicError::validation(
            "attachment reference ciphertext bytes must be positive",
        ));
    }
    symmetric_key_from_bytes(&blob_ref.file_key)?;
    if blob_ref.enc_context.trim().is_empty() {
        return Err(PublicError::validation(
            "attachment reference encryption context cannot be empty",
        ));
    }
    Ok(blob_ref)
}

pub fn build_comment_payload_envelope(
    body: CommentPayloadBody,
    version: u8,
) -> CommentPayloadEnvelope {
    CommentPayloadEnvelope {
        kind: "comment".to_string(),
        version,
        body,
    }
}

pub fn plaintext_rich_text(markdown: &str) -> Option<TaskPayloadRichText> {
    let trimmed = markdown.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(TaskPayloadRichText {
        format: "markdown".to_string(),
        version: 1,
        blocks: vec![RichTextBlock {
            block_type: "paragraph".to_string(),
            text: trimmed.to_string(),
        }],
    })
}

pub fn encrypt_task_payload(
    envelope: &TaskPayloadEnvelope,
    list_key: &SymmetricKey,
) -> PublicResult<SealedBlobPayload> {
    encrypt_sealed_payload(
        envelope,
        list_key,
        TASK_PAYLOAD_CONTEXT,
        "failed to seal task payload",
    )
}

pub fn encrypt_comment_payload(
    envelope: &CommentPayloadEnvelope,
    list_key: &SymmetricKey,
) -> PublicResult<SealedBlobPayload> {
    encrypt_sealed_payload(
        envelope,
        list_key,
        COMMENT_PAYLOAD_CONTEXT,
        "failed to seal comment payload",
    )
}

pub fn seal_text_value(value: &str) -> PublicResult<SealedBlobPayload> {
    let ciphertext = serialize_to_cbor(&serde_json::json!({ "value": value }))?;
    sealed_blob_from_payload(SealedPayload::new(ciphertext))
}

pub fn compute_payload_proof(
    ciphertext: &[u8],
    binding_key: &SymmetricKey,
) -> PublicResult<String> {
    type PayloadMac = Hmac<Sha256>;

    let mut mac = <PayloadMac as Mac>::new_from_slice(binding_key.as_bytes())
        .map_err(|err| PublicError::crypto(format!("failed to create HMAC: {err}")))?;
    mac.update(ciphertext);
    let bytes = mac.finalize().into_bytes();
    Ok(STANDARD_NO_PAD.encode(bytes))
}

pub fn decode_sealed_blob(b64: &str) -> PublicResult<Vec<u8>> {
    decode_base64(b64)
}

pub fn deserialize_from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> PublicResult<T> {
    let mut cursor = Cursor::new(bytes);
    strong_box::ciborium::de::from_reader(&mut cursor)
        .map_err(|err| PublicError::crypto(format!("failed to deserialize payload: {err}")))
}

pub fn serialize_to_cbor<T: Serialize + ?Sized>(value: &T) -> PublicResult<Vec<u8>> {
    let mut buffer = Vec::new();
    strong_box::ciborium::ser::into_writer(value, &mut buffer)
        .map_err(|err| PublicError::crypto(format!("failed to serialize payload: {err}")))?;
    Ok(buffer)
}

fn decode_base64(value: &str) -> PublicResult<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PublicError::validation("ciphertext cannot be empty"));
    }

    STANDARD_NO_PAD
        .decode(trimmed.as_bytes())
        .or_else(|_| STANDARD.decode(trimmed.as_bytes()))
        .map_err(|err| PublicError::validation(format!("ciphertext must be base64: {err}")))
}

fn decrypt_sealed_payload<T: DeserializeOwned>(
    key: &SymmetricKey,
    payload_ciphertext: &[u8],
    context: &[u8],
    error_context: &str,
) -> PublicResult<T> {
    let plaintext = decrypt_sealed_bytes(key, payload_ciphertext, context, error_context)?;
    deserialize_from_cbor(&plaintext)
}

fn decrypt_sealed_bytes(
    key: &SymmetricKey,
    payload_ciphertext: &[u8],
    context: &[u8],
    error_context: &str,
) -> PublicResult<Vec<u8>> {
    let sealed = SealedPayload::from_bytes(payload_ciphertext)?;
    ensure_payload_version(sealed.version)?;

    StrongBoxKeyRing::new(key.clone())
        .strong_box()
        .decrypt(&sealed.ciphertext, context)
        .map_err(|err| PublicError::crypto(format!("{error_context}: {err}")))
}

fn decrypt_raw_attachment_bytes(
    key: &SymmetricKey,
    ciphertext: &[u8],
    context: &[u8],
) -> PublicResult<Vec<u8>> {
    StrongBoxKeyRing::new(key.clone())
        .strong_box()
        .decrypt(ciphertext, context)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt attachment bytes: {err}")))
}

fn encrypt_sealed_payload<T: Serialize + ?Sized>(
    value: &T,
    key: &SymmetricKey,
    context: &[u8],
    error_context: &str,
) -> PublicResult<SealedBlobPayload> {
    let plaintext = serialize_to_cbor(value)?;
    let ciphertext = StrongBoxKeyRing::new(key.clone())
        .strong_box()
        .encrypt(plaintext, context)
        .map_err(|err| PublicError::crypto(format!("{error_context}: {err}")))?;
    sealed_blob_from_payload(SealedPayload::new(ciphertext))
}

fn symmetric_key_from_bytes(bytes: &[u8]) -> PublicResult<SymmetricKey> {
    if bytes.len() != KEY_SIZE {
        return Err(PublicError::validation(format!(
            "expected {KEY_SIZE}-byte key, got {} bytes",
            bytes.len()
        )));
    }

    let mut array = [0u8; KEY_SIZE];
    array.copy_from_slice(bytes);
    let key = SymmetricKey::new(array);
    array.zeroize();
    Ok(key)
}

fn ensure_payload_version(version: u8) -> PublicResult<()> {
    if version != SealedPayload::CURRENT_VERSION {
        return Err(PublicError::validation(format!(
            "unsupported sealed payload version {version}"
        )));
    }
    Ok(())
}

fn sealed_blob_from_payload(payload: SealedPayload) -> PublicResult<SealedBlobPayload> {
    let bytes = payload.to_bytes()?;
    Ok(SealedBlobPayload {
        base64: STANDARD_NO_PAD.encode(&bytes),
        bytes,
    })
}

fn decode_work_list_key_bytes(plaintext: &[u8]) -> PublicResult<Vec<u8>> {
    let Some(bytes) = try_decode_envelope(plaintext)? else {
        return if plaintext.is_empty() {
            Err(PublicError::validation("work list key cannot be empty"))
        } else {
            Ok(plaintext.to_vec())
        };
    };

    if bytes.is_empty() {
        return Err(PublicError::validation("work list key cannot be empty"));
    }

    Ok(bytes)
}

fn try_decode_envelope(bytes: &[u8]) -> PublicResult<Option<Vec<u8>>> {
    if let Ok(envelope) = deserialize_from_cbor::<WorkListKeyEnvelope>(bytes) {
        let bytes = match envelope.key {
            WorkListKeyField::Bytes(data) => data,
            WorkListKeyField::Text(text) => decode_membership_key_string(&text)?,
        };
        return Ok(Some(bytes));
    }

    if let Ok(raw_bytes) = deserialize_from_cbor::<Vec<u8>>(bytes) {
        return Ok(Some(raw_bytes));
    }

    Ok(None)
}

fn decode_membership_key_string(value: &str) -> PublicResult<Vec<u8>> {
    let normalized = value.trim().replace('-', "+").replace('_', "/");
    if normalized.is_empty() {
        return Err(PublicError::validation(
            "membership key string cannot be empty",
        ));
    }

    STANDARD_NO_PAD
        .decode(normalized.as_bytes())
        .or_else(|_| STANDARD.decode(normalized.as_bytes()))
        .map_err(|err| PublicError::validation(format!("membership key must be base64: {err}")))
}

#[derive(Deserialize)]
struct WorkListKeyEnvelope {
    key: WorkListKeyField,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WorkListKeyField {
    Bytes(Vec<u8>),
    Text(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64_standard() {
        let encoded = STANDARD.encode(b"hello");
        let decoded = decode_base64(&encoded).expect("decode");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_decode_base64_no_pad() {
        let encoded = STANDARD_NO_PAD.encode(b"hello");
        let decoded = decode_base64(&encoded).expect("decode");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_derive_child_key_is_deterministic() {
        let key_derivation = KeyDerivationService::new();
        let master = key_derivation
            .derive_master_key("secret", b"salty-salt")
            .expect("master key");
        let child_a = derive_child_key(&master, "worklist:test").expect("child");
        let child_b = derive_child_key(&master, "worklist:test").expect("child");
        assert_eq!(child_a, child_b);
    }

    #[test]
    fn encrypt_agent_work_list_key_round_trips() {
        let work_list_id = uuid::Uuid::now_v7();
        let list_key = SymmetricKey::new([0x42; KEY_SIZE]);
        let recipient_private = X25519StaticSecret::random();
        let recipient_public = X25519PublicKey::from(&recipient_private);

        let sealed =
            encrypt_agent_work_list_key(recipient_public.as_bytes(), &work_list_id, &list_key)
                .expect("encrypt agent grant");
        let decrypted = decrypt_agent_work_list_key(
            &recipient_private.to_bytes(),
            &work_list_id,
            &sealed.bytes,
        )
        .expect("decrypt agent grant");

        assert_eq!(decrypted, list_key);
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

    #[test]
    fn decode_attachment_blob_key_accepts_nested_legacy_blob_ref_shapes() {
        let list_key = SymmetricKey::new([7; KEY_SIZE]);
        let legacy_blob_ref = serde_json::json!({
            "version": 1,
            "locator": {
                "bucket": "ignored",
                "key": "workspaces/test/attachments/attachment-1",
            },
            "ciphertextBytes": 123,
            "fileKey": {
                "bytes": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]
            },
            "encContext": "worklist.attachment.blob.v1"
        });
        let blob_key = encrypt_sealed_payload(
            &json_value_to_flexible(legacy_blob_ref),
            &list_key,
            ATTACHMENT_REF_CONTEXT,
            "failed to seal attachment reference",
        )
        .expect("seal blob ref")
        .bytes;

        let decoded = decode_attachment_blob_key(&list_key, &blob_key).expect("decode blob ref");

        assert_eq!(decoded.version, 1);
        assert_eq!(
            decoded.object_key,
            "workspaces/test/attachments/attachment-1"
        );
        assert_eq!(decoded.ciphertext_bytes, 123);
        assert_eq!(decoded.file_key, (1u8..=32).collect::<Vec<_>>());
        assert_eq!(decoded.enc_context, ATTACHMENT_BLOB_CONTEXT_LABEL);
    }

    #[test]
    fn decrypt_attachment_bytes_supports_raw_strongbox_ciphertext() {
        let file_key = SymmetricKey::new([9; KEY_SIZE]);
        let plaintext = b"attachment body";
        let ciphertext = StrongBoxKeyRing::new(file_key.clone())
            .strong_box()
            .encrypt(plaintext.as_slice(), ATTACHMENT_BLOB_CONTEXT)
            .expect("encrypt attachment");

        let decrypted = decrypt_attachment_bytes(
            &ciphertext,
            file_key.as_bytes(),
            Some(ATTACHMENT_BLOB_CONTEXT_LABEL),
        )
        .expect("decrypt attachment");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_attachment_bytes_keeps_wrapped_payload_fallback() {
        let file_key = SymmetricKey::new([11; KEY_SIZE]);
        let plaintext = b"wrapped attachment body";
        let raw_ciphertext = StrongBoxKeyRing::new(file_key.clone())
            .strong_box()
            .encrypt(plaintext.as_slice(), ATTACHMENT_BLOB_CONTEXT)
            .expect("encrypt attachment");
        let wrapped_ciphertext = SealedPayload::new(raw_ciphertext)
            .to_bytes()
            .expect("wrap attachment");

        let decrypted = decrypt_attachment_bytes(
            &wrapped_ciphertext,
            file_key.as_bytes(),
            Some(ATTACHMENT_BLOB_CONTEXT_LABEL),
        )
        .expect("decrypt attachment");

        assert_eq!(decrypted, plaintext);
    }
}
