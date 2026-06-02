use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use hkdf::Hkdf;
use serde::Deserialize;
use sha2::Sha256;
use strong_box::{Key as StrongBoxKey, StaticStrongBox, StrongBox};
use zeroize::Zeroize;

use worklist_client_core::{PublicError, PublicResult};

use crate::{
    DATA_KEY_SALT_BYTES, KEY_SIZE, SealedPayload, USER_DATA_KEY_CONTEXT,
    WORK_LIST_MEMBERSHIP_CONTEXT, cbor::deserialize_complete_from_cbor, decode_base64,
    decrypt_sealed_bytes,
};

const LEGACY_PASSWORD_ARGON2_PAYLOAD_VERSION: u8 = 1;
const OPAQUE_EXPORT_KEY_PAYLOAD_VERSION: u8 = 2;
const OPAQUE_EXPORT_KEY_INFO: &[u8] = b"worklist.opaque.export_key.data_key.v1";
const OPAQUE_EXPORT_KEY_REQUIRED_MESSAGE: &str =
    "OPAQUE export key is required to decrypt this data key payload; run auth login again";

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
    decrypt_user_data_key_with_login_secret(password, None, data_key_ciphertext_b64)
}

pub fn decrypt_user_data_key_with_login_secret(
    password: &str,
    opaque_export_key: Option<&str>,
    data_key_ciphertext_b64: &str,
) -> PublicResult<SymmetricKey> {
    let bytes = decode_base64(data_key_ciphertext_b64)?;
    let payload = SealedPayload::from_bytes(&bytes)?;

    match payload.version {
        LEGACY_PASSWORD_ARGON2_PAYLOAD_VERSION => {
            decrypt_legacy_user_data_key(password, &payload.ciphertext)
        }
        OPAQUE_EXPORT_KEY_PAYLOAD_VERSION => {
            let export_key = opaque_export_key
                .ok_or_else(|| PublicError::validation(OPAQUE_EXPORT_KEY_REQUIRED_MESSAGE))?;
            decrypt_opaque_export_key_user_data_key(export_key, &payload.ciphertext)
        }
        version => Err(PublicError::validation(format!(
            "unsupported data key payload version {version}"
        ))),
    }
}

fn decrypt_legacy_user_data_key(
    password: &str,
    payload_ciphertext: &[u8],
) -> PublicResult<SymmetricKey> {
    if payload_ciphertext.len() <= DATA_KEY_SALT_BYTES {
        return Err(PublicError::validation("data key payload is truncated"));
    }

    let (salt, sealed) = payload_ciphertext.split_at(DATA_KEY_SALT_BYTES);
    let key_derivation = KeyDerivationService::new();
    let wrapping_key = key_derivation.derive_master_key(password.as_bytes(), salt)?;
    decrypt_data_key_with_wrapping_key(wrapping_key, sealed)
}

fn decrypt_opaque_export_key_user_data_key(
    opaque_export_key: &str,
    sealed: &[u8],
) -> PublicResult<SymmetricKey> {
    let wrapping_key = derive_data_key_wrapping_key_from_opaque_export_key(opaque_export_key)?;
    decrypt_data_key_with_wrapping_key(wrapping_key, sealed)
}

fn decrypt_data_key_with_wrapping_key(
    wrapping_key: SymmetricKey,
    sealed: &[u8],
) -> PublicResult<SymmetricKey> {
    let strong_box = StrongBoxKeyRing::new(wrapping_key).strong_box();
    let mut data_key = strong_box
        .decrypt(sealed, USER_DATA_KEY_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt data key: {err}")))?;

    let key_result = symmetric_key_from_bytes(&data_key);
    data_key.zeroize();
    key_result
}

pub fn derive_data_key_wrapping_key_from_opaque_export_key(
    opaque_export_key: &str,
) -> PublicResult<SymmetricKey> {
    let mut export_key_bytes = decode_base64(opaque_export_key)?;
    if export_key_bytes.is_empty() {
        return Err(PublicError::validation("OPAQUE export key cannot be empty"));
    }

    let mut okm = [0u8; KEY_SIZE];
    let hkdf = Hkdf::<Sha256>::new(None, &export_key_bytes);
    let expand_result = hkdf.expand(OPAQUE_EXPORT_KEY_INFO, &mut okm);
    export_key_bytes.zeroize();
    if let Err(err) = expand_result {
        okm.zeroize();
        return Err(PublicError::crypto(format!("hkdf expansion failed: {err}")));
    }

    let key = SymmetricKey::new(okm);
    okm.zeroize();
    Ok(key)
}

pub fn is_opaque_export_key_required_error(error: &PublicError) -> bool {
    matches!(error, PublicError::Validation(message) if message == OPAQUE_EXPORT_KEY_REQUIRED_MESSAGE)
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
pub(crate) fn symmetric_key_from_bytes(bytes: &[u8]) -> PublicResult<SymmetricKey> {
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
pub(crate) fn decode_work_list_key_bytes(plaintext: &[u8]) -> PublicResult<Vec<u8>> {
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
    if let Ok(envelope) = deserialize_complete_from_cbor::<WorkListKeyEnvelope>(bytes) {
        let bytes = match envelope.key {
            WorkListKeyField::Bytes(data) => data,
            WorkListKeyField::Text(text) => decode_membership_key_string(&text)?,
        };
        return Ok(Some(bytes));
    }

    if let Ok(raw_bytes) = deserialize_complete_from_cbor::<Vec<u8>>(bytes) {
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
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};

    use super::*;

    const OPAQUE_EXPORT_KEY_VECTOR: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw";
    const BROWSER_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT: &str =
        "uQACZ3ZlcnNpb24CamNpcGhlcnRleHTYQFhUsbj1g1ASAyVSxOht8es25TKWnoYATJCRkpOUlZaXmJmam1gwO1DSTcsSYAhB/HTiL6uF9RyJkn2wF1suIqrKn5oJOOYXf8Y9ntSemXs3WD7Uevil";
    const RUST_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT: &str =
        "omd2ZXJzaW9uAmpjaXBoZXJ0ZXh0mFQYsRi4GPUYgxhQEgMYJRhSGMQY6BhtGPEY6xg2GOUYMhiWGJ4YhgAYTBjcGJ8YSBhrAhifGKsY5BjrGOQY4RjDGFgYMBh6GCUY1xjYGGMYqhhKBBjoBBh5GOYY7hjIGNYYrhj/Bhj3GGoYwBj+GIYYehjPGG8YdhhbGK0YfRi1BxiFGJwYwRheGN4YfxjuGIkYgBhcGCQYhxhzGPIYbRji";

    #[test]
    fn decrypt_user_data_key_accepts_legacy_argon2_payloads() {
        let password = "correct horse battery staple";
        let data_key = SymmetricKey::new([0x11; KEY_SIZE]);
        let salt = [0x33; DATA_KEY_SALT_BYTES];
        let ciphertext =
            encode_legacy_data_key_ciphertext(password, &salt, &data_key).expect("ciphertext");

        let decrypted = decrypt_user_data_key_with_login_secret(password, None, &ciphertext)
            .expect("decrypt legacy data key");

        assert_eq!(decrypted, data_key);
    }

    #[test]
    fn decrypt_user_data_key_accepts_opaque_export_key_payloads() {
        let data_key = SymmetricKey::new([0x22; KEY_SIZE]);
        let export_key = URL_SAFE_NO_PAD.encode([0xfb; 64]);
        let ciphertext =
            encode_opaque_data_key_ciphertext(&export_key, &data_key).expect("ciphertext");

        let decrypted = decrypt_user_data_key_with_login_secret(
            "unused-password",
            Some(&export_key),
            &ciphertext,
        )
        .expect("decrypt opaque data key");

        assert_eq!(decrypted, data_key);
    }

    #[test]
    fn decrypt_user_data_key_accepts_browser_produced_opaque_export_key_vector() {
        let decrypted = decrypt_user_data_key_with_login_secret(
            "unused-password",
            Some(OPAQUE_EXPORT_KEY_VECTOR),
            BROWSER_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT,
        )
        .expect("decrypt browser-produced opaque data key");

        assert_eq!(decrypted, opaque_data_key_vector());
    }

    #[test]
    fn decrypt_user_data_key_accepts_rust_produced_opaque_export_key_vector() {
        let decrypted = decrypt_user_data_key_with_login_secret(
            "unused-password",
            Some(OPAQUE_EXPORT_KEY_VECTOR),
            RUST_PRODUCED_OPAQUE_DATA_KEY_CIPHERTEXT,
        )
        .expect("decrypt rust-produced opaque data key");

        assert_eq!(decrypted, opaque_data_key_vector());
    }

    #[test]
    fn decrypt_user_data_key_requires_export_key_for_opaque_payloads() {
        let data_key = SymmetricKey::new([0x22; KEY_SIZE]);
        let export_key = URL_SAFE_NO_PAD.encode([0xfb; 64]);
        let ciphertext =
            encode_opaque_data_key_ciphertext(&export_key, &data_key).expect("ciphertext");

        let error = decrypt_user_data_key("password", &ciphertext)
            .expect_err("v2 payload should require export key");

        assert!(matches!(
            error,
            PublicError::Validation(message)
                if message.contains("OPAQUE export key is required")
        ));
    }

    fn encode_legacy_data_key_ciphertext(
        password: &str,
        salt: &[u8; DATA_KEY_SALT_BYTES],
        data_key: &SymmetricKey,
    ) -> PublicResult<String> {
        let wrapping_key =
            KeyDerivationService::new().derive_master_key(password.as_bytes(), salt)?;
        let strong_box = StrongBoxKeyRing::new(wrapping_key).strong_box();
        let sealed = strong_box
            .encrypt(data_key.as_bytes(), USER_DATA_KEY_CONTEXT)
            .expect("seal data key");
        let payload = SealedPayload {
            version: LEGACY_PASSWORD_ARGON2_PAYLOAD_VERSION,
            ciphertext: [salt.as_slice(), sealed.as_slice()].concat(),
        }
        .to_bytes()?;
        Ok(STANDARD_NO_PAD.encode(payload))
    }

    fn encode_opaque_data_key_ciphertext(
        export_key: &str,
        data_key: &SymmetricKey,
    ) -> PublicResult<String> {
        let wrapping_key = derive_data_key_wrapping_key_from_opaque_export_key(export_key)?;
        let strong_box = StrongBoxKeyRing::new(wrapping_key).strong_box();
        let sealed = strong_box
            .encrypt(data_key.as_bytes(), USER_DATA_KEY_CONTEXT)
            .expect("seal data key");
        let payload = SealedPayload {
            version: OPAQUE_EXPORT_KEY_PAYLOAD_VERSION,
            ciphertext: sealed,
        }
        .to_bytes()?;
        Ok(STANDARD_NO_PAD.encode(payload))
    }

    fn opaque_data_key_vector() -> SymmetricKey {
        SymmetricKey::new([
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
            0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9,
            0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
        ])
    }
}
