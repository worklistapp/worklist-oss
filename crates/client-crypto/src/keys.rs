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
    decrypt_sealed_bytes, ensure_payload_version,
};

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
