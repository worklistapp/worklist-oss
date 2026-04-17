#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::{fmt::Debug, io::Cursor};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use strong_box::{Key as StrongBoxKey, StaticStrongBox, StrongBox};

use worklist_client_core::{PublicError, PublicResult};

pub const USER_DATA_KEY_CONTEXT: &[u8] = b"worklist.user.data_key";
pub const WORK_LIST_PAYLOAD_CONTEXT: &[u8] = b"worklist.work_list.v1";
pub const WORK_LIST_MEMBERSHIP_CONTEXT: &[u8] = b"worklist.membership";
pub const TASK_PAYLOAD_CONTEXT: &[u8] = b"worklist.task.v1";
pub const COMMENT_PAYLOAD_CONTEXT: &[u8] = b"worklist.comment.v1";
pub const DATA_KEY_SALT_BYTES: usize = 32;
pub const KEY_SIZE: usize = 32;

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
        let params =
            Params::new(64 * 1024, 3, 1, None).expect("frontend-compatible argon2 params");
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
        self.argon2
            .hash_password_into(secret.as_ref(), salt, &mut output)
            .map_err(|err| PublicError::crypto(format!("argon2id derivation failed: {err}")))?;

        Ok(SymmetricKey::new(output))
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
    pub attachments: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mentions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_meta: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recurrence_state: Option<serde_json::Value>,
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
    pub attachments: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_meta: Option<serde_json::Value>,
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
    hkdf.expand(purpose.as_ref(), &mut okm)
        .map_err(|err| PublicError::crypto(format!("hkdf expansion failed: {err}")))?;
    Ok(SymmetricKey::new(okm))
}

pub fn derive_work_list_key(data_key: &SymmetricKey, work_list_id: &uuid::Uuid) -> PublicResult<SymmetricKey> {
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
    let data_key = strong_box
        .decrypt(sealed, USER_DATA_KEY_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt data key: {err}")))?;

    symmetric_key_from_bytes(&data_key)
}

pub fn decrypt_work_list_key(
    data_key: &SymmetricKey,
    work_list_key_ciphertext: &[u8],
) -> PublicResult<SymmetricKey> {
    let sealed = SealedPayload::from_bytes(work_list_key_ciphertext)?;
    ensure_payload_version(sealed.version)?;

    let strong_box = StrongBoxKeyRing::new(data_key.clone()).strong_box();
    let plaintext = strong_box
        .decrypt(&sealed.ciphertext, WORK_LIST_MEMBERSHIP_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt work list key: {err}")))?;

    let key_bytes = decode_work_list_key_bytes(&plaintext)?;
    symmetric_key_from_bytes(&key_bytes)
}

pub fn decrypt_work_list_payload<T: DeserializeOwned>(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<T> {
    let sealed = SealedPayload::from_bytes(payload_ciphertext)?;
    ensure_payload_version(sealed.version)?;

    let strong_box = StrongBoxKeyRing::new(list_key.clone()).strong_box();
    let plaintext = strong_box
        .decrypt(&sealed.ciphertext, WORK_LIST_PAYLOAD_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt payload: {err}")))?;

    deserialize_from_cbor(&plaintext)
}

pub fn decrypt_task_payload(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<TaskPayloadEnvelope> {
    let sealed = SealedPayload::from_bytes(payload_ciphertext)?;
    ensure_payload_version(sealed.version)?;

    let strong_box = StrongBoxKeyRing::new(list_key.clone()).strong_box();
    let plaintext = strong_box
        .decrypt(&sealed.ciphertext, TASK_PAYLOAD_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt task payload: {err}")))?;

    deserialize_from_cbor(&plaintext)
}

pub fn decrypt_comment_payload(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<CommentPayloadEnvelope> {
    let sealed = SealedPayload::from_bytes(payload_ciphertext)?;
    ensure_payload_version(sealed.version)?;

    let strong_box = StrongBoxKeyRing::new(list_key.clone()).strong_box();
    let plaintext = strong_box
        .decrypt(&sealed.ciphertext, COMMENT_PAYLOAD_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt comment payload: {err}")))?;

    deserialize_from_cbor(&plaintext)
}

pub fn build_task_payload_envelope(body: TaskPayloadBody, version: u8) -> TaskPayloadEnvelope {
    TaskPayloadEnvelope {
        kind: "task".to_string(),
        version,
        body,
    }
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
    let plaintext = serialize_to_cbor(envelope)?;
    let strong_box = StrongBoxKeyRing::new(list_key.clone()).strong_box();
    let ciphertext = strong_box
        .encrypt(plaintext, TASK_PAYLOAD_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to seal task payload: {err}")))?;
    sealed_blob_from_payload(SealedPayload::new(ciphertext))
}

pub fn encrypt_comment_payload(
    envelope: &CommentPayloadEnvelope,
    list_key: &SymmetricKey,
) -> PublicResult<SealedBlobPayload> {
    let plaintext = serialize_to_cbor(envelope)?;
    let strong_box = StrongBoxKeyRing::new(list_key.clone()).strong_box();
    let ciphertext = strong_box
        .encrypt(plaintext, COMMENT_PAYLOAD_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to seal comment payload: {err}")))?;
    sealed_blob_from_payload(SealedPayload::new(ciphertext))
}

pub fn seal_text_value(value: &str) -> PublicResult<SealedBlobPayload> {
    let ciphertext = serialize_to_cbor(&serde_json::json!({ "value": value }))?;
    sealed_blob_from_payload(SealedPayload::new(ciphertext))
}

pub fn compute_payload_proof(ciphertext: &[u8], binding_key: &SymmetricKey) -> PublicResult<String> {
    type PayloadMac = Hmac<Sha256>;

    let mut mac = PayloadMac::new_from_slice(binding_key.as_bytes())
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

fn symmetric_key_from_bytes(bytes: &[u8]) -> PublicResult<SymmetricKey> {
    if bytes.len() != KEY_SIZE {
        return Err(PublicError::validation(format!(
            "expected {KEY_SIZE}-byte key, got {} bytes",
            bytes.len()
        )));
    }

    let mut array = [0u8; KEY_SIZE];
    array.copy_from_slice(bytes);
    Ok(SymmetricKey::new(array))
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
    if let Some(bytes) = try_decode_envelope(plaintext)? {
        if bytes.is_empty() {
            return Err(PublicError::validation("work list key cannot be empty"));
        }
        return Ok(bytes);
    }

    if plaintext.is_empty() {
        return Err(PublicError::validation("work list key cannot be empty"));
    }

    Ok(plaintext.to_vec())
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
        return Err(PublicError::validation("membership key string cannot be empty"));
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
}
