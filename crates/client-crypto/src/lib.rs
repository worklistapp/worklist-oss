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
pub const ATTACHMENT_BLOB_CONTEXT: &[u8] = b"worklist.attachment.blob.v1";
pub const ATTACHMENT_REF_CONTEXT: &[u8] = b"worklist.attachment.ref.v1";
pub const ATTACHMENT_BLOB_CONTEXT_LABEL: &str = "worklist.attachment.blob.v1";
pub const ATTACHMENT_BLOB_REF_VERSION: u8 = 1;
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
pub struct AttachmentBlobRef {
    pub version: u8,
    pub object_key: String,
    pub ciphertext_bytes: u64,
    pub file_key: Vec<u8>,
    #[serde(default = "default_attachment_blob_context_label")]
    pub enc_context: String,
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
    hkdf.expand(purpose.as_ref(), &mut okm)
        .map_err(|err| PublicError::crypto(format!("hkdf expansion failed: {err}")))?;
    Ok(SymmetricKey::new(okm))
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
    let data_key = strong_box
        .decrypt(sealed, USER_DATA_KEY_CONTEXT)
        .map_err(|err| PublicError::crypto(format!("failed to decrypt data key: {err}")))?;

    symmetric_key_from_bytes(&data_key)
}

pub fn decrypt_work_list_key(
    data_key: &SymmetricKey,
    work_list_key_ciphertext: &[u8],
) -> PublicResult<SymmetricKey> {
    let plaintext = decrypt_sealed_bytes(
        data_key,
        work_list_key_ciphertext,
        WORK_LIST_MEMBERSHIP_CONTEXT,
        "failed to decrypt work list key",
    )?;
    let key_bytes = decode_work_list_key_bytes(&plaintext)?;
    symmetric_key_from_bytes(&key_bytes)
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
