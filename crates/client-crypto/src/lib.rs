#![cfg_attr(test, allow(clippy::unwrap_used))]

mod agent_grants;
mod attachments;
mod cbor;
mod keys;
mod payloads;
mod text_fields;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use strong_box::StrongBox;

use worklist_client_core::{PublicError, PublicResult};

pub use agent_grants::{
    decrypt_agent_work_list_key, encrypt_agent_work_list_key, legacy_agent_grant_hpke_open_count,
};
pub use attachments::{decode_attachment_blob_key, decrypt_attachment_bytes};
pub(crate) use cbor::deserialize_complete_from_cbor;
pub use cbor::{
    deserialize_from_cbor, flexible_value_to_json, json_value_to_flexible, serialize_to_cbor,
};
pub(crate) use keys::symmetric_key_from_bytes;
pub use keys::{
    KeyDerivationService, StrongBoxKeyRing, SymmetricKey, decrypt_user_data_key,
    decrypt_work_list_key, derive_child_key, derive_payload_binding_key, derive_work_list_key,
};
pub use payloads::{
    AttachmentBlobRef, ChecklistItemPayload, CommentPayloadBody, CommentPayloadEnvelope,
    FlexibleValue, RichTextBlock, SealedBlobPayload, SealedPayload, TaskPayloadBody,
    TaskPayloadEnvelope, TaskPayloadRichText,
};
pub use text_fields::{
    decrypt_note_title, decrypt_note_title_for_id, decrypt_task_title, decrypt_task_title_for_id,
    decrypt_work_list_description, decrypt_work_list_description_for_id, decrypt_work_list_title,
    decrypt_work_list_title_for_id, seal_note_title, seal_note_title_for_id, seal_task_title,
    seal_task_title_for_id, seal_work_list_description, seal_work_list_description_for_id,
    seal_work_list_title, seal_work_list_title_for_id,
};

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    #[test]
    fn raw_work_list_key_does_not_accept_partial_cbor_decode() {
        let mut key = [0x42; KEY_SIZE];
        key[0] = 0x4d;
        let decoded = crate::keys::decode_work_list_key_bytes(&key).expect("decode raw key");

        assert_eq!(decoded, key);
    }

    #[test]
    fn task_title_helpers_encrypt_with_context_and_round_trip() {
        let list_key = SymmetricKey::new([17; KEY_SIZE]);
        let sealed = seal_task_title("Encrypted title", &list_key).expect("seal task title");

        let decoded = decrypt_task_title(&list_key, &sealed.bytes).expect("decrypt task title");

        assert_eq!(decoded, "Encrypted title");
    }

    #[test]
    fn decrypt_text_value_rejects_wrong_context() {
        let list_key = SymmetricKey::new([18; KEY_SIZE]);
        let sealed = seal_task_title("Encrypted title", &list_key).expect("seal text");

        let wrong_context = decrypt_work_list_title(&list_key, &sealed.bytes);

        assert!(wrong_context.is_err());
    }

    #[test]
    fn decrypt_text_value_rejects_unencrypted_text_payload() {
        let list_key = SymmetricKey::new([19; KEY_SIZE]);
        #[derive(serde::Serialize)]
        struct PlainTextValuePayload {
            value: String,
        }

        let plaintext_payload = serialize_to_cbor(&PlainTextValuePayload {
            value: "Plain server value".to_string(),
        })
        .expect("serialize text payload");
        let sealed = sealed_blob_from_payload(SealedPayload::new(plaintext_payload))
            .expect("seal text payload wrapper");

        let unencrypted_text = decrypt_task_title(&list_key, &sealed.bytes);

        assert!(unencrypted_text.is_err());
    }
}
