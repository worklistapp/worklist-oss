use serde::{Deserialize, Serialize};
use worklist_client_core::PublicResult;

use crate::{
    ATTACHMENT_BLOB_CONTEXT_LABEL,
    cbor::{deserialize_from_cbor, serialize_to_cbor},
};

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

fn default_attachment_blob_context_label() -> String {
    ATTACHMENT_BLOB_CONTEXT_LABEL.to_string()
}
