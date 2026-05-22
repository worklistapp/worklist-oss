use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worklist_client_core::PublicResult;

use crate::{SealedBlob, audit::validate_optional_audit_patch};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentResponse {
    pub id: Uuid,
    pub task_id: Uuid,
    pub author_membership_id: Uuid,
    pub author_agent_id: Option<Uuid>,
    pub author_agent_handle: Option<String>,
    pub author_agent_display_name: Option<String>,
    pub body_ciphertext: SealedBlob,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCommentRequest {
    pub body_ciphertext: String,
    pub body_ciphertext_proof: String,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCommentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_ciphertext_proof: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCommentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_patch: Option<crate::AuditPatchRequest>,
}

impl DeleteCommentRequest {
    pub fn validate_encrypted_boundary(&self) -> PublicResult<()> {
        validate_optional_audit_patch(self.audit_patch.as_ref())
    }
}
