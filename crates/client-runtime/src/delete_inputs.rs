use serde::Deserialize;
use worklist_client_api::{
    AuditPatchFieldRequest, AuditPatchRequest, DeleteCommentRequest, DeleteTaskRequest,
};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAuditPatchFieldInput {
    pub field: String,
    pub change_kind: String,
    pub before_scalar: Option<String>,
    pub after_scalar: Option<String>,
    pub before_ciphertext_digest: Option<String>,
    pub after_ciphertext_digest: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteAuditPatchInput {
    #[serde(default)]
    pub fields: Vec<DeleteAuditPatchFieldInput>,
    pub payload_ciphertext: String,
    pub payload_ciphertext_proof: String,
    pub payload_version: i64,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTaskInput {
    pub audit_patch: Option<DeleteAuditPatchInput>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCommentInput {
    pub audit_patch: Option<DeleteAuditPatchInput>,
}

impl DeleteTaskInput {
    pub(crate) fn into_api_request(self) -> DeleteTaskRequest {
        DeleteTaskRequest {
            audit_patch: self
                .audit_patch
                .map(DeleteAuditPatchInput::into_api_request),
        }
    }
}

impl DeleteCommentInput {
    pub(crate) fn into_api_request(self) -> DeleteCommentRequest {
        DeleteCommentRequest {
            audit_patch: self
                .audit_patch
                .map(DeleteAuditPatchInput::into_api_request),
        }
    }
}

impl DeleteAuditPatchInput {
    fn into_api_request(self) -> AuditPatchRequest {
        AuditPatchRequest {
            fields: self
                .fields
                .into_iter()
                .map(DeleteAuditPatchFieldInput::into_api_request)
                .collect(),
            payload_ciphertext: self.payload_ciphertext,
            payload_ciphertext_proof: self.payload_ciphertext_proof,
            payload_version: self.payload_version,
        }
    }
}

impl DeleteAuditPatchFieldInput {
    fn into_api_request(self) -> AuditPatchFieldRequest {
        AuditPatchFieldRequest {
            field: self.field,
            change_kind: self.change_kind,
            before_scalar: self.before_scalar,
            after_scalar: self.after_scalar,
            before_ciphertext_digest: self.before_ciphertext_digest,
            after_ciphertext_digest: self.after_ciphertext_digest,
        }
    }
}
