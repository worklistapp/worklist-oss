#![cfg_attr(test, allow(clippy::unwrap_used))]

mod agents;
mod attachments;
mod audit;
mod client;
mod comments;
mod errors;
mod tasks;
mod users;
mod work_lists;

pub use agents::{
    AgentEnrollmentResponse, AgentGrantResponse, AgentSummaryResponse, AgentTokenResponse,
    ApproveAgentEnrollmentRequest, ApproveAgentGrantRequest, LookupAgentEnrollmentRequest,
};
pub use attachments::DownloadAttachmentResponse;
pub use audit::{AuditPatchFieldRequest, AuditPatchRequest};
pub use client::PublicApiClient;
pub use comments::{
    CommentResponse, CreateCommentRequest, DeleteCommentRequest, UpdateCommentRequest,
};
pub use errors::ApiErrorResponse;
pub use tasks::{
    ArchiveTaskRequest, ArchivedTaskCountResponse, CreateTaskRequest, DelegationResponse,
    DeleteTaskRequest, MoveTaskRequest, MyTaskResponse, MyTasksResponse, PublicTaskRef,
    TaskDetailResponse, TaskListResponse, TaskResponse, UnarchiveTaskRequest, UpdateTaskRequest,
};
pub use users::{CurrentUserResponse, DashboardStatsResponse};
pub use work_lists::{
    MembershipResponse, SectionSnapshotPayload, WorkListDetailResponse, WorkListResponse,
};

pub type SealedBlob = String;

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    #[test]
    fn agent_token_response_debug_redacts_access_token() {
        let response = AgentTokenResponse {
            access_token: "agent-access-secret".to_string(),
            expires_in: 900,
            token_type: "Bearer".to_string(),
            agent_id: Uuid::now_v7(),
            owner_user_id: Uuid::now_v7(),
        };

        let debug_output = format!("{response:?}");

        assert!(debug_output.contains("[redacted]"));
        assert!(!debug_output.contains("agent-access-secret"));
    }

    #[test]
    fn delete_audit_patch_rejects_plaintext_scalar_fields() {
        let request = DeleteTaskRequest {
            audit_patch: Some(AuditPatchRequest {
                fields: vec![AuditPatchFieldRequest {
                    field: "CLIENT-ENC field sentinel".to_string(),
                    change_kind: "clear".to_string(),
                    before_scalar: Some("plaintext sentinel".to_string()),
                    after_scalar: None,
                    before_ciphertext_digest: None,
                    after_ciphertext_digest: None,
                }],
                payload_ciphertext: "ciphertext".to_string(),
                payload_ciphertext_proof: "proof".to_string(),
                payload_version: 1,
            }),
        };

        let err = request
            .validate_encrypted_boundary()
            .expect_err("scalar audit field should be rejected");

        assert!(err.to_string().contains("plaintext scalar values"));
        assert!(!err.to_string().contains("CLIENT-ENC field sentinel"));
    }

    #[test]
    fn delete_audit_patch_allows_ciphertext_digest_fields() {
        let task_request = DeleteTaskRequest {
            audit_patch: Some(AuditPatchRequest {
                fields: vec![AuditPatchFieldRequest {
                    field: "body".to_string(),
                    change_kind: "clear".to_string(),
                    before_scalar: None,
                    after_scalar: None,
                    before_ciphertext_digest: Some("before-digest".to_string()),
                    after_ciphertext_digest: None,
                }],
                payload_ciphertext: "ciphertext".to_string(),
                payload_ciphertext_proof: "proof".to_string(),
                payload_version: 1,
            }),
        };
        let comment_request = DeleteCommentRequest {
            audit_patch: task_request.audit_patch.clone(),
        };

        task_request
            .validate_encrypted_boundary()
            .expect("ciphertext-only task audit patch should pass");
        comment_request
            .validate_encrypted_boundary()
            .expect("ciphertext-only comment audit patch should pass");
    }
}
