use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worklist_client_core::PublicResult;

use crate::{CommentResponse, SealedBlob, audit::validate_optional_audit_patch};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicTaskRef {
    pub id: Uuid,
    pub work_list_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskResponse {
    pub id: Uuid,
    pub work_list_id: Uuid,
    pub created_by_membership_id: Uuid,
    pub title_ciphertext: SealedBlob,
    pub payload_ciphertext: SealedBlob,
    pub section_id: Option<Uuid>,
    pub priority: Option<i8>,
    pub position: String,
    pub due_at: Option<DateTime<Utc>>,
    pub start_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub archived_at: Option<DateTime<Utc>>,
    pub is_completed: bool,
    pub recurrence_id: Option<Uuid>,
    pub recurrence_schedule: Option<String>,
    pub recurrence_iteration: Option<i64>,
    pub materialized_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub comment_count: i64,
    #[serde(default)]
    pub delegations: Vec<DelegationResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskDetailResponse {
    #[serde(flatten)]
    pub task: TaskResponse,
    pub comments: Vec<CommentResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationResponse {
    pub id: Uuid,
    pub task_id: Uuid,
    pub membership_id: Uuid,
    pub role: String,
    pub status: String,
    pub note_ciphertext: Option<SealedBlob>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskListResponse {
    pub tasks: Vec<TaskResponse>,
    #[serde(default)]
    pub archived_counts: Vec<ArchivedTaskCountResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedTaskCountResponse {
    pub section_id: Option<Uuid>,
    pub count: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MyTasksResponse {
    pub tasks: Vec<MyTaskResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MyTaskResponse {
    pub id: Uuid,
    pub work_list_id: Uuid,
    pub work_list_title_ciphertext: SealedBlob,
    pub created_by_membership_id: Uuid,
    pub title_ciphertext: SealedBlob,
    pub payload_ciphertext: SealedBlob,
    pub section_id: Option<Uuid>,
    pub priority: Option<i8>,
    pub due_at: Option<DateTime<Utc>>,
    pub start_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub is_completed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub comment_count: i64,
    #[serde(default)]
    pub delegations: Vec<DelegationResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTaskRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<Uuid>,
    pub title_ciphertext: String,
    pub title_ciphertext_proof: String,
    pub payload_ciphertext: String,
    pub payload_ciphertext_proof: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachment_ids: Vec<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_id: Option<Uuid>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTaskRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_ciphertext_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_ciphertext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_ciphertext_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment_ids: Option<Vec<Uuid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<Option<i8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_at: Option<Option<DateTime<Utc>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_id: Option<Option<Uuid>>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveTaskRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert_before_task_id: Option<Uuid>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveTaskRequest {}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnarchiveTaskRequest {}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTaskRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_patch: Option<crate::AuditPatchRequest>,
}

impl DeleteTaskRequest {
    pub fn validate_encrypted_boundary(&self) -> PublicResult<()> {
        validate_optional_audit_patch(self.audit_patch.as_ref())
    }
}
