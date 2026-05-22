use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;
use worklist_client_api::SectionSnapshotPayload;
use worklist_client_crypto::{ChecklistItemPayload, TaskPayloadRichText};

use crate::{DeleteCommentInput, DeleteTaskInput};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMembership {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub user_name: String,
    pub user_avatar_color: String,
    pub role: String,
    pub status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentWorkListSummary {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub workspace_id: Uuid,
    pub timezone: String,
    pub section_snapshots: Vec<SectionSnapshotPayload>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub membership: AgentMembership,
    pub title: Option<String>,
    pub description: Option<String>,
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<ReadError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentWorkListDetail {
    #[serde(flatten)]
    pub work_list: AgentWorkListSummary,
    pub members: Vec<AgentMembership>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentDelegation {
    pub id: Uuid,
    pub task_id: Uuid,
    pub membership_id: Uuid,
    pub role: String,
    pub status: String,
    pub note_present: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAttachment {
    pub id: Uuid,
    pub file_name: String,
    pub content_type: String,
    pub size_bytes: u64,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub(crate) blob_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentTaskSummary {
    pub id: Uuid,
    pub work_list_id: Uuid,
    pub work_list_title: Option<String>,
    pub created_by_membership_id: Uuid,
    pub section_id: Option<Uuid>,
    pub priority: Option<i8>,
    pub position: Option<String>,
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
    pub title: Option<String>,
    pub body_markdown: Option<String>,
    pub body_rich_text: Option<TaskPayloadRichText>,
    pub checklist: Option<Vec<ChecklistItemPayload>>,
    pub attachments: Option<Vec<AgentAttachment>>,
    pub references: Option<Vec<Value>>,
    pub mentions: Option<Vec<String>>,
    pub client_meta: Option<Value>,
    pub recurrence_state: Option<Value>,
    pub delegations: Vec<AgentDelegation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<ReadError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentComment {
    pub id: Uuid,
    pub task_id: Uuid,
    pub author_membership_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_agent_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_agent_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_agent_display_name: Option<String>,
    pub body_markdown: Option<String>,
    pub content: Option<TaskPayloadRichText>,
    pub mentions: Option<Vec<String>>,
    pub attachments: Option<Vec<AgentAttachment>>,
    pub client_meta: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_error: Option<ReadError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentTaskDetail {
    #[serde(flatten)]
    pub task: AgentTaskSummary,
    pub comments: Vec<AgentComment>,
}

#[derive(Debug, Clone)]
pub struct DownloadedAttachment {
    pub attachment: AgentAttachment,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReadableAttachmentContentFormat {
    Text,
    Markdown,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReadableAttachmentSourceKind {
    PlainText,
    DocxRendered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadableAttachment {
    pub attachment: AgentAttachment,
    pub text: String,
    pub content_format: ReadableAttachmentContentFormat,
    pub source_kind: ReadableAttachmentSourceKind,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskCreateInput {
    pub title: String,
    pub body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskUpdateInput {
    pub title: Option<String>,
    pub body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentInput {
    pub body: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveTaskInput {
    pub section_id: Option<Uuid>,
    pub insert_before_task_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct CreateTaskArgs {
    pub work_list_id: Uuid,
    pub input: TaskCreateInput,
    pub password_stdin: bool,
}

#[derive(Debug)]
pub struct UpdateTaskArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub input: TaskUpdateInput,
    pub password_stdin: bool,
}

#[derive(Debug)]
pub struct MoveTaskArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub input: MoveTaskInput,
    pub password_stdin: bool,
}

#[derive(Debug)]
pub struct ArchiveTaskArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub password_stdin: bool,
}

#[derive(Debug)]
pub struct UnarchiveTaskArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub password_stdin: bool,
}

#[derive(Debug)]
pub struct DeleteTaskArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub input: DeleteTaskInput,
}

#[derive(Debug)]
pub struct CreateCommentArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub input: CommentInput,
    pub password_stdin: bool,
}

#[derive(Debug)]
pub struct UpdateCommentArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub comment_id: Uuid,
    pub input: CommentInput,
    pub password_stdin: bool,
}

#[derive(Debug)]
pub struct DeleteCommentArgs {
    pub work_list_id: Uuid,
    pub task_id: Uuid,
    pub comment_id: Uuid,
    pub input: DeleteCommentInput,
}
