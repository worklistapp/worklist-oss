use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationTargetType {
    Membership,
    Agent,
    Unknown(String),
}

impl DelegationTargetType {
    fn as_str(&self) -> &str {
        match self {
            Self::Membership => "membership",
            Self::Agent => "agent",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

impl From<String> for DelegationTargetType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "membership" => Self::Membership,
            "agent" => Self::Agent,
            _ => Self::Unknown(value),
        }
    }
}

impl Serialize for DelegationTargetType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DelegationTargetType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationRole {
    Assignee,
    Follower,
    Unknown(String),
}

impl DelegationRole {
    fn as_str(&self) -> &str {
        match self {
            Self::Assignee => "assignee",
            Self::Follower => "follower",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

impl From<String> for DelegationRole {
    fn from(value: String) -> Self {
        match value.as_str() {
            "assignee" => Self::Assignee,
            "follower" => Self::Follower,
            _ => Self::Unknown(value),
        }
    }
}

impl Serialize for DelegationRole {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DelegationRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationStatus {
    Pending,
    Accepted,
    Declined,
    Unknown(String),
}

impl DelegationStatus {
    fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Declined => "declined",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

impl From<String> for DelegationStatus {
    fn from(value: String) -> Self {
        match value.as_str() {
            "pending" => Self::Pending,
            "accepted" => Self::Accepted,
            "declined" => Self::Declined,
            _ => Self::Unknown(value),
        }
    }
}

impl Serialize for DelegationStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DelegationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationTarget {
    Membership {
        membership_id: Uuid,
    },
    Agent {
        agent_id: Uuid,
    },
    Unknown {
        target_type: String,
        membership_id: Option<Uuid>,
        agent_id: Option<Uuid>,
    },
}

impl DelegationTarget {
    pub fn target_type(&self) -> DelegationTargetType {
        match self {
            Self::Membership { .. } => DelegationTargetType::Membership,
            Self::Agent { .. } => DelegationTargetType::Agent,
            Self::Unknown { target_type, .. } => DelegationTargetType::Unknown(target_type.clone()),
        }
    }

    pub fn membership_id(&self) -> Option<Uuid> {
        match self {
            Self::Membership { membership_id } => Some(*membership_id),
            Self::Agent { .. } => None,
            Self::Unknown { membership_id, .. } => *membership_id,
        }
    }

    pub fn agent_id(&self) -> Option<Uuid> {
        match self {
            Self::Membership { .. } => None,
            Self::Agent { agent_id } => Some(*agent_id),
            Self::Unknown { agent_id, .. } => *agent_id,
        }
    }
}

impl Serialize for DelegationTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DelegationTargetWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DelegationTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DelegationTargetWire::deserialize(deserializer)?;
        Self::try_from(wire).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationResponse {
    pub id: Uuid,
    pub task_id: Uuid,
    #[serde(flatten)]
    pub target: DelegationTarget,
    pub role: DelegationRole,
    pub status: DelegationStatus,
    pub note_ciphertext: Option<SealedBlob>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DelegationTargetWire {
    target_type: DelegationTargetType,
    membership_id: Option<Uuid>,
    agent_id: Option<Uuid>,
}

impl TryFrom<DelegationTargetWire> for DelegationTarget {
    type Error = String;

    fn try_from(value: DelegationTargetWire) -> Result<Self, Self::Error> {
        match value.target_type {
            DelegationTargetType::Membership => {
                let membership_id = value
                    .membership_id
                    .ok_or_else(|| "membership delegation missing membershipId".to_string())?;
                if value.agent_id.is_some() {
                    return Err("membership delegation cannot include agentId".to_string());
                }
                Ok(Self::Membership { membership_id })
            }
            DelegationTargetType::Agent => {
                let agent_id = value
                    .agent_id
                    .ok_or_else(|| "agent delegation missing agentId".to_string())?;
                if value.membership_id.is_some() {
                    return Err("agent delegation cannot include membershipId".to_string());
                }
                Ok(Self::Agent { agent_id })
            }
            DelegationTargetType::Unknown(target_type) => Ok(Self::Unknown {
                target_type,
                membership_id: value.membership_id,
                agent_id: value.agent_id,
            }),
        }
    }
}

impl From<&DelegationTarget> for DelegationTargetWire {
    fn from(value: &DelegationTarget) -> Self {
        Self {
            target_type: value.target_type(),
            membership_id: value.membership_id(),
            agent_id: value.agent_id(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDelegationRequest {
    /// The public agent client only uses status updates. The server also accepts
    /// encrypted note fields for the full app API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<DelegationStatus>,
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
