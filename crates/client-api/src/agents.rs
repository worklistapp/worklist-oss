use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentEnrollmentResponse {
    pub agent_id: Uuid,
    pub owner_user_id: Option<Uuid>,
    pub status: String,
    pub approved: bool,
    pub auth_public_key: String,
    pub recipient_public_key: String,
    pub enrollment_code: Option<String>,
    pub enrollment_expires_at: Option<DateTime<Utc>>,
    pub handle: Option<String>,
    pub proposed_handle: Option<String>,
    pub display_name: Option<String>,
    pub scope_mode: String,
    pub fingerprint: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub agent_id: Uuid,
    pub owner_user_id: Uuid,
}

impl fmt::Debug for AgentTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentTokenResponse")
            .field("access_token", &"[redacted]")
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .field("agent_id", &self.agent_id)
            .field("owner_user_id", &self.owner_user_id)
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupAgentEnrollmentRequest {
    pub code: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveAgentGrantRequest {
    pub work_list_id: Uuid,
    pub key_ciphertext: String,
    #[serde(flatten)]
    pub permissions: AgentGrantPermissions,
}

impl fmt::Debug for ApproveAgentGrantRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApproveAgentGrantRequest")
            .field("work_list_id", &self.work_list_id)
            .field("key_ciphertext", &"[redacted]")
            .field("permissions", &self.permissions)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentTaskReadScope {
    AssignedOnly,
    FullBoard,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentBoardScope {
    None,
    AssignedOnly,
    FullBoard,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentAssignmentScope {
    None,
    SelfAcceptOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentGrantPermissions {
    pub task_read_scope: AgentTaskReadScope,
    pub task_write_scope: AgentBoardScope,
    pub comment_scope: AgentBoardScope,
    pub attachment_scope: AgentBoardScope,
    pub assignment_scope: AgentAssignmentScope,
}

impl AgentGrantPermissions {
    pub fn assigned_task_worker() -> Self {
        Self {
            task_read_scope: AgentTaskReadScope::AssignedOnly,
            task_write_scope: AgentBoardScope::AssignedOnly,
            comment_scope: AgentBoardScope::AssignedOnly,
            attachment_scope: AgentBoardScope::AssignedOnly,
            assignment_scope: AgentAssignmentScope::SelfAcceptOnly,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveAgentEnrollmentRequest {
    pub code: String,
    pub handle: String,
    pub display_name: String,
    pub scope_mode: String,
    pub fingerprint: String,
    pub grants: Vec<ApproveAgentGrantRequest>,
}

impl fmt::Debug for ApproveAgentEnrollmentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApproveAgentEnrollmentRequest")
            .field("code", &"[redacted]")
            .field("handle", &self.handle)
            .field("display_name", &self.display_name)
            .field("scope_mode", &self.scope_mode)
            .field("fingerprint", &self.fingerprint)
            .field("grants", &self.grants)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentGrantResponse {
    pub work_list_id: Uuid,
    #[serde(flatten)]
    pub permissions: AgentGrantPermissions,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSummaryResponse {
    pub agent_id: Uuid,
    pub owner_user_id: Option<Uuid>,
    pub status: String,
    pub approved: bool,
    pub handle: Option<String>,
    pub proposed_handle: Option<String>,
    pub display_name: Option<String>,
    pub scope_mode: String,
    pub fingerprint: String,
    pub activated_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub grants: Vec<AgentGrantResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_agent_grant_debug_redacts_key_ciphertext() {
        let request = ApproveAgentGrantRequest {
            work_list_id: Uuid::now_v7(),
            key_ciphertext: "secret-agent-work-list-key".to_string(),
            permissions: AgentGrantPermissions::assigned_task_worker(),
        };

        let debug = format!("{request:?}");

        assert!(debug.contains("ApproveAgentGrantRequest"));
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("secret-agent-work-list-key"));
    }
}
