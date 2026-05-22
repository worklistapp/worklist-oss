#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::time::Duration as StdDuration;

use worklist_client_auth::{Credentials, PrincipalSelection, normalize_api_url};
use worklist_client_core::{PublicError, PublicResult};

pub use delete_inputs::{
    DeleteAuditPatchFieldInput, DeleteAuditPatchInput, DeleteCommentInput, DeleteTaskInput,
};
pub use models::{
    AcceptTaskAssignmentArgs, AgentAttachment, AgentComment, AgentDelegation, AgentMembership,
    AgentTaskDetail, AgentTaskSummary, AgentWorkListDetail, AgentWorkListSummary, ArchiveTaskArgs,
    CommentInput, CreateCommentArgs, CreateTaskArgs, DeleteCommentArgs, DeleteTaskArgs,
    DownloadedAttachment, MoveTaskArgs, MoveTaskInput, ReadError, ReadableAttachment,
    ReadableAttachmentContentFormat, ReadableAttachmentSourceKind, TaskCreateInput,
    TaskUpdateInput, UnarchiveTaskArgs, UpdateCommentArgs, UpdateTaskArgs,
};
pub use unlock_daemon::{
    SessionKey, UnlockStatus, clear_session, fetch_data_key, lock, serve, session_key, socket_path,
    unlock, unlock_status,
};

mod agent_grants;
mod attachments;
mod auth;
mod comments;
mod delete_inputs;
mod keys;
mod models;
mod projections;
mod tasks;
mod unlock;
mod unlock_daemon;
mod work_lists;

const DEFAULT_AUTO_UNLOCK_TTL_SECONDS: u64 = 8 * 60 * 60;
const AUTH_HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(30);

#[derive(Debug, Clone)]
pub struct RuntimeClient {
    pub(crate) api_url: String,
    pub(crate) principal_selection: PrincipalSelection,
}

impl RuntimeClient {
    pub fn new(api_url: impl Into<String>) -> Self {
        Self::with_principal_selection(api_url, PrincipalSelection::Auto)
    }

    pub fn with_principal_selection(
        api_url: impl Into<String>,
        principal_selection: PrincipalSelection,
    ) -> Self {
        Self {
            api_url: normalize_api_url(&api_url.into()),
            principal_selection,
        }
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    pub fn current_session_key(&self, credentials: &Credentials) -> PublicResult<SessionKey> {
        session_key(
            &self.api_url,
            credentials.user_id,
            &credentials.data_key_ciphertext,
        )
    }
}

fn auth_http_client() -> PublicResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(AUTH_HTTP_TIMEOUT)
        .build()
        .map_err(|err| PublicError::unexpected(format!("failed to build auth HTTP client: {err}")))
}
