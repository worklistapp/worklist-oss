#![cfg_attr(test, allow(clippy::unwrap_used))]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use worklist_client_auth::{
    AgentEnrollmentResponse, AgentTokenResponse, PrincipalCredentials, mint_agent_access_token,
    refresh_access_token, save_agent_credentials, save_credentials, update_credentials_with_refresh,
};
use worklist_client_core::{PublicError, PublicResult};

pub type SealedBlob = String;

#[derive(Debug, Clone)]
pub struct PublicApiClient {
    client: reqwest::Client,
    base_url: String,
    credentials: Option<PrincipalCredentials>,
}

impl PublicApiClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: normalize_base_url(base_url.into()),
            credentials: None,
        }
    }

    pub fn with_credentials(
        base_url: impl Into<String>,
        credentials: PrincipalCredentials,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: normalize_base_url(base_url.into()),
            credentials: Some(credentials),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn has_credentials(&self) -> bool {
        self.credentials.is_some()
    }

    async fn get_access_token(&mut self) -> PublicResult<String> {
        let credentials = self
            .credentials
            .as_mut()
            .ok_or_else(|| PublicError::validation("not logged in"))?;

        match credentials {
            PrincipalCredentials::User(credentials) => {
                if credentials.access_expires_within(60) {
                    if credentials.is_refresh_expired() {
                        return Err(PublicError::validation(
                            "session expired, please login again",
                        ));
                    }

                    let refresh_response = refresh_access_token(
                        &self.client,
                        &self.base_url,
                        &credentials.refresh_token,
                    )
                    .await?;
                    update_credentials_with_refresh(credentials, refresh_response);
                    save_credentials(credentials)?;
                }

                Ok(credentials.access_token.clone())
            }
            PrincipalCredentials::Agent(credentials) => {
                if credentials.access_expires_within(60) {
                    let response: AgentTokenResponse =
                        mint_agent_access_token(&self.client, credentials).await?;
                    credentials.access_token = Some(response.access_token);
                    credentials.access_expires_at =
                        Some(Utc::now() + chrono::Duration::seconds(response.expires_in as i64));
                    credentials.owner_user_id = Some(response.owner_user_id);
                    save_agent_credentials(credentials)?;
                }

                credentials
                    .access_token
                    .clone()
                    .ok_or_else(|| PublicError::validation("agent access token missing"))
            }
        }
    }

    async fn get<T: for<'de> Deserialize<'de>>(&mut self, path: &str) -> PublicResult<T> {
        let url = format!("{}{}", self.base_url, path);
        self.send(self.client.get(url), path).await
    }

    pub async fn get_me(&mut self) -> PublicResult<CurrentUserResponse> {
        self.get("/me").await
    }

    pub async fn list_work_lists(&mut self) -> PublicResult<Vec<WorkListResponse>> {
        self.get("/work-lists").await
    }

    pub async fn get_work_list(&mut self, id: Uuid) -> PublicResult<WorkListDetailResponse> {
        self.get(&format!("/work-lists/{id}")).await
    }

    pub async fn get_tasks(
        &mut self,
        work_list_id: Uuid,
        include_archived: bool,
    ) -> PublicResult<TaskListResponse> {
        let path = if include_archived {
            format!("/work-lists/{work_list_id}/tasks?includeArchived=true")
        } else {
            format!("/work-lists/{work_list_id}/tasks")
        };
        self.get(&path).await
    }

    pub async fn get_my_tasks(
        &mut self,
        limit: Option<i64>,
        offset: Option<i64>,
    ) -> PublicResult<MyTasksResponse> {
        let mut params = Vec::new();
        if let Some(limit) = limit {
            params.push(format!("limit={limit}"));
        }
        if let Some(offset) = offset {
            params.push(format!("offset={offset}"));
        }

        let path = if params.is_empty() {
            "/me/tasks".to_string()
        } else {
            format!("/me/tasks?{}", params.join("&"))
        };

        self.get(&path).await
    }

    pub async fn get_dashboard_stats(&mut self) -> PublicResult<DashboardStatsResponse> {
        self.get("/me/dashboard-stats").await
    }

    pub async fn get_agent_enrollment(
        &mut self,
        code: &str,
    ) -> PublicResult<AgentEnrollmentResponse> {
        self.get(&format!("/agents/enrollments/{code}")).await
    }

    pub async fn list_agents(&mut self) -> PublicResult<Vec<AgentSummaryResponse>> {
        self.get("/agents").await
    }

    pub async fn approve_agent_enrollment(
        &mut self,
        code: &str,
        payload: &ApproveAgentEnrollmentRequest,
    ) -> PublicResult<AgentSummaryResponse> {
        self.post(&format!("/agents/enrollments/{code}/approve"), payload)
            .await
    }

    pub async fn revoke_agent(&mut self, agent_id: Uuid) -> PublicResult<AgentSummaryResponse> {
        self.post_empty(&format!("/agents/{agent_id}/revoke")).await
    }

    pub async fn get_task(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
    ) -> PublicResult<TaskDetailResponse> {
        self.get(&format!("/work-lists/{work_list_id}/tasks/{task_id}"))
            .await
    }

    pub async fn get_attachment_download(
        &mut self,
        work_list_id: Uuid,
        attachment_id: Uuid,
    ) -> PublicResult<DownloadAttachmentResponse> {
        self.get(&format!(
            "/work-lists/{work_list_id}/attachments/{attachment_id}/download"
        ))
        .await
    }

    pub async fn create_task(
        &mut self,
        work_list_id: Uuid,
        payload: &CreateTaskRequest,
    ) -> PublicResult<TaskResponse> {
        self.post(&format!("/work-lists/{work_list_id}/tasks"), payload)
            .await
    }

    pub async fn update_task(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        payload: &UpdateTaskRequest,
    ) -> PublicResult<TaskResponse> {
        self.patch(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}"),
            payload,
        )
        .await
    }

    pub async fn move_task(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        payload: &MoveTaskRequest,
    ) -> PublicResult<TaskResponse> {
        self.post(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}/move"),
            payload,
        )
        .await
    }

    pub async fn archive_task(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        payload: &ArchiveTaskRequest,
    ) -> PublicResult<TaskResponse> {
        self.post(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}/archive"),
            payload,
        )
        .await
    }

    pub async fn unarchive_task(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        payload: &UnarchiveTaskRequest,
    ) -> PublicResult<TaskResponse> {
        self.post(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}/unarchive"),
            payload,
        )
        .await
    }

    pub async fn delete_task(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        payload: &DeleteTaskRequest,
    ) -> PublicResult<()> {
        self.delete_no_content_with_body(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}"),
            payload,
        )
        .await
    }

    pub async fn list_comments(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
    ) -> PublicResult<Vec<CommentResponse>> {
        self.get(&format!(
            "/work-lists/{work_list_id}/tasks/{task_id}/comments"
        ))
        .await
    }

    pub async fn create_comment(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        payload: &CreateCommentRequest,
    ) -> PublicResult<CommentResponse> {
        self.post(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}/comments"),
            payload,
        )
        .await
    }

    pub async fn update_comment(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        comment_id: Uuid,
        payload: &UpdateCommentRequest,
    ) -> PublicResult<CommentResponse> {
        self.patch(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}/comments/{comment_id}"),
            payload,
        )
        .await
    }

    pub async fn delete_comment(
        &mut self,
        work_list_id: Uuid,
        task_id: Uuid,
        comment_id: Uuid,
        payload: &DeleteCommentRequest,
    ) -> PublicResult<()> {
        self.delete_no_content_with_body(
            &format!("/work-lists/{work_list_id}/tasks/{task_id}/comments/{comment_id}"),
            payload,
        )
        .await
    }

    async fn post<T: for<'de> Deserialize<'de>, B: Serialize>(
        &mut self,
        path: &str,
        body: &B,
    ) -> PublicResult<T> {
        let url = format!("{}{}", self.base_url, path);
        self.send(self.client.post(url).json(body), path).await
    }

    async fn patch<T: for<'de> Deserialize<'de>, B: Serialize>(
        &mut self,
        path: &str,
        body: &B,
    ) -> PublicResult<T> {
        let url = format!("{}{}", self.base_url, path);
        self.send(self.client.patch(url).json(body), path).await
    }

    async fn delete_no_content_with_body<B: Serialize>(
        &mut self,
        path: &str,
        body: &B,
    ) -> PublicResult<()> {
        let url = format!("{}{}", self.base_url, path);
        self.send_no_content(self.client.delete(url).json(body), path)
            .await
    }

    async fn post_empty<T: for<'de> Deserialize<'de>>(&mut self, path: &str) -> PublicResult<T> {
        let url = format!("{}{}", self.base_url, path);
        self.send(self.client.post(url), path).await
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &mut self,
        request: reqwest::RequestBuilder,
        path: &str,
    ) -> PublicResult<T> {
        let token = self.get_access_token().await?;
        let response = self
            .authorized(request, &token)
            .send()
            .await
            .map_err(|err| map_reqwest_error(err, path))?;

        handle_response(response, path).await
    }

    async fn send_no_content(
        &mut self,
        request: reqwest::RequestBuilder,
        path: &str,
    ) -> PublicResult<()> {
        let token = self.get_access_token().await?;
        let response = self
            .authorized(request, &token)
            .send()
            .await
            .map_err(|err| map_reqwest_error(err, path))?;

        handle_empty_response(response, path).await
    }

    fn authorized(
        &self,
        request: reqwest::RequestBuilder,
        access_token: &str,
    ) -> reqwest::RequestBuilder {
        request.bearer_auth(access_token)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTaskRef {
    pub id: Uuid,
    pub work_list_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentUserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub timezone: String,
    pub avatar_color: String,
    pub data_key_ciphertext: String,
    pub workspace_lock_timeout_minutes: Option<i32>,
    pub theme_preference: String,
    pub email_verified: bool,
    pub last_accessed_work_list_id: Option<Uuid>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkListResponse {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub workspace_id: Uuid,
    pub title_ciphertext: SealedBlob,
    pub description_ciphertext: Option<SealedBlob>,
    pub payload_ciphertext: SealedBlob,
    pub timezone: String,
    pub section_snapshots: Vec<SectionSnapshotPayload>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub membership: MembershipResponse,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkListDetailResponse {
    #[serde(flatten)]
    pub work_list: WorkListResponse,
    pub members: Vec<MembershipResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionSnapshotPayload {
    pub id: Uuid,
    pub position: i64,
    pub auto_archive_enabled: bool,
    pub auto_archive_after_days: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub user_name: String,
    pub user_avatar_color: String,
    pub role: String,
    pub status: String,
    pub work_list_key_ciphertext: SealedBlob,
    pub recipient_ciphertext: Option<SealedBlob>,
    pub invite_package_ciphertext: Option<SealedBlob>,
    pub salt_member: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub joined_at: DateTime<Utc>,
    pub payload_binding_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveAgentGrantRequest {
    pub work_list_id: Uuid,
    pub key_ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApproveAgentEnrollmentRequest {
    pub handle: String,
    pub display_name: String,
    pub scope_mode: String,
    pub fingerprint: String,
    pub grants: Vec<ApproveAgentGrantRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentGrantResponse {
    pub work_list_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskDetailResponse {
    #[serde(flatten)]
    pub task: TaskResponse,
    pub comments: Vec<CommentResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommentResponse {
    pub id: Uuid,
    pub task_id: Uuid,
    pub author_membership_id: Uuid,
    pub body_ciphertext: SealedBlob,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskListResponse {
    pub tasks: Vec<TaskResponse>,
    #[serde(default)]
    pub archived_counts: Vec<ArchivedTaskCountResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchivedTaskCountResponse {
    pub section_id: Option<Uuid>,
    pub count: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MyTasksResponse {
    pub tasks: Vec<MyTaskResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardStatsResponse {
    pub tasks_overdue: i64,
    pub tasks_due_today: i64,
    pub tasks_due_this_week: i64,
    pub completed: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadAttachmentResponse {
    pub download_url: String,
    pub download_headers: std::collections::HashMap<String, String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTaskRequest {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPatchFieldRequest {
    pub field: String,
    pub change_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_scalar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_scalar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_ciphertext_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_ciphertext_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPatchRequest {
    #[serde(default)]
    pub fields: Vec<AuditPatchFieldRequest>,
    pub payload_ciphertext: String,
    pub payload_ciphertext_proof: String,
    pub payload_version: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteTaskRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_patch: Option<AuditPatchRequest>,
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCommentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_patch: Option<AuditPatchRequest>,
}

#[derive(Debug, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: Option<String>,
}

async fn handle_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    path: &str,
) -> PublicResult<T> {
    let status = response.status();
    if status.is_success() {
        response.json().await.map_err(|err| {
            PublicError::unexpected(format!("failed to parse response from {path}: {err}"))
        })
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        Err(map_api_error(status.as_u16(), &error_text, path))
    }
}

async fn handle_empty_response(response: reqwest::Response, path: &str) -> PublicResult<()> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        Err(map_api_error(status.as_u16(), &error_text, path))
    }
}

fn normalize_base_url(value: String) -> String {
    value.trim_end_matches('/').to_string()
}

fn map_reqwest_error(err: reqwest::Error, path: &str) -> PublicError {
    if err.is_connect() {
        PublicError::unexpected(format!("failed to connect to API for {path}: {err}"))
    } else if err.is_timeout() {
        PublicError::unexpected(format!("API request timed out for {path}"))
    } else {
        PublicError::unexpected(format!("API request failed for {path}: {err}"))
    }
}

fn map_api_error(status: u16, body: &str, path: &str) -> PublicError {
    if let Ok(api_error) = serde_json::from_str::<ApiErrorResponse>(body) {
        let message = api_error.message.unwrap_or(api_error.error);
        return match status {
            401 => PublicError::validation(format!("authentication failed: {message}")),
            403 => PublicError::validation(format!("access denied: {message}")),
            404 => PublicError::validation(format!("not found: {message} ({path})")),
            400 | 422 => PublicError::validation(message),
            _ => PublicError::unexpected(format!("API error ({status}) for {path}: {message}")),
        };
    }

    match status {
        401 => PublicError::validation("authentication failed"),
        403 => PublicError::validation("access denied"),
        404 => PublicError::validation(format!("not found: {path}")),
        _ => PublicError::unexpected(format!("API error ({status}) for {path}: {body}")),
    }
}
