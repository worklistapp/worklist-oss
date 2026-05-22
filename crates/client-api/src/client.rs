use std::{fmt, time::Duration as StdDuration};

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worklist_client_core::{PublicError, PublicResult};

use crate::{
    AgentEnrollmentResponse, AgentSummaryResponse, ApproveAgentEnrollmentRequest,
    ArchiveTaskRequest, CommentResponse, CreateCommentRequest, CreateTaskRequest,
    CurrentUserResponse, DashboardStatsResponse, DeleteCommentRequest, DeleteTaskRequest,
    DownloadAttachmentResponse, LookupAgentEnrollmentRequest, MoveTaskRequest, MyTasksResponse,
    TaskDetailResponse, TaskListResponse, TaskResponse, UnarchiveTaskRequest, UpdateCommentRequest,
    UpdateTaskRequest, WorkListDetailResponse, WorkListResponse,
    errors::{handle_empty_response, handle_response, map_reqwest_error},
};

const API_HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(30);

#[derive(Clone)]
pub struct PublicApiClient {
    client: reqwest::Client,
    base_url: String,
    bearer_token: Option<String>,
}

impl PublicApiClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: normalize_base_url(base_url.into()),
            bearer_token: None,
        }
    }

    pub fn with_bearer_token(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: normalize_base_url(base_url.into()),
            bearer_token: Some(bearer_token.into()),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn has_credentials(&self) -> bool {
        self.bearer_token.is_some()
    }

    fn access_token(&self) -> PublicResult<&str> {
        self.bearer_token
            .as_deref()
            .ok_or_else(|| PublicError::validation("not logged in"))
    }

    async fn get<T: for<'de> Deserialize<'de>>(&mut self, path: &str) -> PublicResult<T> {
        let url = format!("{}{}", self.base_url, path);
        self.send(self.client.get(url), path).await
    }

    async fn post_public<T: for<'de> Deserialize<'de>, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> PublicResult<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .send_request(self.client.post(url).json(body), path)
            .await?;
        handle_response(response, path).await
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
        self.post_public(
            "/agents/enrollments/lookup",
            &LookupAgentEnrollmentRequest {
                code: code.to_string(),
            },
        )
        .await
    }

    pub async fn list_agents(&mut self) -> PublicResult<Vec<AgentSummaryResponse>> {
        self.get("/agents").await
    }

    pub async fn approve_agent_enrollment(
        &mut self,
        payload: &ApproveAgentEnrollmentRequest,
    ) -> PublicResult<AgentSummaryResponse> {
        self.post("/agents/enrollments/approve", payload).await
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
        payload.validate_encrypted_boundary()?;
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
        payload.validate_encrypted_boundary()?;
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
        let token = self.access_token()?;
        let request = self.authorized(request, token);
        let response = self.send_request(request, path).await?;

        handle_response(response, path).await
    }

    async fn send_no_content(
        &mut self,
        request: reqwest::RequestBuilder,
        path: &str,
    ) -> PublicResult<()> {
        let token = self.access_token()?;
        let request = self.authorized(request, token);
        let response = self.send_request(request, path).await?;

        handle_empty_response(response, path).await
    }

    async fn send_request(
        &self,
        request: reqwest::RequestBuilder,
        path: &str,
    ) -> PublicResult<reqwest::Response> {
        request
            .timeout(API_HTTP_TIMEOUT)
            .send()
            .await
            .map_err(|err| map_reqwest_error(err, path))
    }

    fn authorized(
        &self,
        request: reqwest::RequestBuilder,
        access_token: &str,
    ) -> reqwest::RequestBuilder {
        request.bearer_auth(access_token)
    }
}

impl fmt::Debug for PublicApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicApiClient")
            .field("client", &self.client)
            .field("base_url", &self.base_url)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

fn normalize_base_url(value: String) -> String {
    value.trim_end_matches('/').to_string()
}
