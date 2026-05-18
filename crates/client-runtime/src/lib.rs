#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::collections::HashMap;
use std::io::{self, Read};
use std::time::Duration as StdDuration;

use base64::Engine as _;
use chrono::Utc;
use rpassword::prompt_password;
use uuid::Uuid;
use worklist_client_api::{
    AgentEnrollmentResponse, ApproveAgentGrantRequest, ArchiveTaskRequest, CommentResponse,
    CreateCommentRequest, CreateTaskRequest, CurrentUserResponse, DashboardStatsResponse,
    MoveTaskRequest, MyTaskResponse, PublicApiClient, TaskResponse, UnarchiveTaskRequest,
    UpdateCommentRequest, UpdateTaskRequest, WorkListDetailResponse, WorkListResponse,
};
use worklist_client_auth::{
    AgentCredentials, Credentials, PersistedDataKeyStatus, PrincipalCredentials,
    PrincipalSelection, agent_key_material_from_seed,
    clear_persisted_data_key as clear_persisted_data_key_secret, load_agent_seed, load_credentials,
    load_credentials_for_url, load_persisted_data_key, load_principal_credentials_for_url,
    mint_agent_access_token, normalize_api_url, persisted_data_key_status, refresh_access_token,
    save_agent_credentials, save_credentials, save_persisted_data_key,
    update_credentials_with_refresh,
};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::{
    CommentPayloadBody, SymmetricKey, TaskPayloadBody, build_comment_payload_envelope,
    build_task_payload_envelope, compute_payload_proof, decode_attachment_blob_key,
    decode_sealed_blob, decrypt_comment_payload, decrypt_task_payload, decrypt_user_data_key,
    derive_payload_binding_key, encrypt_agent_work_list_key, encrypt_comment_payload,
    encrypt_task_payload, flexible_value_to_json, plaintext_rich_text, seal_task_title,
};

use crate::attachments::{
    AttachmentReadStrategy, ResolvedTaskAttachmentDownload, build_readable_attachment,
    download_and_decrypt_attachment, find_task_attachment, unsupported_attachment_read_error,
};
use crate::projections::{
    PrincipalWorkListKeySource, TaskProjectionInput, TaskProjectionMetadata, WorkListContext,
    build_work_list_summary, decode_work_list_description_fallback, decode_work_list_payload_value,
    decode_work_list_title_fallback, extract_work_list_description, extract_work_list_title,
    make_read_error, missing_work_list_key_source_error, project_attachments, project_membership,
    project_task, read_error_to_public_error, resolve_list_key,
    resolve_work_list_key_for_principal_source, rich_text_to_markdown,
    unreadable_work_list_context,
};

pub use models::*;
pub use unlock_daemon::{
    SessionKey, UnlockStatus, clear_session, fetch_data_key, lock, serve, session_key, socket_path,
    unlock, unlock_status,
};

mod attachments;
mod models;
mod projections;
mod unlock_daemon;

const DEFAULT_AUTO_UNLOCK_TTL_SECONDS: u64 = 8 * 60 * 60;
const AUTH_HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(30);

#[derive(Debug, Clone)]
pub struct RuntimeClient {
    api_url: String,
    principal_selection: PrincipalSelection,
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

    pub fn require_logged_in_credentials(&self) -> PublicResult<Credentials> {
        load_credentials_for_url(&self.api_url)?.ok_or_else(|| {
            PublicError::validation("not logged in - run 'worklist auth login' first")
        })
    }

    pub fn require_principal_credentials(&self) -> PublicResult<PrincipalCredentials> {
        load_principal_credentials_for_url(&self.api_url, self.principal_selection)?.ok_or_else(
            || {
                PublicError::validation(
                    "not logged in - run 'worklist auth login' or 'worklist agent register' first",
                )
            },
        )
    }

    pub async fn authenticated_api_client(&self) -> PublicResult<PublicApiClient> {
        let access_token = self.fresh_principal_access_token().await?;
        Ok(PublicApiClient::with_bearer_token(
            &self.api_url,
            access_token,
        ))
    }

    pub async fn authenticated_owner_api_client(&self) -> PublicResult<PublicApiClient> {
        let mut credentials = load_credentials_for_url(&self.api_url)?.ok_or_else(|| {
            PublicError::validation("owner credentials required - run 'worklist auth login' first")
        })?;
        self.refresh_user_credentials_if_needed(&mut credentials)
            .await?;
        Ok(PublicApiClient::with_bearer_token(
            &self.api_url,
            credentials.access_token,
        ))
    }

    fn require_user_principal_credentials(&self, operation: &str) -> PublicResult<Credentials> {
        match self.require_principal_credentials()? {
            PrincipalCredentials::User(credentials) if credentials.is_refresh_expired() => {
                Err(PublicError::validation(
                    "session expired - run 'worklist auth login' to authenticate",
                ))
            }
            PrincipalCredentials::User(credentials) => Ok(credentials),
            PrincipalCredentials::Agent(_) => Err(PublicError::validation(format!(
                "{operation} requires user credentials; rerun with --principal user until agent-authored content is supported"
            ))),
        }
    }

    async fn fresh_principal_access_token(&self) -> PublicResult<String> {
        match self.require_principal_credentials()? {
            PrincipalCredentials::User(mut credentials) => {
                self.refresh_user_credentials_if_needed(&mut credentials)
                    .await?;
                Ok(credentials.access_token)
            }
            PrincipalCredentials::Agent(mut credentials) => {
                self.refresh_agent_credentials_if_needed(&mut credentials)
                    .await?;
                credentials
                    .access_token
                    .ok_or_else(|| PublicError::validation("agent access token missing"))
            }
        }
    }

    async fn refresh_user_credentials_if_needed(
        &self,
        credentials: &mut Credentials,
    ) -> PublicResult<()> {
        if !credentials.access_expires_within(60) {
            return Ok(());
        }
        if credentials.is_refresh_expired() {
            return Err(PublicError::validation(
                "session expired - run 'worklist auth login' to authenticate",
            ));
        }

        let client = auth_http_client()?;
        let refresh_response =
            refresh_access_token(&client, &self.api_url, &credentials.refresh_token).await?;
        update_credentials_with_refresh(credentials, refresh_response);
        save_credentials(credentials)
    }

    async fn refresh_agent_credentials_if_needed(
        &self,
        credentials: &mut AgentCredentials,
    ) -> PublicResult<()> {
        if !credentials.access_expires_within(60) {
            return Ok(());
        }

        let client = auth_http_client()?;
        let response = mint_agent_access_token(&client, credentials).await?;
        let expires_in = i64::try_from(response.expires_in)
            .map_err(|_| PublicError::unexpected("agent access ttl overflow"))?;
        credentials.access_token = Some(response.access_token);
        credentials.access_expires_at = Some(Utc::now() + chrono::Duration::seconds(expires_in));
        credentials.owner_user_id = Some(response.owner_user_id);
        save_agent_credentials(credentials)
    }

    pub async fn get_me(&self) -> PublicResult<CurrentUserResponse> {
        let mut client = self.authenticated_api_client().await?;
        client.get_me().await
    }

    pub async fn get_stats(&self) -> PublicResult<DashboardStatsResponse> {
        let mut client = self.authenticated_api_client().await?;
        client.get_dashboard_stats().await
    }

    pub fn unlock_daemon(&self, ttl_seconds: u64, password_stdin: bool) -> PublicResult<()> {
        let credentials = self.require_logged_in_credentials()?;
        let password = read_required_password(
            password_stdin,
            Some("Password required to unlock the local daemon."),
        )?;
        let data_key = decrypt_user_data_key(&password, &credentials.data_key_ciphertext)?;
        let session_key = self.current_session_key(&credentials)?;
        unlock(&session_key, &data_key, ttl_seconds)
    }

    pub fn store_persisted_data_key(&self, password_stdin: bool) -> PublicResult<()> {
        let credentials = self.require_logged_in_credentials()?;
        let password = read_required_password(
            password_stdin,
            Some("Password required to store a local bootstrap secret."),
        )?;
        let data_key = decrypt_user_data_key(&password, &credentials.data_key_ciphertext)?;
        save_persisted_data_key(&credentials, data_key.as_bytes())?;
        Ok(())
    }

    pub fn clear_persisted_data_key(&self) -> PublicResult<()> {
        let credentials = match load_credentials_for_url(&self.api_url)? {
            Some(credentials) => credentials,
            None => return Ok(()),
        };
        clear_persisted_data_key_secret(&credentials)
    }

    pub fn clear_unlock_daemon_session(&self) -> PublicResult<()> {
        let credentials = match load_credentials_for_url(&self.api_url)? {
            Some(credentials) => credentials,
            None => return Ok(()),
        };
        let session_key = self.current_session_key(&credentials)?;
        clear_session(&session_key)
    }

    pub fn unlock_status(&self) -> PublicResult<UnlockStatus> {
        match load_credentials()? {
            Some(credentials) => {
                let session_key = session_key(
                    &credentials.api_url,
                    credentials.user_id,
                    &credentials.data_key_ciphertext,
                )?;
                unlock_status(Some(&session_key))
            }
            None => unlock_status(None),
        }
    }

    pub fn persisted_data_key_status(&self) -> PublicResult<Option<PersistedDataKeyStatus>> {
        Ok(load_credentials_for_url(&self.api_url)?
            .map(|credentials| persisted_data_key_status(&credentials)))
    }

    pub async fn build_agent_grants_for_enrollment(
        &self,
        enrollment: &AgentEnrollmentResponse,
        password_stdin: bool,
    ) -> PublicResult<Vec<ApproveAgentGrantRequest>> {
        let mut credentials = self.require_logged_in_credentials()?;
        let data_key = self.load_data_key(
            &credentials,
            password_stdin,
            "Password required to approve agent access.",
        )?;
        let recipient_public_key = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(enrollment.recipient_public_key.trim())
            .map_err(|err| {
                PublicError::validation(format!("invalid recipient public key: {err}"))
            })?;
        self.refresh_user_credentials_if_needed(&mut credentials)
            .await?;
        let mut client =
            PublicApiClient::with_bearer_token(&self.api_url, credentials.access_token);
        let work_lists = client.list_work_lists().await?;
        let mut grants = Vec::new();
        for work_list in work_lists
            .into_iter()
            .filter(|work_list| work_list.membership.role.eq_ignore_ascii_case("owner"))
        {
            let list_key = resolve_list_key(
                &data_key,
                work_list.id,
                &work_list.membership.work_list_key_ciphertext,
            )?;
            let ciphertext =
                encrypt_agent_work_list_key(&recipient_public_key, &work_list.id, &list_key)?;
            grants.push(ApproveAgentGrantRequest {
                work_list_id: work_list.id,
                key_ciphertext: ciphertext.base64,
            });
        }
        Ok(grants)
    }

    pub async fn list_work_lists(
        &self,
        password_stdin: bool,
    ) -> PublicResult<Vec<AgentWorkListSummary>> {
        let key_source = self.load_principal_work_list_key_source(
            password_stdin,
            "Password required to decrypt work lists.",
        )?;
        let mut client = self.authenticated_api_client().await?;
        let lists = client.list_work_lists().await?;
        Ok(lists
            .into_iter()
            .map(|list| self.project_work_list_summary(list, Some(&key_source)))
            .collect())
    }

    pub async fn get_work_list(
        &self,
        work_list_id: Uuid,
        password_stdin: bool,
    ) -> PublicResult<AgentWorkListDetail> {
        let key_source = self.load_principal_work_list_key_source(
            password_stdin,
            "Password required to decrypt work list data.",
        )?;
        let mut client = self.authenticated_api_client().await?;
        let detail = client.get_work_list(work_list_id).await?;
        Ok(self.project_work_list_detail(detail, Some(&key_source)))
    }

    pub async fn list_tasks(
        &self,
        work_list_id: Option<Uuid>,
        include_completed: bool,
        all: bool,
        password_stdin: bool,
    ) -> PublicResult<Vec<AgentTaskSummary>> {
        let key_source = self.load_principal_work_list_key_source(
            password_stdin,
            "Password required to decrypt task data.",
        )?;
        let mut client = self.authenticated_api_client().await?;

        if all || work_list_id.is_none() {
            let work_lists = client.list_work_lists().await?;
            let contexts = self.build_work_list_contexts(&work_lists, Some(&key_source));
            let response = client.get_my_tasks(Some(100), None).await?;
            let tasks = if include_completed {
                response.tasks
            } else {
                response
                    .tasks
                    .into_iter()
                    .filter(|task| !task.is_completed)
                    .collect()
            };

            return Ok(tasks
                .into_iter()
                .map(|task| {
                    let context = contexts.get(&task.work_list_id);
                    self.project_my_task_summary(task, context)
                })
                .collect());
        }

        let work_list_id = work_list_id.expect("validated work list id");
        let work_list = client.get_work_list(work_list_id).await?;
        let context = self.context_from_work_list_detail(&work_list, Some(&key_source));
        let response = client.get_tasks(work_list_id, false).await?;
        let tasks = if include_completed {
            response.tasks
        } else {
            response
                .tasks
                .into_iter()
                .filter(|task| !task.is_completed)
                .collect()
        };

        Ok(tasks
            .into_iter()
            .map(|task| self.project_task_summary(task, Some(&context)))
            .collect())
    }

    pub async fn get_task(
        &self,
        work_list_id: Uuid,
        task_id: Uuid,
        password_stdin: bool,
    ) -> PublicResult<AgentTaskDetail> {
        let (mut client, context) = self
            .load_work_list_context(
                work_list_id,
                password_stdin,
                "Password required to decrypt task data.",
            )
            .await?;
        let detail = client.get_task(work_list_id, task_id).await?;

        let task = self.project_task_summary(detail.task, Some(&context));
        let comments = detail
            .comments
            .into_iter()
            .map(|comment| self.project_comment(comment, context.list_key.as_ref()))
            .collect();
        Ok(AgentTaskDetail { task, comments })
    }

    pub async fn list_comments(
        &self,
        work_list_id: Uuid,
        task_id: Uuid,
        password_stdin: bool,
    ) -> PublicResult<Vec<AgentComment>> {
        let (mut client, context) = self
            .load_work_list_context(
                work_list_id,
                password_stdin,
                "Password required to decrypt task comments.",
            )
            .await?;
        let comments = client.list_comments(work_list_id, task_id).await?;

        Ok(comments
            .into_iter()
            .map(|comment| self.project_comment(comment, context.list_key.as_ref()))
            .collect())
    }

    pub async fn read_task_attachment(
        &self,
        work_list_id: Uuid,
        task_id: Uuid,
        attachment_id: Uuid,
        password_stdin: bool,
    ) -> PublicResult<ReadableAttachment> {
        let resolved = self
            .resolve_task_attachment_download(work_list_id, task_id, attachment_id, password_stdin)
            .await?;
        let read_strategy = resolved.attachment.read_strategy();
        if let AttachmentReadStrategy::Unsupported = read_strategy {
            return Err(unsupported_attachment_read_error(
                &resolved.attachment.file_name,
            ));
        }
        let DownloadedAttachment { attachment, bytes } =
            download_and_decrypt_attachment(resolved).await?;
        build_readable_attachment(attachment, bytes, read_strategy)
    }

    pub async fn download_task_attachment(
        &self,
        work_list_id: Uuid,
        task_id: Uuid,
        attachment_id: Uuid,
        password_stdin: bool,
    ) -> PublicResult<DownloadedAttachment> {
        let resolved = self
            .resolve_task_attachment_download(work_list_id, task_id, attachment_id, password_stdin)
            .await?;
        download_and_decrypt_attachment(resolved).await
    }

    async fn resolve_task_attachment_download(
        &self,
        work_list_id: Uuid,
        task_id: Uuid,
        attachment_id: Uuid,
        password_stdin: bool,
    ) -> PublicResult<ResolvedTaskAttachmentDownload> {
        let (mut client, context) = self
            .load_work_list_context(
                work_list_id,
                password_stdin,
                "Password required to decrypt attachment data.",
            )
            .await?;
        let list_key = self.require_work_list_key(&context)?;
        let task_detail = client.get_task(work_list_id, task_id).await?;
        let task = self.project_task_summary(task_detail.task, Some(&context));
        let attachment = find_task_attachment(&task, attachment_id)?;
        let blob_ref =
            decode_attachment_blob_key(list_key, attachment.blob_key()).map_err(|err| {
                PublicError::validation(format!("failed to decode attachment blob key: {err}"))
            })?;
        let download = client
            .get_attachment_download(work_list_id, attachment_id)
            .await?;
        Ok(ResolvedTaskAttachmentDownload {
            attachment,
            blob_ref,
            download,
        })
    }

    pub async fn create_task(&self, args: CreateTaskArgs) -> PublicResult<AgentTaskSummary> {
        let (mut client, context) = self
            .load_user_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to create encrypted task payloads.",
                "task creation",
            )
            .await?;
        let list_key = self.require_work_list_key(&context)?;
        let binding_key = derive_payload_binding_key(list_key)?;

        let normalized_title = args.input.title.trim();
        if normalized_title.is_empty() {
            return Err(PublicError::validation("title is required"));
        }

        let task_body = TaskPayloadBody {
            title: normalized_title.to_string(),
            rich_text: args.input.body.as_deref().and_then(plaintext_rich_text),
            checklist: None,
            attachments: None,
            references: None,
            mentions: None,
            client_meta: None,
            recurrence_state: None,
        };
        let envelope = build_task_payload_envelope(task_body, 1);
        let payload_ciphertext = encrypt_task_payload(&envelope, list_key)?;
        let title_ciphertext = seal_task_title(normalized_title, list_key)?;
        let payload_proof = compute_payload_proof(&payload_ciphertext.bytes, &binding_key)?;
        let title_proof = compute_payload_proof(&title_ciphertext.bytes, &binding_key)?;

        let created = client
            .create_task(
                args.work_list_id,
                &CreateTaskRequest {
                    title_ciphertext: title_ciphertext.base64,
                    title_ciphertext_proof: title_proof,
                    payload_ciphertext: payload_ciphertext.base64,
                    payload_ciphertext_proof: payload_proof,
                    attachment_ids: Vec::new(),
                    priority: None,
                    due_at: None,
                    section_id: None,
                },
            )
            .await?;

        Ok(self.project_task_summary(created, Some(&context)))
    }

    pub async fn update_task(&self, args: UpdateTaskArgs) -> PublicResult<AgentTaskSummary> {
        let (mut client, context) = self
            .load_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to update encrypted task payloads.",
            )
            .await?;
        let list_key = self.require_work_list_key(&context)?;
        let binding_key = derive_payload_binding_key(list_key)?;
        let task_detail = client.get_task(args.work_list_id, args.task_id).await?;

        let existing_payload_bytes = decode_sealed_blob(&task_detail.task.payload_ciphertext)?;
        let existing_payload = decrypt_task_payload(list_key, &existing_payload_bytes)?;
        let existing_body = existing_payload.body;

        if args.input.title.is_none() && args.input.body.is_none() {
            return Err(PublicError::validation(
                "provide at least one of --title or --body",
            ));
        }

        let next_title = args
            .input
            .title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| existing_body.title.clone());
        let next_rich_text = match args.input.body.as_deref() {
            Some(value) if value.trim().is_empty() => None,
            Some(value) => plaintext_rich_text(value),
            None => existing_body.rich_text.clone(),
        };

        let next_body = TaskPayloadBody {
            title: next_title.clone(),
            rich_text: next_rich_text,
            checklist: existing_body.checklist,
            attachments: existing_body.attachments,
            references: existing_body.references,
            mentions: existing_body.mentions,
            client_meta: existing_body.client_meta,
            recurrence_state: existing_body.recurrence_state,
        };
        let envelope = build_task_payload_envelope(next_body, 1);
        let payload_ciphertext = encrypt_task_payload(&envelope, list_key)?;
        let payload_proof = compute_payload_proof(&payload_ciphertext.bytes, &binding_key)?;

        let mut request = UpdateTaskRequest {
            payload_ciphertext: Some(payload_ciphertext.base64),
            payload_ciphertext_proof: Some(payload_proof),
            ..UpdateTaskRequest::default()
        };

        if let Some(new_title) = args.input.title.as_deref() {
            let normalized_title = new_title.trim();
            if normalized_title.is_empty() {
                return Err(PublicError::validation("title cannot be empty"));
            }
            let title_ciphertext = seal_task_title(normalized_title, list_key)?;
            let title_proof = compute_payload_proof(&title_ciphertext.bytes, &binding_key)?;
            request.title_ciphertext = Some(title_ciphertext.base64);
            request.title_ciphertext_proof = Some(title_proof);
        }

        let updated = client
            .update_task(args.work_list_id, args.task_id, &request)
            .await?;
        Ok(self.project_task_summary(updated, Some(&context)))
    }

    pub async fn move_task(&self, args: MoveTaskArgs) -> PublicResult<AgentTaskSummary> {
        let (mut client, context) = self
            .load_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to decrypt moved task data.",
            )
            .await?;
        let moved = client
            .move_task(
                args.work_list_id,
                args.task_id,
                &MoveTaskRequest {
                    section_id: args.input.section_id,
                    insert_before_task_id: args.input.insert_before_task_id,
                },
            )
            .await?;
        Ok(self.project_task_summary(moved, Some(&context)))
    }

    pub async fn archive_task(&self, args: ArchiveTaskArgs) -> PublicResult<AgentTaskSummary> {
        let (mut client, context) = self
            .load_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to decrypt archived task data.",
            )
            .await?;
        let archived = client
            .archive_task(
                args.work_list_id,
                args.task_id,
                &ArchiveTaskRequest::default(),
            )
            .await?;
        Ok(self.project_task_summary(archived, Some(&context)))
    }

    pub async fn unarchive_task(&self, args: UnarchiveTaskArgs) -> PublicResult<AgentTaskSummary> {
        let (mut client, context) = self
            .load_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to decrypt unarchived task data.",
            )
            .await?;
        let unarchived = client
            .unarchive_task(
                args.work_list_id,
                args.task_id,
                &UnarchiveTaskRequest::default(),
            )
            .await?;
        Ok(self.project_task_summary(unarchived, Some(&context)))
    }

    pub async fn delete_task(&self, args: DeleteTaskArgs) -> PublicResult<()> {
        let mut client = self.authenticated_api_client().await?;
        client
            .delete_task(args.work_list_id, args.task_id, &args.input)
            .await
    }

    pub async fn create_comment(&self, args: CreateCommentArgs) -> PublicResult<AgentComment> {
        let (mut client, context) = self
            .load_user_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to create encrypted comments.",
                "comment creation",
            )
            .await?;
        let list_key = self.require_work_list_key(&context)?;
        let binding_key = derive_payload_binding_key(list_key)?;

        let normalized_body = args.input.body.trim();
        if normalized_body.is_empty() {
            return Err(PublicError::validation("comment body is required"));
        }

        let rich_text = plaintext_rich_text(normalized_body)
            .ok_or_else(|| PublicError::validation("comment body is required"))?;
        let envelope = build_comment_payload_envelope(
            CommentPayloadBody {
                content: rich_text,
                mentions: None,
                attachments: None,
                client_meta: None,
            },
            1,
        );
        let body_ciphertext = encrypt_comment_payload(&envelope, list_key)?;
        let body_proof = compute_payload_proof(&body_ciphertext.bytes, &binding_key)?;

        let created = client
            .create_comment(
                args.work_list_id,
                args.task_id,
                &CreateCommentRequest {
                    body_ciphertext: body_ciphertext.base64,
                    body_ciphertext_proof: body_proof,
                },
            )
            .await?;
        Ok(self.project_comment(created, Some(list_key)))
    }

    pub async fn update_comment(&self, args: UpdateCommentArgs) -> PublicResult<AgentComment> {
        let (mut client, context) = self
            .load_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to update encrypted comments.",
            )
            .await?;
        let list_key = self.require_work_list_key(&context)?;
        let binding_key = derive_payload_binding_key(list_key)?;

        let normalized_body = args.input.body.trim();
        if normalized_body.is_empty() {
            return Err(PublicError::validation("comment body is required"));
        }
        let rich_text = plaintext_rich_text(normalized_body)
            .ok_or_else(|| PublicError::validation("comment body is required"))?;

        let task_detail = client.get_task(args.work_list_id, args.task_id).await?;
        let existing_comment = task_detail
            .comments
            .iter()
            .find(|comment| comment.id == args.comment_id)
            .ok_or_else(|| PublicError::validation("comment not found"))?;
        let existing_body_ciphertext = decode_sealed_blob(&existing_comment.body_ciphertext)?;
        let existing_payload = decrypt_comment_payload(list_key, &existing_body_ciphertext)?;

        let envelope = build_comment_payload_envelope(
            CommentPayloadBody {
                content: rich_text,
                mentions: existing_payload.body.mentions,
                attachments: existing_payload.body.attachments,
                client_meta: existing_payload.body.client_meta,
            },
            1,
        );
        let body_ciphertext = encrypt_comment_payload(&envelope, list_key)?;
        let body_proof = compute_payload_proof(&body_ciphertext.bytes, &binding_key)?;

        let updated = client
            .update_comment(
                args.work_list_id,
                args.task_id,
                args.comment_id,
                &UpdateCommentRequest {
                    body_ciphertext: Some(body_ciphertext.base64),
                    body_ciphertext_proof: Some(body_proof),
                },
            )
            .await?;
        Ok(self.project_comment(updated, Some(list_key)))
    }

    pub async fn delete_comment(&self, args: DeleteCommentArgs) -> PublicResult<()> {
        let mut client = self.authenticated_api_client().await?;
        client
            .delete_comment(
                args.work_list_id,
                args.task_id,
                args.comment_id,
                &args.input,
            )
            .await
    }

    async fn load_work_list_context(
        &self,
        work_list_id: Uuid,
        password_stdin: bool,
        prompt_message: &str,
    ) -> PublicResult<(PublicApiClient, WorkListContext)> {
        let key_source =
            self.load_principal_work_list_key_source(password_stdin, prompt_message)?;
        let mut client = self.authenticated_api_client().await?;
        let work_list = client.get_work_list(work_list_id).await?;
        let context = self.context_from_work_list_detail(&work_list, Some(&key_source));
        Ok((client, context))
    }

    async fn load_user_work_list_context(
        &self,
        work_list_id: Uuid,
        password_stdin: bool,
        prompt_message: &str,
        operation: &str,
    ) -> PublicResult<(PublicApiClient, WorkListContext)> {
        let mut credentials = self.require_user_principal_credentials(operation)?;
        let key_source = PrincipalWorkListKeySource::UserDataKey(self.load_data_key(
            &credentials,
            password_stdin,
            prompt_message,
        )?);
        self.refresh_user_credentials_if_needed(&mut credentials)
            .await?;
        let mut client =
            PublicApiClient::with_bearer_token(&self.api_url, credentials.access_token);
        let work_list = client.get_work_list(work_list_id).await?;
        let context = self.context_from_work_list_detail(&work_list, Some(&key_source));
        Ok((client, context))
    }

    fn require_work_list_key<'a>(
        &self,
        context: &'a WorkListContext,
    ) -> PublicResult<&'a SymmetricKey> {
        context.list_key.as_ref().ok_or_else(|| {
            read_error_to_public_error(
                context.read_error.as_ref(),
                "failed to resolve work list key",
            )
        })
    }

    fn load_data_key(
        &self,
        credentials: &Credentials,
        password_stdin: bool,
        prompt_message: &str,
    ) -> PublicResult<SymmetricKey> {
        let session_key = self.current_session_key(credentials)?;
        if password_stdin {
            let password = read_required_password(password_stdin, Some(prompt_message))?;
            return decrypt_user_data_key(&password, &credentials.data_key_ciphertext);
        }

        if let Some(data_key) = fetch_data_key(&session_key)? {
            return Ok(data_key);
        }

        match self.load_data_key_from_persisted_secret(credentials, &session_key) {
            Ok(Some(data_key)) => Ok(data_key),
            Ok(None) => Err(missing_unlock_error(prompt_message)),
            Err(err) => Err(persisted_unlock_error(prompt_message, err)),
        }
    }

    fn load_data_key_from_persisted_secret(
        &self,
        credentials: &Credentials,
        session_key: &SessionKey,
    ) -> PublicResult<Option<SymmetricKey>> {
        let Some(data_key_bytes) = load_persisted_data_key(credentials)? else {
            return Ok(None);
        };
        let data_key = SymmetricKey::from_slice(&data_key_bytes)?;
        unlock(session_key, &data_key, auto_unlock_ttl_seconds()?)?;
        Ok(Some(data_key))
    }

    fn load_principal_work_list_key_source(
        &self,
        password_stdin: bool,
        prompt_message: &str,
    ) -> PublicResult<PrincipalWorkListKeySource> {
        match self.require_principal_credentials()? {
            PrincipalCredentials::User(credentials) => Ok(PrincipalWorkListKeySource::UserDataKey(
                self.load_data_key(&credentials, password_stdin, prompt_message)?,
            )),
            PrincipalCredentials::Agent(credentials) => {
                Ok(PrincipalWorkListKeySource::AgentRecipientPrivateKey(
                    self.load_agent_recipient_private_key(&credentials)?,
                ))
            }
        }
    }

    fn load_agent_recipient_private_key(
        &self,
        credentials: &AgentCredentials,
    ) -> PublicResult<[u8; 32]> {
        let seed = load_agent_seed(credentials)?.ok_or_else(|| {
            PublicError::validation("agent seed missing from local secure storage")
        })?;
        Ok(agent_key_material_from_seed(seed)?.recipient_private_key)
    }

    fn build_work_list_contexts(
        &self,
        work_lists: &[WorkListResponse],
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> HashMap<Uuid, WorkListContext> {
        work_lists
            .iter()
            .map(|work_list| {
                (
                    work_list.id,
                    self.context_from_work_list_response(work_list, key_source),
                )
            })
            .collect()
    }

    fn context_from_work_list_detail(
        &self,
        work_list: &WorkListDetailResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> WorkListContext {
        self.context_from_work_list_response(&work_list.work_list, key_source)
    }

    fn context_from_work_list_response(
        &self,
        work_list: &WorkListResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> WorkListContext {
        let Some(key_source) = key_source else {
            return unreadable_work_list_context(None, missing_work_list_key_source_error());
        };

        let list_key = match resolve_work_list_key_for_principal_source(
            key_source,
            work_list.id,
            &work_list.membership.work_list_key_ciphertext,
        ) {
            Ok(list_key) => list_key,
            Err(err) => {
                return unreadable_work_list_context(None, make_read_error("work_list_key", err));
            }
        };

        let fallback_title =
            decode_work_list_title_fallback(&work_list.title_ciphertext, &list_key);
        let payload = decode_work_list_payload_value(&list_key, &work_list.payload_ciphertext);
        let title = payload
            .as_ref()
            .ok()
            .and_then(extract_work_list_title)
            .or(fallback_title);
        WorkListContext {
            work_list_title: title,
            list_key: Some(list_key),
            read_error: payload
                .err()
                .map(|err| make_read_error("work_list_payload", err)),
        }
    }

    fn project_work_list_summary(
        &self,
        work_list: WorkListResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> AgentWorkListSummary {
        let membership = project_membership(&work_list.membership);

        let Some(key_source) = key_source else {
            return build_work_list_summary(
                work_list,
                membership,
                None,
                None,
                None,
                Some(missing_work_list_key_source_error()),
            );
        };

        self.project_work_list_summary_with_key_source(work_list, membership, key_source)
    }

    fn project_work_list_summary_with_key_source(
        &self,
        work_list: WorkListResponse,
        membership: AgentMembership,
        key_source: &PrincipalWorkListKeySource,
    ) -> AgentWorkListSummary {
        let list_key = match resolve_work_list_key_for_principal_source(
            key_source,
            work_list.id,
            &work_list.membership.work_list_key_ciphertext,
        ) {
            Ok(list_key) => list_key,
            Err(err) => {
                return build_work_list_summary(
                    work_list,
                    membership,
                    None,
                    None,
                    None,
                    Some(make_read_error("work_list_key", err)),
                );
            }
        };

        let fallback_title =
            decode_work_list_title_fallback(&work_list.title_ciphertext, &list_key);
        let fallback_description = work_list
            .description_ciphertext
            .as_deref()
            .and_then(|ciphertext| decode_work_list_description_fallback(ciphertext, &list_key));
        match decode_work_list_payload_value(&list_key, &work_list.payload_ciphertext) {
            Ok(payload) => {
                let title = extract_work_list_title(&payload).or(fallback_title);
                let description = extract_work_list_description(&payload).or(fallback_description);
                build_work_list_summary(
                    work_list,
                    membership,
                    title,
                    description,
                    Some(payload),
                    None,
                )
            }
            Err(err) => build_work_list_summary(
                work_list,
                membership,
                fallback_title,
                fallback_description,
                None,
                Some(make_read_error("work_list_payload", err)),
            ),
        }
    }

    fn project_work_list_detail(
        &self,
        work_list: WorkListDetailResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> AgentWorkListDetail {
        let members = work_list.members.iter().map(project_membership).collect();
        AgentWorkListDetail {
            work_list: self.project_work_list_summary(work_list.work_list, key_source),
            members,
        }
    }

    fn project_task_summary(
        &self,
        task: TaskResponse,
        context: Option<&WorkListContext>,
    ) -> AgentTaskSummary {
        project_task(TaskProjectionInput {
            metadata: TaskProjectionMetadata {
                id: task.id,
                work_list_id: task.work_list_id,
                work_list_title: context.and_then(|item| item.work_list_title.clone()),
                created_by_membership_id: task.created_by_membership_id,
                section_id: task.section_id,
                priority: task.priority,
                position: Some(task.position),
                due_at: task.due_at,
                start_at: task.start_at,
                completed_at: task.completed_at,
                archived_at: task.archived_at,
                is_completed: task.is_completed,
                recurrence_id: task.recurrence_id,
                recurrence_schedule: task.recurrence_schedule,
                recurrence_iteration: task.recurrence_iteration,
                materialized_at: task.materialized_at,
                created_at: task.created_at,
                updated_at: task.updated_at,
                comment_count: task.comment_count,
            },
            delegations: task.delegations,
            title_ciphertext: &task.title_ciphertext,
            payload_ciphertext: &task.payload_ciphertext,
            list_key: context.and_then(|item| item.list_key.as_ref()),
            inherited_error: context.and_then(|item| item.read_error.clone()),
        })
    }

    fn project_my_task_summary(
        &self,
        task: MyTaskResponse,
        context: Option<&WorkListContext>,
    ) -> AgentTaskSummary {
        let fallback_work_list_title =
            context
                .and_then(|item| item.list_key.as_ref())
                .and_then(|list_key| {
                    decode_work_list_title_fallback(&task.work_list_title_ciphertext, list_key)
                });
        let work_list_title = context
            .and_then(|item| item.work_list_title.clone())
            .or(fallback_work_list_title);
        let list_key = context.and_then(|item| item.list_key.as_ref());
        let read_error = context.and_then(|item| item.read_error.clone());

        project_task(TaskProjectionInput {
            metadata: TaskProjectionMetadata {
                id: task.id,
                work_list_id: task.work_list_id,
                work_list_title,
                created_by_membership_id: task.created_by_membership_id,
                section_id: task.section_id,
                priority: task.priority,
                position: None,
                due_at: task.due_at,
                start_at: task.start_at,
                completed_at: task.completed_at,
                archived_at: None,
                is_completed: task.is_completed,
                recurrence_id: None,
                recurrence_schedule: None,
                recurrence_iteration: None,
                materialized_at: None,
                created_at: task.created_at,
                updated_at: task.updated_at,
                comment_count: task.comment_count,
            },
            delegations: task.delegations,
            title_ciphertext: &task.title_ciphertext,
            payload_ciphertext: &task.payload_ciphertext,
            list_key,
            inherited_error: read_error,
        })
    }

    fn project_comment(
        &self,
        comment: CommentResponse,
        list_key: Option<&SymmetricKey>,
    ) -> AgentComment {
        match list_key {
            Some(list_key) => match decode_sealed_blob(&comment.body_ciphertext)
                .and_then(|bytes| decrypt_comment_payload(list_key, &bytes))
            {
                Ok(payload) => {
                    let CommentPayloadBody {
                        content,
                        mentions,
                        attachments,
                        client_meta,
                    } = payload.body;
                    let (attachments, read_error) = match project_attachments(attachments) {
                        Ok(attachments) => (attachments, None),
                        Err(err) => (None, Some(make_read_error("comment_attachments", err))),
                    };

                    AgentComment {
                        id: comment.id,
                        task_id: comment.task_id,
                        author_membership_id: comment.author_membership_id,
                        body_markdown: rich_text_to_markdown(&content),
                        content: Some(content),
                        mentions,
                        attachments,
                        client_meta: client_meta.map(flexible_value_to_json),
                        created_at: comment.created_at,
                        updated_at: comment.updated_at,
                        read_error,
                    }
                }
                Err(err) => AgentComment {
                    id: comment.id,
                    task_id: comment.task_id,
                    author_membership_id: comment.author_membership_id,
                    body_markdown: None,
                    content: None,
                    mentions: None,
                    attachments: None,
                    client_meta: None,
                    created_at: comment.created_at,
                    updated_at: comment.updated_at,
                    read_error: Some(make_read_error("comment_payload", err)),
                },
            },
            None => AgentComment {
                id: comment.id,
                task_id: comment.task_id,
                author_membership_id: comment.author_membership_id,
                body_markdown: None,
                content: None,
                mentions: None,
                attachments: None,
                client_meta: None,
                created_at: comment.created_at,
                updated_at: comment.updated_at,
                read_error: Some(ReadError {
                    code: "work_list_key_missing".to_string(),
                    message: "could not resolve work list key for comment decryption".to_string(),
                }),
            },
        }
    }
}

fn auto_unlock_ttl_seconds() -> PublicResult<u64> {
    match std::env::var("WORKLIST_UNLOCK_TTL_SECONDS") {
        Ok(value) => {
            let trimmed = value.trim();
            let ttl_seconds = trimmed.parse::<u64>().map_err(|err| {
                PublicError::validation(format!(
                    "invalid WORKLIST_UNLOCK_TTL_SECONDS value '{trimmed}': {err}"
                ))
            })?;
            if ttl_seconds == 0 {
                return Err(PublicError::validation(
                    "WORKLIST_UNLOCK_TTL_SECONDS must be greater than zero",
                ));
            }
            Ok(ttl_seconds)
        }
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_AUTO_UNLOCK_TTL_SECONDS),
        Err(std::env::VarError::NotUnicode(_)) => Err(PublicError::validation(
            "WORKLIST_UNLOCK_TTL_SECONDS must be valid UTF-8",
        )),
    }
}

fn missing_unlock_error(prompt_message: &str) -> PublicError {
    PublicError::validation(format!(
        "{prompt_message} No unlocked local session or persisted bootstrap secret is available. Run 'worklist auth unlock --password-stdin' for a temporary session or 'worklist auth keychain store --password-stdin' to persist a local bootstrap secret."
    ))
}

fn persisted_unlock_error(prompt_message: &str, err: PublicError) -> PublicError {
    PublicError::validation(format!(
        "{prompt_message} Failed to load the persisted bootstrap secret: {err}. Run 'worklist auth unlock --password-stdin' for a temporary session or 'worklist auth keychain store --password-stdin' to refresh the local bootstrap secret."
    ))
}

fn auth_http_client() -> PublicResult<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(AUTH_HTTP_TIMEOUT)
        .build()
        .map_err(|err| PublicError::unexpected(format!("failed to build auth HTTP client: {err}")))
}

fn read_password(label: &str) -> PublicResult<String> {
    prompt_password(label)
        .map_err(|err| PublicError::unexpected(format!("failed to read password: {err}")))
}

fn read_password_from_stdin() -> PublicResult<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|err| {
        PublicError::unexpected(format!("failed to read password from stdin: {err}"))
    })?;
    Ok(input.trim().to_string())
}

fn read_required_password(
    password_stdin: bool,
    prompt_message: Option<&str>,
) -> PublicResult<String> {
    let password = if password_stdin {
        read_password_from_stdin()?
    } else {
        if let Some(prompt_message) = prompt_message {
            println!("{prompt_message}");
        }
        read_password("Password: ")?
    };

    if password.is_empty() {
        return Err(PublicError::validation("password is required"));
    }

    Ok(password)
}
