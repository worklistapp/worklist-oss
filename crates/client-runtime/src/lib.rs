#![cfg_attr(test, allow(clippy::unwrap_used))]

mod unlock_daemon;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;
use uuid::Uuid;
use worklist_client_api::{
    ApproveAgentGrantRequest, ArchiveTaskRequest, CommentResponse, CreateCommentRequest,
    CreateTaskRequest, CurrentUserResponse, DashboardStatsResponse, DeleteCommentRequest,
    DeleteTaskRequest, DownloadAttachmentResponse, MembershipResponse, MoveTaskRequest,
    MyTaskResponse, PublicApiClient, TaskResponse, UnarchiveTaskRequest, UpdateCommentRequest,
    UpdateTaskRequest, WorkListDetailResponse, WorkListResponse,
};
use worklist_client_auth::{
    AgentCredentials, AgentEnrollmentResponse, Credentials, PersistedDataKeyStatus,
    PrincipalCredentials, PrincipalSelection, agent_key_material_from_seed,
    clear_persisted_data_key as clear_persisted_data_key_secret, load_agent_seed, load_credentials,
    load_credentials_for_url, load_persisted_data_key, load_principal_credentials_for_url,
    normalize_api_url, persisted_data_key_status, save_persisted_data_key,
};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::{
    AttachmentBlobRef, ChecklistItemPayload, CommentPayloadBody, FlexibleValue, SymmetricKey,
    TaskPayloadBody, TaskPayloadRichText, build_comment_payload_envelope,
    build_task_payload_envelope, compute_payload_proof, decode_attachment_blob_key,
    decode_sealed_blob, decrypt_agent_work_list_key, decrypt_attachment_bytes,
    decrypt_comment_payload, decrypt_task_payload, decrypt_text_value, decrypt_user_data_key,
    decrypt_work_list_key, decrypt_work_list_payload, derive_payload_binding_key,
    derive_work_list_key, encrypt_agent_work_list_key, encrypt_comment_payload,
    encrypt_task_payload, flexible_value_to_json, plaintext_rich_text, seal_text_value,
};

pub use unlock_daemon::{
    SessionKey, UnlockStatus, clear_session, fetch_data_key, lock, serve, session_key, socket_path,
    unlock, unlock_status,
};

const DEFAULT_AUTO_UNLOCK_TTL_SECONDS: u64 = 8 * 60 * 60;

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
    pub section_snapshots: Vec<worklist_client_api::SectionSnapshotPayload>,
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
    blob_key: Vec<u8>,
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
pub enum ReadableAttachmentContentFormat {
    Text,
    Markdown,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone)]
pub struct RuntimeClient {
    api_url: String,
    principal_selection: PrincipalSelection,
}

#[derive(Debug, Clone)]
struct WorkListContext {
    work_list_title: Option<String>,
    list_key: Option<SymmetricKey>,
    read_error: Option<ReadError>,
}

#[derive(Debug, Clone)]
enum PrincipalWorkListKeySource {
    UserDataKey(SymmetricKey),
    AgentRecipientPrivateKey([u8; 32]),
}

#[derive(Debug)]
struct TaskProjectionMetadata {
    id: Uuid,
    work_list_id: Uuid,
    work_list_title: Option<String>,
    created_by_membership_id: Uuid,
    section_id: Option<Uuid>,
    priority: Option<i8>,
    position: Option<String>,
    due_at: Option<DateTime<Utc>>,
    start_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    archived_at: Option<DateTime<Utc>>,
    is_completed: bool,
    recurrence_id: Option<Uuid>,
    recurrence_schedule: Option<String>,
    recurrence_iteration: Option<i64>,
    materialized_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    comment_count: i64,
}

#[derive(Debug)]
struct TaskProjectionInput<'a> {
    metadata: TaskProjectionMetadata,
    delegations: Vec<worklist_client_api::DelegationResponse>,
    title_ciphertext: &'a str,
    payload_ciphertext: &'a str,
    list_key: Option<&'a SymmetricKey>,
    inherited_error: Option<ReadError>,
}

#[derive(Debug)]
struct ResolvedTaskAttachmentDownload {
    attachment: AgentAttachment,
    blob_ref: AttachmentBlobRef,
    download: DownloadAttachmentResponse,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AttachmentReadStrategy {
    Utf8Text,
    DocxMarkdown,
    Unsupported,
}

const DOCX_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

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

impl AgentAttachment {
    fn blob_key(&self) -> &[u8] {
        &self.blob_key
    }

    #[must_use]
    fn read_strategy(&self) -> AttachmentReadStrategy {
        if content_type_is_docx(&self.content_type) {
            return AttachmentReadStrategy::DocxMarkdown;
        }

        if content_type_is_textual(&self.content_type) {
            return AttachmentReadStrategy::Utf8Text;
        }

        if file_extension_is_docx(&self.file_name) {
            return AttachmentReadStrategy::DocxMarkdown;
        }

        if file_extension_is_textual(&self.file_name) {
            return AttachmentReadStrategy::Utf8Text;
        }

        AttachmentReadStrategy::Unsupported
    }

    #[must_use]
    fn readable_content_format(
        &self,
        read_strategy: AttachmentReadStrategy,
    ) -> ReadableAttachmentContentFormat {
        match read_strategy {
            AttachmentReadStrategy::Utf8Text => {
                if content_type_is_markdown(&self.content_type)
                    || file_extension_is_markdown(&self.file_name)
                {
                    ReadableAttachmentContentFormat::Markdown
                } else {
                    ReadableAttachmentContentFormat::Text
                }
            }
            AttachmentReadStrategy::DocxMarkdown => ReadableAttachmentContentFormat::Markdown,
            AttachmentReadStrategy::Unsupported => {
                unreachable!("unsupported attachments are rejected before render")
            }
        }
    }
}

impl AttachmentReadStrategy {
    #[must_use]
    fn source_kind(self) -> ReadableAttachmentSourceKind {
        match self {
            Self::Utf8Text => ReadableAttachmentSourceKind::PlainText,
            Self::DocxMarkdown => ReadableAttachmentSourceKind::DocxRendered,
            Self::Unsupported => unreachable!("unsupported attachments are rejected before render"),
        }
    }
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

    pub fn authenticated_api_client(&self) -> PublicResult<PublicApiClient> {
        let credentials = self.require_principal_credentials()?;
        match &credentials {
            PrincipalCredentials::User(user) if user.is_refresh_expired() => {
                Err(PublicError::validation(
                    "session expired - run 'worklist auth login' to authenticate",
                ))
            }
            _ => Ok(PublicApiClient::with_credentials(
                &self.api_url,
                credentials,
            )),
        }
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

    pub async fn get_me(&self) -> PublicResult<CurrentUserResponse> {
        let mut client = self.authenticated_api_client()?;
        client.get_me().await
    }

    pub async fn get_stats(&self) -> PublicResult<DashboardStatsResponse> {
        let mut client = self.authenticated_api_client()?;
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
        let credentials = self.require_logged_in_credentials()?;
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
        let mut client = PublicApiClient::with_credentials(
            &self.api_url,
            PrincipalCredentials::User(credentials),
        );
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
        let mut client = self.authenticated_api_client()?;
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
        let mut client = self.authenticated_api_client()?;
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
        let mut client = self.authenticated_api_client()?;

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
        let title_ciphertext = seal_text_value(normalized_title)?;
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
            let title_ciphertext = seal_text_value(normalized_title)?;
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
        let mut client = self.authenticated_api_client()?;
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
        let mut client = self.authenticated_api_client()?;
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
        let mut client = self.authenticated_api_client()?;
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
        let credentials = self.require_user_principal_credentials(operation)?;
        let key_source = PrincipalWorkListKeySource::UserDataKey(self.load_data_key(
            &credentials,
            password_stdin,
            prompt_message,
        )?);
        let mut client = PublicApiClient::with_credentials(
            &self.api_url,
            PrincipalCredentials::User(credentials),
        );
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
        let fallback_title = decode_text_fallback(&work_list.title_ciphertext);
        match key_source {
            Some(key_source) => match resolve_work_list_key_for_principal_source(
                key_source,
                work_list.id,
                &work_list.membership.work_list_key_ciphertext,
            ) {
                Ok(list_key) => {
                    let payload =
                        decode_work_list_payload_value(&list_key, &work_list.payload_ciphertext);
                    let title = payload
                        .as_ref()
                        .ok()
                        .and_then(extract_work_list_title)
                        .or(fallback_title.clone());
                    WorkListContext {
                        work_list_title: title,
                        list_key: Some(list_key),
                        read_error: payload
                            .err()
                            .map(|err| make_read_error("work_list_payload", err)),
                    }
                }
                Err(err) => unreadable_work_list_context(
                    fallback_title,
                    make_read_error("work_list_key", err),
                ),
            },
            None => {
                unreadable_work_list_context(fallback_title, missing_work_list_key_source_error())
            }
        }
    }

    fn project_work_list_summary(
        &self,
        work_list: WorkListResponse,
        key_source: Option<&PrincipalWorkListKeySource>,
    ) -> AgentWorkListSummary {
        let fallback_title = decode_text_fallback(&work_list.title_ciphertext);
        let fallback_description = work_list
            .description_ciphertext
            .as_deref()
            .and_then(decode_text_fallback);
        let membership = project_membership(&work_list.membership);

        match key_source {
            Some(key_source) => self.project_work_list_summary_with_key_source(
                work_list,
                membership,
                fallback_title,
                fallback_description,
                key_source,
            ),
            None => build_work_list_summary(
                work_list,
                membership,
                fallback_title,
                fallback_description,
                None,
                Some(missing_work_list_key_source_error()),
            ),
        }
    }

    fn project_work_list_summary_with_key_source(
        &self,
        work_list: WorkListResponse,
        membership: AgentMembership,
        fallback_title: Option<String>,
        fallback_description: Option<String>,
        key_source: &PrincipalWorkListKeySource,
    ) -> AgentWorkListSummary {
        match resolve_work_list_key_for_principal_source(
            key_source,
            work_list.id,
            &work_list.membership.work_list_key_ciphertext,
        ) {
            Ok(list_key) => {
                match decode_work_list_payload_value(&list_key, &work_list.payload_ciphertext) {
                    Ok(payload) => {
                        let title = extract_work_list_title(&payload).or(fallback_title);
                        let description =
                            extract_work_list_description(&payload).or(fallback_description);
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
            Err(err) => build_work_list_summary(
                work_list,
                membership,
                fallback_title,
                fallback_description,
                None,
                Some(make_read_error("work_list_key", err)),
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
        let fallback_work_list_title = decode_text_fallback(&task.work_list_title_ciphertext);
        let work_list_title = context
            .and_then(|item| item.work_list_title.clone())
            .or(fallback_work_list_title.clone());
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
    pub input: DeleteTaskRequest,
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
    pub input: DeleteCommentRequest,
}

fn project_attachments(
    values: Option<Vec<FlexibleValue>>,
) -> PublicResult<Option<Vec<AgentAttachment>>> {
    values
        .map(|values| values.into_iter().map(project_attachment).collect())
        .transpose()
}

fn project_attachment(value: FlexibleValue) -> PublicResult<AgentAttachment> {
    let FlexibleValue::Map(entries) = value else {
        return Err(PublicError::validation("attachment must be an object"));
    };

    let mut id = None;
    let mut file_name = None;
    let mut content_type = None;
    let mut size_bytes = None;
    let mut blob_key = None;

    for (key, value) in entries {
        match flexible_key_to_string(key).as_str() {
            "id" => id = Some(value),
            "file_name" => file_name = Some(value),
            "content_type" => content_type = Some(value),
            "size_bytes" => size_bytes = Some(value),
            "blob_key" => blob_key = Some(value),
            _ => {}
        }
    }

    Ok(AgentAttachment {
        id: parse_attachment_uuid(id, "attachment.id")?,
        file_name: parse_attachment_text(file_name, "attachment.file_name")?,
        content_type: parse_attachment_text(content_type, "attachment.content_type")?,
        size_bytes: parse_attachment_u64(size_bytes, "attachment.size_bytes")?,
        blob_key: parse_attachment_bytes(blob_key, "attachment.blob_key")?,
    })
}

fn parse_attachment_uuid(value: Option<FlexibleValue>, field: &str) -> PublicResult<Uuid> {
    match value {
        Some(FlexibleValue::Text(value)) => Uuid::parse_str(&value).map_err(|err| {
            PublicError::validation(format!("{field} must be a UUID string: {err}"))
        }),
        Some(FlexibleValue::Bytes(value)) if value.len() == 16 => Uuid::from_slice(&value)
            .map_err(|err| PublicError::validation(format!("{field} must be a UUID: {err}"))),
        Some(_) => Err(PublicError::validation(format!(
            "{field} must be a UUID string or 16-byte UUID"
        ))),
        None => Err(PublicError::validation(format!("{field} is required"))),
    }
}

fn parse_attachment_text(value: Option<FlexibleValue>, field: &str) -> PublicResult<String> {
    match value {
        Some(FlexibleValue::Text(value)) if !value.trim().is_empty() => Ok(value),
        Some(FlexibleValue::Text(_)) => {
            Err(PublicError::validation(format!("{field} cannot be empty")))
        }
        Some(_) => Err(PublicError::validation(format!("{field} must be text"))),
        None => Err(PublicError::validation(format!("{field} is required"))),
    }
}

fn parse_attachment_u64(value: Option<FlexibleValue>, field: &str) -> PublicResult<u64> {
    let Some(value) = value else {
        return Err(PublicError::validation(format!("{field} is required")));
    };

    match value {
        FlexibleValue::Integer(value) => u64::try_from(i128::from(value)).map_err(|_| {
            PublicError::validation(format!("{field} must be a non-negative integer"))
        }),
        _ => Err(PublicError::validation(format!(
            "{field} must be a non-negative integer"
        ))),
    }
}

fn parse_attachment_bytes(value: Option<FlexibleValue>, field: &str) -> PublicResult<Vec<u8>> {
    match value {
        Some(FlexibleValue::Bytes(value)) if !value.is_empty() => Ok(value),
        Some(FlexibleValue::Bytes(_)) => {
            Err(PublicError::validation(format!("{field} cannot be empty")))
        }
        Some(_) => Err(PublicError::validation(format!("{field} must be bytes"))),
        None => Err(PublicError::validation(format!("{field} is required"))),
    }
}

fn flexible_key_to_string(value: FlexibleValue) -> String {
    match value {
        FlexibleValue::Text(value) => value,
        other => flexible_value_to_json(other).to_string(),
    }
}

fn project_task(input: TaskProjectionInput<'_>) -> AgentTaskSummary {
    let TaskProjectionInput {
        metadata,
        delegations,
        title_ciphertext,
        payload_ciphertext,
        list_key,
        inherited_error,
    } = input;
    let fallback_title = decode_text_fallback(title_ciphertext);
    let projected_delegations = delegations.into_iter().map(project_delegation).collect();

    match list_key {
        Some(list_key) => match decode_sealed_blob(payload_ciphertext)
            .and_then(|bytes| decrypt_task_payload(list_key, &bytes))
        {
            Ok(payload) => {
                let TaskPayloadBody {
                    title,
                    rich_text,
                    checklist,
                    attachments,
                    references,
                    mentions,
                    client_meta,
                    recurrence_state,
                } = payload.body;
                let (attachments, read_error) = match project_attachments(attachments) {
                    Ok(attachments) => (attachments, None),
                    Err(err) => (None, Some(make_read_error("task_attachments", err))),
                };

                AgentTaskSummary {
                    id: metadata.id,
                    work_list_id: metadata.work_list_id,
                    work_list_title: metadata.work_list_title,
                    created_by_membership_id: metadata.created_by_membership_id,
                    section_id: metadata.section_id,
                    priority: metadata.priority,
                    position: metadata.position,
                    due_at: metadata.due_at,
                    start_at: metadata.start_at,
                    completed_at: metadata.completed_at,
                    archived_at: metadata.archived_at,
                    is_completed: metadata.is_completed,
                    recurrence_id: metadata.recurrence_id,
                    recurrence_schedule: metadata.recurrence_schedule,
                    recurrence_iteration: metadata.recurrence_iteration,
                    materialized_at: metadata.materialized_at,
                    created_at: metadata.created_at,
                    updated_at: metadata.updated_at,
                    comment_count: metadata.comment_count,
                    title: Some(title).or(fallback_title),
                    body_markdown: rich_text.as_ref().and_then(rich_text_to_markdown),
                    body_rich_text: rich_text,
                    checklist,
                    attachments,
                    references: references
                        .map(|values| values.into_iter().map(flexible_value_to_json).collect()),
                    mentions,
                    client_meta: client_meta.map(flexible_value_to_json),
                    recurrence_state: recurrence_state.map(flexible_value_to_json),
                    delegations: projected_delegations,
                    read_error,
                }
            }
            Err(err) => AgentTaskSummary {
                id: metadata.id,
                work_list_id: metadata.work_list_id,
                work_list_title: metadata.work_list_title,
                created_by_membership_id: metadata.created_by_membership_id,
                section_id: metadata.section_id,
                priority: metadata.priority,
                position: metadata.position,
                due_at: metadata.due_at,
                start_at: metadata.start_at,
                completed_at: metadata.completed_at,
                archived_at: metadata.archived_at,
                is_completed: metadata.is_completed,
                recurrence_id: metadata.recurrence_id,
                recurrence_schedule: metadata.recurrence_schedule,
                recurrence_iteration: metadata.recurrence_iteration,
                materialized_at: metadata.materialized_at,
                created_at: metadata.created_at,
                updated_at: metadata.updated_at,
                comment_count: metadata.comment_count,
                title: fallback_title,
                body_markdown: None,
                body_rich_text: None,
                checklist: None,
                attachments: None,
                references: None,
                mentions: None,
                client_meta: None,
                recurrence_state: None,
                delegations: projected_delegations,
                read_error: Some(make_read_error("task_payload", err)),
            },
        },
        None => AgentTaskSummary {
            id: metadata.id,
            work_list_id: metadata.work_list_id,
            work_list_title: metadata.work_list_title,
            created_by_membership_id: metadata.created_by_membership_id,
            section_id: metadata.section_id,
            priority: metadata.priority,
            position: metadata.position,
            due_at: metadata.due_at,
            start_at: metadata.start_at,
            completed_at: metadata.completed_at,
            archived_at: metadata.archived_at,
            is_completed: metadata.is_completed,
            recurrence_id: metadata.recurrence_id,
            recurrence_schedule: metadata.recurrence_schedule,
            recurrence_iteration: metadata.recurrence_iteration,
            materialized_at: metadata.materialized_at,
            created_at: metadata.created_at,
            updated_at: metadata.updated_at,
            comment_count: metadata.comment_count,
            title: fallback_title,
            body_markdown: None,
            body_rich_text: None,
            checklist: None,
            attachments: None,
            references: None,
            mentions: None,
            client_meta: None,
            recurrence_state: None,
            delegations: projected_delegations,
            read_error: Some(inherited_error.unwrap_or(ReadError {
                code: "work_list_key_missing".to_string(),
                message: "could not resolve work list key for task decryption".to_string(),
            })),
        },
    }
}

fn project_membership(membership: &MembershipResponse) -> AgentMembership {
    AgentMembership {
        id: membership.id,
        user_id: membership.user_id,
        user_email: membership.user_email.clone(),
        user_name: membership.user_name.clone(),
        user_avatar_color: membership.user_avatar_color.clone(),
        role: membership.role.clone(),
        status: membership.status.clone(),
        expires_at: membership.expires_at,
        joined_at: membership.joined_at,
    }
}

fn project_delegation(delegation: worklist_client_api::DelegationResponse) -> AgentDelegation {
    AgentDelegation {
        id: delegation.id,
        task_id: delegation.task_id,
        membership_id: delegation.membership_id,
        role: delegation.role,
        status: delegation.status,
        note_present: delegation.note_ciphertext.is_some(),
        created_at: delegation.created_at,
        updated_at: delegation.updated_at,
    }
}

fn unreadable_work_list_context(
    work_list_title: Option<String>,
    read_error: ReadError,
) -> WorkListContext {
    WorkListContext {
        work_list_title,
        list_key: None,
        read_error: Some(read_error),
    }
}

fn build_work_list_summary(
    work_list: WorkListResponse,
    membership: AgentMembership,
    title: Option<String>,
    description: Option<String>,
    payload: Option<Value>,
    read_error: Option<ReadError>,
) -> AgentWorkListSummary {
    AgentWorkListSummary {
        id: work_list.id,
        owner_user_id: work_list.owner_user_id,
        workspace_id: work_list.workspace_id,
        timezone: work_list.timezone,
        section_snapshots: work_list.section_snapshots,
        created_at: work_list.created_at,
        updated_at: work_list.updated_at,
        membership,
        title,
        description,
        payload,
        read_error,
    }
}

fn missing_work_list_key_source_error() -> ReadError {
    ReadError {
        code: "work_list_key_source_missing".to_string(),
        message: "could not load work list key material for decryption".to_string(),
    }
}

fn resolve_work_list_key_for_principal_source(
    key_source: &PrincipalWorkListKeySource,
    work_list_id: Uuid,
    membership_ciphertext: &str,
) -> PublicResult<SymmetricKey> {
    match key_source {
        PrincipalWorkListKeySource::UserDataKey(data_key) => {
            resolve_list_key(data_key, work_list_id, membership_ciphertext)
        }
        PrincipalWorkListKeySource::AgentRecipientPrivateKey(recipient_private_key) => {
            if membership_ciphertext.trim().is_empty() {
                return Err(PublicError::validation("agent work list grant missing"));
            }

            let work_list_key_bytes = decode_sealed_blob(membership_ciphertext)?;
            decrypt_agent_work_list_key(recipient_private_key, &work_list_id, &work_list_key_bytes)
        }
    }
}

fn resolve_list_key(
    data_key: &SymmetricKey,
    work_list_id: Uuid,
    membership_ciphertext: &str,
) -> PublicResult<SymmetricKey> {
    if membership_ciphertext.trim().is_empty() {
        return derive_work_list_key(data_key, &work_list_id);
    }

    let work_list_key_bytes = decode_sealed_blob(membership_ciphertext)?;
    decrypt_work_list_key(data_key, &work_list_key_bytes)
}

fn decode_work_list_payload_value(
    list_key: &SymmetricKey,
    payload_ciphertext: &str,
) -> PublicResult<Value> {
    let payload_bytes = decode_sealed_blob(payload_ciphertext)?;
    let payload: FlexibleValue = decrypt_work_list_payload(list_key, &payload_bytes)?;
    Ok(flexible_value_to_json(payload))
}

fn extract_work_list_title(payload: &Value) -> Option<String> {
    payload
        .get("body")
        .and_then(|body| body.get("title"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn extract_work_list_description(payload: &Value) -> Option<String> {
    payload
        .get("body")
        .and_then(|body| body.get("description"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn decode_text_fallback(ciphertext: &str) -> Option<String> {
    decode_sealed_blob(ciphertext)
        .and_then(|bytes| decrypt_text_value(&bytes))
        .ok()
}

fn make_read_error(code: &str, err: PublicError) -> ReadError {
    ReadError {
        code: code.to_string(),
        message: err.to_string(),
    }
}

fn find_task_attachment(
    task: &AgentTaskSummary,
    attachment_id: Uuid,
) -> PublicResult<AgentAttachment> {
    let attachments = match task.attachments.as_ref() {
        Some(attachments) => attachments,
        None if task.read_error.is_some() => {
            return Err(read_error_to_public_error(
                task.read_error.as_ref(),
                "failed to read task attachments",
            ));
        }
        None => {
            return Err(PublicError::validation("task does not include attachments"));
        }
    };

    attachments
        .iter()
        .find(|attachment| attachment.id == attachment_id)
        .cloned()
        .ok_or_else(|| PublicError::validation(format!("attachment {attachment_id} not found")))
}

async fn download_and_decrypt_attachment(
    resolved: ResolvedTaskAttachmentDownload,
) -> PublicResult<DownloadedAttachment> {
    let ResolvedTaskAttachmentDownload {
        attachment,
        blob_ref,
        download,
    } = resolved;
    let ciphertext = download_presigned_attachment(&download).await?;
    if u64::try_from(ciphertext.len()).ok() != Some(blob_ref.ciphertext_bytes) {
        return Err(PublicError::validation(format!(
            "attachment '{}' download size mismatch: expected {} bytes, got {}",
            attachment.file_name,
            blob_ref.ciphertext_bytes,
            ciphertext.len()
        )));
    }
    let bytes =
        decrypt_attachment_bytes(&ciphertext, &blob_ref.file_key, Some(&blob_ref.enc_context))?;
    Ok(DownloadedAttachment { attachment, bytes })
}

async fn download_presigned_attachment(
    download: &DownloadAttachmentResponse,
) -> PublicResult<Vec<u8>> {
    let client = reqwest::Client::new();
    let mut request = client.get(&download.download_url);
    for (name, value) in &download.download_headers {
        request = request.header(name, value);
    }

    let response = request.send().await.map_err(|err| {
        PublicError::unexpected(format!("failed to download attachment ciphertext: {err}"))
    })?;
    let status = response.status();
    if !status.is_success() {
        return Err(PublicError::unexpected(format!(
            "attachment download failed with status {}",
            status
        )));
    }

    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|err| {
            PublicError::unexpected(format!("failed to read attachment ciphertext: {err}"))
        })
}

fn build_readable_attachment(
    attachment: AgentAttachment,
    bytes: Vec<u8>,
    read_strategy: AttachmentReadStrategy,
) -> PublicResult<ReadableAttachment> {
    let content_format = attachment.readable_content_format(read_strategy);
    let text = match read_strategy {
        AttachmentReadStrategy::Utf8Text => {
            decode_attachment_utf8_text(&attachment.file_name, bytes)?
        }
        AttachmentReadStrategy::DocxMarkdown => {
            render_docx_attachment_as_markdown(&attachment.file_name, &bytes)?
        }
        AttachmentReadStrategy::Unsupported => {
            return Err(unsupported_attachment_render_error(&attachment.file_name));
        }
    };

    Ok(ReadableAttachment {
        attachment,
        text,
        content_format,
        source_kind: read_strategy.source_kind(),
    })
}

fn decode_attachment_utf8_text(file_name: &str, bytes: Vec<u8>) -> PublicResult<String> {
    String::from_utf8(bytes).map_err(|err| {
        PublicError::validation(format!(
            "attachment '{}' is not valid UTF-8 text: {}",
            file_name, err
        ))
    })
}

fn render_docx_attachment_as_markdown(file_name: &str, bytes: &[u8]) -> PublicResult<String> {
    undocx::builder()
        .skip_images()
        .convert_bytes(bytes)
        .map(|markdown| normalize_docx_markdown(&markdown))
        .map_err(|err| {
            PublicError::validation(format!(
                "attachment '{}' could not be rendered as Markdown: {}",
                file_name, err
            ))
        })
}

fn normalize_docx_markdown(markdown: &str) -> String {
    let mut normalized = String::new();
    let mut prose_buffer = String::new();
    let mut in_code_fence = false;

    for line in markdown.split_inclusive('\n') {
        if line.trim_start().starts_with("```") {
            if !prose_buffer.is_empty() {
                normalized.push_str(&normalize_non_code_docx_markdown(&prose_buffer));
                prose_buffer.clear();
            }

            normalized.push_str(line);
            in_code_fence = !in_code_fence;
            continue;
        }

        if in_code_fence {
            normalized.push_str(line);
        } else {
            prose_buffer.push_str(line);
        }
    }

    if !prose_buffer.is_empty() {
        normalized.push_str(&normalize_non_code_docx_markdown(&prose_buffer));
    }

    normalized
}

fn normalize_non_code_docx_markdown(markdown: &str) -> String {
    let markdown = normalize_docx_html_tables(markdown);
    let markdown = normalize_docx_inline_tag_pair(&markdown, "strong", "**");
    let markdown = normalize_docx_inline_tag_pair(&markdown, "em", "*");
    let markdown = normalize_docx_inline_tag_pair(&markdown, "s", "~~");
    normalize_docx_inline_tag_pair(&markdown, "del", "~~")
}

fn normalize_docx_inline_tag_pair(markdown: &str, tag: &str, marker: &str) -> String {
    let open_tag = format!("<{tag}>");
    let close_tag = format!("</{tag}>");
    let mut normalized = String::new();
    let mut remaining = markdown;

    while let Some(tag_start) = remaining.find(&open_tag) {
        normalized.push_str(&remaining[..tag_start]);

        let inner_start = tag_start + open_tag.len();
        let Some(close_offset) = remaining[inner_start..].find(&close_tag) else {
            normalized.push_str(&remaining[tag_start..]);
            return normalized;
        };

        let inner_end = inner_start + close_offset;
        let inner = &remaining[inner_start..inner_end];
        let trimmed_start = inner.trim_start_matches(char::is_whitespace);
        let trimmed = inner.trim_matches(char::is_whitespace);
        let leading_whitespace_len = inner.len() - trimmed_start.len();
        let trailing_whitespace_len =
            inner.len() - inner.trim_end_matches(char::is_whitespace).len();

        normalized.push_str(&inner[..leading_whitespace_len]);

        if !trimmed.is_empty() {
            normalized.push_str(marker);
            normalized.push_str(trimmed);
            normalized.push_str(marker);
        }

        if trailing_whitespace_len > 0 {
            normalized.push_str(&inner[inner.len() - trailing_whitespace_len..]);
        }

        remaining = &remaining[inner_end + close_tag.len()..];
    }

    normalized.push_str(remaining);
    normalized
}

fn normalize_docx_html_tables(markdown: &str) -> String {
    let mut normalized = String::new();
    let mut remaining = markdown;

    while let Some(table_start) = remaining.find("<table") {
        normalized.push_str(&remaining[..table_start]);

        let Some(table_end) = find_docx_html_table_end(remaining, table_start) else {
            normalized.push_str(&remaining[table_start..]);
            return normalized;
        };

        let table_markdown = html2md::parse_html(&remaining[table_start..table_end]);
        normalized.push_str(table_markdown.trim_matches('\n'));
        remaining = &remaining[table_end..];
    }

    normalized.push_str(remaining);
    normalized
}

fn find_docx_html_table_end(markdown: &str, table_start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut search_from = table_start;

    while search_from < markdown.len() {
        let next_open = markdown[search_from..]
            .find("<table")
            .map(|offset| search_from + offset);
        let next_close = markdown[search_from..]
            .find("</table>")
            .map(|offset| search_from + offset);

        match (next_open, next_close) {
            (Some(open), Some(close)) if open < close => {
                depth += 1;
                search_from = open + "<table".len();
            }
            (_, Some(close)) => {
                if depth == 0 {
                    return None;
                }

                depth -= 1;
                search_from = close + "</table>".len();

                if depth == 0 {
                    return Some(search_from);
                }
            }
            _ => return None,
        }
    }

    None
}

fn unsupported_attachment_read_error(file_name: &str) -> PublicError {
    PublicError::validation(format!(
        "attachment '{}' is not readable in the CLI; use download instead",
        file_name
    ))
}

fn unsupported_attachment_render_error(file_name: &str) -> PublicError {
    PublicError::validation(format!(
        "attachment '{}' is not readable in the CLI",
        file_name
    ))
}

fn read_error_to_public_error(read_error: Option<&ReadError>, fallback: &str) -> PublicError {
    match read_error {
        Some(read_error) => PublicError::validation(read_error.message.clone()),
        None => PublicError::validation(fallback),
    }
}

fn normalized_content_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase()
}

fn file_extension(file_name: &str) -> Option<String> {
    Path::new(file_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|extension| extension.to_ascii_lowercase())
}

fn content_type_is_textual(content_type: &str) -> bool {
    let normalized = normalized_content_type(content_type);
    if normalized.starts_with("text/") {
        return true;
    }

    matches!(normalized.as_str(), "application/json" | "application/xml")
        || normalized.ends_with("+json")
        || normalized.ends_with("+xml")
}

fn file_extension_is_textual(file_name: &str) -> bool {
    let Some(extension) = file_extension(file_name) else {
        return false;
    };

    matches!(
        extension.as_str(),
        "txt" | "md" | "markdown" | "json" | "yaml" | "yml" | "toml" | "csv" | "log"
    )
}

fn content_type_is_docx(content_type: &str) -> bool {
    normalized_content_type(content_type) == DOCX_CONTENT_TYPE
}

fn file_extension_is_docx(file_name: &str) -> bool {
    matches!(file_extension(file_name).as_deref(), Some("docx"))
}

fn content_type_is_markdown(content_type: &str) -> bool {
    normalized_content_type(content_type) == "text/markdown"
}

fn file_extension_is_markdown(file_name: &str) -> bool {
    matches!(
        file_extension(file_name).as_deref(),
        Some("md" | "markdown")
    )
}

fn rich_text_to_markdown(rich_text: &TaskPayloadRichText) -> Option<String> {
    let text = rich_text
        .blocks
        .iter()
        .map(|block| block.text.trim())
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if text.is_empty() { None } else { Some(text) }
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DOCX_BASE64: &str = "UEsDBBQAAAAIAOp8kVzXeYTq8QAAALgBAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH2QzU7DMBCE730Ky9cqccoBIZSkB36OwKE8wMreJFb9J69b2rdn00KREOVozXwz62nXB+/EHjPZGDq5qhspMOhobBg7+b55ru6koALBgIsBO3lEkut+0W6OCUkwHKiTUynpXinSE3qgOiYMrAwxeyj8zKNKoLcworppmlulYygYSlXmDNkvhGgfcYCdK+LpwMr5loyOpHg4e+e6TkJKzmoorKt9ML+Kqq+SmsmThyabaMkGqa6VzOL1jh/0lSfK1qB4g1xewLNRfcRslIl65xmu/0/649o4DFbjhZ/TUo4aiXh77+qL4sGG71+06jR8/wlQSwMEFAAAAAgA6nyRXCAbhuqyAAAALgEAAAsAAABfcmVscy8ucmVsc43Puw6CMBQG4J2naM4uBQdjDIXFmLAafICmPZRGeklbL7y9HRzEODie23fyN93TzOSOIWpnGdRlBQStcFJbxeAynDZ7IDFxK/nsLDJYMELXFs0ZZ57yTZy0jyQjNjKYUvIHSqOY0PBYOo82T0YXDE+5DIp6Lq5cId1W1Y6GTwPagpAVS3rJIPSyBjIsHv/h3ThqgUcnbgZt+vHlayPLPChMDB4uSCrf7TKzQHNKuorZvgBQSwMEFAAAAAgA6nyRXDbicKixAAAADAEAABEAAAB3b3JkL2RvY3VtZW50LnhtbG2PMQ+CMBCFd35F012KDsYQKIPGuLlo4lrpKST0rmmryL+3xbixfHkv9/Lurmo+ZmBvcL4nrPk6LzgDbEn3+Kz59XJc7TjzQaFWAyHUfALPG5lVY6mpfRnAwGID+nKseReCLYXwbQdG+ZwsYJw9yBkVonVPMZLT1lEL3scFZhCbotgKo3rkMmMstt5JT0nOxsoIlxDkCVQ6qhLJJLqZdjF8OO9vLFUtxpP47Unq/4f8AlBLAQIUAxQAAAAIAOp8kVzXeYTq8QAAALgBAAATAAAAAAAAAAAAAACAAQAAAABbQ29udGVudF9UeXBlc10ueG1sUEsBAhQDFAAAAAgA6nyRXCAbhuqyAAAALgEAAAsAAAAAAAAAAAAAAIABIgEAAF9yZWxzLy5yZWxzUEsBAhQDFAAAAAgA6nyRXDbicKixAAAADAEAABEAAAAAAAAAAAAAAIAB/QEAAHdvcmQvZG9jdW1lbnQueG1sUEsFBgAAAAADAAMAuQAAAN0CAAAAAA==";

    #[test]
    fn rich_text_to_markdown_joins_non_empty_blocks() {
        let rich_text = TaskPayloadRichText {
            format: "markdown".to_string(),
            version: 1,
            blocks: vec![
                worklist_client_crypto::RichTextBlock {
                    block_type: "paragraph".to_string(),
                    text: "First".to_string(),
                },
                worklist_client_crypto::RichTextBlock {
                    block_type: "paragraph".to_string(),
                    text: "Second".to_string(),
                },
            ],
        };

        assert_eq!(
            rich_text_to_markdown(&rich_text).as_deref(),
            Some("First\n\nSecond")
        );
    }

    #[test]
    fn attachment_read_strategy_detects_text_docx_and_binary() {
        let text_attachment = AgentAttachment {
            id: Uuid::nil(),
            file_name: "notes.md".to_string(),
            content_type: "text/markdown".to_string(),
            size_bytes: 0,
            blob_key: Vec::new(),
        };
        let docx_attachment = AgentAttachment {
            id: Uuid::nil(),
            file_name: "spec.docx".to_string(),
            content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                .to_string(),
            size_bytes: 0,
            blob_key: Vec::new(),
        };
        let binary_attachment = AgentAttachment {
            id: Uuid::nil(),
            file_name: "spec.pdf".to_string(),
            content_type: "application/pdf".to_string(),
            size_bytes: 0,
            blob_key: Vec::new(),
        };

        assert_eq!(
            text_attachment.read_strategy(),
            AttachmentReadStrategy::Utf8Text
        );
        assert_eq!(
            docx_attachment.read_strategy(),
            AttachmentReadStrategy::DocxMarkdown
        );
        assert_eq!(
            binary_attachment.read_strategy(),
            AttachmentReadStrategy::Unsupported
        );
    }

    #[test]
    fn attachment_read_strategy_prefers_text_content_type_over_docx_extension() {
        let attachment = AgentAttachment {
            id: Uuid::nil(),
            file_name: "notes.docx".to_string(),
            content_type: "text/plain".to_string(),
            size_bytes: 0,
            blob_key: Vec::new(),
        };

        assert_eq!(attachment.read_strategy(), AttachmentReadStrategy::Utf8Text);
    }

    #[test]
    fn markdown_text_attachment_reports_markdown_content_format() {
        let attachment = AgentAttachment {
            id: Uuid::nil(),
            file_name: "notes.md".to_string(),
            content_type: "text/markdown".to_string(),
            size_bytes: 0,
            blob_key: Vec::new(),
        };

        let readable = build_readable_attachment(
            attachment,
            b"# Heading\n\nAttachment body\n".to_vec(),
            AttachmentReadStrategy::Utf8Text,
        )
        .expect("render markdown text attachment");

        assert_eq!(
            readable.content_format,
            ReadableAttachmentContentFormat::Markdown
        );
        assert_eq!(
            readable.source_kind,
            ReadableAttachmentSourceKind::PlainText
        );
    }

    #[test]
    fn docx_attachment_bytes_render_to_markdown() {
        let attachment = AgentAttachment {
            id: Uuid::nil(),
            file_name: "spec.docx".to_string(),
            content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                .to_string(),
            size_bytes: 0,
            blob_key: Vec::new(),
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(TEST_DOCX_BASE64)
            .expect("decode docx fixture");

        let readable =
            build_readable_attachment(attachment, bytes, AttachmentReadStrategy::DocxMarkdown)
                .expect("render docx attachment");

        assert_eq!(readable.text, "Heading\n\nDOCX body\n\n");
        assert_eq!(
            readable.content_format,
            ReadableAttachmentContentFormat::Markdown
        );
        assert_eq!(
            readable.source_kind,
            ReadableAttachmentSourceKind::DocxRendered
        );
    }

    #[test]
    fn normalize_docx_markdown_converts_html_fragments_and_preserves_code_fences() {
        let markdown = "\
<strong>UI Implementation Spec</strong>

<table>
  <tr>
    <td><strong>Usage</strong></td>
    <td>Duration</td>
  </tr>
  <tr>
    <td><strong>Slide panels open/close</strong></td>
    <td>0.28s</td>
  </tr>
</table>

<strong>prefers-reduced-motion</strong>

```
<Button variant=\"ghost\" />
<strong>leave me alone</strong>
```
";

        let normalized = normalize_docx_markdown(markdown);

        assert!(normalized.contains("**UI Implementation Spec**"));
        assert!(normalized.contains("**Usage**"));
        assert!(normalized.contains("Duration"));
        assert!(normalized.contains("**Slide panels open/close**"));
        assert!(normalized.contains("0.28s"));
        assert!(normalized.contains("**prefers-reduced-motion**"));
        assert!(!normalized.contains("<table>"));
        assert!(!normalized.contains("<td>"));
        assert!(
            normalized.contains(
                "```\n<Button variant=\"ghost\" />\n<strong>leave me alone</strong>\n```"
            )
        );
    }

    #[test]
    fn normalize_docx_inline_tag_pair_moves_outer_whitespace_outside_markers() {
        let normalized = normalize_docx_markdown(
            "<strong>⚠️  Note to engineering: </strong>Ignore legacy prototype remnants.\n",
        );

        assert_eq!(
            normalized,
            "**⚠️  Note to engineering:** Ignore legacy prototype remnants.\n"
        );
    }

    #[test]
    fn user_key_source_resolves_owner_work_list_key() {
        let data_key = SymmetricKey::new([0x11; 32]);
        let work_list_id = Uuid::now_v7();
        let expected = derive_work_list_key(&data_key, &work_list_id).expect("derive list key");

        let resolved = resolve_work_list_key_for_principal_source(
            &PrincipalWorkListKeySource::UserDataKey(data_key),
            work_list_id,
            "",
        )
        .expect("resolve owner list key");

        assert_eq!(resolved, expected);
    }

    #[test]
    fn agent_key_source_decrypts_agent_work_list_grant() {
        let work_list_id = Uuid::now_v7();
        let list_key = SymmetricKey::new([0x22; 32]);
        let key_material =
            agent_key_material_from_seed([0x33; 32]).expect("derive agent key material");
        let grant = encrypt_agent_work_list_key(
            &key_material.recipient_public_key,
            &work_list_id,
            &list_key,
        )
        .expect("encrypt agent grant");

        let resolved = resolve_work_list_key_for_principal_source(
            &PrincipalWorkListKeySource::AgentRecipientPrivateKey(
                key_material.recipient_private_key,
            ),
            work_list_id,
            &grant.base64,
        )
        .expect("resolve agent work list key");

        assert_eq!(resolved, list_key);
    }
}
