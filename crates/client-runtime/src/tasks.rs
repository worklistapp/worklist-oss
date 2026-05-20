use uuid::Uuid;
use worklist_client_api::{
    ArchiveTaskRequest, CreateTaskRequest, MoveTaskRequest, MyTaskResponse, PublicApiClient,
    TaskResponse, UnarchiveTaskRequest, UpdateTaskRequest,
};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::{
    SymmetricKey, TaskPayloadBody, build_task_payload_envelope, compute_payload_proof,
    decode_attachment_blob_key, decode_sealed_blob, decrypt_task_payload,
    derive_payload_binding_key, encrypt_task_payload, plaintext_rich_text, seal_task_title_for_id,
};

use crate::RuntimeClient;
use crate::attachments::{
    AttachmentReadStrategy, ResolvedTaskAttachmentDownload, build_readable_attachment,
    download_and_decrypt_attachment, find_task_attachment, unsupported_attachment_read_error,
};
use crate::models::{
    AgentTaskDetail, AgentTaskSummary, ArchiveTaskArgs, CreateTaskArgs, DeleteTaskArgs,
    DownloadedAttachment, MoveTaskArgs, ReadableAttachment, UnarchiveTaskArgs, UpdateTaskArgs,
};
use crate::projections::{
    TaskProjectionInput, TaskProjectionMetadata, WorkListContext, decode_work_list_title_fallback,
    project_task, read_error_to_public_error,
};

impl RuntimeClient {
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

        if !all && let Some(work_list_id) = work_list_id {
            let work_list = client.get_work_list(work_list_id).await?;
            let context = self.context_from_work_list_detail(&work_list, Some(&key_source));
            let response = client.get_tasks(work_list_id, false).await?;

            return Ok(response
                .tasks
                .into_iter()
                .filter(|task| include_completed || !task.is_completed)
                .map(|task| self.project_task_summary(task, Some(&context)))
                .collect());
        }

        let work_lists = client.list_work_lists().await?;
        let contexts = self.build_work_list_contexts(&work_lists, Some(&key_source));
        let response = client.get_my_tasks(Some(100), None).await?;
        Ok(response
            .tasks
            .into_iter()
            .filter(|task| include_completed || !task.is_completed)
            .map(|task| {
                let context = contexts.get(&task.work_list_id);
                self.project_my_task_summary(task, context)
            })
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
            .load_work_list_context(
                args.work_list_id,
                args.password_stdin,
                "Password required to create encrypted task payloads.",
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
        let task_id = Uuid::now_v7();
        let title_ciphertext = seal_task_title_for_id(normalized_title, list_key, task_id)?;
        let payload_proof = compute_payload_proof(&payload_ciphertext.bytes, &binding_key)?;
        let title_proof = compute_payload_proof(&title_ciphertext.bytes, &binding_key)?;

        let created = client
            .create_task(
                args.work_list_id,
                &CreateTaskRequest {
                    task_id: Some(task_id),
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
            let title_ciphertext =
                seal_task_title_for_id(normalized_title, list_key, args.task_id)?;
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

    pub(crate) async fn load_work_list_context(
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

    pub(crate) fn require_work_list_key<'a>(
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
                    decode_work_list_title_fallback(
                        &task.work_list_title_ciphertext,
                        list_key,
                        task.work_list_id,
                    )
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
}
