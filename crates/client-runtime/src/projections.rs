use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;
use worklist_client_api::{DelegationResponse, MembershipResponse, WorkListResponse};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::{
    FlexibleValue, SymmetricKey, TaskPayloadBody, TaskPayloadRichText, decode_sealed_blob,
    decrypt_agent_work_list_key, decrypt_task_payload, decrypt_task_title,
    decrypt_work_list_description, decrypt_work_list_key, decrypt_work_list_payload,
    decrypt_work_list_title, derive_work_list_key, flexible_value_to_json,
};

use crate::{
    AgentAttachment, AgentDelegation, AgentMembership, AgentTaskSummary, AgentWorkListSummary,
    ReadError,
};

#[derive(Debug, Clone)]
pub(crate) struct WorkListContext {
    pub(crate) work_list_title: Option<String>,
    pub(crate) list_key: Option<SymmetricKey>,
    pub(crate) read_error: Option<ReadError>,
}

#[derive(Debug, Clone)]
pub(crate) enum PrincipalWorkListKeySource {
    UserDataKey(SymmetricKey),
    AgentRecipientPrivateKey([u8; 32]),
}

#[derive(Debug)]
pub(crate) struct TaskProjectionMetadata {
    pub(crate) id: Uuid,
    pub(crate) work_list_id: Uuid,
    pub(crate) work_list_title: Option<String>,
    pub(crate) created_by_membership_id: Uuid,
    pub(crate) section_id: Option<Uuid>,
    pub(crate) priority: Option<i8>,
    pub(crate) position: Option<String>,
    pub(crate) due_at: Option<DateTime<Utc>>,
    pub(crate) start_at: Option<DateTime<Utc>>,
    pub(crate) completed_at: Option<DateTime<Utc>>,
    pub(crate) archived_at: Option<DateTime<Utc>>,
    pub(crate) is_completed: bool,
    pub(crate) recurrence_id: Option<Uuid>,
    pub(crate) recurrence_schedule: Option<String>,
    pub(crate) recurrence_iteration: Option<i64>,
    pub(crate) materialized_at: Option<DateTime<Utc>>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) comment_count: i64,
}

#[derive(Debug)]
pub(crate) struct TaskProjectionInput<'a> {
    pub(crate) metadata: TaskProjectionMetadata,
    pub(crate) delegations: Vec<DelegationResponse>,
    pub(crate) title_ciphertext: &'a str,
    pub(crate) payload_ciphertext: &'a str,
    pub(crate) list_key: Option<&'a SymmetricKey>,
    pub(crate) inherited_error: Option<ReadError>,
}

pub(crate) fn project_attachments(
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

pub(crate) fn project_task(input: TaskProjectionInput<'_>) -> AgentTaskSummary {
    let TaskProjectionInput {
        metadata,
        delegations,
        title_ciphertext,
        payload_ciphertext,
        list_key,
        inherited_error,
    } = input;
    let fallback_title =
        list_key.and_then(|list_key| decode_task_title_fallback(title_ciphertext, list_key));
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

pub(crate) fn project_membership(membership: &MembershipResponse) -> AgentMembership {
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

fn project_delegation(delegation: DelegationResponse) -> AgentDelegation {
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

pub(crate) fn unreadable_work_list_context(
    work_list_title: Option<String>,
    read_error: ReadError,
) -> WorkListContext {
    WorkListContext {
        work_list_title,
        list_key: None,
        read_error: Some(read_error),
    }
}

pub(crate) fn build_work_list_summary(
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

pub(crate) fn missing_work_list_key_source_error() -> ReadError {
    ReadError {
        code: "work_list_key_source_missing".to_string(),
        message: "could not load work list key material for decryption".to_string(),
    }
}

pub(crate) fn resolve_work_list_key_for_principal_source(
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

pub(crate) fn resolve_list_key(
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

pub(crate) fn decode_work_list_payload_value(
    list_key: &SymmetricKey,
    payload_ciphertext: &str,
) -> PublicResult<Value> {
    let payload_bytes = decode_sealed_blob(payload_ciphertext)?;
    let payload: FlexibleValue = decrypt_work_list_payload(list_key, &payload_bytes)?;
    Ok(flexible_value_to_json(payload))
}

pub(crate) fn extract_work_list_title(payload: &Value) -> Option<String> {
    payload
        .get("body")
        .and_then(|body| body.get("title"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

pub(crate) fn extract_work_list_description(payload: &Value) -> Option<String> {
    payload
        .get("body")
        .and_then(|body| body.get("description"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn decode_text_fallback(
    ciphertext: &str,
    list_key: &SymmetricKey,
    decrypt: fn(&SymmetricKey, &[u8]) -> PublicResult<String>,
) -> Option<String> {
    // Fallback text fields preserve older clients' display behavior. Payload decode
    // errors remain the authoritative read diagnostic, so fallback failures only
    // remove the optional display fallback.
    decode_sealed_blob(ciphertext)
        .and_then(|bytes| decrypt(list_key, &bytes))
        .ok()
}

pub(crate) fn decode_work_list_title_fallback(
    ciphertext: &str,
    list_key: &SymmetricKey,
) -> Option<String> {
    decode_text_fallback(ciphertext, list_key, decrypt_work_list_title)
}

pub(crate) fn decode_work_list_description_fallback(
    ciphertext: &str,
    list_key: &SymmetricKey,
) -> Option<String> {
    decode_text_fallback(ciphertext, list_key, decrypt_work_list_description)
}

fn decode_task_title_fallback(ciphertext: &str, list_key: &SymmetricKey) -> Option<String> {
    decode_text_fallback(ciphertext, list_key, decrypt_task_title)
}

pub(crate) fn make_read_error(code: &str, err: PublicError) -> ReadError {
    ReadError {
        code: code.to_string(),
        message: err.to_string(),
    }
}

pub(crate) fn read_error_to_public_error(
    read_error: Option<&ReadError>,
    fallback: &str,
) -> PublicError {
    match read_error {
        Some(read_error) => PublicError::validation(read_error.message.clone()),
        None => PublicError::validation(fallback),
    }
}

pub(crate) fn rich_text_to_markdown(rich_text: &TaskPayloadRichText) -> Option<String> {
    let text = rich_text
        .blocks
        .iter()
        .map(|block| block.text.trim())
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(test)]
mod tests {
    use worklist_client_auth::agent_key_material_from_seed;
    use worklist_client_crypto::{RichTextBlock, encrypt_agent_work_list_key};

    use super::*;

    #[test]
    fn rich_text_to_markdown_joins_non_empty_blocks() {
        let rich_text = TaskPayloadRichText {
            format: "markdown".to_string(),
            version: 1,
            blocks: vec![
                RichTextBlock {
                    block_type: "paragraph".to_string(),
                    text: "First".to_string(),
                },
                RichTextBlock {
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
