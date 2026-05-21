use serde::{Deserialize, Serialize};
use uuid::Uuid;

use worklist_client_core::PublicResult;

use crate::{SealedBlobPayload, SymmetricKey, decrypt_sealed_payload, encrypt_sealed_payload};

const WORK_LIST_TITLE_CONTEXT: &[u8] = b"worklist.work_list.title.v1";
const WORK_LIST_DESCRIPTION_CONTEXT: &[u8] = b"worklist.work_list.description.v1";
const TASK_TITLE_CONTEXT: &[u8] = b"worklist.task.title.v1";
const NOTE_TITLE_CONTEXT: &[u8] = b"worklist.note.title.v1";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TextValueContext {
    WorkListTitle,
    WorkListDescription,
    TaskTitle,
    NoteTitle,
}

impl TextValueContext {
    #[must_use]
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::WorkListTitle => WORK_LIST_TITLE_CONTEXT,
            Self::WorkListDescription => WORK_LIST_DESCRIPTION_CONTEXT,
            Self::TaskTitle => TASK_TITLE_CONTEXT,
            Self::NoteTitle => NOTE_TITLE_CONTEXT,
        }
    }

    fn for_entity(self, entity_id: Uuid) -> Vec<u8> {
        entity_bound_context(self.as_bytes(), entity_id)
    }
}

fn entity_bound_context(base_context: &[u8], entity_id: Uuid) -> Vec<u8> {
    let mut context = Vec::with_capacity(base_context.len() + 1 + 36);
    context.extend_from_slice(base_context);
    context.push(b':');
    context.extend_from_slice(entity_id.to_string().as_bytes());
    context
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TextValuePayload {
    value: String,
}

fn decrypt_text_value(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
    context: TextValueContext,
) -> PublicResult<String> {
    decrypt_text_value_with_context(list_key, payload_ciphertext, context.as_bytes())
}

fn decrypt_text_value_for_entity(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
    context: TextValueContext,
    entity_id: Uuid,
) -> PublicResult<String> {
    let entity_context = context.for_entity(entity_id);
    // Older stored text fields used only the base context. Keep reads tolerant
    // while those fields are rewritten to entity-bound contexts.
    decrypt_text_value_with_context(list_key, payload_ciphertext, &entity_context)
        .or_else(|_| decrypt_text_value(list_key, payload_ciphertext, context))
}

fn decrypt_text_value_with_context(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
    context: &[u8],
) -> PublicResult<String> {
    let payload: TextValuePayload = decrypt_sealed_payload(
        list_key,
        payload_ciphertext,
        context,
        "failed to decrypt text value",
    )?;
    Ok(payload.value)
}

pub fn decrypt_work_list_title(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<String> {
    decrypt_text_value(
        list_key,
        payload_ciphertext,
        TextValueContext::WorkListTitle,
    )
}

pub fn decrypt_work_list_title_for_id(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
    work_list_id: Uuid,
) -> PublicResult<String> {
    decrypt_text_value_for_entity(
        list_key,
        payload_ciphertext,
        TextValueContext::WorkListTitle,
        work_list_id,
    )
}

pub fn decrypt_work_list_description(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<String> {
    decrypt_text_value(
        list_key,
        payload_ciphertext,
        TextValueContext::WorkListDescription,
    )
}

pub fn decrypt_work_list_description_for_id(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
    work_list_id: Uuid,
) -> PublicResult<String> {
    decrypt_text_value_for_entity(
        list_key,
        payload_ciphertext,
        TextValueContext::WorkListDescription,
        work_list_id,
    )
}

pub fn decrypt_task_title(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<String> {
    decrypt_text_value(list_key, payload_ciphertext, TextValueContext::TaskTitle)
}

pub fn decrypt_task_title_for_id(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
    task_id: Uuid,
) -> PublicResult<String> {
    decrypt_text_value_for_entity(
        list_key,
        payload_ciphertext,
        TextValueContext::TaskTitle,
        task_id,
    )
}

pub fn decrypt_note_title(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
) -> PublicResult<String> {
    decrypt_text_value(list_key, payload_ciphertext, TextValueContext::NoteTitle)
}

pub fn decrypt_note_title_for_id(
    list_key: &SymmetricKey,
    payload_ciphertext: &[u8],
    note_id: Uuid,
) -> PublicResult<String> {
    decrypt_text_value_for_entity(
        list_key,
        payload_ciphertext,
        TextValueContext::NoteTitle,
        note_id,
    )
}
fn seal_text_value(
    value: &str,
    list_key: &SymmetricKey,
    context: TextValueContext,
) -> PublicResult<SealedBlobPayload> {
    seal_text_value_with_context(value, list_key, context.as_bytes())
}

fn seal_text_value_for_entity(
    value: &str,
    list_key: &SymmetricKey,
    context: TextValueContext,
    entity_id: Uuid,
) -> PublicResult<SealedBlobPayload> {
    let entity_context = context.for_entity(entity_id);
    seal_text_value_with_context(value, list_key, &entity_context)
}

fn seal_text_value_with_context(
    value: &str,
    list_key: &SymmetricKey,
    context: &[u8],
) -> PublicResult<SealedBlobPayload> {
    encrypt_sealed_payload(
        &TextValuePayload {
            value: value.to_string(),
        },
        list_key,
        context,
        "failed to seal text value",
    )
}

pub fn seal_work_list_title(
    value: &str,
    list_key: &SymmetricKey,
) -> PublicResult<SealedBlobPayload> {
    seal_text_value(value, list_key, TextValueContext::WorkListTitle)
}

pub fn seal_work_list_title_for_id(
    value: &str,
    list_key: &SymmetricKey,
    work_list_id: Uuid,
) -> PublicResult<SealedBlobPayload> {
    seal_text_value_for_entity(
        value,
        list_key,
        TextValueContext::WorkListTitle,
        work_list_id,
    )
}

pub fn seal_work_list_description(
    value: &str,
    list_key: &SymmetricKey,
) -> PublicResult<SealedBlobPayload> {
    seal_text_value(value, list_key, TextValueContext::WorkListDescription)
}

pub fn seal_work_list_description_for_id(
    value: &str,
    list_key: &SymmetricKey,
    work_list_id: Uuid,
) -> PublicResult<SealedBlobPayload> {
    seal_text_value_for_entity(
        value,
        list_key,
        TextValueContext::WorkListDescription,
        work_list_id,
    )
}

pub fn seal_task_title(value: &str, list_key: &SymmetricKey) -> PublicResult<SealedBlobPayload> {
    seal_text_value(value, list_key, TextValueContext::TaskTitle)
}

pub fn seal_task_title_for_id(
    value: &str,
    list_key: &SymmetricKey,
    task_id: Uuid,
) -> PublicResult<SealedBlobPayload> {
    seal_text_value_for_entity(value, list_key, TextValueContext::TaskTitle, task_id)
}

pub fn seal_note_title(value: &str, list_key: &SymmetricKey) -> PublicResult<SealedBlobPayload> {
    seal_text_value(value, list_key, TextValueContext::NoteTitle)
}

pub fn seal_note_title_for_id(
    value: &str,
    list_key: &SymmetricKey,
    note_id: Uuid,
) -> PublicResult<SealedBlobPayload> {
    seal_text_value_for_entity(value, list_key, TextValueContext::NoteTitle, note_id)
}
