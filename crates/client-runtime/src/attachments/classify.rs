use std::path::Path;

use uuid::Uuid;
use worklist_client_core::{PublicError, PublicResult};

use crate::{
    AgentAttachment, AgentTaskSummary, ReadError, ReadableAttachmentContentFormat,
    ReadableAttachmentSourceKind,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AttachmentReadStrategy {
    Utf8Text,
    DocxMarkdown,
    Unsupported,
}

const DOCX_CONTENT_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

impl AgentAttachment {
    pub(crate) fn blob_key(&self) -> &[u8] {
        &self.blob_key
    }

    #[must_use]
    pub(crate) fn read_strategy(&self) -> AttachmentReadStrategy {
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
    pub(crate) fn readable_content_format(
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
    pub(crate) fn source_kind(self) -> ReadableAttachmentSourceKind {
        match self {
            Self::Utf8Text => ReadableAttachmentSourceKind::PlainText,
            Self::DocxMarkdown => ReadableAttachmentSourceKind::DocxRendered,
            Self::Unsupported => unreachable!("unsupported attachments are rejected before render"),
        }
    }
}

pub(crate) fn find_task_attachment(
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

pub(crate) fn unsupported_attachment_read_error(file_name: &str) -> PublicError {
    PublicError::validation(format!(
        "attachment '{}' is not readable in the CLI; use download instead",
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
