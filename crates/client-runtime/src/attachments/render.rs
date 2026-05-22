use worklist_client_core::{PublicError, PublicResult};

use super::AttachmentReadStrategy;
use crate::{AgentAttachment, ReadableAttachment};

pub(crate) fn build_readable_attachment(
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

fn unsupported_attachment_render_error(file_name: &str) -> PublicError {
    PublicError::validation(format!(
        "attachment '{}' is not readable in the CLI",
        file_name
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::Engine as _;
    use uuid::Uuid;

    use crate::{ReadableAttachmentContentFormat, ReadableAttachmentSourceKind};

    const TEST_DOCX_BASE64: &str = "UEsDBBQAAAAIAOp8kVzXeYTq8QAAALgBAAATAAAAW0NvbnRlbnRfVHlwZXNdLnhtbH2QzU7DMBCE730Ky9cqccoBIZSkB36OwKE8wMreJFb9J69b2rdn00KREOVozXwz62nXB+/EHjPZGDq5qhspMOhobBg7+b55ru6koALBgIsBO3lEkut+0W6OCUkwHKiTUynpXinSE3qgOiYMrAwxeyj8zKNKoLcworppmlulYygYSlXmDNkvhGgfcYCdK+LpwMr5loyOpHg4e+e6TkJKzmoorKt9ML+Kqq+SmsmThyabaMkGqa6VzOL1jh/0lSfK1qB4g1xewLNRfcRslIl65xmu/0/649o4DFbjhZ/TUo4aiXh77+qL4sGG71+06jR8/wlQSwMEFAAAAAgA6nyRXCAbhuqyAAAALgEAAAsAAABfcmVscy8ucmVsc43Puw6CMBQG4J2naM4uBQdjDIXFmLAafICmPZRGeklbL7y9HRzEODie23fyN93TzOSOIWpnGdRlBQStcFJbxeAynDZ7IDFxK/nsLDJYMELXFs0ZZ57yTZy0jyQjNjKYUvIHSqOY0PBYOo82T0YXDE+5DIp6Lq5cId1W1Y6GTwPagpAVS3rJIPSyBjIsHv/h3ThqgUcnbgZt+vHlayPLPChMDB4uSCrf7TKzQHNKuorZvgBQSwMEFAAAAAgA6nyRXDbicKixAAAADAEAABEAAAB3b3JkL2RvY3VtZW50LnhtbG2PMQ+CMBCFd35F012KDsYQKIPGuLlo4lrpKST0rmmryL+3xbixfHkv9/Lurmo+ZmBvcL4nrPk6LzgDbEn3+Kz59XJc7TjzQaFWAyHUfALPG5lVY6mpfRnAwGID+nKseReCLYXwbQdG+ZwsYJw9yBkVonVPMZLT1lEL3scFZhCbotgKo3rkMmMstt5JT0nOxsoIlxDkCVQ6qhLJJLqZdjF8OO9vLFUtxpP47Unq/4f8AlBLAQIUAxQAAAAIAOp8kVzXeYTq8QAAALgBAAATAAAAAAAAAAAAAACAAQAAAABbQ29udGVudF9UeXBlc10ueG1sUEsBAhQDFAAAAAgA6nyRXCAbhuqyAAAALgEAAAsAAAAAAAAAAAAAAIABIgEAAF9yZWxzLy5yZWxzUEsBAhQDFAAAAAgA6nyRXDbicKixAAAADAEAABEAAAAAAAAAAAAAAIAB/QEAAHdvcmQvZG9jdW1lbnQueG1sUEsFBgAAAAADAAMAuQAAAN0CAAAAAA==";

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
    <td><em>2s</em></td>
  </tr>
</table>

```
<strong>literal</strong>
```
";

        let normalized = normalize_docx_markdown(markdown);

        assert!(normalized.contains("**UI Implementation Spec**"));
        assert!(normalized.contains("**Usage**"));
        assert!(normalized.contains("**Slide panels open/close**"));
        assert!(normalized.contains("*2s*"));
        assert!(normalized.contains("<strong>literal</strong>"));
    }

    #[test]
    fn normalize_docx_inline_tag_pair_moves_outer_whitespace_outside_markers() {
        let normalized =
            normalize_docx_inline_tag_pair("<strong> spaced </strong>", "strong", "**");

        assert_eq!(normalized, " **spaced** ");
    }
}
