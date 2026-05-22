use std::time::Duration as StdDuration;

use worklist_client_api::DownloadAttachmentResponse;
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::{AttachmentBlobRef, decrypt_attachment_bytes};

use crate::{AgentAttachment, DownloadedAttachment};

#[derive(Debug)]
pub(crate) struct ResolvedTaskAttachmentDownload {
    pub(crate) attachment: AgentAttachment,
    pub(crate) blob_ref: AttachmentBlobRef,
    pub(crate) download: DownloadAttachmentResponse,
}

const ATTACHMENT_DOWNLOAD_TIMEOUT: StdDuration = StdDuration::from_secs(30);

pub(crate) async fn download_and_decrypt_attachment(
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

    let response = request
        .timeout(ATTACHMENT_DOWNLOAD_TIMEOUT)
        .send()
        .await
        .map_err(|err| {
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
