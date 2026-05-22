use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadAttachmentResponse {
    pub download_url: String,
    pub download_headers: HashMap<String, String>,
    pub expires_at: DateTime<Utc>,
}
