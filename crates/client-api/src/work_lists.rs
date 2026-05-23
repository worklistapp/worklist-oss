use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::SealedBlob;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkListResponse {
    pub id: Uuid,
    pub owner_user_id: Uuid,
    pub workspace_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title_ciphertext: Option<SealedBlob>,
    pub description_ciphertext: Option<SealedBlob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ciphertext: Option<SealedBlob>,
    pub timezone: String,
    pub section_snapshots: Vec<SectionSnapshotPayload>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub membership: MembershipResponse,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkListDetailResponse {
    #[serde(flatten)]
    pub work_list: WorkListResponse,
    pub members: Vec<MembershipResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SectionSnapshotPayload {
    pub id: Uuid,
    pub position: i64,
    pub auto_archive_enabled: bool,
    pub auto_archive_after_days: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MembershipResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub user_email: String,
    pub user_name: String,
    pub user_avatar_color: String,
    pub role: String,
    pub status: String,
    pub work_list_key_ciphertext: SealedBlob,
    pub recipient_ciphertext: Option<SealedBlob>,
    pub invite_package_ciphertext: Option<SealedBlob>,
    pub salt_member: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub joined_at: DateTime<Utc>,
    pub payload_binding_key: Option<String>,
}
