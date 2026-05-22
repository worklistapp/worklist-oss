use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentUserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub timezone: String,
    pub avatar_color: String,
    pub data_key_ciphertext: String,
    pub workspace_lock_timeout_minutes: Option<i32>,
    pub theme_preference: String,
    pub email_verified: bool,
    pub last_accessed_work_list_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardStatsResponse {
    pub tasks_overdue: i64,
    pub tasks_due_today: i64,
    pub tasks_due_this_week: i64,
    pub completed: i64,
}
