use std::{fmt, time::Duration as StdDuration};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use worklist_client_core::{PublicError, PublicResult};

use crate::credentials::{Credentials, REDACTED_SECRET_FIELD};
use crate::opaque::{opaque_login_finish, opaque_login_start};

const AUTH_HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(30);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStartResponse {
    pub server_login_state: String,
    pub session_token: String,
    pub expires_in: u64,
}

impl fmt::Debug for LoginStartResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginStartResponse")
            .field("server_login_state", &REDACTED_SECRET_FIELD)
            .field("session_token", &REDACTED_SECRET_FIELD)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    pub token_type: String,
    pub user: UserResponse,
    pub data_key_ciphertext: String,
    #[serde(default)]
    pub opaque_export_key: Option<String>,
}

impl fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthResponse")
            .field("access_token", &REDACTED_SECRET_FIELD)
            .field("refresh_token", &REDACTED_SECRET_FIELD)
            .field("expires_in", &self.expires_in)
            .field("refresh_expires_in", &self.refresh_expires_in)
            .field("token_type", &self.token_type)
            .field("user", &self.user)
            .field("data_key_ciphertext", &REDACTED_SECRET_FIELD)
            .field(
                "opaque_export_key",
                &self
                    .opaque_export_key
                    .as_ref()
                    .map(|_| REDACTED_SECRET_FIELD),
            )
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub timezone: String,
    pub avatar_color: String,
    pub theme_preference: String,
    pub email_verified: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    pub token_type: String,
}

impl fmt::Debug for RefreshResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshResponse")
            .field("access_token", &REDACTED_SECRET_FIELD)
            .field("refresh_token", &REDACTED_SECRET_FIELD)
            .field("expires_in", &self.expires_in)
            .field("refresh_expires_in", &self.refresh_expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// Internal wire DTO; public for compatibility only.
#[doc(hidden)]
#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginStartRequest {
    email: String,
    client_login_state: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginFinishRequest {
    session_token: String,
    client_finish_message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshRequest {
    refresh_token: String,
}

pub fn normalize_api_url(api_url: &str) -> String {
    // This public normalizer is intentionally best-effort for legacy callers
    // that may pass partial local config. Assertion signing uses the fallible
    // canonicalizer so invalid audiences fail locally before a request is sent.
    canonicalize_api_url(api_url)
        .unwrap_or_else(|_| api_url.trim().trim_end_matches('/').to_string())
}

pub(crate) fn canonicalize_api_url(api_url: &str) -> PublicResult<String> {
    let mut url = reqwest::Url::parse(api_url.trim()).map_err(|err| {
        PublicError::validation(format!(
            "API URL must be an absolute HTTP(S) base URL: {err}"
        ))
    })?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(PublicError::validation(
            "API URL must be an absolute HTTP(S) base URL",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(PublicError::validation(
            "API URL must not include query parameters or a fragment",
        ));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(PublicError::validation(
            "API URL must not include credentials",
        ));
    }
    if matches!(
        (url.scheme(), url.port()),
        ("http", Some(80)) | ("https", Some(443))
    ) {
        url.set_port(None)
            .map_err(|_| PublicError::validation("API URL default port could not be removed"))?;
    }
    if url.path() == "/" {
        url.set_path("");
    } else {
        let path = url.path().trim_end_matches('/').to_string();
        url.set_path(&path);
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

pub async fn login(
    client: &reqwest::Client,
    base_url: &str,
    email: &str,
    password: &str,
) -> PublicResult<AuthResponse> {
    let login_start_url = api_endpoint(base_url, "/auth/opaque/login/start");
    let login_finish_url = api_endpoint(base_url, "/auth/opaque/login/finish");
    let (opaque_state, client_login_state) = opaque_login_start(password)?;

    let start_response = send_auth_request(
        client.post(login_start_url).json(&LoginStartRequest {
            email: email.to_string(),
            client_login_state,
        }),
        "login start",
    )
    .await?;
    let start_result: LoginStartResponse =
        parse_json_response(start_response, "login start response").await?;

    let opaque_finish = opaque_login_finish(
        opaque_state,
        email,
        password,
        &start_result.server_login_state,
    )?;

    let finish_response = send_auth_request(
        client.post(login_finish_url).json(&LoginFinishRequest {
            session_token: start_result.session_token,
            client_finish_message: opaque_finish.finish_message,
        }),
        "login finish",
    )
    .await?;

    let mut auth_response: AuthResponse =
        parse_json_response(finish_response, "auth response").await?;
    auth_response.opaque_export_key = Some(opaque_finish.export_key);
    Ok(auth_response)
}

pub async fn refresh_access_token(
    client: &reqwest::Client,
    base_url: &str,
    refresh_token: &str,
) -> PublicResult<RefreshResponse> {
    let response = send_auth_request(
        client
            .post(api_endpoint(base_url, "/auth/refresh"))
            .json(&RefreshRequest {
                refresh_token: refresh_token.to_string(),
            }),
        "token refresh",
    )
    .await?;

    parse_json_response(response, "refresh response").await
}

pub async fn logout(
    client: &reqwest::Client,
    base_url: &str,
    refresh_token: &str,
) -> PublicResult<Option<String>> {
    let status = send_auth_request(
        client
            .post(api_endpoint(base_url, "/auth/logout"))
            .json(&RefreshRequest {
                refresh_token: refresh_token.to_string(),
            }),
        "logout",
    )
    .await?
    .status();

    Ok((!status.is_success()).then(|| format!("server logout returned status {status}")))
}

pub fn auth_response_to_credentials(
    api_url: &str,
    response: AuthResponse,
) -> PublicResult<Credentials> {
    let now = Utc::now();
    let access_expires_at = expires_at_from(now, response.expires_in, "access token")?;
    let refresh_expires_at = expires_at_from(now, response.refresh_expires_in, "refresh token")?;

    Ok(Credentials {
        api_url: normalize_api_url(api_url),
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        access_expires_at,
        refresh_expires_at,
        user_id: response.user.id,
        email: response.user.email,
        data_key_ciphertext: response.data_key_ciphertext,
    })
}

pub fn update_credentials_with_refresh(
    credentials: &mut Credentials,
    refresh_response: RefreshResponse,
) -> PublicResult<()> {
    let now = Utc::now();
    let access_expires_at = expires_at_from(now, refresh_response.expires_in, "access token")?;
    let refresh_expires_at =
        expires_at_from(now, refresh_response.refresh_expires_in, "refresh token")?;

    credentials.access_token = refresh_response.access_token;
    credentials.refresh_token = refresh_response.refresh_token;
    credentials.access_expires_at = access_expires_at;
    credentials.refresh_expires_at = refresh_expires_at;
    Ok(())
}

fn expires_at_from(
    now: DateTime<Utc>,
    expires_in_seconds: u64,
    token_name: &'static str,
) -> PublicResult<DateTime<Utc>> {
    // TTLs come from server responses, so keep conversion fallible before
    // updating any stored credential fields. The second check covers chrono's
    // narrower TimeDelta range after the u64-to-i64 conversion succeeds.
    let seconds = i64::try_from(expires_in_seconds).map_err(|err| {
        PublicError::unexpected(format!(
            "{token_name} ttl seconds overflow for expires_in={expires_in_seconds}: {err}"
        ))
    })?;
    let ttl = chrono::Duration::try_seconds(seconds).ok_or_else(|| {
        PublicError::unexpected(format!(
            "{token_name} ttl duration overflow for expires_in={expires_in_seconds}"
        ))
    })?;
    now.checked_add_signed(ttl).ok_or_else(|| {
        PublicError::unexpected(format!(
            "{token_name} expiry overflow for expires_in={expires_in_seconds}"
        ))
    })
}

pub(crate) fn api_endpoint(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

pub(crate) fn encode_bytes(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

pub(crate) fn decode_bytes(value: &str) -> PublicResult<Vec<u8>> {
    let trimmed = value.trim();
    STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| STANDARD.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .map_err(|err| PublicError::validation(format!("invalid base64: {err}")))
}

pub(crate) async fn send_auth_request(
    request: reqwest::RequestBuilder,
    context: &'static str,
) -> PublicResult<reqwest::Response> {
    request
        .timeout(AUTH_HTTP_TIMEOUT)
        .send()
        .await
        .map_err(|err| map_reqwest_error(err, context))
}

fn map_reqwest_error(err: reqwest::Error, context: &str) -> PublicError {
    if err.is_connect() {
        PublicError::unexpected(format!("failed to connect to API during {context}: {err}"))
    } else if err.is_timeout() {
        PublicError::unexpected(format!("API request timed out during {context}"))
    } else {
        PublicError::unexpected(format!("API request failed during {context}: {err}"))
    }
}

pub(crate) async fn parse_json_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    context: &str,
) -> PublicResult<T> {
    let status = response.status();
    if !status.is_success() {
        let error_text = error_response_text(response, context, status).await;
        return Err(map_api_error(status.as_u16(), &error_text));
    }

    response
        .json()
        .await
        .map_err(|err| PublicError::unexpected(format!("failed to parse {context}: {err}")))
}

async fn error_response_text(
    response: reqwest::Response,
    context: &str,
    status: reqwest::StatusCode,
) -> String {
    response.text().await.unwrap_or_else(|err| {
        format!("failed to read {context} error response (status {status}): {err}")
    })
}

fn map_api_error(status: u16, body: &str) -> PublicError {
    if let Ok(api_error) = serde_json::from_str::<ApiError>(body) {
        let message = api_error.message.unwrap_or(api_error.error);
        return match status {
            401 => PublicError::validation(format!("authentication failed: {message}")),
            403 => PublicError::validation(format!("access denied: {message}")),
            404 => PublicError::validation(format!("not found: {message}")),
            400 | 422 => PublicError::validation(message),
            _ => PublicError::unexpected(format!("API error ({status}): {message}")),
        };
    }

    match status {
        401 => PublicError::validation("authentication failed"),
        403 => PublicError::validation("access denied"),
        404 => PublicError::validation("resource not found"),
        _ => PublicError::unexpected(format!("API error ({status}): {body}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_response(expires_in: u64, refresh_expires_in: u64) -> AuthResponse {
        AuthResponse {
            access_token: "access-token".to_string(),
            refresh_token: "refresh-token".to_string(),
            expires_in,
            refresh_expires_in,
            token_type: "Bearer".to_string(),
            user: UserResponse {
                id: Uuid::now_v7(),
                email: "user@example.com".to_string(),
                name: "User".to_string(),
                timezone: "UTC".to_string(),
                avatar_color: "blue".to_string(),
                theme_preference: "system".to_string(),
                email_verified: true,
            },
            data_key_ciphertext: "data-key".to_string(),
            opaque_export_key: Some("opaque-export-key".to_string()),
        }
    }

    #[test]
    fn auth_response_to_credentials_rejects_ttl_overflow() {
        let error =
            auth_response_to_credentials("https://worklist.example", auth_response(u64::MAX, 3600))
                .expect_err("overflowing access ttl should fail");

        assert!(matches!(
            error,
            PublicError::Unexpected(message)
                if message.contains("access token ttl seconds overflow")
        ));
    }

    #[test]
    fn auth_response_to_credentials_rejects_refresh_ttl_overflow() {
        let error =
            auth_response_to_credentials("https://worklist.example", auth_response(900, u64::MAX))
                .expect_err("overflowing refresh ttl should fail");

        assert!(matches!(
            error,
            PublicError::Unexpected(message)
                if message.contains("refresh token ttl seconds overflow")
        ));
    }

    #[test]
    fn update_credentials_with_refresh_updates_tokens_and_expiries() {
        let mut credentials =
            auth_response_to_credentials("https://worklist.example", auth_response(900, 3600))
                .expect("initial credentials");
        let original_access_expires_at = credentials.access_expires_at;
        let original_refresh_expires_at = credentials.refresh_expires_at;

        update_credentials_with_refresh(
            &mut credentials,
            RefreshResponse {
                access_token: "new-access-token".to_string(),
                refresh_token: "new-refresh-token".to_string(),
                expires_in: 1800,
                refresh_expires_in: 7200,
                token_type: "Bearer".to_string(),
            },
        )
        .expect("refresh update should succeed");

        assert_eq!(credentials.access_token, "new-access-token");
        assert_eq!(credentials.refresh_token, "new-refresh-token");
        assert!(credentials.access_expires_at > original_access_expires_at);
        assert!(credentials.refresh_expires_at > original_refresh_expires_at);
    }

    #[test]
    fn auth_response_to_credentials_does_not_persist_opaque_export_key() {
        let credentials =
            auth_response_to_credentials("https://worklist.example", auth_response(900, 3600))
                .expect("credentials");

        let serialized = serde_json::to_string(&credentials).expect("serialize credentials");
        assert!(!serialized.contains("opaque_export_key"));
        assert!(!serialized.contains("opaqueExportKey"));
        assert!(!serialized.contains("opaque-export-key"));
    }

    #[test]
    fn update_credentials_with_refresh_is_atomic_when_ttl_overflows() {
        let mut credentials =
            auth_response_to_credentials("https://worklist.example", auth_response(900, 3600))
                .expect("initial credentials");
        let original_access_token = credentials.access_token.clone();
        let original_refresh_token = credentials.refresh_token.clone();
        let original_access_expires_at = credentials.access_expires_at;
        let original_refresh_expires_at = credentials.refresh_expires_at;

        let error = update_credentials_with_refresh(
            &mut credentials,
            RefreshResponse {
                access_token: "new-access-token".to_string(),
                refresh_token: "new-refresh-token".to_string(),
                expires_in: 900,
                refresh_expires_in: u64::MAX,
                token_type: "Bearer".to_string(),
            },
        )
        .expect_err("overflowing refresh ttl should fail");

        assert!(matches!(
            error,
            PublicError::Unexpected(message)
                if message.contains("refresh token ttl seconds overflow")
        ));
        assert_eq!(credentials.access_token, original_access_token);
        assert_eq!(credentials.refresh_token, original_refresh_token);
        assert_eq!(credentials.access_expires_at, original_access_expires_at);
        assert_eq!(credentials.refresh_expires_at, original_refresh_expires_at);
    }

    #[test]
    fn update_credentials_with_refresh_is_atomic_when_access_ttl_overflows() {
        let mut credentials =
            auth_response_to_credentials("https://worklist.example", auth_response(900, 3600))
                .expect("initial credentials");
        let original_access_token = credentials.access_token.clone();
        let original_refresh_token = credentials.refresh_token.clone();
        let original_access_expires_at = credentials.access_expires_at;
        let original_refresh_expires_at = credentials.refresh_expires_at;

        let error = update_credentials_with_refresh(
            &mut credentials,
            RefreshResponse {
                access_token: "new-access-token".to_string(),
                refresh_token: "new-refresh-token".to_string(),
                expires_in: u64::MAX,
                refresh_expires_in: 3600,
                token_type: "Bearer".to_string(),
            },
        )
        .expect_err("overflowing access ttl should fail");

        assert!(matches!(
            error,
            PublicError::Unexpected(message)
                if message.contains("access token ttl seconds overflow")
        ));
        assert_eq!(credentials.access_token, original_access_token);
        assert_eq!(credentials.refresh_token, original_refresh_token);
        assert_eq!(credentials.access_expires_at, original_access_expires_at);
        assert_eq!(credentials.refresh_expires_at, original_refresh_expires_at);
    }
}
