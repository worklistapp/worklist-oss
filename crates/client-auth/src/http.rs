use std::fmt;
use std::time::Duration as StdDuration;

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

    let client_finish_message = opaque_login_finish(
        opaque_state,
        email,
        password,
        &start_result.server_login_state,
    )?;

    let finish_response = send_auth_request(
        client.post(login_finish_url).json(&LoginFinishRequest {
            session_token: start_result.session_token,
            client_finish_message,
        }),
        "login finish",
    )
    .await?;

    parse_json_response(finish_response, "auth response").await
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

pub fn auth_response_to_credentials(api_url: &str, response: AuthResponse) -> Credentials {
    let now = Utc::now();
    Credentials {
        api_url: normalize_api_url(api_url),
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        access_expires_at: expires_at_from(now, response.expires_in),
        refresh_expires_at: expires_at_from(now, response.refresh_expires_in),
        user_id: response.user.id,
        email: response.user.email,
        data_key_ciphertext: response.data_key_ciphertext,
    }
}

pub fn update_credentials_with_refresh(
    credentials: &mut Credentials,
    refresh_response: RefreshResponse,
) {
    let now = Utc::now();
    credentials.access_token = refresh_response.access_token;
    credentials.refresh_token = refresh_response.refresh_token;
    credentials.access_expires_at = expires_at_from(now, refresh_response.expires_in);
    credentials.refresh_expires_at = expires_at_from(now, refresh_response.refresh_expires_in);
}

fn expires_at_from(now: DateTime<Utc>, expires_in_seconds: u64) -> DateTime<Utc> {
    now + chrono::Duration::seconds(expires_in_seconds as i64)
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
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown error".to_string());
        return Err(map_api_error(status.as_u16(), &error_text));
    }

    response
        .json()
        .await
        .map_err(|err| PublicError::unexpected(format!("failed to parse {context}: {err}")))
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
