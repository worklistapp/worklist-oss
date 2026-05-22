use serde::Deserialize;
use worklist_client_core::{PublicError, PublicResult};

#[derive(Debug, Deserialize)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: Option<String>,
}

pub(crate) async fn handle_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    path: &str,
) -> PublicResult<T> {
    let status = response.status();
    if status.is_success() {
        response.json().await.map_err(|err| {
            PublicError::unexpected(format!("failed to parse response from {path}: {err}"))
        })
    } else {
        let error_text = error_response_text(response, path, status).await;
        Err(map_api_error(status.as_u16(), &error_text, path))
    }
}

pub(crate) async fn handle_empty_response(
    response: reqwest::Response,
    path: &str,
) -> PublicResult<()> {
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        let error_text = error_response_text(response, path, status).await;
        Err(map_api_error(status.as_u16(), &error_text, path))
    }
}

async fn error_response_text(
    response: reqwest::Response,
    path: &str,
    status: reqwest::StatusCode,
) -> String {
    response.text().await.unwrap_or_else(|err| {
        format!("failed to read API error response from {path} (status {status}): {err}")
    })
}

pub(crate) fn map_reqwest_error(err: reqwest::Error, path: &str) -> PublicError {
    if err.is_connect() {
        PublicError::unexpected(format!("failed to connect to API for {path}: {err}"))
    } else if err.is_timeout() {
        PublicError::unexpected(format!("API request timed out for {path}"))
    } else {
        PublicError::unexpected(format!("API request failed for {path}: {err}"))
    }
}

fn map_api_error(status: u16, body: &str, path: &str) -> PublicError {
    if let Ok(api_error) = serde_json::from_str::<ApiErrorResponse>(body) {
        let message = api_error.message.unwrap_or(api_error.error);
        return match status {
            401 => PublicError::validation(format!("authentication failed: {message}")),
            403 => PublicError::validation(format!("access denied: {message}")),
            404 => PublicError::validation(format!("not found: {message} ({path})")),
            400 | 422 => PublicError::validation(message),
            _ => PublicError::unexpected(format!("API error ({status}) for {path}: {message}")),
        };
    }

    match status {
        401 => PublicError::validation("authentication failed"),
        403 => PublicError::validation("access denied"),
        404 => PublicError::validation(format!("not found: {path}")),
        _ => PublicError::unexpected(format!("API error ({status}) for {path}: {body}")),
    }
}
