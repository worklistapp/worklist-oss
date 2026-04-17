use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use worklist_client_auth::{config_dir, normalize_api_url};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::SymmetricKey;

const SOCKET_FILE_NAME: &str = "unlock.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockStatus {
    pub unlocked: bool,
    pub session_key: Option<SessionKey>,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionKey {
    pub api_url: String,
    pub user_id: Uuid,
    pub data_key_fingerprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum DaemonRequest {
    Put {
        session_key: SessionKey,
        data_key_b64: String,
        expires_at_unix: u64,
    },
    Get {
        session_key: SessionKey,
    },
    Status {
        session_key: Option<SessionKey>,
    },
    Delete {
        session_key: SessionKey,
    },
    Shutdown,
}

#[derive(Debug, Serialize, Deserialize)]
enum DaemonResponse {
    Stored,
    Deleted,
    DataKey { data_key_b64: Option<String> },
    Status(UnlockStatus),
    Shutdown,
    Error { message: String },
}

#[derive(Debug, Default)]
struct UnlockStore {
    sessions: HashMap<SessionKey, StoredSession>,
}

#[derive(Debug, Clone)]
struct StoredSession {
    data_key_b64: String,
    expires_at_unix: u64,
}

impl UnlockStore {
    fn put(&mut self, session_key: SessionKey, session: StoredSession) {
        self.sessions.insert(session_key, session);
    }

    fn get(&mut self, session_key: &SessionKey) -> Option<String> {
        self.prune_expired();
        self.sessions
            .get(session_key)
            .map(|session| session.data_key_b64.clone())
    }

    fn delete(&mut self, session_key: &SessionKey) {
        self.prune_expired();
        self.sessions.remove(session_key);
    }

    fn status(&mut self, session_key: Option<&SessionKey>) -> UnlockStatus {
        self.prune_expired();

        match session_key {
            Some(session_key) => build_status(
                Some(session_key.clone()),
                self.sessions
                    .get(session_key)
                    .map(|session| session.expires_at_unix),
            ),
            None => self
                .sessions
                .iter()
                .next()
                .map(|(session_key, session)| {
                    build_status(Some(session_key.clone()), Some(session.expires_at_unix))
                })
                .unwrap_or_else(|| build_status(None, None)),
        }
    }

    fn prune_expired(&mut self) {
        let now = unix_now();
        self.sessions
            .retain(|_, session| session.expires_at_unix > now);
    }
}

pub fn socket_path() -> PublicResult<PathBuf> {
    Ok(config_dir()?.join(SOCKET_FILE_NAME))
}

pub fn session_key(
    api_url: &str,
    user_id: Uuid,
    data_key_ciphertext: &str,
) -> PublicResult<SessionKey> {
    let ciphertext_bytes = decode_base64(
        data_key_ciphertext.trim(),
        "invalid data key ciphertext for daemon session key",
    )?;

    let mut hasher = Sha256::new();
    hasher.update(ciphertext_bytes);
    let digest = hasher.finalize();

    Ok(SessionKey {
        api_url: normalize_api_url(api_url),
        user_id,
        data_key_fingerprint: STANDARD_NO_PAD.encode(digest),
    })
}

pub fn unlock_status(session_key: Option<&SessionKey>) -> PublicResult<UnlockStatus> {
    let response = match try_send_request(DaemonRequest::Status {
        session_key: session_key.cloned(),
    }) {
        Ok(response) => response,
        Err(err) if is_daemon_unavailable(&err) => {
            return Ok(build_status(session_key.cloned(), None));
        }
        Err(err) => {
            return Err(PublicError::unexpected(format!(
                "failed to query unlock daemon status: {err}"
            )));
        }
    };

    match response {
        DaemonResponse::Status(status) => Ok(status),
        DaemonResponse::Error { message } => Err(PublicError::unexpected(message)),
        _ => Err(PublicError::unexpected(
            "unexpected daemon response to status",
        )),
    }
}

pub fn unlock(
    session_key: &SessionKey,
    data_key: &SymmetricKey,
    ttl_seconds: u64,
) -> PublicResult<()> {
    ensure_running()?;

    let expires_at_unix = unix_now() + ttl_seconds;
    let response = send_request(DaemonRequest::Put {
        session_key: session_key.clone(),
        data_key_b64: STANDARD_NO_PAD.encode(data_key.as_bytes()),
        expires_at_unix,
    })?;

    match response {
        DaemonResponse::Stored => Ok(()),
        DaemonResponse::Error { message } => Err(PublicError::unexpected(message)),
        _ => Err(PublicError::unexpected(
            "unexpected daemon response to unlock",
        )),
    }
}

pub fn fetch_data_key(session_key: &SessionKey) -> PublicResult<Option<SymmetricKey>> {
    let response = match try_send_request(DaemonRequest::Get {
        session_key: session_key.clone(),
    }) {
        Ok(response) => response,
        Err(err) if is_daemon_unavailable(&err) => return Ok(None),
        Err(err) => {
            return Err(PublicError::unexpected(format!(
                "failed to fetch data key from unlock daemon: {err}"
            )));
        }
    };

    match response {
        DaemonResponse::DataKey {
            data_key_b64: Some(data_key_b64),
        } => {
            let bytes = decode_base64(&data_key_b64, "invalid daemon data key")?;
            SymmetricKey::from_slice(&bytes).map(Some)
        }
        DaemonResponse::DataKey { data_key_b64: None } => Ok(None),
        DaemonResponse::Error { message } => Err(PublicError::unexpected(message)),
        _ => Err(PublicError::unexpected("unexpected daemon response to get")),
    }
}

pub fn lock() -> PublicResult<()> {
    let response = match try_send_request(DaemonRequest::Shutdown) {
        Ok(response) => response,
        Err(err) if is_daemon_unavailable(&err) => return Ok(()),
        Err(err) => {
            return Err(PublicError::unexpected(format!(
                "failed to shut down unlock daemon: {err}"
            )));
        }
    };

    match response {
        DaemonResponse::Shutdown => Ok(()),
        DaemonResponse::Error { message } => Err(PublicError::unexpected(message)),
        _ => Err(PublicError::unexpected(
            "unexpected daemon response to shutdown",
        )),
    }
}

pub fn clear_session(session_key: &SessionKey) -> PublicResult<()> {
    let response = match try_send_request(DaemonRequest::Delete {
        session_key: session_key.clone(),
    }) {
        Ok(response) => response,
        Err(err) if is_daemon_unavailable(&err) => return Ok(()),
        Err(err) => {
            return Err(PublicError::unexpected(format!(
                "failed to clear unlock daemon session: {err}"
            )));
        }
    };

    match response {
        DaemonResponse::Deleted => Ok(()),
        DaemonResponse::Error { message } => Err(PublicError::unexpected(message)),
        _ => Err(PublicError::unexpected(
            "unexpected daemon response to session delete",
        )),
    }
}

pub async fn serve(socket_path: &Path) -> PublicResult<()> {
    #[cfg(not(unix))]
    {
        let _ = socket_path;
        return Err(PublicError::unexpected(
            "unlock daemon is only supported on unix platforms",
        ));
    }

    #[cfg(unix)]
    {
        use tokio::net::UnixListener;

        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|err| {
                PublicError::unexpected(format!(
                    "failed to create daemon directory {}: {err}",
                    parent.display()
                ))
            })?;
            set_daemon_dir_permissions(parent)?;
        }

        if socket_path.exists() {
            let _ = tokio::fs::remove_file(socket_path).await;
        }

        let listener = UnixListener::bind(socket_path).map_err(|err| {
            PublicError::unexpected(format!(
                "failed to bind unlock socket {}: {err}",
                socket_path.display()
            ))
        })?;
        set_socket_permissions(socket_path)?;
        let mut store = UnlockStore::default();

        loop {
            let (mut stream, _) = listener.accept().await.map_err(|err| {
                PublicError::unexpected(format!("failed to accept unlock connection: {err}"))
            })?;

            let mut request_bytes = Vec::new();
            stream
                .read_to_end(&mut request_bytes)
                .await
                .map_err(|err| {
                    PublicError::unexpected(format!("failed to read unlock request: {err}"))
                })?;

            let request: DaemonRequest = serde_json::from_slice(&request_bytes)
                .map_err(|err| PublicError::unexpected(format!("invalid unlock request: {err}")))?;

            let (response, should_exit) = handle_request(&mut store, request);
            let response_bytes = serde_json::to_vec(&response).map_err(|err| {
                PublicError::unexpected(format!("failed to encode unlock response: {err}"))
            })?;
            stream.write_all(&response_bytes).await.map_err(|err| {
                PublicError::unexpected(format!("failed to write unlock response: {err}"))
            })?;

            if should_exit {
                let _ = tokio::fs::remove_file(socket_path).await;
                return Ok(());
            }
        }
    }
}

fn ensure_running() -> PublicResult<()> {
    if try_send_request(DaemonRequest::Status { session_key: None }).is_ok() {
        return Ok(());
    }

    let socket_path = socket_path()?;
    let current_exe = std::env::current_exe().map_err(|err| {
        PublicError::unexpected(format!("failed to resolve current executable: {err}"))
    })?;

    std::process::Command::new(current_exe)
        .arg("--serve-unlock-daemon")
        .arg(socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| PublicError::unexpected(format!("failed to spawn unlock daemon: {err}")))?;

    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(50));
        if try_send_request(DaemonRequest::Status { session_key: None }).is_ok() {
            return Ok(());
        }
    }

    Err(PublicError::unexpected("unlock daemon did not start"))
}

fn send_request(request: DaemonRequest) -> PublicResult<DaemonResponse> {
    try_send_request(request)
        .map_err(|err| PublicError::unexpected(format!("failed to contact unlock daemon: {err}")))
}

fn try_send_request(request: DaemonRequest) -> std::io::Result<DaemonResponse> {
    #[cfg(not(unix))]
    {
        let _ = request;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unlock daemon is only supported on unix platforms",
        ));
    }

    #[cfg(unix)]
    {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let socket_path = socket_path().map_err(std::io::Error::other)?;
        let mut stream = UnixStream::connect(&socket_path)?;
        let request_bytes = serde_json::to_vec(&request).map_err(std::io::Error::other)?;
        stream.write_all(&request_bytes)?;
        stream.shutdown(std::net::Shutdown::Write)?;

        let mut response_bytes = Vec::new();
        stream.read_to_end(&mut response_bytes)?;
        serde_json::from_slice(&response_bytes).map_err(std::io::Error::other)
    }
}

fn handle_request(store: &mut UnlockStore, request: DaemonRequest) -> (DaemonResponse, bool) {
    match request {
        DaemonRequest::Put {
            session_key,
            data_key_b64,
            expires_at_unix,
        } => {
            store.put(
                session_key,
                StoredSession {
                    data_key_b64,
                    expires_at_unix,
                },
            );
            (DaemonResponse::Stored, false)
        }
        DaemonRequest::Get { session_key } => (
            DaemonResponse::DataKey {
                data_key_b64: store.get(&session_key),
            },
            false,
        ),
        DaemonRequest::Status { session_key } => (
            DaemonResponse::Status(store.status(session_key.as_ref())),
            false,
        ),
        DaemonRequest::Delete { session_key } => {
            store.delete(&session_key);
            (DaemonResponse::Deleted, false)
        }
        DaemonRequest::Shutdown => (DaemonResponse::Shutdown, true),
    }
}

fn build_status(session_key: Option<SessionKey>, expires_at_unix: Option<u64>) -> UnlockStatus {
    UnlockStatus {
        unlocked: expires_at_unix.is_some(),
        session_key,
        expires_at_unix,
    }
}

fn decode_base64(value: &str, error_context: &str) -> PublicResult<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(value.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value.as_bytes()))
        .map_err(|err| PublicError::unexpected(format!("{error_context}: {err}")))
}

fn is_daemon_unavailable(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_secs()
}

#[cfg(unix)]
fn set_daemon_dir_permissions(dir: &Path) -> PublicResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to set daemon directory permissions on {}: {err}",
            dir.display()
        ))
    })
}

#[cfg(unix)]
fn set_socket_permissions(socket_path: &Path) -> PublicResult<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to set unlock socket permissions on {}: {err}",
            socket_path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_key_normalizes_api_url() {
        let user_id = Uuid::now_v7();
        let ciphertext = STANDARD_NO_PAD.encode(b"ciphertext");
        let left = session_key("https://worklist.app", user_id, &ciphertext).expect("left");
        let right = session_key("https://worklist.app/", user_id, &ciphertext).expect("right");
        assert_eq!(left, right);
    }

    #[test]
    fn session_key_changes_when_ciphertext_changes() {
        let user_id = Uuid::now_v7();
        let left = session_key(
            "https://worklist.app",
            user_id,
            &STANDARD_NO_PAD.encode(b"ciphertext-a"),
        )
        .expect("left");
        let right = session_key(
            "https://worklist.app",
            user_id,
            &STANDARD_NO_PAD.encode(b"ciphertext-b"),
        )
        .expect("right");
        assert_ne!(left, right);
    }

    #[test]
    fn session_key_normalizes_equivalent_base64() {
        let user_id = Uuid::now_v7();
        let padded = base64::engine::general_purpose::STANDARD.encode(b"ciphertext");
        let unpadded = STANDARD_NO_PAD.encode(b"ciphertext");
        let left = session_key("https://worklist.app", user_id, &padded).expect("left");
        let right = session_key("https://worklist.app", user_id, &unpadded).expect("right");
        assert_eq!(left, right);
    }
}
