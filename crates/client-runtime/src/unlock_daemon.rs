use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

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
                "failed to lock unlock daemon: {err}"
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
            "unexpected daemon response to delete",
        )),
    }
}

pub async fn serve(socket_path: &Path) -> PublicResult<()> {
    let socket_dir = socket_path.parent().ok_or_else(|| {
        PublicError::unexpected(format!(
            "unlock daemon socket path has no parent: {}",
            socket_path.display()
        ))
    })?;
    if !socket_dir.exists() {
        std::fs::create_dir_all(socket_dir).map_err(|err| {
            PublicError::unexpected(format!(
                "failed to create unlock daemon directory {}: {err}",
                socket_dir.display()
            ))
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(socket_dir, std::fs::Permissions::from_mode(0o700)).map_err(
            |err| {
                PublicError::unexpected(format!(
                    "failed to secure unlock daemon directory {}: {err}",
                    socket_dir.display()
                ))
            },
        )?;
    }

    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(|err| {
            PublicError::unexpected(format!(
                "failed to remove stale unlock daemon socket {}: {err}",
                socket_path.display()
            ))
        })?;
    }

    let listener = tokio::net::UnixListener::bind(socket_path).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to bind unlock daemon socket {}: {err}",
            socket_path.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |err| {
                PublicError::unexpected(format!(
                    "failed to secure unlock daemon socket {}: {err}",
                    socket_path.display()
                ))
            },
        )?;
    }

    let store = std::sync::Arc::new(tokio::sync::Mutex::new(UnlockStore::default()));

    loop {
        let (mut stream, _) = listener.accept().await.map_err(|err| {
            PublicError::unexpected(format!("unlock daemon accept failed: {err}"))
        })?;
        let store = store.clone();

        let should_shutdown = {
            let mut request_bytes = Vec::new();
            stream
                .read_to_end(&mut request_bytes)
                .await
                .map_err(|err| {
                    PublicError::unexpected(format!("unlock daemon read failed: {err}"))
                })?;

            let request: DaemonRequest = serde_json::from_slice(&request_bytes).map_err(|err| {
                PublicError::unexpected(format!("failed to decode unlock daemon request: {err}"))
            })?;

            let response = handle_request(request, &store).await;
            let shutdown = matches!(response, DaemonResponse::Shutdown);
            let response_bytes = serde_json::to_vec(&response).map_err(|err| {
                PublicError::unexpected(format!("failed to encode unlock daemon response: {err}"))
            })?;
            stream.write_all(&response_bytes).await.map_err(|err| {
                PublicError::unexpected(format!("unlock daemon write failed: {err}"))
            })?;
            shutdown
        };

        if should_shutdown {
            break;
        }
    }

    if socket_path.exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    Ok(())
}

async fn handle_request(
    request: DaemonRequest,
    store: &std::sync::Arc<tokio::sync::Mutex<UnlockStore>>,
) -> DaemonResponse {
    match request {
        DaemonRequest::Put {
            session_key,
            data_key_b64,
            expires_at_unix,
        } => {
            store.lock().await.put(
                session_key,
                StoredSession {
                    data_key_b64,
                    expires_at_unix,
                },
            );
            DaemonResponse::Stored
        }
        DaemonRequest::Get { session_key } => DaemonResponse::DataKey {
            data_key_b64: store.lock().await.get(&session_key),
        },
        DaemonRequest::Status { session_key } => {
            DaemonResponse::Status(store.lock().await.status(session_key.as_ref()))
        }
        DaemonRequest::Delete { session_key } => {
            store.lock().await.delete(&session_key);
            DaemonResponse::Deleted
        }
        DaemonRequest::Shutdown => DaemonResponse::Shutdown,
    }
}

fn send_request(request: DaemonRequest) -> PublicResult<DaemonResponse> {
    try_send_request(request).map_err(|err| {
        PublicError::unexpected(format!("failed to communicate with unlock daemon: {err}"))
    })
}

fn try_send_request(request: DaemonRequest) -> PublicResult<DaemonResponse> {
    let socket_path = socket_path()?;
    let stream = std::os::unix::net::UnixStream::connect(&socket_path).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to connect to unlock daemon at {}: {err}",
            socket_path.display()
        ))
    })?;
    let response = send_request_over_stream(stream, request)?;
    Ok(response)
}

fn send_request_over_stream(
    mut stream: std::os::unix::net::UnixStream,
    request: DaemonRequest,
) -> PublicResult<DaemonResponse> {
    let payload = serde_json::to_vec(&request).map_err(|err| {
        PublicError::unexpected(format!("failed to encode unlock daemon request: {err}"))
    })?;
    use std::io::{Read, Write};
    stream.write_all(&payload).map_err(|err| {
        PublicError::unexpected(format!("failed to write unlock daemon request: {err}"))
    })?;
    stream.shutdown(std::net::Shutdown::Write).map_err(|err| {
        PublicError::unexpected(format!("failed to finish unlock daemon request: {err}"))
    })?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(|err| {
        PublicError::unexpected(format!("failed to read unlock daemon response: {err}"))
    })?;

    serde_json::from_slice(&response).map_err(|err| {
        PublicError::unexpected(format!("failed to decode unlock daemon response: {err}"))
    })
}

fn ensure_running() -> PublicResult<()> {
    match try_send_request(DaemonRequest::Status { session_key: None }) {
        Ok(_) => Ok(()),
        Err(err) if is_daemon_unavailable(&err) => spawn_daemon(),
        Err(err) => Err(PublicError::unexpected(format!(
            "failed to check unlock daemon: {err}"
        ))),
    }
}

fn spawn_daemon() -> PublicResult<()> {
    let socket_path = socket_path()?;
    let executable = std::env::current_exe().map_err(|err| {
        PublicError::unexpected(format!("failed to locate current executable: {err}"))
    })?;
    let mut command = std::process::Command::new(executable);
    command
        .arg("--serve-unlock-daemon")
        .arg(&socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    command
        .spawn()
        .map_err(|err| PublicError::unexpected(format!("failed to start unlock daemon: {err}")))?;

    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(20));
        if try_send_request(DaemonRequest::Status { session_key: None }).is_ok() {
            return Ok(());
        }
    }

    Err(PublicError::unexpected(
        "unlock daemon did not become ready in time",
    ))
}

fn is_daemon_unavailable(err: &PublicError) -> bool {
    matches!(err, PublicError::Unexpected(message) if message.contains("failed to connect to unlock daemon"))
}

fn build_status(session_key: Option<SessionKey>, expires_at_unix: Option<u64>) -> UnlockStatus {
    UnlockStatus {
        unlocked: expires_at_unix.is_some(),
        session_key,
        expires_at_unix,
    }
}

fn decode_base64(value: &str, message: &str) -> PublicResult<Vec<u8>> {
    STANDARD_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .map_err(|err| PublicError::validation(format!("{message}: {err}")))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be after unix epoch")
        .as_secs()
}
