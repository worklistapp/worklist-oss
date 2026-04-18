#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use generic_array::{ArrayLength, GenericArray};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginStartResult,
    CredentialResponse, Identifiers, Ristretto255, errors::InternalError,
    key_exchange::tripledh::TripleDh, ksf::Ksf,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use uuid::Uuid;

use worklist_client_core::{PublicError, PublicResult};

const OPAQUE_SERVER_ID: &[u8] = b"worklist.api";
const DATA_KEY_KEYCHAIN_SERVICE: &str = "worklist.data-key";
const TEST_KEYCHAIN_DIR_ENV: &str = "WORKLIST_TEST_KEYCHAIN_DIR";

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlockMode {
    SingleCommand,
    Daemon,
}

impl UnlockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleCommand => "single_command",
            Self::Daemon => "daemon",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub user_id: Uuid,
    pub api_url: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub api_url: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub email: String,
    pub data_key_ciphertext: String,
}

impl Credentials {
    pub fn is_access_expired(&self) -> bool {
        Utc::now() >= self.access_expires_at
    }

    pub fn is_refresh_expired(&self) -> bool {
        Utc::now() >= self.refresh_expires_at
    }

    pub fn access_expires_within(&self, seconds: i64) -> bool {
        Utc::now() + chrono::Duration::seconds(seconds) >= self.access_expires_at
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PersistedDataKeyStatus {
    Available,
    Missing,
    Unavailable(String),
}

impl PersistedDataKeyStatus {
    #[must_use]
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStartResponse {
    pub server_login_state: String,
    pub session_token: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    pub token_type: String,
}

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

pub struct ClientKsf {
    argon: Argon2<'static>,
}

impl Default for ClientKsf {
    fn default() -> Self {
        let params = Params::new(65536, 3, 4, None).expect("valid argon2 params");
        Self {
            argon: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }
}

impl Ksf for ClientKsf {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        self.argon
            .hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ClientCipherSuite;

impl CipherSuite for ClientCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = ClientKsf;
}

pub fn config_dir() -> PublicResult<PathBuf> {
    dirs::home_dir()
        .map(|home| home.join(".worklist"))
        .ok_or_else(|| PublicError::unexpected("could not determine home directory"))
}

pub fn credentials_path() -> PublicResult<PathBuf> {
    Ok(config_dir()?.join("credentials.json"))
}

pub fn normalize_api_url(api_url: &str) -> String {
    api_url.trim_end_matches('/').to_string()
}

pub fn load_credentials() -> PublicResult<Option<Credentials>> {
    let path = credentials_path()?;
    if !path.exists() {
        return Ok(None);
    }

    let file = File::open(&path).map_err(|err| {
        PublicError::unexpected(format!("failed to open credentials file: {err}"))
    })?;
    let reader = BufReader::new(file);
    let credentials: Credentials = serde_json::from_reader(reader).map_err(|err| {
        PublicError::unexpected(format!("failed to parse credentials file: {err}"))
    })?;
    Ok(Some(credentials))
}

pub fn load_credentials_for_url(api_url: &str) -> PublicResult<Option<Credentials>> {
    let normalized_api_url = normalize_api_url(api_url);
    match load_credentials()? {
        Some(credentials) if credentials.api_url == normalized_api_url => Ok(Some(credentials)),
        _ => Ok(None),
    }
}

pub fn save_credentials(credentials: &Credentials) -> PublicResult<()> {
    let dir = config_dir()?;
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|err| {
            PublicError::unexpected(format!("failed to create config directory: {err}"))
        })?;
    }
    set_config_dir_permissions(&dir)?;

    let path = credentials_path()?;
    let file = File::create(&path).map_err(|err| {
        PublicError::unexpected(format!("failed to create credentials file: {err}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, permissions).map_err(|err| {
            PublicError::unexpected(format!("failed to set credentials file permissions: {err}"))
        })?;
    }

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, credentials).map_err(|err| {
        PublicError::unexpected(format!("failed to write credentials file: {err}"))
    })?;
    Ok(())
}

pub fn clear_credentials() -> PublicResult<()> {
    let path = credentials_path()?;
    if path.exists() {
        fs::remove_file(&path).map_err(|err| {
            PublicError::unexpected(format!("failed to remove credentials file: {err}"))
        })?;
    }
    Ok(())
}

pub fn load_persisted_data_key(credentials: &Credentials) -> PublicResult<Option<Vec<u8>>> {
    persisted_data_key_backend().load(credentials)
}

pub fn save_persisted_data_key(credentials: &Credentials, data_key: &[u8]) -> PublicResult<()> {
    persisted_data_key_backend().save(credentials, data_key)
}

pub fn clear_persisted_data_key(credentials: &Credentials) -> PublicResult<()> {
    persisted_data_key_backend().clear(credentials)
}

#[must_use]
pub fn persisted_data_key_status(credentials: &Credentials) -> PersistedDataKeyStatus {
    match load_persisted_data_key(credentials) {
        Ok(Some(_)) => PersistedDataKeyStatus::Available,
        Ok(None) => PersistedDataKeyStatus::Missing,
        Err(err) => PersistedDataKeyStatus::Unavailable(err.to_string()),
    }
}

#[cfg(unix)]
fn set_config_dir_permissions(dir: &Path) -> PublicResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to set config directory permissions on {}: {err}",
            dir.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_config_dir_permissions(_dir: &Path) -> PublicResult<()> {
    Ok(())
}

pub fn opaque_login_start(
    password: &str,
) -> PublicResult<(ClientLogin<ClientCipherSuite>, String)> {
    let mut rng = OsRng;
    let ClientLoginStartResult { message, state } =
        ClientLogin::<ClientCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|err| PublicError::crypto(format!("OPAQUE login start failed: {err}")))?;
    Ok((state, encode_bytes(message.serialize().as_slice())))
}

pub fn opaque_login_finish(
    state: ClientLogin<ClientCipherSuite>,
    email: &str,
    password: &str,
    server_response_b64: &str,
) -> PublicResult<String> {
    let mut rng = OsRng;
    let server_bytes = decode_bytes(server_response_b64)?;
    let credential_response = CredentialResponse::<ClientCipherSuite>::deserialize(&server_bytes)
        .map_err(|err| {
        PublicError::crypto(format!("failed to deserialize server response: {err}"))
    })?;

    let normalized_email = email.trim().to_lowercase();
    let identifiers = Identifiers {
        client: Some(normalized_email.as_bytes()),
        server: Some(OPAQUE_SERVER_ID),
    };
    let params = ClientLoginFinishParameters::new(None, identifiers, None);

    let finish_result = state
        .finish(&mut rng, password.as_bytes(), credential_response, params)
        .map_err(|err| PublicError::crypto(format!("OPAQUE login finish failed: {err}")))?;

    Ok(encode_bytes(finish_result.message.serialize().as_slice()))
}

pub async fn login(
    client: &reqwest::Client,
    base_url: &str,
    email: &str,
    password: &str,
) -> PublicResult<AuthResponse> {
    let (opaque_state, client_login_state) = opaque_login_start(password)?;

    let start_response = client
        .post(format!(
            "{}/auth/opaque/login/start",
            base_url.trim_end_matches('/')
        ))
        .json(&LoginStartRequest {
            email: email.to_string(),
            client_login_state,
        })
        .send()
        .await
        .map_err(|err| map_reqwest_error(err, "login start"))?;
    let start_result: LoginStartResponse =
        parse_json_response(start_response, "login start response").await?;

    let client_finish_message = opaque_login_finish(
        opaque_state,
        email,
        password,
        &start_result.server_login_state,
    )?;

    let finish_response = client
        .post(format!(
            "{}/auth/opaque/login/finish",
            base_url.trim_end_matches('/')
        ))
        .json(&LoginFinishRequest {
            session_token: start_result.session_token,
            client_finish_message,
        })
        .send()
        .await
        .map_err(|err| map_reqwest_error(err, "login finish"))?;

    parse_json_response(finish_response, "auth response").await
}

pub async fn refresh_access_token(
    client: &reqwest::Client,
    base_url: &str,
    refresh_token: &str,
) -> PublicResult<RefreshResponse> {
    let response = client
        .post(format!("{}/auth/refresh", base_url.trim_end_matches('/')))
        .json(&RefreshRequest {
            refresh_token: refresh_token.to_string(),
        })
        .send()
        .await
        .map_err(|err| map_reqwest_error(err, "token refresh"))?;

    parse_json_response(response, "refresh response").await
}

pub async fn logout(
    client: &reqwest::Client,
    base_url: &str,
    refresh_token: &str,
) -> PublicResult<Option<String>> {
    let status = client
        .post(format!("{}/auth/logout", base_url.trim_end_matches('/')))
        .json(&RefreshRequest {
            refresh_token: refresh_token.to_string(),
        })
        .send()
        .await
        .map_err(|err| map_reqwest_error(err, "logout"))?
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

enum PersistedDataKeyBackend {
    PlatformKeyring,
    TestDirectory(PathBuf),
}

impl PersistedDataKeyBackend {
    fn load(&self, credentials: &Credentials) -> PublicResult<Option<Vec<u8>>> {
        match self {
            Self::PlatformKeyring => {
                let entry = platform_keyring_entry(credentials)?;
                match entry.get_secret() {
                    Ok(secret) => Ok(Some(secret)),
                    Err(keyring::Error::NoEntry) => Ok(None),
                    Err(err) => Err(map_keyring_error("read from the platform keychain", err)),
                }
            }
            Self::TestDirectory(dir) => load_test_persisted_data_key(dir, credentials),
        }
    }

    fn save(&self, credentials: &Credentials, data_key: &[u8]) -> PublicResult<()> {
        match self {
            Self::PlatformKeyring => {
                let entry = platform_keyring_entry(credentials)?;
                entry
                    .set_secret(data_key)
                    .map_err(|err| map_keyring_error("write to the platform keychain", err))
            }
            Self::TestDirectory(dir) => save_test_persisted_data_key(dir, credentials, data_key),
        }
    }

    fn clear(&self, credentials: &Credentials) -> PublicResult<()> {
        match self {
            Self::PlatformKeyring => {
                let entry = platform_keyring_entry(credentials)?;
                match entry.delete_credential() {
                    Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                    Err(err) => Err(map_keyring_error("clear the platform keychain entry", err)),
                }
            }
            Self::TestDirectory(dir) => clear_test_persisted_data_key(dir, credentials),
        }
    }
}

fn persisted_data_key_backend() -> PersistedDataKeyBackend {
    match std::env::var(TEST_KEYCHAIN_DIR_ENV) {
        Ok(dir) if !dir.trim().is_empty() => PersistedDataKeyBackend::TestDirectory(dir.into()),
        _ => PersistedDataKeyBackend::PlatformKeyring,
    }
}

fn platform_keyring_entry(credentials: &Credentials) -> PublicResult<keyring::Entry> {
    let entry_name = persisted_data_key_entry_name(credentials)?;
    keyring::Entry::new(DATA_KEY_KEYCHAIN_SERVICE, &entry_name)
        .map_err(|err| map_keyring_error("create the platform keychain entry", err))
}

fn persisted_data_key_entry_name(credentials: &Credentials) -> PublicResult<String> {
    let fingerprint = data_key_fingerprint(&credentials.data_key_ciphertext)?;
    Ok(format!(
        "{}::{}::{}",
        normalize_api_url(&credentials.api_url),
        credentials.user_id,
        fingerprint
    ))
}

fn data_key_fingerprint(data_key_ciphertext: &str) -> PublicResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(decode_bytes(data_key_ciphertext)?);
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn map_keyring_error(action: &str, err: keyring::Error) -> PublicError {
    PublicError::validation(format!("failed to {action}: {err}"))
}

fn load_test_persisted_data_key(
    dir: &Path,
    credentials: &Credentials,
) -> PublicResult<Option<Vec<u8>>> {
    let path = test_persisted_data_key_path(dir, credentials)?;
    if !path.exists() {
        return Ok(None);
    }

    fs::read(&path).map(Some).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to read the persisted test keychain secret {}: {err}",
            path.display()
        ))
    })
}

fn save_test_persisted_data_key(
    dir: &Path,
    credentials: &Credentials,
    data_key: &[u8],
) -> PublicResult<()> {
    fs::create_dir_all(dir).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to create the persisted test keychain directory {}: {err}",
            dir.display()
        ))
    })?;
    set_config_dir_permissions(dir)?;

    let path = test_persisted_data_key_path(dir, credentials)?;
    fs::write(&path, data_key).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to write the persisted test keychain secret {}: {err}",
            path.display()
        ))
    })?;
    set_secret_file_permissions(&path)?;
    Ok(())
}

fn clear_test_persisted_data_key(dir: &Path, credentials: &Credentials) -> PublicResult<()> {
    let path = test_persisted_data_key_path(dir, credentials)?;
    if !path.exists() {
        return Ok(());
    }

    fs::remove_file(&path).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to remove the persisted test keychain secret {}: {err}",
            path.display()
        ))
    })
}

fn test_persisted_data_key_path(dir: &Path, credentials: &Credentials) -> PublicResult<PathBuf> {
    let entry_name = persisted_data_key_entry_name(credentials)?;
    let file_name = format!(
        "persisted-data-key-{}.bin",
        URL_SAFE_NO_PAD.encode(Sha256::digest(entry_name.as_bytes()))
    );
    Ok(dir.join(file_name))
}

fn encode_bytes(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes)
}

fn decode_bytes(value: &str) -> PublicResult<Vec<u8>> {
    let trimmed = value.trim();
    STANDARD_NO_PAD
        .decode(trimmed)
        .or_else(|_| STANDARD.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .map_err(|err| PublicError::validation(format!("invalid base64: {err}")))
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

async fn parse_json_response<T: for<'de> Deserialize<'de>>(
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

#[cfg(unix)]
fn set_secret_file_permissions(path: &Path) -> PublicResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to set secret file permissions on {}: {err}",
            path.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_secret_file_permissions(_path: &Path) -> PublicResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tempfile::TempDir;

    fn test_credentials() -> Credentials {
        Credentials {
            api_url: "https://worklist.example.test".to_string(),
            access_token: "access".to_string(),
            refresh_token: "refresh".to_string(),
            access_expires_at: Utc::now() + Duration::hours(1),
            refresh_expires_at: Utc::now() + Duration::days(1),
            user_id: Uuid::now_v7(),
            email: "test@example.com".to_string(),
            data_key_ciphertext: STANDARD_NO_PAD.encode(b"ciphertext"),
        }
    }

    #[test]
    fn test_persisted_data_key_round_trips_through_test_backend() {
        let temp = TempDir::new().expect("temp dir");
        let credentials = test_credentials();
        unsafe {
            std::env::set_var(TEST_KEYCHAIN_DIR_ENV, temp.path());
        }

        save_persisted_data_key(&credentials, b"secret").expect("store key");
        let loaded = load_persisted_data_key(&credentials).expect("load key");

        assert_eq!(loaded.as_deref(), Some(b"secret".as_slice()));
        assert_eq!(
            persisted_data_key_status(&credentials),
            PersistedDataKeyStatus::Available
        );

        clear_persisted_data_key(&credentials).expect("clear key");
        assert_eq!(
            load_persisted_data_key(&credentials).expect("reload key"),
            None
        );
        assert_eq!(
            persisted_data_key_status(&credentials),
            PersistedDataKeyStatus::Missing
        );

        unsafe {
            std::env::remove_var(TEST_KEYCHAIN_DIR_ENV);
        }
    }
}
