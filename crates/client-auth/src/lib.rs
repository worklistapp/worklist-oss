#![cfg_attr(test, allow(clippy::unwrap_used))]

use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use generic_array::{ArrayLength, GenericArray};
use hkdf::Hkdf;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginStartResult,
    CredentialResponse, Identifiers, Ristretto255, errors::InternalError,
    key_exchange::tripledh::TripleDh, ksf::Ksf,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use worklist_client_core::{PublicError, PublicResult};

pub use worklist_client_api::{AgentEnrollmentResponse, AgentTokenResponse};

const OPAQUE_SERVER_ID: &[u8] = b"worklist.api";
const AGENT_ASSERTION_PURPOSE_TOKEN_MINT: &str = "token_mint";
#[cfg(test)]
const AGENT_ASSERTION_PURPOSE_CANCEL_ENROLLMENT: &str = "cancel_enrollment";
const DATA_KEY_KEYCHAIN_SERVICE: &str = "worklist.data-key";
const AGENT_SEED_KEYCHAIN_SERVICE: &str = "worklist.agent-seed";
const TEST_KEYCHAIN_DIR_ENV: &str = "WORKLIST_TEST_KEYCHAIN_DIR";
const AGENT_SEED_FILE_ONLY_ENV: &str = "WORKLIST_AGENT_SEED_FILE_ONLY";
const KEY_SIZE: usize = 32;
const AUTH_HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const REDACTED_SECRET_FIELD: &str = "[redacted]";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthSession {
    pub user_id: Uuid,
    pub api_url: String,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize)]
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

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("api_url", &self.api_url)
            .field("access_token", &REDACTED_SECRET_FIELD)
            .field("refresh_token", &REDACTED_SECRET_FIELD)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("user_id", &self.user_id)
            .field("email", &self.email)
            .field("data_key_ciphertext", &REDACTED_SECRET_FIELD)
            .finish()
    }
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

#[derive(Clone, Serialize, Deserialize)]
pub struct AgentCredentials {
    pub api_url: String,
    pub agent_id: Uuid,
    pub owner_user_id: Option<Uuid>,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub access_token: Option<String>,
    pub access_expires_at: Option<DateTime<Utc>>,
}

impl fmt::Debug for AgentCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentCredentials")
            .field("api_url", &self.api_url)
            .field("agent_id", &self.agent_id)
            .field("owner_user_id", &self.owner_user_id)
            .field("handle", &self.handle)
            .field("display_name", &self.display_name)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| REDACTED_SECRET_FIELD),
            )
            .field("access_expires_at", &self.access_expires_at)
            .finish()
    }
}

impl AgentCredentials {
    pub fn access_expires_within(&self, seconds: i64) -> bool {
        match self.access_expires_at {
            Some(expires_at) => Utc::now() + chrono::Duration::seconds(seconds) >= expires_at,
            None => true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "principal_type", rename_all = "snake_case")]
pub enum PrincipalCredentials {
    User(Credentials),
    Agent(AgentCredentials),
}

impl fmt::Debug for PrincipalCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(credentials) => f.debug_tuple("User").field(credentials).finish(),
            Self::Agent(credentials) => f.debug_tuple("Agent").field(credentials).finish(),
        }
    }
}

impl PrincipalCredentials {
    pub fn api_url(&self) -> &str {
        match self {
            Self::User(credentials) => &credentials.api_url,
            Self::Agent(credentials) => &credentials.api_url,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalSelection {
    #[default]
    Auto,
    User,
    Agent,
}

impl PrincipalSelection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::User => "user",
            Self::Agent => "agent",
        }
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

/// Internal wire DTO; public for compatibility only.
#[doc(hidden)]
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAgentEnrollmentRequest {
    auth_public_key: String,
    recipient_public_key: String,
    proposed_handle: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LookupAgentEnrollmentRequest {
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AgentTokenRequestBody {
    assertion: String,
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

pub fn agent_credentials_path() -> PublicResult<PathBuf> {
    Ok(config_dir()?.join("agent.json"))
}

pub fn normalize_api_url(api_url: &str) -> String {
    // This public normalizer is intentionally best-effort for legacy callers
    // that may pass partial local config. Assertion signing uses the fallible
    // canonicalizer so invalid audiences fail locally before a request is sent.
    canonicalize_api_url(api_url)
        .unwrap_or_else(|_| api_url.trim().trim_end_matches('/').to_string())
}

fn canonicalize_api_url(api_url: &str) -> PublicResult<String> {
    let mut url = reqwest::Url::parse(api_url.trim()).map_err(|err| {
        PublicError::validation(format!("API URL must be an absolute HTTP(S) base URL: {err}"))
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
        return Err(PublicError::validation("API URL must not include credentials"));
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

pub fn load_credentials() -> PublicResult<Option<Credentials>> {
    load_config_file(&credentials_path()?, "credentials")
}

pub fn load_credentials_for_url(api_url: &str) -> PublicResult<Option<Credentials>> {
    let normalized_api_url = normalize_api_url(api_url);
    match load_credentials()? {
        Some(credentials) if credentials.api_url == normalized_api_url => Ok(Some(credentials)),
        _ => Ok(None),
    }
}

pub fn load_agent_credentials() -> PublicResult<Option<AgentCredentials>> {
    load_config_file(&agent_credentials_path()?, "agent credentials")
}

pub fn load_agent_credentials_for_url(api_url: &str) -> PublicResult<Option<AgentCredentials>> {
    let normalized_api_url = normalize_api_url(api_url);
    match load_agent_credentials()? {
        Some(credentials) if credentials.api_url == normalized_api_url => Ok(Some(credentials)),
        _ => Ok(None),
    }
}

pub fn load_principal_credentials_for_url(
    api_url: &str,
    selection: PrincipalSelection,
) -> PublicResult<Option<PrincipalCredentials>> {
    let user_credentials = load_credentials_for_url(api_url)?;
    let agent_credentials = load_agent_credentials_for_url(api_url)?;
    select_principal_credentials(selection, user_credentials, agent_credentials)
}

fn select_principal_credentials(
    selection: PrincipalSelection,
    user_credentials: Option<Credentials>,
    agent_credentials: Option<AgentCredentials>,
) -> PublicResult<Option<PrincipalCredentials>> {
    match (selection, user_credentials, agent_credentials) {
        (PrincipalSelection::Auto, None, None) => Ok(None),
        (PrincipalSelection::Auto, Some(credentials), None) => {
            Ok(Some(PrincipalCredentials::User(credentials)))
        }
        (PrincipalSelection::Auto, None, Some(credentials)) => {
            Ok(Some(PrincipalCredentials::Agent(credentials)))
        }
        (PrincipalSelection::Auto, Some(_), Some(_)) => Err(PublicError::validation(
            "both user and agent credentials exist for this API URL; rerun with --principal user or --principal agent",
        )),
        (PrincipalSelection::User, Some(credentials), _) => {
            Ok(Some(PrincipalCredentials::User(credentials)))
        }
        (PrincipalSelection::User, None, _) => Err(PublicError::validation(
            "user credentials not found for this API URL - run 'worklist auth login' first",
        )),
        (PrincipalSelection::Agent, _, Some(credentials)) => {
            Ok(Some(PrincipalCredentials::Agent(credentials)))
        }
        (PrincipalSelection::Agent, _, None) => Err(PublicError::validation(
            "agent credentials not found for this API URL - run 'worklist agent register' first",
        )),
    }
}

pub fn save_credentials(credentials: &Credentials) -> PublicResult<()> {
    save_config_file(&credentials_path()?, credentials, "credentials")
}

pub fn save_agent_credentials(credentials: &AgentCredentials) -> PublicResult<()> {
    save_config_file(&agent_credentials_path()?, credentials, "agent credentials")
}

/// Clears persisted user credentials without affecting local agent credentials.
pub fn clear_credentials() -> PublicResult<()> {
    remove_config_file(&credentials_path()?, "credentials")
}

pub fn clear_agent_credentials() -> PublicResult<()> {
    remove_config_file(&agent_credentials_path()?, "agent credentials")
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

fn load_config_file<T>(path: &Path, label: &str) -> PublicResult<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    if !path.exists() {
        return Ok(None);
    }

    let file = File::open(path)
        .map_err(|err| PublicError::unexpected(format!("failed to open {label} file: {err}")))?;
    let reader = BufReader::new(file);
    let value = serde_json::from_reader(reader)
        .map_err(|err| PublicError::unexpected(format!("failed to parse {label} file: {err}")))?;
    Ok(Some(value))
}

fn save_config_file<T>(path: &Path, value: &T, label: &str) -> PublicResult<()>
where
    T: Serialize,
{
    ensure_config_dir()?;

    let file = File::create(path)
        .map_err(|err| PublicError::unexpected(format!("failed to create {label} file: {err}")))?;
    set_config_file_permissions(path, label)?;

    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, value)
        .map_err(|err| PublicError::unexpected(format!("failed to write {label} file: {err}")))
}

#[cfg(unix)]
fn set_config_file_permissions(path: &Path, label: &str) -> PublicResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions).map_err(|err| {
        PublicError::unexpected(format!("failed to set {label} file permissions: {err}"))
    })
}

#[cfg(not(unix))]
fn set_config_file_permissions(_path: &Path, _label: &str) -> PublicResult<()> {
    Ok(())
}

fn ensure_config_dir() -> PublicResult<PathBuf> {
    let dir = config_dir()?;
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|err| {
            PublicError::unexpected(format!("failed to create config directory: {err}"))
        })?;
    }
    set_config_dir_permissions(&dir)?;
    Ok(dir)
}

fn remove_config_file(path: &Path, label: &str) -> PublicResult<()> {
    if path.exists() {
        fs::remove_file(path).map_err(|err| {
            PublicError::unexpected(format!("failed to remove {label} file: {err}"))
        })?;
    }
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

pub struct AgentKeyMaterial {
    pub seed: [u8; KEY_SIZE],
    pub signing_key: SigningKey,
    pub auth_public_key: [u8; KEY_SIZE],
    pub recipient_private_key: [u8; KEY_SIZE],
    pub recipient_public_key: [u8; KEY_SIZE],
}

impl Drop for AgentKeyMaterial {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.recipient_private_key.zeroize();
    }
}

pub fn generate_agent_key_material() -> PublicResult<AgentKeyMaterial> {
    let mut seed = [0u8; KEY_SIZE];
    getrandom_fill(&mut seed)?;
    agent_key_material_from_seed(seed)
}

pub fn agent_key_material_from_seed(seed: [u8; KEY_SIZE]) -> PublicResult<AgentKeyMaterial> {
    let mut auth_seed = hkdf_expand_label(&seed, b"worklist.agent.auth")?;
    let mut recipient_seed = hkdf_expand_label(&seed, b"worklist.agent.recipient")?;
    let signing_key = SigningKey::from_bytes(&auth_seed);
    let auth_public_key = signing_key.verifying_key().to_bytes();
    let recipient_private_key = recipient_seed;
    let recipient_private = X25519StaticSecret::from(recipient_private_key);
    let recipient_public_key = X25519PublicKey::from(&recipient_private).to_bytes();

    let key_material = AgentKeyMaterial {
        seed,
        signing_key,
        auth_public_key,
        recipient_private_key,
        recipient_public_key,
    };
    auth_seed.zeroize();
    recipient_seed.zeroize();
    Ok(key_material)
}

pub async fn register_agent(
    client: &reqwest::Client,
    base_url: &str,
    key_material: &AgentKeyMaterial,
    proposed_handle: Option<String>,
) -> PublicResult<AgentEnrollmentResponse> {
    let response = send_auth_request(
        client
            .post(api_endpoint(base_url, "/agents/enrollments"))
            .json(&CreateAgentEnrollmentRequest {
                auth_public_key: encode_bytes(&key_material.auth_public_key),
                recipient_public_key: encode_bytes(&key_material.recipient_public_key),
                proposed_handle,
            }),
        "agent enrollment",
    )
    .await?;
    parse_json_response(response, "agent enrollment response").await
}

pub async fn fetch_agent_enrollment(
    client: &reqwest::Client,
    base_url: &str,
    code: &str,
) -> PublicResult<AgentEnrollmentResponse> {
    let response = send_auth_request(
        client
            .post(api_endpoint(base_url, "/agents/enrollments/lookup"))
            .json(&LookupAgentEnrollmentRequest {
                code: code.to_string(),
            }),
        "agent enrollment lookup",
    )
    .await?;
    parse_json_response(response, "agent enrollment response").await
}

pub async fn mint_agent_access_token(
    client: &reqwest::Client,
    credentials: &AgentCredentials,
) -> PublicResult<AgentTokenResponse> {
    let seed = load_agent_seed(credentials)?
        .ok_or_else(|| PublicError::validation("agent seed missing from local secure storage"))?;
    let key_material = agent_key_material_from_seed(seed)?;
    let assertion = build_agent_token_mint_assertion(
        &credentials.agent_id,
        &key_material.signing_key,
        &canonicalize_api_url(&credentials.api_url)?,
    )?;
    let response = send_auth_request(
        client
            .post(api_endpoint(&credentials.api_url, "/auth/agents/token"))
            .json(&AgentTokenRequestBody { assertion }),
        "agent token mint",
    )
    .await?;
    parse_json_response(response, "agent token response").await
}

pub fn build_agent_token_mint_assertion(
    agent_id: &Uuid,
    signing_key: &SigningKey,
    audience: &str,
) -> PublicResult<String> {
    build_agent_assertion(
        agent_id,
        signing_key,
        audience,
        AGENT_ASSERTION_PURPOSE_TOKEN_MINT,
    )
}

#[cfg(test)]
fn build_agent_cancel_enrollment_assertion(
    agent_id: &Uuid,
    signing_key: &SigningKey,
    audience: &str,
) -> PublicResult<String> {
    build_agent_assertion(
        agent_id,
        signing_key,
        audience,
        AGENT_ASSERTION_PURPOSE_CANCEL_ENROLLMENT,
    )
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

fn api_endpoint(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

enum PersistedDataKeyBackend {
    PlatformKeyring,
    TestDirectory(PathBuf),
}

fn hkdf_expand_label(seed: &[u8; KEY_SIZE], label: &[u8]) -> PublicResult<[u8; KEY_SIZE]> {
    let hkdf = Hkdf::<Sha256>::new(None, seed);
    let mut output = [0u8; KEY_SIZE];
    hkdf.expand(label, &mut output)
        .map_err(|err| PublicError::crypto(format!("hkdf expansion failed: {err}")))?;
    Ok(output)
}

fn getrandom_fill(bytes: &mut [u8]) -> PublicResult<()> {
    let mut rng = OsRng;
    rng.try_fill_bytes(bytes)
        .map_err(|err| PublicError::crypto(format!("os random generation failed: {err}")))
}

fn build_agent_assertion(
    agent_id: &Uuid,
    signing_key: &SigningKey,
    audience: &str,
    purpose: &str,
) -> PublicResult<String> {
    let now = Utc::now().timestamp();
    let header_json = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
    });
    let claims_json = serde_json::json!({
        "iss": agent_id,
        "aud": audience,
        "jti": Uuid::now_v7(),
        "iat": now,
        "exp": now + 60,
        "purpose": purpose,
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_json).map_err(|err| {
        PublicError::unexpected(format!("failed to serialize JWT header: {err}"))
    })?);
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims_json).map_err(|err| {
        PublicError::unexpected(format!("failed to serialize JWT claims: {err}"))
    })?);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
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

pub fn save_agent_seed(credentials: &AgentCredentials, seed: &[u8; KEY_SIZE]) -> PublicResult<()> {
    if should_force_agent_seed_file_backend() {
        return save_agent_seed_to_file(credentials, seed);
    }

    let entry = agent_seed_keyring_entry(credentials)?;
    match entry.set_secret(seed) {
        Ok(()) => clear_agent_seed_file(credentials),
        Err(err) if should_fallback_from_keyring(&err) => {
            save_agent_seed_to_file(credentials, seed)
        }
        Err(err) => Err(map_keyring_error(
            "write agent seed to the platform keychain",
            err,
        )),
    }
}

pub fn load_agent_seed(credentials: &AgentCredentials) -> PublicResult<Option<[u8; KEY_SIZE]>> {
    if should_force_agent_seed_file_backend() {
        return load_agent_seed_from_file(credentials);
    }

    let entry = agent_seed_keyring_entry(credentials)?;
    match entry.get_secret() {
        Ok(secret) => Ok(Some(decode_agent_seed_bytes(
            secret,
            "agent seed in keychain",
        )?)),
        Err(keyring::Error::NoEntry) => load_agent_seed_from_file(credentials),
        Err(err) if should_fallback_from_keyring(&err) => load_agent_seed_from_file(credentials),
        Err(err) => Err(map_keyring_error(
            "read agent seed from the platform keychain",
            err,
        )),
    }
}

pub fn clear_agent_seed(credentials: &AgentCredentials) -> PublicResult<()> {
    if should_force_agent_seed_file_backend() {
        return clear_agent_seed_file(credentials);
    }

    let entry = agent_seed_keyring_entry(credentials)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => clear_agent_seed_file(credentials),
        Err(err) if should_fallback_from_keyring(&err) => clear_agent_seed_file(credentials),
        Err(err) => Err(map_keyring_error(
            "clear the agent seed platform keychain entry",
            err,
        )),
    }
}

fn platform_keyring_entry(credentials: &Credentials) -> PublicResult<keyring::Entry> {
    let entry_name = persisted_data_key_entry_name(credentials)?;
    keyring::Entry::new(DATA_KEY_KEYCHAIN_SERVICE, &entry_name)
        .map_err(|err| map_keyring_error("create the platform keychain entry", err))
}

fn agent_seed_keyring_entry(credentials: &AgentCredentials) -> PublicResult<keyring::Entry> {
    let entry_name = agent_seed_entry_name(credentials);
    keyring::Entry::new(AGENT_SEED_KEYCHAIN_SERVICE, &entry_name)
        .map_err(|err| map_keyring_error("create the agent seed keychain entry", err))
}

fn should_force_agent_seed_file_backend() -> bool {
    matches!(
        std::env::var(AGENT_SEED_FILE_ONLY_ENV),
        Ok(value) if matches!(value.trim(), "1" | "true" | "yes" | "on")
    )
}

fn should_fallback_from_keyring(err: &keyring::Error) -> bool {
    matches!(
        err,
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_)
    )
}

fn decode_agent_seed_bytes(secret: Vec<u8>, source: &str) -> PublicResult<[u8; KEY_SIZE]> {
    if secret.len() != KEY_SIZE {
        return Err(PublicError::validation(format!(
            "{source} has invalid length",
        )));
    }

    let mut output = [0u8; KEY_SIZE];
    output.copy_from_slice(&secret);
    Ok(output)
}

fn agent_seed_file_path(credentials: &AgentCredentials) -> PublicResult<PathBuf> {
    let entry_name = agent_seed_entry_name(credentials);
    let file_name = format!(
        "agent-seed-{}.bin",
        URL_SAFE_NO_PAD.encode(Sha256::digest(entry_name.as_bytes()))
    );
    Ok(config_dir()?.join(file_name))
}

fn agent_seed_entry_name(credentials: &AgentCredentials) -> String {
    format!(
        "{}::{}",
        normalize_api_url(&credentials.api_url),
        credentials.agent_id
    )
}

fn load_agent_seed_from_file(
    credentials: &AgentCredentials,
) -> PublicResult<Option<[u8; KEY_SIZE]>> {
    let path = agent_seed_file_path(credentials)?;
    if !path.exists() {
        return Ok(None);
    }

    let secret = fs::read(&path).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to read the local agent seed file {}: {err}",
            path.display()
        ))
    })?;
    Ok(Some(decode_agent_seed_bytes(
        secret,
        "local agent seed file",
    )?))
}

fn save_agent_seed_to_file(
    credentials: &AgentCredentials,
    seed: &[u8; KEY_SIZE],
) -> PublicResult<()> {
    ensure_config_dir()?;
    let path = agent_seed_file_path(credentials)?;
    fs::write(&path, seed).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to write the local agent seed file {}: {err}",
            path.display()
        ))
    })?;
    set_secret_file_permissions(&path)?;
    Ok(())
}

fn clear_agent_seed_file(credentials: &AgentCredentials) -> PublicResult<()> {
    let path = agent_seed_file_path(credentials)?;
    if !path.exists() {
        return Ok(());
    }

    fs::remove_file(&path).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to remove the local agent seed file {}: {err}",
            path.display()
        ))
    })
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

async fn send_auth_request(
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
    use std::{
        ffi::OsString,
        sync::{Mutex, OnceLock},
    };
    use tempfile::TempDir;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set_path(key: &'static str, value: &std::path::Path) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }

        fn set_value(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => unsafe {
                    std::env::set_var(self.key, value);
                },
                None => unsafe {
                    std::env::remove_var(self.key);
                },
            }
        }
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn normalize_api_url_canonicalizes_http_base_urls() {
        let cases = [
            (
                " HTTPS://API.EXAMPLE.TEST:443/ ",
                "https://api.example.test",
            ),
            ("http://LOCALHOST:80/api/", "http://localhost/api"),
            (
                "https://API.EXAMPLE.TEST:8443/root/",
                "https://api.example.test:8443/root",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(normalize_api_url(input), expected);
        }
    }

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

    fn test_agent_credentials() -> AgentCredentials {
        AgentCredentials {
            api_url: "https://worklist.example.test".to_string(),
            agent_id: Uuid::now_v7(),
            owner_user_id: None,
            handle: Some("fixture-agent".to_string()),
            display_name: Some("Fixture Agent".to_string()),
            access_token: Some("agent-access".to_string()),
            access_expires_at: Some(Utc::now() + Duration::hours(1)),
        }
    }

    fn assert_agent_credentials_eq(actual: &AgentCredentials, expected: &AgentCredentials) {
        assert_eq!(actual.api_url, expected.api_url);
        assert_eq!(actual.agent_id, expected.agent_id);
        assert_eq!(actual.owner_user_id, expected.owner_user_id);
        assert_eq!(actual.handle, expected.handle);
        assert_eq!(actual.display_name, expected.display_name);
        assert_eq!(actual.access_token, expected.access_token);
        assert_eq!(
            actual
                .access_expires_at
                .map(|value| value.timestamp_micros()),
            expected
                .access_expires_at
                .map(|value| value.timestamp_micros())
        );
    }

    #[test]
    fn credentials_debug_output_redacts_tokens() {
        let credentials = test_credentials();
        let agent_credentials = test_agent_credentials();
        let principal_credentials = PrincipalCredentials::Agent(agent_credentials);
        let auth_response = AuthResponse {
            access_token: "auth-access-secret".to_string(),
            refresh_token: "auth-refresh-secret".to_string(),
            expires_in: 900,
            refresh_expires_in: 3600,
            token_type: "Bearer".to_string(),
            user: UserResponse {
                id: Uuid::now_v7(),
                email: "debug@example.com".to_string(),
                name: "Debug User".to_string(),
                timezone: "UTC".to_string(),
                avatar_color: "blue".to_string(),
                theme_preference: "system".to_string(),
                email_verified: true,
            },
            data_key_ciphertext: "data-key-ciphertext".to_string(),
        };
        let refresh_response = RefreshResponse {
            access_token: "refresh-access-secret".to_string(),
            refresh_token: "refresh-token-secret".to_string(),
            expires_in: 900,
            refresh_expires_in: 3600,
            token_type: "Bearer".to_string(),
        };
        let login_start_response = LoginStartResponse {
            server_login_state: "server-state".to_string(),
            session_token: "login-session-secret".to_string(),
            expires_in: 120,
        };

        let debug_output = format!(
            "{credentials:?} {principal_credentials:?} {auth_response:?} {refresh_response:?} {login_start_response:?}"
        );

        assert!(debug_output.contains(REDACTED_SECRET_FIELD));
        assert!(!debug_output.contains("agent-access"));
        assert!(!debug_output.contains("\"access\""));
        assert!(!debug_output.contains("\"refresh\""));
        assert!(!debug_output.contains("auth-access-secret"));
        assert!(!debug_output.contains("auth-refresh-secret"));
        assert!(!debug_output.contains("refresh-access-secret"));
        assert!(!debug_output.contains("refresh-token-secret"));
        assert!(!debug_output.contains("server-state"));
        assert!(!debug_output.contains("login-session-secret"));
        assert!(!debug_output.contains("data-key-ciphertext"));
    }

    #[test]
    fn test_persisted_data_key_round_trips_through_test_backend() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = TempDir::new().expect("temp dir");
        let credentials = test_credentials();
        let _keychain_dir = EnvVarGuard::set_path(TEST_KEYCHAIN_DIR_ENV, temp.path());

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
    }

    #[test]
    fn agent_seed_round_trips_through_file_backend() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = TempDir::new().expect("temp dir");
        let credentials = test_agent_credentials();
        let _home = EnvVarGuard::set_path("HOME", temp.path());
        let _file_backend = EnvVarGuard::set_value(AGENT_SEED_FILE_ONLY_ENV, "1");

        save_agent_seed(&credentials, &[0x5A; KEY_SIZE]).expect("store agent seed");
        let loaded = load_agent_seed(&credentials).expect("load agent seed");

        assert_eq!(loaded, Some([0x5A; KEY_SIZE]));

        clear_agent_seed(&credentials).expect("clear agent seed");
        assert_eq!(
            load_agent_seed(&credentials).expect("reload agent seed"),
            None
        );
    }

    #[test]
    fn agent_key_material_derives_recipient_public_key_from_private_key() {
        let material = agent_key_material_from_seed([0x5A; KEY_SIZE]).expect("derive key material");
        let recipient_private = X25519StaticSecret::from(material.recipient_private_key);
        let expected_public_key = X25519PublicKey::from(&recipient_private).to_bytes();

        assert_eq!(material.recipient_public_key, expected_public_key);
    }

    #[test]
    fn build_agent_assertion_includes_unique_jti() {
        let agent_id = Uuid::now_v7();
        let material = agent_key_material_from_seed([0x5B; KEY_SIZE]).expect("derive key material");
        let first = build_agent_assertion(
            &agent_id,
            &material.signing_key,
            "https://api.example.test",
            AGENT_ASSERTION_PURPOSE_TOKEN_MINT,
        )
        .expect("first assertion");
        let second = build_agent_assertion(
            &agent_id,
            &material.signing_key,
            "https://api.example.test",
            AGENT_ASSERTION_PURPOSE_TOKEN_MINT,
        )
        .expect("second assertion");

        let first_jti = assertion_jti(&first);
        let second_jti = assertion_jti(&second);

        assert_ne!(first_jti, second_jti);
        Uuid::parse_str(&first_jti).expect("jti should be a UUID");
        Uuid::parse_str(&second_jti).expect("jti should be a UUID");
    }

    #[test]
    fn build_agent_assertion_binds_audience_and_purpose() {
        let agent_id = Uuid::now_v7();
        let material = agent_key_material_from_seed([0x5C; KEY_SIZE]).expect("derive key material");
        let assertion = build_agent_token_mint_assertion(
            &agent_id,
            &material.signing_key,
            "https://api.example.test",
        )
        .expect("assertion");

        let claims = assertion_claims(&assertion);
        assert_eq!(claims["aud"], "https://api.example.test");
        assert_eq!(claims["purpose"], AGENT_ASSERTION_PURPOSE_TOKEN_MINT);
    }

    #[test]
    fn build_agent_cancel_enrollment_assertion_binds_cancel_purpose() {
        let agent_id = Uuid::now_v7();
        let material = agent_key_material_from_seed([0x5D; KEY_SIZE]).expect("derive key material");
        let assertion = build_agent_cancel_enrollment_assertion(
            &agent_id,
            &material.signing_key,
            "https://api.example.test",
        )
        .expect("assertion");

        let claims = assertion_claims(&assertion);
        assert_eq!(claims["aud"], "https://api.example.test");
        assert_eq!(claims["purpose"], AGENT_ASSERTION_PURPOSE_CANCEL_ENROLLMENT);
    }

    fn assertion_jti(assertion: &str) -> String {
        assertion_claims(assertion)["jti"]
            .as_str()
            .expect("jti claim")
            .to_string()
    }

    fn assertion_claims(assertion: &str) -> serde_json::Value {
        let payload_segment = assertion.split('.').nth(1).expect("JWT payload segment");
        let payload = URL_SAFE_NO_PAD
            .decode(payload_segment)
            .expect("decode JWT payload");
        serde_json::from_slice(&payload).expect("deserialize JWT payload")
    }

    #[test]
    fn auto_principal_selection_prefers_the_only_available_user_credentials() {
        let resolved =
            select_principal_credentials(PrincipalSelection::Auto, Some(test_credentials()), None)
                .expect("resolve principal");

        assert!(matches!(resolved, Some(PrincipalCredentials::User(_))));
    }

    #[test]
    fn auto_principal_selection_prefers_the_only_available_agent_credentials() {
        let resolved = select_principal_credentials(
            PrincipalSelection::Auto,
            None,
            Some(test_agent_credentials()),
        )
        .expect("resolve principal");

        assert!(matches!(resolved, Some(PrincipalCredentials::Agent(_))));
    }

    #[test]
    fn auto_principal_selection_rejects_ambiguous_credentials() {
        let error = select_principal_credentials(
            PrincipalSelection::Auto,
            Some(test_credentials()),
            Some(test_agent_credentials()),
        )
        .expect_err("ambiguous principal selection should fail");

        assert!(
            matches!(error, PublicError::Validation(ref message) if message.contains("--principal user") && message.contains("--principal agent")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn explicit_user_selection_requires_user_credentials() {
        let error = select_principal_credentials(
            PrincipalSelection::User,
            None,
            Some(test_agent_credentials()),
        )
        .expect_err("missing user credentials should fail");

        assert!(
            matches!(error, PublicError::Validation(ref message) if message.contains("worklist auth login")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn explicit_agent_selection_requires_agent_credentials() {
        let error =
            select_principal_credentials(PrincipalSelection::Agent, Some(test_credentials()), None)
                .expect_err("missing agent credentials should fail");

        assert!(
            matches!(error, PublicError::Validation(ref message) if message.contains("worklist agent register")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn clear_credentials_preserves_agent_credentials() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = TempDir::new().expect("temp dir");
        let _home = EnvVarGuard::set_path("HOME", temp.path());
        let user_credentials = test_credentials();
        let agent_credentials = test_agent_credentials();

        save_credentials(&user_credentials).expect("save user credentials");
        save_agent_credentials(&agent_credentials).expect("save agent credentials");

        clear_credentials().expect("clear user credentials");

        assert!(
            !credentials_path().expect("credentials path").exists(),
            "user credentials file should be removed"
        );
        let reloaded_agent = load_agent_credentials()
            .expect("reload agent credentials")
            .expect("agent credentials should remain");
        assert_agent_credentials_eq(&reloaded_agent, &agent_credentials);
    }
}
