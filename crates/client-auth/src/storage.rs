use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use worklist_client_core::{PublicError, PublicResult};

use crate::KEY_SIZE;
use crate::credentials::{
    AgentCredentials, Credentials, PersistedDataKeyStatus, PrincipalCredentials,
    PrincipalSelection, select_principal_credentials,
};
use crate::http::{decode_bytes, normalize_api_url};

const DATA_KEY_KEYCHAIN_SERVICE: &str = "worklist.data-key";
pub(crate) const TEST_KEYCHAIN_DIR_ENV: &str = "WORKLIST_TEST_KEYCHAIN_DIR";
const AGENT_SEED_KEYCHAIN_SERVICE: &str = "worklist.agent-seed";
pub(crate) const AGENT_SEED_FILE_ONLY_ENV: &str = "WORKLIST_AGENT_SEED_FILE_ONLY";

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
    let contents = serde_json::to_vec_pretty(value)
        .map_err(|err| PublicError::unexpected(format!("failed to write {label} file: {err}")))?;
    write_secret_file_atomic(path, &contents, label)
}

#[cfg(unix)]
fn create_secret_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(unix)]
fn write_secret_file_atomic(path: &Path, contents: &[u8], label: &str) -> PublicResult<()> {
    let parent = path.parent().ok_or_else(|| {
        PublicError::unexpected(format!("{label} file path has no parent directory"))
    })?;
    let temp_path = temporary_secret_path(path);
    let mut file = create_secret_file(&temp_path).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to create temporary {label} file {}: {err}",
            temp_path.display()
        ))
    })?;

    let write_result = (|| -> PublicResult<()> {
        use std::io::Write;

        file.write_all(contents).map_err(|err| {
            PublicError::unexpected(format!(
                "failed to write temporary {label} file {}: {err}",
                temp_path.display()
            ))
        })?;
        file.flush().map_err(|err| {
            PublicError::unexpected(format!(
                "failed to flush temporary {label} file {}: {err}",
                temp_path.display()
            ))
        })?;
        file.sync_all().map_err(|err| {
            PublicError::unexpected(format!(
                "failed to sync temporary {label} file {}: {err}",
                temp_path.display()
            ))
        })?;
        drop(file);
        fs::rename(&temp_path, path).map_err(|err| {
            PublicError::unexpected(format!(
                "failed to replace {label} file {}: {err}",
                path.display()
            ))
        })?;
        sync_directory(parent, label)?;
        Ok(())
    })();

    if let Err(original_error) = write_result {
        match fs::remove_file(&temp_path) {
            Ok(()) => {}
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(cleanup_error) => {
                return Err(PublicError::unexpected(format!(
                    "{original_error}; additionally failed to remove temporary {label} file {}: {cleanup_error}",
                    temp_path.display()
                )));
            }
        }
        return Err(original_error);
    }

    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file_atomic(path: &Path, contents: &[u8], label: &str) -> PublicResult<()> {
    fs::write(path, contents).map_err(|err| {
        PublicError::unexpected(format!(
            "failed to write {label} file {}: {err}",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn temporary_secret_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secret");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce))
}

#[cfg(unix)]
fn sync_directory(path: &Path, label: &str) -> PublicResult<()> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| {
            PublicError::unexpected(format!(
                "failed to sync {label} parent directory {}: {err}",
                path.display()
            ))
        })
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
    write_secret_file_atomic(&path, seed, "local agent seed")
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
    write_secret_file_atomic(&path, data_key, "persisted test keychain secret")
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
