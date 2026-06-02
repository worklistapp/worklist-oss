use std::io::{self, Read};

use rpassword::prompt_password;
use worklist_client_auth::{
    AgentCredentials, Credentials, PrincipalCredentials, agent_key_material_from_seed,
    auth_response_to_credentials, load_agent_seed, load_persisted_data_key, login,
};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::{
    SymmetricKey, decrypt_user_data_key_with_login_secret, is_opaque_export_key_required_error,
};

use crate::projections::PrincipalWorkListKeySource;
use crate::unlock_daemon::{SessionKey, fetch_data_key, unlock};
use crate::{DEFAULT_AUTO_UNLOCK_TTL_SECONDS, RuntimeClient, auth_http_client};

impl RuntimeClient {
    pub(crate) async fn load_data_key(
        &self,
        credentials: &Credentials,
        password_stdin: bool,
        prompt_message: &str,
    ) -> PublicResult<SymmetricKey> {
        let session_key = self.current_session_key(credentials)?;
        if password_stdin {
            let password = read_required_password(password_stdin, Some(prompt_message))?;
            return self
                .decrypt_user_data_key_with_password(credentials, &password)
                .await;
        }

        if let Some(data_key) = fetch_data_key(&session_key)? {
            return Ok(data_key);
        }

        match self.load_data_key_from_persisted_secret(credentials, &session_key) {
            Ok(Some(data_key)) => Ok(data_key),
            Ok(None) => Err(missing_unlock_error(prompt_message)),
            Err(err) => Err(persisted_unlock_error(prompt_message, err)),
        }
    }

    fn load_data_key_from_persisted_secret(
        &self,
        credentials: &Credentials,
        session_key: &SessionKey,
    ) -> PublicResult<Option<SymmetricKey>> {
        let Some(data_key_bytes) = load_persisted_data_key(credentials)? else {
            return Ok(None);
        };
        let data_key = SymmetricKey::from_slice(&data_key_bytes)?;
        unlock(session_key, &data_key, auto_unlock_ttl_seconds()?)?;
        Ok(Some(data_key))
    }

    pub(crate) async fn load_principal_work_list_key_source(
        &self,
        password_stdin: bool,
        prompt_message: &str,
    ) -> PublicResult<PrincipalWorkListKeySource> {
        match self.require_principal_credentials()? {
            PrincipalCredentials::User(credentials) => Ok(PrincipalWorkListKeySource::UserDataKey(
                self.load_data_key(&credentials, password_stdin, prompt_message)
                    .await?,
            )),
            PrincipalCredentials::Agent(credentials) => {
                Ok(PrincipalWorkListKeySource::AgentRecipientPrivateKey(
                    self.load_agent_recipient_private_key(&credentials)?,
                ))
            }
            _ => Err(PublicError::validation(
                "unsupported principal credentials type",
            )),
        }
    }

    pub(crate) async fn decrypt_user_data_key_with_password(
        &self,
        credentials: &Credentials,
        password: &str,
    ) -> PublicResult<SymmetricKey> {
        match decrypt_user_data_key_with_login_secret(
            password,
            None,
            &credentials.data_key_ciphertext,
        ) {
            Ok(data_key) => Ok(data_key),
            Err(err) if is_opaque_export_key_required_error(&err) => {
                self.decrypt_user_data_key_after_opaque_login(credentials, password)
                    .await
            }
            Err(err) => Err(err),
        }
    }

    async fn decrypt_user_data_key_after_opaque_login(
        &self,
        credentials: &Credentials,
        password: &str,
    ) -> PublicResult<SymmetricKey> {
        let client = auth_http_client()?;
        let mut auth_response = login(&client, &self.api_url, &credentials.email, password).await?;
        let opaque_export_key = auth_response.opaque_export_key.take().ok_or_else(|| {
            PublicError::unexpected("OPAQUE login did not return a client export key")
        })?;
        let data_key_ciphertext = auth_response.data_key_ciphertext.clone();
        let data_key = decrypt_user_data_key_with_login_secret(
            password,
            Some(&opaque_export_key),
            &data_key_ciphertext,
        )?;
        let updated_credentials = auth_response_to_credentials(&self.api_url, auth_response)?;
        crate::auth::save_credentials_blocking(updated_credentials).await?;
        Ok(data_key)
    }

    fn load_agent_recipient_private_key(
        &self,
        credentials: &AgentCredentials,
    ) -> PublicResult<[u8; 32]> {
        let seed = load_agent_seed(credentials)?.ok_or_else(|| {
            PublicError::validation("agent seed missing from local secure storage")
        })?;
        Ok(*agent_key_material_from_seed(seed)?.recipient_private_key())
    }
}

fn auto_unlock_ttl_seconds() -> PublicResult<u64> {
    match std::env::var("WORKLIST_UNLOCK_TTL_SECONDS") {
        Ok(value) => {
            let trimmed = value.trim();
            let ttl_seconds = trimmed.parse::<u64>().map_err(|err| {
                PublicError::validation(format!(
                    "invalid WORKLIST_UNLOCK_TTL_SECONDS value '{trimmed}': {err}"
                ))
            })?;
            if ttl_seconds == 0 {
                return Err(PublicError::validation(
                    "WORKLIST_UNLOCK_TTL_SECONDS must be greater than zero",
                ));
            }
            Ok(ttl_seconds)
        }
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_AUTO_UNLOCK_TTL_SECONDS),
        Err(std::env::VarError::NotUnicode(_)) => Err(PublicError::validation(
            "WORKLIST_UNLOCK_TTL_SECONDS must be valid UTF-8",
        )),
    }
}

fn missing_unlock_error(prompt_message: &str) -> PublicError {
    PublicError::validation(format!(
        "{prompt_message} No unlocked local session or persisted bootstrap secret is available. Run 'worklist auth unlock --password-stdin' for a temporary session or 'worklist auth keychain store --password-stdin' to persist a local bootstrap secret."
    ))
}

fn persisted_unlock_error(prompt_message: &str, err: PublicError) -> PublicError {
    PublicError::validation(format!(
        "{prompt_message} Failed to load the persisted bootstrap secret: {err}. Run 'worklist auth unlock --password-stdin' for a temporary session or 'worklist auth keychain store --password-stdin' to refresh the local bootstrap secret."
    ))
}

fn read_password(label: &str) -> PublicResult<String> {
    prompt_password(label)
        .map_err(|err| PublicError::unexpected(format!("failed to read password: {err}")))
}

fn read_password_from_stdin() -> PublicResult<String> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|err| {
        PublicError::unexpected(format!("failed to read password from stdin: {err}"))
    })?;
    Ok(input.trim().to_string())
}

pub(crate) fn read_required_password(
    password_stdin: bool,
    prompt_message: Option<&str>,
) -> PublicResult<String> {
    let password = if password_stdin {
        read_password_from_stdin()?
    } else {
        if let Some(prompt_message) = prompt_message {
            println!("{prompt_message}");
        }
        read_password("Password: ")?
    };

    if password.is_empty() {
        return Err(PublicError::validation("password is required"));
    }

    Ok(password)
}
