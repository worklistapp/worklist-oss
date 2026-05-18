use worklist_client_auth::{
    PersistedDataKeyStatus, clear_persisted_data_key as clear_persisted_data_key_secret,
    load_credentials, load_credentials_for_url, persisted_data_key_status, save_persisted_data_key,
};
use worklist_client_core::PublicResult;
use worklist_client_crypto::decrypt_user_data_key;

use crate::RuntimeClient;
use crate::keys::read_required_password;
use crate::unlock_daemon::{UnlockStatus, clear_session, session_key, unlock, unlock_status};

impl RuntimeClient {
    pub fn unlock_daemon(&self, ttl_seconds: u64, password_stdin: bool) -> PublicResult<()> {
        let credentials = self.require_logged_in_credentials()?;
        let password = read_required_password(
            password_stdin,
            Some("Password required to unlock the local daemon."),
        )?;
        let data_key = decrypt_user_data_key(&password, &credentials.data_key_ciphertext)?;
        let session_key = self.current_session_key(&credentials)?;
        unlock(&session_key, &data_key, ttl_seconds)
    }

    pub fn store_persisted_data_key(&self, password_stdin: bool) -> PublicResult<()> {
        let credentials = self.require_logged_in_credentials()?;
        let password = read_required_password(
            password_stdin,
            Some("Password required to store a local bootstrap secret."),
        )?;
        let data_key = decrypt_user_data_key(&password, &credentials.data_key_ciphertext)?;
        save_persisted_data_key(&credentials, data_key.as_bytes())?;
        Ok(())
    }

    pub fn clear_persisted_data_key(&self) -> PublicResult<()> {
        let credentials = match load_credentials_for_url(&self.api_url)? {
            Some(credentials) => credentials,
            None => return Ok(()),
        };
        clear_persisted_data_key_secret(&credentials)
    }

    pub fn clear_unlock_daemon_session(&self) -> PublicResult<()> {
        let credentials = match load_credentials_for_url(&self.api_url)? {
            Some(credentials) => credentials,
            None => return Ok(()),
        };
        let session_key = self.current_session_key(&credentials)?;
        clear_session(&session_key)
    }

    pub fn unlock_status(&self) -> PublicResult<UnlockStatus> {
        match load_credentials()? {
            Some(credentials) => {
                let session_key = session_key(
                    &credentials.api_url,
                    credentials.user_id,
                    &credentials.data_key_ciphertext,
                )?;
                unlock_status(Some(&session_key))
            }
            None => unlock_status(None),
        }
    }

    pub fn persisted_data_key_status(&self) -> PublicResult<Option<PersistedDataKeyStatus>> {
        Ok(load_credentials_for_url(&self.api_url)?
            .map(|credentials| persisted_data_key_status(&credentials)))
    }
}
