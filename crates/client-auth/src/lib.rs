#![cfg_attr(test, allow(clippy::unwrap_used))]

mod agent_keys;
mod credentials;
mod http;
mod opaque;
mod storage;

pub use agent_keys::{
    AgentKeyMaterial, agent_key_material_from_seed, build_agent_token_mint_assertion,
    fetch_agent_enrollment, generate_agent_key_material, mint_agent_access_token, register_agent,
};
pub use credentials::{
    AgentCredentialState, AgentCredentials, AuthSession, Credentials, PersistedDataKeyStatus,
    PrincipalCredentials, PrincipalSelection, UnlockMode,
};
pub use http::{
    ApiError, AuthResponse, LoginStartResponse, RefreshResponse, UserResponse,
    auth_response_to_credentials, login, logout, normalize_api_url, refresh_access_token,
    update_credentials_with_refresh,
};
pub use opaque::{ClientCipherSuite, ClientKsf, opaque_login_finish, opaque_login_start};
pub use storage::{
    agent_credentials_path, clear_agent_credentials, clear_agent_seed, clear_credentials,
    clear_persisted_data_key, config_dir, credentials_path, load_agent_credentials,
    load_agent_credentials_for_url, load_agent_seed, load_credentials, load_credentials_for_url,
    load_persisted_data_key, load_principal_credentials_for_url, persisted_data_key_status,
    save_agent_credentials, save_agent_seed, save_credentials, save_persisted_data_key,
};
pub use worklist_client_api::{AgentEnrollmentResponse, AgentTokenResponse};

#[cfg(test)]
pub(crate) use credentials::{REDACTED_SECRET_FIELD, select_principal_credentials};
pub(crate) use http::{
    api_endpoint, canonicalize_api_url, encode_bytes, parse_json_response, send_auth_request,
};
#[cfg(test)]
pub(crate) use storage::{AGENT_SEED_FILE_ONLY_ENV, TEST_KEYCHAIN_DIR_ENV};

pub(crate) const AGENT_ASSERTION_PURPOSE_TOKEN_MINT: &str = "token_mint";
pub(crate) const KEY_SIZE: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use chrono::{Duration, Utc};
    use std::{
        ffi::OsString,
        sync::{Mutex, OnceLock},
    };
    use tempfile::TempDir;
    use uuid::Uuid;
    use worklist_client_core::PublicError;

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
