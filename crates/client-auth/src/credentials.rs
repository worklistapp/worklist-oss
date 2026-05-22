use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use worklist_client_core::{PublicError, PublicResult};

pub(crate) const REDACTED_SECRET_FIELD: &str = "[redacted]";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
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
    pub(crate) api_url: String,
    pub(crate) agent_id: Uuid,
    pub(crate) owner_user_id: Option<Uuid>,
    pub(crate) handle: Option<String>,
    pub(crate) display_name: Option<String>,
    pub(crate) access_token: Option<String>,
    pub(crate) access_expires_at: Option<DateTime<Utc>>,
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
    pub fn registered(
        api_url: impl Into<String>,
        agent_id: Uuid,
        owner_user_id: Option<Uuid>,
        handle: Option<String>,
        display_name: Option<String>,
    ) -> Self {
        Self {
            api_url: api_url.into(),
            agent_id,
            owner_user_id,
            handle,
            display_name,
            access_token: None,
            access_expires_at: None,
        }
    }

    pub fn active(
        api_url: impl Into<String>,
        agent_id: Uuid,
        owner_user_id: Uuid,
        handle: Option<String>,
        display_name: Option<String>,
        access_token: impl Into<String>,
        access_expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            api_url: api_url.into(),
            agent_id,
            owner_user_id: Some(owner_user_id),
            handle,
            display_name,
            access_token: Some(access_token.into()),
            access_expires_at: Some(access_expires_at),
        }
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    pub fn agent_id(&self) -> Uuid {
        self.agent_id
    }

    pub fn owner_user_id(&self) -> Option<Uuid> {
        self.owner_user_id
    }

    pub fn handle(&self) -> Option<&str> {
        self.handle.as_deref()
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    pub fn access_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_expires_at
    }

    pub fn set_active_access_token(
        &mut self,
        owner_user_id: Uuid,
        access_token: impl Into<String>,
        access_expires_at: DateTime<Utc>,
    ) {
        self.owner_user_id = Some(owner_user_id);
        self.access_token = Some(access_token.into());
        self.access_expires_at = Some(access_expires_at);
    }

    pub fn state(&self) -> PublicResult<AgentCredentialState<'_>> {
        match (
            self.owner_user_id,
            self.access_token.as_deref(),
            self.access_expires_at,
        ) {
            (Some(owner_user_id), Some(access_token), Some(access_expires_at)) => {
                Ok(AgentCredentialState::Active {
                    owner_user_id,
                    access_token,
                    access_expires_at,
                })
            }
            (None, Some(_), Some(_)) => Err(PublicError::validation(
                "agent credentials have an access token but no owner user id",
            )),
            (_, Some(_), None) | (_, None, Some(_)) => Err(PublicError::validation(
                "agent credentials have a partial access token state",
            )),
            (owner_user_id, None, None) => Ok(AgentCredentialState::Registered { owner_user_id }),
        }
    }

    pub fn access_expires_within(&self, seconds: i64) -> bool {
        match self.access_expires_at {
            Some(expires_at) => Utc::now() + chrono::Duration::seconds(seconds) >= expires_at,
            None => true,
        }
    }

    pub fn needs_access_token_within(&self, seconds: i64) -> PublicResult<bool> {
        match self.state()? {
            AgentCredentialState::Active {
                access_expires_at, ..
            } => Ok(Utc::now() + chrono::Duration::seconds(seconds) >= access_expires_at),
            AgentCredentialState::Registered { .. } => Ok(true),
        }
    }

    pub fn active_access_token(&self) -> PublicResult<&str> {
        match self.state()? {
            AgentCredentialState::Active { access_token, .. } => Ok(access_token),
            AgentCredentialState::Registered { .. } => {
                Err(PublicError::validation("agent access token missing"))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum AgentCredentialState<'a> {
    Registered {
        owner_user_id: Option<Uuid>,
    },
    Active {
        owner_user_id: Uuid,
        access_token: &'a str,
        access_expires_at: DateTime<Utc>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "principal_type", rename_all = "snake_case")]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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

pub(crate) fn select_principal_credentials(
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
