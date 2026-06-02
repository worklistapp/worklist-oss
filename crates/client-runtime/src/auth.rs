use chrono::{DateTime, Utc};
use worklist_client_api::{CurrentUserResponse, DashboardStatsResponse, PublicApiClient};
use worklist_client_auth::{
    AgentCredentials, Credentials, PrincipalCredentials, load_credentials_for_url,
    load_principal_credentials_for_url, mint_agent_access_token, refresh_access_token,
    save_agent_credentials, save_credentials, update_credentials_with_refresh,
};
use worklist_client_core::{PublicError, PublicResult};

use crate::{RuntimeClient, auth_http_client};

impl RuntimeClient {
    pub fn require_logged_in_credentials(&self) -> PublicResult<Credentials> {
        load_credentials_for_url(&self.api_url)?.ok_or_else(|| {
            PublicError::validation("not logged in - run 'worklist auth login' first")
        })
    }

    pub fn require_principal_credentials(&self) -> PublicResult<PrincipalCredentials> {
        load_principal_credentials_for_url(&self.api_url, self.principal_selection)?.ok_or_else(
            || {
                PublicError::validation(
                    "not logged in - run 'worklist auth login' or 'worklist agent register' first",
                )
            },
        )
    }

    pub async fn authenticated_api_client(&self) -> PublicResult<PublicApiClient> {
        let access_token = self.fresh_principal_access_token().await?;
        Ok(PublicApiClient::with_bearer_token(
            &self.api_url,
            access_token,
        ))
    }

    pub async fn authenticated_owner_api_client(&self) -> PublicResult<PublicApiClient> {
        let mut credentials = load_credentials_for_url(&self.api_url)?.ok_or_else(|| {
            PublicError::validation("owner credentials required - run 'worklist auth login' first")
        })?;
        self.refresh_user_credentials_if_needed(&mut credentials)
            .await?;
        Ok(PublicApiClient::with_bearer_token(
            &self.api_url,
            credentials.access_token,
        ))
    }

    pub async fn get_me(&self) -> PublicResult<CurrentUserResponse> {
        let mut client = self.authenticated_api_client().await?;
        client.get_me().await
    }

    pub async fn get_stats(&self) -> PublicResult<DashboardStatsResponse> {
        let mut client = self.authenticated_api_client().await?;
        client.get_dashboard_stats().await
    }

    async fn fresh_principal_access_token(&self) -> PublicResult<String> {
        match self.require_principal_credentials()? {
            PrincipalCredentials::User(mut credentials) => {
                self.refresh_user_credentials_if_needed(&mut credentials)
                    .await?;
                Ok(credentials.access_token)
            }
            PrincipalCredentials::Agent(mut credentials) => {
                self.refresh_agent_credentials_if_needed(&mut credentials)
                    .await?;
                credentials.active_access_token().map(ToOwned::to_owned)
            }
            _ => Err(PublicError::validation(
                "unsupported principal credentials type",
            )),
        }
    }

    pub(crate) async fn refresh_user_credentials_if_needed(
        &self,
        credentials: &mut Credentials,
    ) -> PublicResult<()> {
        if !credentials.access_expires_within(60) {
            return Ok(());
        }
        if credentials.is_refresh_expired() {
            return Err(PublicError::validation(
                "session expired - run 'worklist auth login' to authenticate",
            ));
        }

        let client = auth_http_client()?;
        let refresh_response =
            refresh_access_token(&client, &self.api_url, &credentials.refresh_token).await?;
        update_credentials_with_refresh(credentials, refresh_response)?;
        save_credentials_blocking(credentials.clone()).await
    }

    pub(crate) async fn refresh_agent_credentials_if_needed(
        &self,
        credentials: &mut AgentCredentials,
    ) -> PublicResult<()> {
        if !credentials.needs_access_token_within(60)? {
            return Ok(());
        }

        let client = auth_http_client()?;
        let response = mint_agent_access_token(&client, credentials).await?;
        let access_expires_at = agent_access_expires_at_from(Utc::now(), response.expires_in)?;
        credentials.set_active_access_token(
            response.owner_user_id,
            response.access_token,
            access_expires_at,
        );
        save_agent_credentials_blocking(credentials.clone()).await
    }
}

pub(crate) async fn save_credentials_blocking(credentials: Credentials) -> PublicResult<()> {
    tokio::task::spawn_blocking(move || save_credentials(&credentials))
        .await
        .map_err(|err| PublicError::unexpected(format!("failed to join credential save: {err}")))?
}

async fn save_agent_credentials_blocking(credentials: AgentCredentials) -> PublicResult<()> {
    tokio::task::spawn_blocking(move || save_agent_credentials(&credentials))
        .await
        .map_err(|err| {
            PublicError::unexpected(format!("failed to join agent credential save: {err}"))
        })?
}

fn agent_access_expires_at_from(
    now: DateTime<Utc>,
    expires_in_seconds: u64,
) -> PublicResult<DateTime<Utc>> {
    let seconds = i64::try_from(expires_in_seconds).map_err(|err| {
        PublicError::unexpected(format!(
            "agent access token ttl seconds overflow for expires_in={expires_in_seconds}: {err}"
        ))
    })?;
    let ttl = chrono::Duration::try_seconds(seconds).ok_or_else(|| {
        PublicError::unexpected(format!(
            "agent access token ttl duration overflow for expires_in={expires_in_seconds}"
        ))
    })?;
    now.checked_add_signed(ttl).ok_or_else(|| {
        PublicError::unexpected(format!(
            "agent access token expiry overflow for expires_in={expires_in_seconds}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_access_expires_at_from_rejects_ttl_overflow() {
        let error = agent_access_expires_at_from(Utc::now(), u64::MAX)
            .expect_err("overflowing agent access ttl should fail");

        assert!(matches!(
            error,
            PublicError::Unexpected(message)
                if message.contains("agent access token ttl seconds overflow")
        ));
    }
}
