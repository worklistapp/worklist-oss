use base64::Engine as _;
use worklist_client_api::{AgentEnrollmentResponse, ApproveAgentGrantRequest, PublicApiClient};
use worklist_client_core::{PublicError, PublicResult};
use worklist_client_crypto::encrypt_agent_work_list_key;

use crate::{RuntimeClient, projections::resolve_list_key};

impl RuntimeClient {
    pub async fn build_agent_grants_for_enrollment(
        &self,
        enrollment: &AgentEnrollmentResponse,
        password_stdin: bool,
    ) -> PublicResult<Vec<ApproveAgentGrantRequest>> {
        let mut credentials = self.require_logged_in_credentials()?;
        let data_key = self.load_data_key(
            &credentials,
            password_stdin,
            "Password required to approve agent access.",
        )?;
        let recipient_public_key = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(enrollment.recipient_public_key.trim())
            .map_err(|err| {
                PublicError::validation(format!("invalid recipient public key: {err}"))
            })?;
        self.refresh_user_credentials_if_needed(&mut credentials)
            .await?;
        let mut client =
            PublicApiClient::with_bearer_token(&self.api_url, credentials.access_token);
        let work_lists = client.list_work_lists().await?;
        let mut grants = Vec::new();
        for work_list in work_lists
            .into_iter()
            .filter(|work_list| work_list.membership.role.eq_ignore_ascii_case("owner"))
        {
            let list_key = resolve_list_key(
                &data_key,
                work_list.id,
                &work_list.membership.work_list_key_ciphertext,
            )?;
            let ciphertext =
                encrypt_agent_work_list_key(&recipient_public_key, &work_list.id, &list_key)?;
            grants.push(ApproveAgentGrantRequest {
                work_list_id: work_list.id,
                key_ciphertext: ciphertext.base64,
            });
        }
        Ok(grants)
    }
}
