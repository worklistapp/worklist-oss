use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use worklist_client_api::{AgentEnrollmentResponse, AgentTokenResponse};
use worklist_client_core::{PublicError, PublicResult};

use crate::{
    AGENT_ASSERTION_PURPOSE_TOKEN_MINT, AgentCredentials, KEY_SIZE, api_endpoint,
    canonicalize_api_url, encode_bytes, load_agent_seed, parse_json_response, send_auth_request,
};

#[cfg(test)]
const AGENT_ASSERTION_PURPOSE_CANCEL_ENROLLMENT: &str = "cancel_enrollment";

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

pub struct AgentKeyMaterial {
    seed: [u8; KEY_SIZE],
    signing_key: SigningKey,
    auth_public_key: [u8; KEY_SIZE],
    recipient_private_key: [u8; KEY_SIZE],
    recipient_public_key: [u8; KEY_SIZE],
}

impl Drop for AgentKeyMaterial {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.recipient_private_key.zeroize();
    }
}

impl AgentKeyMaterial {
    pub fn seed(&self) -> &[u8; KEY_SIZE] {
        &self.seed
    }

    pub fn auth_public_key(&self) -> &[u8; KEY_SIZE] {
        &self.auth_public_key
    }

    pub fn recipient_private_key(&self) -> &[u8; KEY_SIZE] {
        &self.recipient_private_key
    }

    pub fn recipient_public_key(&self) -> &[u8; KEY_SIZE] {
        &self.recipient_public_key
    }

    pub fn build_token_mint_assertion(
        &self,
        agent_id: &Uuid,
        audience: &str,
    ) -> PublicResult<String> {
        build_agent_assertion(
            agent_id,
            &self.signing_key,
            audience,
            AGENT_ASSERTION_PURPOSE_TOKEN_MINT,
        )
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
                auth_public_key: encode_bytes(key_material.auth_public_key()),
                recipient_public_key: encode_bytes(key_material.recipient_public_key()),
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
    let assertion = key_material.build_token_mint_assertion(
        &credentials.agent_id,
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
    key_material: &AgentKeyMaterial,
    audience: &str,
) -> PublicResult<String> {
    key_material.build_token_mint_assertion(agent_id, audience)
}

#[cfg(test)]
fn build_agent_cancel_enrollment_assertion(
    agent_id: &Uuid,
    key_material: &AgentKeyMaterial,
    audience: &str,
) -> PublicResult<String> {
    build_agent_assertion(
        agent_id,
        &key_material.signing_key,
        audience,
        AGENT_ASSERTION_PURPOSE_CANCEL_ENROLLMENT,
    )
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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

    use super::*;

    #[test]
    fn agent_key_material_derives_recipient_public_key_from_private_key() {
        let material = agent_key_material_from_seed([0x5A; KEY_SIZE]).expect("derive key material");
        let recipient_private = X25519StaticSecret::from(*material.recipient_private_key());
        let expected_public_key = X25519PublicKey::from(&recipient_private).to_bytes();

        assert_eq!(*material.recipient_public_key(), expected_public_key);
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
        let assertion =
            build_agent_token_mint_assertion(&agent_id, &material, "https://api.example.test")
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
            &material,
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

    fn assertion_claims(assertion: &str) -> Value {
        let payload_segment = assertion.split('.').nth(1).expect("JWT payload segment");
        let payload = URL_SAFE_NO_PAD
            .decode(payload_segment)
            .expect("decode payload");
        serde_json::from_slice(&payload).expect("claims json")
    }
}
