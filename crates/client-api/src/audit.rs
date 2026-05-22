use serde::{Deserialize, Serialize};
use worklist_client_core::{PublicError, PublicResult};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPatchFieldRequest {
    pub field: String,
    pub change_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_scalar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_scalar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before_ciphertext_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after_ciphertext_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPatchRequest {
    #[serde(default)]
    pub fields: Vec<AuditPatchFieldRequest>,
    pub payload_ciphertext: String,
    pub payload_ciphertext_proof: String,
    pub payload_version: i64,
}

impl AuditPatchRequest {
    pub fn validate_encrypted_boundary(&self) -> PublicResult<()> {
        for field in &self.fields {
            field.validate_encrypted_boundary()?;
        }
        Ok(())
    }
}

impl AuditPatchFieldRequest {
    fn validate_encrypted_boundary(&self) -> PublicResult<()> {
        if self.before_scalar.is_some() || self.after_scalar.is_some() {
            return Err(PublicError::validation(
                "audit patch fields must use ciphertext digests, not plaintext scalar values",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_optional_audit_patch(
    audit_patch: Option<&AuditPatchRequest>,
) -> PublicResult<()> {
    match audit_patch {
        Some(audit_patch) => audit_patch.validate_encrypted_boundary(),
        None => Ok(()),
    }
}
