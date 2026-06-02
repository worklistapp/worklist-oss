use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use generic_array::{ArrayLength, GenericArray};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginStartResult,
    CredentialResponse, Identifiers, Ristretto255, errors::InternalError,
    key_exchange::tripledh::TripleDh, ksf::Ksf,
};
use rand_core::OsRng;
use sha2::Sha512;

use worklist_client_core::{PublicError, PublicResult};

use crate::credentials::REDACTED_SECRET_FIELD;
use crate::http::{decode_bytes, encode_bytes};

const OPAQUE_SERVER_ID: &[u8] = b"worklist.api";

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

pub fn opaque_login_start(
    password: &str,
) -> PublicResult<(ClientLogin<ClientCipherSuite>, String)> {
    let mut rng = OsRng;
    let ClientLoginStartResult { message, state } =
        ClientLogin::<ClientCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|err| PublicError::crypto(format!("OPAQUE login start failed: {err}")))?;
    Ok((state, encode_bytes(message.serialize().as_slice())))
}

#[derive(Clone)]
pub struct OpaqueLoginFinish {
    pub finish_message: String,
    pub export_key: String,
}

impl fmt::Debug for OpaqueLoginFinish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueLoginFinish")
            .field("finish_message", &REDACTED_SECRET_FIELD)
            .field("export_key", &REDACTED_SECRET_FIELD)
            .finish()
    }
}

pub fn opaque_login_finish(
    state: ClientLogin<ClientCipherSuite>,
    email: &str,
    password: &str,
    server_response_b64: &str,
) -> PublicResult<OpaqueLoginFinish> {
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

    Ok(OpaqueLoginFinish {
        finish_message: encode_bytes(finish_result.message.serialize().as_slice()),
        export_key: encode_bytes(finish_result.export_key.as_slice()),
    })
}
