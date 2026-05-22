#![cfg_attr(test, allow(clippy::unwrap_used))]

use thiserror::Error;

pub type PublicResult<T> = Result<T, PublicError>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PublicError {
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Unexpected(String),
}

impl PublicError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }

    pub fn unexpected(message: impl Into<String>) -> Self {
        Self::Unexpected(message.into())
    }
}
