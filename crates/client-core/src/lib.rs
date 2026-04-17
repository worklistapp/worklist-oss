#![cfg_attr(test, allow(clippy::unwrap_used))]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type PublicResult<T> = Result<T, PublicError>;

#[derive(Debug, Error)]
pub enum PublicError {
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Crypto(String),
    #[error("{0}")]
    Unexpected(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicWorkspaceStage {
    Draft,
}

impl PublicWorkspaceStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
        }
    }
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
