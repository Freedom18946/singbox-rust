//! Unified error model for all adapters

use std::time::Duration;
use thiserror::Error;

/// Unified error type for all adapter operations
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),

    #[error("Connection timeout after {0:?}")]
    Timeout(Duration),

    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    #[error("Not implemented: {what}")]
    NotImplemented { what: &'static str },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl Clone for AdapterError {
    fn clone(&self) -> Self {
        match self {
            AdapterError::Io(e) => AdapterError::Io(std::io::Error::new(e.kind(), e.to_string())),
            AdapterError::Timeout(d) => AdapterError::Timeout(*d),
            AdapterError::UnsupportedProtocol(s) => AdapterError::UnsupportedProtocol(s.clone()),
            AdapterError::NotImplemented { what } => AdapterError::NotImplemented { what },
            AdapterError::InvalidConfig(s) => AdapterError::InvalidConfig(s),
            AdapterError::AuthenticationFailed => AdapterError::AuthenticationFailed,
            AdapterError::Protocol(s) => AdapterError::Protocol(s.clone()),
            AdapterError::Network(s) => AdapterError::Network(s.clone()),
            AdapterError::Other(s) => AdapterError::Other(s.clone()),
        }
    }
}

impl From<anyhow::Error> for AdapterError {
    fn from(err: anyhow::Error) -> Self {
        AdapterError::Other(err.to_string())
    }
}

impl From<std::io::Error> for AdapterError {
    fn from(err: std::io::Error) -> Self {
        AdapterError::Io(err)
    }
}

/// Adapter-specific result type
pub type Result<T, E = AdapterError> = std::result::Result<T, E>;
