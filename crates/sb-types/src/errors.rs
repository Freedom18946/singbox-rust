//! Core error types for cross-crate error handling.
//!
//! # Strategic Purpose
//! Typed errors allow pattern matching and policy-based handling.
//! `anyhow` is NOT allowed in sb-core; only typed errors here.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use thiserror::Error;

/// High-level error classification for metrics and logging.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ErrorClass {
    /// I/O or network connectivity errors.
    Io,
    /// Operation timed out.
    Timeout,
    /// DNS resolution failed.
    Dns,
    /// Authentication or authorization failed.
    Auth,
    /// Protocol-level error (handshake, framing, etc.).
    Protocol,
    /// Policy or routing decision blocked the request.
    Policy,
    /// Resource exhausted (connection pool, memory, etc.).
    ResourceExhausted,
    /// Internal logic error (bug).
    Internal,
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Io => "io",
            Self::Timeout => "timeout",
            Self::Dns => "dns",
            Self::Auth => "auth",
            Self::Protocol => "protocol",
            Self::Policy => "policy",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Internal => "internal",
        };
        f.write_str(s)
    }
}

/// Core error type for data plane operations.
///
/// This is the primary error type used across sb-core and its consumers.
/// All adapters should map their errors to this type at boundaries.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum CoreError {
    /// I/O error (network, file, etc.).
    #[error("io error: {message}")]
    Io { class: ErrorClass, message: String },

    /// Operation timed out.
    #[error("timeout after {duration:?}: {operation}")]
    Timeout {
        operation: String,
        #[serde(with = "duration_serde")]
        duration: Duration,
    },

    /// DNS resolution failed.
    #[error("dns error: {message}")]
    Dns { message: String },

    /// Authentication failed.
    #[error("auth error: {message}")]
    Auth { message: String },

    /// Protocol error (handshake, framing, etc.).
    #[error("protocol error: {message}")]
    Protocol { message: String },

    /// Policy blocked the request.
    #[error("policy blocked: {reason}")]
    Policy { reason: String },

    /// Resource exhausted.
    #[error("resource exhausted: {resource}")]
    ResourceExhausted { resource: String },

    /// Internal error (logic bug).
    #[error("internal error: {message}")]
    Internal { message: String },
}

impl CoreError {
    /// Get the error class for categorization.
    #[inline]
    pub fn class(&self) -> ErrorClass {
        match self {
            Self::Io { class, .. } => *class,
            Self::Timeout { .. } => ErrorClass::Timeout,
            Self::Dns { .. } => ErrorClass::Dns,
            Self::Auth { .. } => ErrorClass::Auth,
            Self::Protocol { .. } => ErrorClass::Protocol,
            Self::Policy { .. } => ErrorClass::Policy,
            Self::ResourceExhausted { .. } => ErrorClass::ResourceExhausted,
            Self::Internal { .. } => ErrorClass::Internal,
        }
    }

    // Convenience constructors

    #[inline]
    pub fn io(message: impl Into<String>) -> Self {
        Self::Io {
            class: ErrorClass::Io,
            message: message.into(),
        }
    }

    #[inline]
    pub fn timeout(operation: impl Into<String>, duration: Duration) -> Self {
        Self::Timeout {
            operation: operation.into(),
            duration,
        }
    }

    #[inline]
    pub fn dns(message: impl Into<String>) -> Self {
        Self::Dns {
            message: message.into(),
        }
    }

    #[inline]
    pub fn auth(message: impl Into<String>) -> Self {
        Self::Auth {
            message: message.into(),
        }
    }

    #[inline]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol {
            message: message.into(),
        }
    }

    #[inline]
    pub fn policy(reason: impl Into<String>) -> Self {
        Self::Policy {
            reason: reason.into(),
        }
    }

    #[inline]
    pub fn resource_exhausted(resource: impl Into<String>) -> Self {
        Self::ResourceExhausted {
            resource: resource.into(),
        }
    }

    #[inline]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

// Serde helper for Duration
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

/// DNS-specific error type.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum DnsError {
    #[error("no records found for {name}")]
    NoRecords { name: String },

    #[error("timeout resolving {name}")]
    Timeout { name: String },

    #[error("server error: {message}")]
    ServerError { message: String },

    #[error("io error: {message}")]
    Io { message: String },
}

impl From<DnsError> for CoreError {
    fn from(e: DnsError) -> Self {
        CoreError::dns(e.to_string())
    }
}

/// Transport-specific error type.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum TransportError {
    #[error("connection refused")]
    ConnectionRefused,

    #[error("connection reset")]
    ConnectionReset,

    #[error("timeout: {message}")]
    Timeout { message: String },

    #[error("tls error: {message}")]
    Tls { message: String },

    #[error("io error: {message}")]
    Io { message: String },
}

impl From<TransportError> for CoreError {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Timeout { message } => {
                CoreError::timeout(message, Duration::from_secs(0))
            }
            _ => CoreError::io(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_error_class() {
        let e = CoreError::timeout("connect", Duration::from_secs(5));
        assert_eq!(e.class(), ErrorClass::Timeout);
    }

    #[test]
    fn core_error_serialization() {
        let e = CoreError::dns("NXDOMAIN");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("NXDOMAIN"));
    }
}
