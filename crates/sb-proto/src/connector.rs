//! Core protocol abstraction layer for outbound connections.
//!
//! This module provides fundamental traits and types for implementing proxy protocols:
//! - [`OutboundConnector`]: Trait for establishing outbound connections
//! - [`Target`]: Represents a connection target (host:port)
//! - [`IoStream`]: Trait alias for async I/O streams
//! - [`ProtoError`]: Common error types for protocol operations

use thiserror::Error;

/// Errors that can occur during protocol operations.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// Feature not yet implemented.
    #[error("not implemented")]
    NotImplemented,

    /// Invalid configuration with dynamic error message.
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// I/O error during protocol operations.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Represents a connection target with host and port.
///
/// # Examples
/// ```
/// # use sb_proto::Target;
/// let target = Target::new("example.com", 443);
/// assert_eq!(target.host(), "example.com");
/// assert_eq!(target.port(), 443);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    host: String,
    port: u16,
}

impl Target {
    /// Creates a new target with the specified host and port.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// Returns the target host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the target port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Consumes the target and returns the host and port as a tuple.
    #[must_use]
    pub fn into_parts(self) -> (String, u16) {
        (self.host, self.port)
    }
}

/// Trait alias for async I/O streams used in protocol implementations.
///
/// Any type implementing `AsyncRead + AsyncWrite + Unpin + Send` automatically
/// implements this trait via blanket implementation.
pub trait IoStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> IoStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Trait for outbound connection establishment.
///
/// Implementors provide protocol-specific logic to establish connections to remote targets.
#[async_trait::async_trait]
pub trait OutboundConnector: Send + Sync {
    /// Establishes a connection to the specified target.
    ///
    /// # Errors
    /// Returns [`ProtoError`] if the connection cannot be established.
    async fn connect(&self, target: &Target) -> Result<Box<dyn IoStream>, ProtoError>;
}
