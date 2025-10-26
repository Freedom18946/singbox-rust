//! Unified error model for all adapters
//!
//! This module provides a centralized error type [`AdapterError`] used across all
//! inbound and outbound adapters in the `sb-adapters` crate. It ensures consistent
//! error handling and propagation throughout the proxy adapter stack.
//!
//! # Usage Examples
//!
//! ```rust,ignore
//! use sb_adapters::error::{AdapterError, Result};
//! use std::time::Duration;
//!
//! // Creating errors using From trait
//! fn perform_io() -> Result<()> {
//!     let file = std::fs::File::open("/nonexistent")?; // Auto-converts io::Error
//!     Ok(())
//! }
//!
//! // Creating specific error variants
//! fn check_protocol(proto: &str) -> Result<()> {
//!     if proto != "socks5" {
//!         return Err(AdapterError::unsupported_protocol(proto.to_string()));
//!     }
//!     Ok(())
//! }
//!
//! // Handling timeouts
//! fn connect_with_timeout() -> Result<Connection> {
//!     // ... timeout logic ...
//!     Err(AdapterError::Timeout(Duration::from_secs(30)))
//! }
//!
//! // Protocol errors
//! fn handshake() -> Result<()> {
//!     Err(AdapterError::protocol("Invalid handshake sequence"))
//! }
//! ```

use std::time::Duration;
use thiserror::Error;

/// Unified error type for all adapter operations.
///
/// This enum covers various failure scenarios encountered in proxy adapters,
/// including I/O failures, protocol errors, authentication issues, and timeouts.
///
/// # Clone Implementation
///
/// This type implements [`Clone`] to support error propagation in concurrent
/// scenarios where the same error needs to be reported to multiple listeners
/// or retried across multiple attempts. Note that cloning `Io` errors loses
/// the original `std::io::Error` source chain but preserves the error kind
/// and message.
///
/// # Thread Safety
///
/// All variants are `Send + Sync`, making them safe to share across thread
/// boundaries in async contexts.
#[derive(Debug, Error)]
pub enum AdapterError {
    /// I/O operation failed.
    ///
    /// Wraps underlying [`std::io::Error`] from network operations, file access,
    /// or other I/O-related failures.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    /// use std::io::{Error, ErrorKind};
    ///
    /// let err = AdapterError::Io(Error::new(ErrorKind::ConnectionRefused, "refused"));
    /// ```
    #[error("I/O error: {0}")]
    Io(#[source] std::io::Error),

    /// Connection attempt exceeded the specified timeout.
    ///
    /// Contains the duration that was waited before timing out.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    /// use std::time::Duration;
    ///
    /// let err = AdapterError::Timeout(Duration::from_secs(30));
    /// ```
    #[error("Connection timeout after {0:?}")]
    Timeout(Duration),

    /// The requested protocol is not supported by this adapter.
    ///
    /// Contains the name of the unsupported protocol.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::unsupported_protocol("http3".to_string());
    /// ```
    #[error("Unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    /// Functionality has not been implemented yet.
    ///
    /// Used for feature stubs or platform-specific code paths.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::NotImplemented { what: "Windows TUN support" };
    /// ```
    #[error("Not implemented: {what}")]
    NotImplemented {
        /// Description of the unimplemented feature.
        what: &'static str,
    },

    /// Invalid adapter configuration detected.
    ///
    /// Contains a static description of the configuration issue. Use static strings
    /// to avoid allocation overhead since config errors are typically detected at
    /// startup.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::InvalidConfig("missing required field 'server'");
    /// ```
    #[error("Invalid configuration: {0}")]
    InvalidConfig(&'static str),

    /// Authentication with the remote server or client failed.
    ///
    /// This may indicate incorrect credentials or an unsupported auth method.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::AuthenticationFailed;
    /// ```
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Protocol-level error occurred.
    ///
    /// This covers handshake failures, invalid messages, or protocol violations.
    /// Use this for errors in protocol state machines or message parsing.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::protocol("Invalid SOCKS5 version byte");
    /// ```
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Network-level error occurred.
    ///
    /// This includes DNS resolution failures, unreachable hosts, or routing issues.
    /// Distinct from I/O errors which are lower-level socket operations.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::network("DNS resolution failed for example.com");
    /// ```
    #[error("Network error: {0}")]
    Network(String),

    /// A catch-all error for cases not covered by other variants.
    ///
    /// Prefer more specific variants when possible. This variant should be used
    /// sparingly for truly exceptional cases or when wrapping external errors
    /// that don't fit other categories.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::other("Unexpected internal state");
    /// ```
    #[error("Other error: {0}")]
    Other(String),
}

impl AdapterError {
    /// Creates an `UnsupportedProtocol` error.
    ///
    /// This is a convenience constructor that makes error creation more ergonomic.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::unsupported_protocol("quic".to_string());
    /// assert!(matches!(err, AdapterError::UnsupportedProtocol(_)));
    /// ```
    #[inline]
    #[must_use]
    pub fn unsupported_protocol(protocol: String) -> Self {
        Self::UnsupportedProtocol(protocol)
    }

    /// Creates a `Protocol` error with the given message.
    ///
    /// This is a convenience constructor for protocol-level errors.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::protocol("Handshake failed");
    /// assert!(matches!(err, AdapterError::Protocol(_)));
    /// ```
    #[inline]
    #[must_use]
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }

    /// Creates a `Network` error with the given message.
    ///
    /// This is a convenience constructor for network-level errors.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::network("Host unreachable");
    /// assert!(matches!(err, AdapterError::Network(_)));
    /// ```
    #[inline]
    #[must_use]
    pub fn network(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    /// Creates an `Other` error with the given message.
    ///
    /// This is a convenience constructor for miscellaneous errors.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::AdapterError;
    ///
    /// let err = AdapterError::other("Unexpected condition");
    /// assert!(matches!(err, AdapterError::Other(_)));
    /// ```
    #[inline]
    #[must_use]
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}

impl Clone for AdapterError {
    /// Clones the error, reconstructing `Io` errors from their kind and message.
    ///
    /// # Note
    ///
    /// Cloning `Io` variants loses the original error's source chain and backtrace,
    /// but preserves the error kind and display message. This trade-off enables
    /// error sharing in concurrent contexts while maintaining essential diagnostic
    /// information.
    ///
    /// # Performance
    ///
    /// This method is marked `#[inline]` to allow the compiler to optimize cloning
    /// of simple variants (like `AuthenticationFailed`) into no-ops in release builds.
    #[inline]
    fn clone(&self) -> Self {
        match self {
            Self::Io(e) => Self::Io(std::io::Error::new(e.kind(), e.to_string())),
            Self::Timeout(d) => Self::Timeout(*d),
            Self::UnsupportedProtocol(s) => Self::UnsupportedProtocol(s.clone()),
            Self::NotImplemented { what } => Self::NotImplemented { what },
            Self::InvalidConfig(s) => Self::InvalidConfig(s),
            Self::AuthenticationFailed => Self::AuthenticationFailed,
            Self::Protocol(s) => Self::Protocol(s.clone()),
            Self::Network(s) => Self::Network(s.clone()),
            Self::Other(s) => Self::Other(s.clone()),
        }
    }
}

impl From<anyhow::Error> for AdapterError {
    /// Converts an `anyhow::Error` to `AdapterError::Other`.
    ///
    /// This enables ergonomic use of `?` operator with functions returning `anyhow::Result`.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::{AdapterError, Result};
    /// use anyhow::anyhow;
    ///
    /// fn example() -> Result<()> {
    ///     let anyhow_err = anyhow!("something went wrong");
    ///     Err(anyhow_err)?
    /// }
    /// ```
    #[inline]
    fn from(err: anyhow::Error) -> Self {
        Self::Other(err.to_string())
    }
}

impl From<std::io::Error> for AdapterError {
    /// Converts a `std::io::Error` to `AdapterError::Io`.
    ///
    /// This enables automatic error conversion for I/O operations, allowing
    /// seamless use of the `?` operator with standard library I/O functions.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::error::Result;
    /// use std::fs::File;
    ///
    /// fn read_file() -> Result<File> {
    ///     let file = File::open("/path/to/file")?; // Auto-converts io::Error
    ///     Ok(file)
    /// }
    /// ```
    #[inline]
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Adapter-specific result type.
///
/// A type alias for `Result<T, AdapterError>`, reducing boilerplate in function signatures
/// throughout the `sb-adapters` crate.
///
/// # Type Parameters
///
/// - `T`: The success value type
/// - `E`: The error type (defaults to [`AdapterError`])
///
/// # Examples
///
/// ```rust,ignore
/// use sb_adapters::error::Result;
/// use tokio::net::TcpStream;
///
/// async fn connect(addr: &str) -> Result<TcpStream> {
///     let stream = TcpStream::connect(addr).await?;
///     Ok(stream)
/// }
/// ```
pub type Result<T, E = AdapterError> = std::result::Result<T, E>;
