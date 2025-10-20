//! # sb-tls: TLS Abstraction & Anti-Censorship Layer
//!
//! This crate provides TLS abstractions and anti-censorship protocols for singbox-rust:
//! - `TlsConnector` trait for extensible TLS implementations
//! - REALITY protocol for anti-censorship (certificate stealing)
//! - uTLS for TLS fingerprint mimicry (future)
//! - ECH (Encrypted Client Hello) support (future)
//!
//! ## Features
//! - `reality`: REALITY anti-censorship protocol (default)
//! - `utls`: uTLS fingerprint mimicry
//! - `ech`: Encrypted Client Hello
//!
//! ## Design Philosophy
//! - **Extensible TLS**: Pluggable TLS implementations
//! - **Anti-Censorship**: Protocols to bypass DPI and SNI filtering
//! - **Security First**: Proper key management and authentication

use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

/// Combined `AsyncRead` + `AsyncWrite` trait
///
/// This trait is automatically implemented for any type that implements
/// `AsyncRead` + `AsyncWrite` + `Unpin` + `Send`.
pub trait TlsStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

/// Blanket implementation for `TlsStream`
impl<T> TlsStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

/// TLS stream type alias
pub type TlsIoStream = Box<dyn TlsStream>;

/// TLS connector trait
///
/// This trait provides an abstraction for different TLS implementations:
/// - Standard TLS 1.3 (rustls)
/// - REALITY (anti-censorship)
/// - uTLS (fingerprint mimicry)
/// - ECH (encrypted client hello)
#[async_trait]
pub trait TlsConnector: Send + Sync {
    /// Connect to a TLS server
    ///
    /// # Arguments
    /// - `stream`: The underlying TCP stream
    /// - `server_name`: The server name for SNI
    async fn connect<S>(&self, stream: S, server_name: &str) -> io::Result<TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static;
}

/// Standard TLS connector (rustls)
pub mod standard;

/// REALITY anti-censorship protocol
#[cfg(feature = "reality")]
pub mod reality;

/// uTLS fingerprint mimicry
/// TODO: Implement uTLS fingerprint mimicry
#[cfg(feature = "utls")]
pub mod utls {
    //! uTLS fingerprint mimicry (placeholder)
    //! TODO: Implement browser fingerprint emulation
}

/// Encrypted Client Hello
#[cfg(feature = "ech")]
pub mod ech;

// Re-exports
pub use standard::StandardTlsConnector;

#[cfg(feature = "reality")]
pub use reality::{RealityAcceptor, RealityClientConfig, RealityConnector, RealityServerConfig};

#[cfg(feature = "ech")]
pub use ech::{EchClientConfig, EchConnector, EchKeypair, EchServerConfig};

/// TLS error types
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("TLS handshake error: {0}")]
    Handshake(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Certificate error: {0}")]
    Certificate(String),
}

pub type TlsResult<T> = Result<T, TlsError>;
