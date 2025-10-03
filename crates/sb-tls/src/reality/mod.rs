//! # REALITY Anti-Censorship Protocol
//!
//! REALITY is an anti-censorship protocol that bypasses SNI whitelisting by:
//! - Stealing TLS certificates from real target websites
//! - Using SNI forgery to appear as legitimate traffic
//! - Authenticating with shared keys
//! - Falling back to real target on auth failure
//!
//! ## How it Works
//!
//! **Client Side:**
//! 1. Connects with forged SNI (e.g., "www.apple.com")
//! 2. Embeds authentication data in TLS handshake
//! 3. Receives either:
//!    - Temporary trusted certificate (proxy connection)
//!    - Real target certificate (fallback mode)
//!
//! **Server Side:**
//! 1. Receives TLS ClientHello
//! 2. Validates authentication data
//! 3. If valid: issues temporary certificate and proxies traffic
//! 4. If invalid: proxies to real target website (disguise)
//!
//! ## Security Model
//!
//! - Uses X25519 key exchange for authentication
//! - Short ID identifies different clients
//! - Target domain certificate is "stolen" (proxied)
//! - Falls back to real website on failure (anti-detection)

pub mod config;
pub mod client;
pub mod server;
pub mod auth;
pub mod tls_record;

pub use config::{RealityClientConfig, RealityServerConfig};
pub use client::RealityConnector;
pub use server::RealityAcceptor;
pub use auth::{RealityAuth, generate_keypair};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RealityError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Target connection failed: {0}")]
    TargetFailed(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type RealityResult<T> = Result<T, RealityError>;
