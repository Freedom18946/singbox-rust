//! QUIC common utilities for TUIC and Hysteria2
//!
//! Provides unified QUIC endpoint configuration, connection establishment,
//! and ALPN handling for QUIC-based protocols.

#[cfg(feature = "out_quic")]
use quinn::{ClientConfig, Connection, Endpoint};
#[cfg(feature = "out_quic")]
use rustls::{ClientConfig as TlsClientConfig, RootCertStore};
#[cfg(feature = "out_quic")]
use std::sync::Arc;

#[cfg(feature = "out_quic")]
#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub server: String,
    pub port: u16,
    pub alpn: Vec<Vec<u8>>,
    pub allow_insecure: bool,
}

#[cfg(feature = "out_quic")]
impl QuicConfig {
    pub fn new(server: String, port: u16) -> Self {
        Self {
            server,
            port,
            alpn: Vec::new(),
            allow_insecure: false,
        }
    }

    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    pub fn with_allow_insecure(mut self, allow: bool) -> Self {
        self.allow_insecure = allow;
        self
    }
}

/// Establish QUIC connection with unified configuration
#[cfg(feature = "out_quic")]
pub async fn connect(_cfg: &QuicConfig) -> anyhow::Result<Connection> {
    // For now, return a placeholder error since QUIC setup is complex
    // In a real implementation, this would establish the QUIC connection
    Err(anyhow::anyhow!(
        "QUIC connection not implemented - placeholder for Hysteria2 testing"
    ))
}

/// Get ALPN protocols from environment variable
#[cfg(feature = "out_quic")]
pub fn alpn_from_env(env_var: &str) -> Vec<Vec<u8>> {
    std::env::var(env_var)
        .ok()
        .map(|alpn_str| {
            alpn_str
                .split(',')
                .map(|proto| proto.trim().as_bytes().to_vec())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(not(feature = "out_quic"))]
pub struct QuicConfig;

#[cfg(not(feature = "out_quic"))]
impl QuicConfig {
    pub fn new(_server: String, _port: u16) -> Self {
        Self
    }
}

#[cfg(test)]
#[cfg(feature = "out_quic")]
mod tests {
    use super::*;

    #[test]
    fn test_quic_config() {
        let config = QuicConfig::new("example.com".to_string(), 443)
            .with_alpn(vec![b"h3".to_vec()])
            .with_allow_insecure(false);

        assert_eq!(config.server, "example.com");
        assert_eq!(config.port, 443);
        assert_eq!(config.alpn, vec![b"h3".to_vec()]);
        assert!(!config.allow_insecure);
    }

    #[test]
    fn test_alpn_from_env() {
        std::env::set_var("TEST_QUIC_ALPN", "h3,h2");
        let alpn = alpn_from_env("TEST_QUIC_ALPN");
        assert_eq!(alpn, vec![b"h3".to_vec(), b"h2".to_vec()]);
    }
}
