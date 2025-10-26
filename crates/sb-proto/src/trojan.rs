//! Legacy Trojan placeholder (returns `NotImplemented`).
//!
//! This module is kept for backward compatibility but does not provide a functional implementation.
//! Use feature-gated modules for real implementations:
//! - `trojan_min` (feature: `proto_trojan_min`): Minimal implementation
//! - `trojan_dry` (feature: `proto_trojan_dry`): Dry-run connector

use super::connector::{IoStream, OutboundConnector, ProtoError, Target};

/// Configuration for Trojan outbound (placeholder).
#[derive(Debug, Clone)]
pub struct TrojanConfig {
    /// Server address.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// Password for authentication.
    pub password: String,
    /// SNI for TLS handshake.
    pub sni: Option<String>,
}

/// Trojan connector (placeholder - not implemented).
///
/// This is a legacy placeholder that always returns [`ProtoError::NotImplemented`].
/// Use `trojan_min` or `trojan_dry` modules for functional implementations.
pub struct Trojan {
    /// Configuration (unused in placeholder).
    pub cfg: TrojanConfig,
}

#[async_trait::async_trait]
impl OutboundConnector for Trojan {
    async fn connect(&self, _target: &Target) -> Result<Box<dyn IoStream>, ProtoError> {
        Err(ProtoError::NotImplemented)
    }
}
