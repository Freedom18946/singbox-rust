//! Legacy Shadowsocks 2022 placeholder (returns `NotImplemented`).
//!
//! This module is kept for backward compatibility but does not provide a functional implementation.
//! Use feature-gated modules for real implementations:
//! - `ss2022_min` (feature: `proto_ss2022_min`): Minimal implementation
//! - `ss2022_core` (feature: `proto_ss2022_core`): Core protocol logic

use super::connector::{IoStream, OutboundConnector, ProtoError, Target};

/// Configuration for Shadowsocks 2022 outbound (placeholder).
#[derive(Debug, Clone)]
pub struct Ss2022Config {
    /// Server address.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// Encryption key (placeholder field).
    pub key: String,
}

/// Shadowsocks 2022 connector (placeholder - not implemented).
///
/// This is a legacy placeholder that always returns [`ProtoError::NotImplemented`].
/// Use `ss2022_min` or `ss2022_core` modules for functional implementations.
pub struct Shadowsocks2022 {
    /// Configuration (unused in placeholder).
    pub cfg: Ss2022Config,
}

#[async_trait::async_trait]
impl OutboundConnector for Shadowsocks2022 {
    async fn connect(&self, _target: &Target) -> Result<Box<dyn IoStream>, ProtoError> {
        Err(ProtoError::NotImplemented)
    }
}
