//! Simplified inbound definitions for app and test usage.
//!
//! This module provides a minimal [`InboundDef`] enum that uses [`serde_json::Value`]
//! for flexibility. Future iterations will introduce strongly-typed schemas.

use serde::Deserialize;
use serde_json::Value;

/// Simplified inbound definition using raw JSON values.
///
/// Used by app layer and tests as a temporary representation until
/// strongly-typed schemas are fully defined.
///
/// # Variants
/// - `Http`: HTTP proxy inbound
/// - `Socks`: SOCKS5 proxy inbound
/// - `Tun`: TUN device inbound (platform-dependent)
///
/// # Future Work
/// Replace `Value` with concrete types (e.g., `HttpInboundConfig`).
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[non_exhaustive]
pub enum InboundDef {
    /// HTTP proxy inbound configuration.
    Http(Value),
    /// SOCKS5 proxy inbound configuration.
    Socks(Value),
    /// TUN device inbound configuration.
    Tun(Value),
}
