//! Multiplex IR helpers shared by inbound/outbound configs.
//!
//! ## Deserialization (WP-30ai)
//!
//! `MultiplexOptionsIR` and `BrutalIR` deserialize via their corresponding
//! Raw bridges in `super::raw`, so unknown nested fields are rejected at parse
//! time.

use serde::{Deserialize, Serialize};

use super::raw::{RawBrutalIR, RawMultiplexOptionsIR};

/// Multiplex options for inbound/outbound connections (yamux-based stream multiplexing).
///
/// Deserialization goes through [`RawMultiplexOptionsIR`](super::raw::RawMultiplexOptionsIR)
/// which carries `#[serde(deny_unknown_fields)]`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct MultiplexOptionsIR {
    /// Enable multiplex support.
    #[serde(default)]
    pub enabled: bool,
    /// Protocol (typically "yamux" or "h2mux").
    #[serde(default)]
    pub protocol: Option<String>,
    /// Maximum number of concurrent connections in pool.
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Minimum number of streams per connection.
    #[serde(default)]
    pub min_streams: Option<usize>,
    /// Maximum number of streams per connection.
    #[serde(default)]
    pub max_streams: Option<usize>,
    /// Enable padding.
    #[serde(default)]
    pub padding: Option<bool>,
    /// Brutal congestion control configuration.
    #[serde(default)]
    pub brutal: Option<BrutalIR>,
    /// Initial stream window size.
    #[serde(default)]
    pub initial_stream_window: Option<u32>,
    /// Maximum stream window size.
    #[serde(default)]
    pub max_stream_window: Option<u32>,
    /// Enable keepalive.
    #[serde(default)]
    pub enable_keepalive: Option<bool>,
    /// Keepalive interval in seconds.
    #[serde(default)]
    pub keepalive_interval: Option<u64>,
}

impl<'de> Deserialize<'de> for MultiplexOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawMultiplexOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// Brutal congestion control configuration.
///
/// Deserialization goes through [`RawBrutalIR`](super::raw::RawBrutalIR)
/// which carries `#[serde(deny_unknown_fields)]`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct BrutalIR {
    /// Upload bandwidth in Mbps.
    pub up: u64,
    /// Download bandwidth in Mbps.
    pub down: u64,
}

impl<'de> Deserialize<'de> for BrutalIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawBrutalIR::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{InboundIR, InboundType, OutboundIR, OutboundType};
    use serde_json::json;

    #[test]
    fn multiplex_options_ir_roundtrip_via_raw_bridge() {
        let mux = MultiplexOptionsIR {
            enabled: true,
            protocol: Some("yamux".to_string()),
            max_connections: Some(8),
            brutal: Some(BrutalIR { up: 100, down: 200 }),
            ..Default::default()
        };
        let json = serde_json::to_value(&mux).unwrap();
        let back: MultiplexOptionsIR = serde_json::from_value(json).unwrap();
        assert!(back.enabled);
        assert_eq!(back.protocol.as_deref(), Some("yamux"));
        assert_eq!(back.max_connections, Some(8));
        let brutal = back.brutal.unwrap();
        assert_eq!(brutal.up, 100);
        assert_eq!(brutal.down, 200);
    }

    #[test]
    fn brutal_ir_rejects_unknown_field_via_raw_bridge() {
        let data = json!({"up": 10, "down": 20, "lateral": 30});
        let result = serde_json::from_value::<BrutalIR>(data);
        assert!(
            result.is_err(),
            "BrutalIR should reject unknown field via Raw bridge"
        );
    }

    #[test]
    fn inbound_ir_preserves_multiplex_fields() {
        let data = json!({
            "ty": "http",
            "listen": "127.0.0.1",
            "port": 8080,
            "multiplex": {
                "enabled": true,
                "protocol": "yamux",
                "max_connections": 4,
                "brutal": {"up": 25, "down": 50}
            }
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Http);
        let mux = ir.multiplex.expect("multiplex should deserialize");
        assert!(mux.enabled);
        assert_eq!(mux.protocol.as_deref(), Some("yamux"));
        assert_eq!(mux.max_connections, Some(4));
        let brutal = mux.brutal.expect("brutal should deserialize");
        assert_eq!(brutal.up, 25);
        assert_eq!(brutal.down, 50);
    }

    #[test]
    fn outbound_ir_preserves_multiplex_fields() {
        let data = json!({
            "ty": "vmess",
            "server": "vmess.example.com",
            "port": 443,
            "uuid": "abcdef00-1234-5678-9abc-def012345678",
            "multiplex": {
                "enabled": true,
                "protocol": "yamux",
                "max_connections": 8,
                "brutal": {"up": 100, "down": 200}
            }
        });
        let ir: OutboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, OutboundType::Vmess);
        let mux = ir.multiplex.expect("multiplex should deserialize");
        assert!(mux.enabled);
        assert_eq!(mux.protocol.as_deref(), Some("yamux"));
        assert_eq!(mux.max_connections, Some(8));
        let brutal = mux.brutal.expect("brutal should deserialize");
        assert_eq!(brutal.up, 100);
        assert_eq!(brutal.down, 200);
    }

    #[test]
    fn wp30ai_pin_multiplex_owner_is_multiplex_rs() {
        let source = include_str!("multiplex.rs");
        for needle in [
            "pub struct MultiplexOptionsIR",
            "pub struct BrutalIR",
            "RawMultiplexOptionsIR::deserialize(deserializer).map(Into::into)",
            "RawBrutalIR::deserialize(deserializer).map(Into::into)",
        ] {
            assert!(
                source.contains(needle),
                "expected `{needle}` to live in ir/multiplex.rs"
            );
        }
    }

    #[test]
    fn wp30ai_pin_mod_rs_only_reexports_multiplex_types() {
        let source = include_str!("mod.rs");
        assert!(
            source.contains("mod multiplex;")
                && source.contains("pub use multiplex::{BrutalIR, MultiplexOptionsIR};"),
            "expected ir/mod.rs to re-export multiplex types"
        );
        for needle in ["pub struct MultiplexOptionsIR", "pub struct BrutalIR"] {
            assert!(
                !source.contains(needle),
                "expected ir/mod.rs to stop owning `{needle}`"
            );
        }
    }
}
