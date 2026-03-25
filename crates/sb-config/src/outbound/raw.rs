//! Raw (serde-facing) outbound configuration types.
//!
//! These types handle deserialization with strict unknown-field rejection
//! (`deny_unknown_fields`). Validated domain types in the parent module are
//! constructed from these via `From<Raw*>` conversions.
//!
//! Design invariant: `serde::Deserialize` lands here, NOT on the domain types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Top-level enum
// ---------------------------------------------------------------------------

/// Raw outbound proxy configuration (serde boundary).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub(super) enum RawOutbound {
    Direct(RawDirectConfig),
    Http(RawHttpProxyConfig),
    Socks5(RawSocks5Config),
    Socks4(RawSocks4Config),
    Vmess(RawVmessConfig),
    Vless(RawVlessConfig),
    Tuic(RawTuicConfig),
    Selector(RawSelectorConfig),
    #[serde(rename = "urltest")]
    UrlTest(RawUrlTestConfig),
}

// ---------------------------------------------------------------------------
// Per-protocol config structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawDirectConfig {
    #[serde(default)]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHttpProxyConfig {
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    #[serde(default)]
    pub tls: Option<RawTlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSocks5Config {
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    #[serde(default)]
    pub tls: Option<RawTlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSocks4Config {
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawVmessConfig {
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    pub uuid: String,
    #[serde(default = "super::default_vmess_security")]
    pub security: String,
    #[serde(default)]
    pub alter_id: u16,
    #[serde(default)]
    pub global_padding: bool,
    #[serde(default)]
    pub authenticated_length: bool,
    #[serde(default)]
    pub network: Option<Vec<String>>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    #[serde(default)]
    pub tls: Option<RawTlsConfig>,
    #[serde(default)]
    pub transport: Option<RawTransportConfig>,
    #[serde(default)]
    pub multiplex: Option<RawMultiplexConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawVlessConfig {
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    pub uuid: String,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default = "super::default_vless_network")]
    pub network: String,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    #[serde(default)]
    pub tls: Option<RawTlsConfig>,
    #[serde(default)]
    pub transport: Option<RawTransportConfig>,
    #[serde(default)]
    pub multiplex: Option<RawMultiplexConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTuicConfig {
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    pub uuid: String,
    pub password: String,
    #[serde(default = "super::default_tuic_congestion_control")]
    pub congestion_control: String,
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    #[serde(default)]
    pub udp_over_stream: bool,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default = "super::default_tuic_heartbeat")]
    pub heartbeat: u64,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    #[serde(default)]
    pub auth_timeout_sec: Option<u64>,
    #[serde(default)]
    pub network: Option<Vec<String>>,
    #[serde(default)]
    pub tls: Option<RawTlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawSelectorConfig {
    #[serde(default)]
    pub tag: Option<String>,
    pub outbounds: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawUrlTestConfig {
    #[serde(default)]
    pub tag: Option<String>,
    pub outbounds: Vec<String>,
    #[serde(default = "super::default_url_test_url")]
    pub url: String,
    #[serde(default = "super::default_url_test_interval")]
    pub interval: u64,
    #[serde(default = "super::default_url_test_timeout")]
    pub timeout: u64,
    #[serde(default = "super::default_url_test_tolerance")]
    pub tolerance: u64,
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

// ---------------------------------------------------------------------------
// Shared / nested types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawTlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub reality: Option<RawRealityConfig>,
    #[serde(default)]
    pub ech: Option<RawEchConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawRealityConfig {
    #[serde(default)]
    pub enabled: bool,
    pub public_key: String,
    #[serde(default)]
    pub short_id: Option<String>,
    pub server_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawEchConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub config: Option<String>,
    #[serde(default)]
    pub pq_signature_schemes_enabled: bool,
    #[serde(default)]
    pub dynamic_record_sizing_disabled: Option<bool>,
}

/// Raw transport configuration. Uses newtype variants so each variant struct
/// can carry `deny_unknown_fields`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub(super) enum RawTransportConfig {
    Tcp,
    #[serde(rename = "ws")]
    WebSocket(RawWebSocketTransport),
    #[serde(rename = "grpc")]
    Grpc(RawGrpcTransport),
    #[serde(rename = "httpupgrade")]
    HttpUpgrade(RawHttpUpgradeTransport),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawWebSocketTransport {
    #[serde(default = "super::default_ws_path")]
    pub path: String,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub max_message_size: Option<usize>,
    #[serde(default)]
    pub max_frame_size: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawGrpcTransport {
    #[serde(default = "super::default_grpc_service")]
    pub service_name: String,
    #[serde(default = "super::default_grpc_method")]
    pub method_name: String,
    #[serde(default)]
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawHttpUpgradeTransport {
    #[serde(default = "super::default_httpupgrade_path")]
    pub path: String,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawMultiplexConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "super::default_multiplex_protocol")]
    pub protocol: String,
    #[serde(default = "super::default_multiplex_max_connections")]
    pub max_connections: usize,
    #[serde(default = "super::default_multiplex_min_streams")]
    pub min_streams: usize,
    #[serde(default = "super::default_multiplex_max_streams")]
    pub max_streams: usize,
    #[serde(default)]
    pub padding: bool,
    #[serde(default)]
    pub brutal: Option<RawBrutalConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawBrutalConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub up_mbps: u32,
    #[serde(default)]
    pub down_mbps: u32,
}
