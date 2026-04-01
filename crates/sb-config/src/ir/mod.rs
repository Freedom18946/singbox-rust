//! Strongly-typed intermediate representation (IR) for config and routing rules.
//! 配置和路由规则的强类型中间表示 (IR)。
//!
//! Both V1 and V2 formats are converted to IR, which is then consumed by routing
//! and adapter layers. Field naming aligns with Go sing-box; new fields extend
//! without changing default behavior.
//! V1 和 V2 格式都会被转换为 IR，然后由路由和适配器层消费。
//! 字段命名与 Go sing-box 保持一致；新字段的扩展不会改变默认行为。

use serde::{Deserialize, Serialize};

pub mod diff;
mod dns;
mod endpoint;
mod inbound;
pub(crate) mod minimize;
pub(crate) mod normalize;
mod outbound;
pub(crate) mod planned;
mod raw;
mod route;
mod service;
mod validated;

pub use dns::{DnsHostIR, DnsIR, DnsRuleIR, DnsServerIR};
pub use endpoint::{EndpointIR, EndpointType, WireGuardPeerIR};
pub use inbound::{
    AnyTlsUserIR, Hysteria2UserIR, HysteriaUserIR, InboundIR, InboundType, ShadowTlsHandshakeIR,
    ShadowTlsUserIR, ShadowsocksUserIR, TrojanUserIR, TuicUserIR, TunOptionsIR, VlessUserIR,
    VmessUserIR,
};
pub use outbound::{HeaderEntry, OutboundIR, OutboundType};
pub use raw::{
    RawAnyTlsUserIR, RawBrutalIR, RawCertificateIR, RawConfigRoot, RawCredentials,
    RawDerpDialOptionsIR, RawDerpDomainResolverIR, RawDerpMeshPeerIR, RawDerpOutboundTlsOptionsIR,
    RawDerpStunOptionsIR, RawDerpStunOptionsObj, RawDerpVerifyClientUrlIR, RawDnsHostIR, RawDnsIR,
    RawDnsRuleIR, RawDnsServerIR, RawDomainResolveOptionsIR, RawEndpointIR, RawHeaderEntry,
    RawHysteria2UserIR, RawHysteriaUserIR, RawInboundIR, RawInboundTlsOptionsIR, RawLogIR,
    RawMasqueradeFileIR, RawMasqueradeIR, RawMasqueradeProxyIR, RawMasqueradeStringIR,
    RawMultiplexOptionsIR, RawNtpIR, RawOutboundIR, RawRouteIR, RawRuleIR, RawRuleSetIR,
    RawServiceIR, RawShadowTlsHandshakeIR, RawShadowTlsUserIR, RawShadowsocksUserIR,
    RawTrojanUserIR, RawTuicUserIR, RawTunOptionsIR, RawVlessUserIR, RawVmessUserIR,
    RawWireGuardPeerIR,
};
pub use route::{DomainResolveOptionsIR, RouteIR, RuleAction, RuleIR, RuleSetIR};
pub use service::{
    DerpDialOptionsIR, DerpDomainResolverIR, DerpMeshPeerIR, DerpOutboundTlsOptionsIR,
    DerpStunOptionsIR, DerpVerifyClientUrlIR, InboundTlsOptionsIR, ServiceIR, ServiceType,
};
pub use validated::{CertificateIR, ConfigIR, LogIR, NtpIR};

/// Authentication credentials with optional environment variable support.
/// 带有可选环境变量支持的认证凭据。
///
/// Deserialization goes through [`RawCredentials`](raw::RawCredentials)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30i).
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Credentials {
    /// Username (literal value).
    #[serde(default)]
    pub username: Option<String>,
    /// Password (literal value).
    #[serde(default)]
    pub password: Option<String>,
    /// Read username from this environment variable (takes precedence over `username`).
    #[serde(default)]
    pub username_env: Option<String>,
    /// Read password from this environment variable (takes precedence over `password`).
    #[serde(default)]
    pub password_env: Option<String>,
}

impl<'de> Deserialize<'de> for Credentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        raw::RawCredentials::deserialize(deserializer).map(Into::into)
    }
}

/// Multiplex options for inbound connections (yamux-based stream multiplexing).
///
/// Deserialization goes through [`RawMultiplexOptionsIR`](raw::RawMultiplexOptionsIR)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30i).
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
        raw::RawMultiplexOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// Brutal congestion control configuration.
///
/// Deserialization goes through [`RawBrutalIR`](raw::RawBrutalIR)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30i).
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
        raw::RawBrutalIR::deserialize(deserializer).map(Into::into)
    }
}

/// Hysteria2 Masquerade configuration.
///
/// Deserialization goes through [`RawMasqueradeIR`](raw::RawMasqueradeIR)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30j).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MasqueradeIR {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub file: Option<MasqueradeFileIR>,
    #[serde(default)]
    pub proxy: Option<MasqueradeProxyIR>,
    #[serde(default)]
    pub string: Option<MasqueradeStringIR>,
}

impl<'de> Deserialize<'de> for MasqueradeIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        raw::RawMasqueradeIR::deserialize(deserializer).map(Into::into)
    }
}

/// Masquerade file serving configuration.
///
/// Deserialization goes through [`RawMasqueradeFileIR`](raw::RawMasqueradeFileIR)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30j).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MasqueradeFileIR {
    pub directory: String,
}

impl<'de> Deserialize<'de> for MasqueradeFileIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        raw::RawMasqueradeFileIR::deserialize(deserializer).map(Into::into)
    }
}

/// Masquerade reverse proxy configuration.
///
/// Deserialization goes through [`RawMasqueradeProxyIR`](raw::RawMasqueradeProxyIR)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30j).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MasqueradeProxyIR {
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
}

impl<'de> Deserialize<'de> for MasqueradeProxyIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        raw::RawMasqueradeProxyIR::deserialize(deserializer).map(Into::into)
    }
}

/// Masquerade static string response configuration.
///
/// Deserialization goes through [`RawMasqueradeStringIR`](raw::RawMasqueradeStringIR)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30j).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MasqueradeStringIR {
    pub content: String,
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub status_code: u16,
}

impl<'de> Deserialize<'de> for MasqueradeStringIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        raw::RawMasqueradeStringIR::deserialize(deserializer).map(Into::into)
    }
}

/// Listable value wrapper (Go parity: `badoption.Listable[T]`).
///
/// Accepts either `T` or `[T]` in JSON/YAML; deserializes to `Vec<T>`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listable<T> {
    pub items: Vec<T>,
}

impl<T> Listable<T> {
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.items
    }
}

impl<'de, T> Deserialize<'de> for Listable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr<T> {
            One(T),
            Many(Vec<T>),
        }

        let items = match Repr::deserialize(deserializer)? {
            Repr::One(v) => vec![v],
            Repr::Many(v) => v,
        };
        Ok(Self { items })
    }
}

impl<T> Serialize for Listable<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.items.serialize(serializer)
    }
}

/// String-or-object wrapper (Go parity: many options accept `"x"` as shorthand for `{...}`).
///
/// Accepts either a string or an object; converts string via `T: From<String>`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StringOrObj<T>(pub T);

impl<T> From<T> for StringOrObj<T> {
    fn from(v: T) -> Self {
        Self(v)
    }
}

impl<T> StringOrObj<T> {
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<'de, T> Deserialize<'de> for StringOrObj<T>
where
    T: Deserialize<'de> + From<String>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr<T> {
            Str(String),
            Obj(T),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Str(s) => Ok(Self(T::from(s))),
            Repr::Obj(v) => Ok(Self(v)),
        }
    }
}

pub mod experimental;
pub use experimental::*;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inbound_type_serialization() {
        let data = json!({
            "ty": "naive",
            "listen": "127.0.0.1",
            "port": 1080usize
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Naive);

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("ty").unwrap(), "naive");
    }

    #[test]
    fn inbound_ir_deserializes_shadowtls_runtime_fields() {
        let inbound: InboundIR = serde_json::from_value(json!({
            "ty": "shadowtls",
            "listen": "127.0.0.1",
            "port": 443,
            "detour": "ss-detour",
            "version": 3,
            "users_shadowtls": [
                { "name": "alice", "password": "pw1" }
            ],
            "shadowtls_handshake": {
                "server": "handshake.example.com",
                "server_port": 443
            },
            "shadowtls_handshake_for_server_name": {
                "cdn.example.com": {
                    "server": "cdn-handshake.example.com",
                    "server_port": 8443
                }
            },
            "shadowtls_strict_mode": true,
            "shadowtls_wildcard_sni": "authed"
        }))
        .unwrap();

        assert_eq!(inbound.detour.as_deref(), Some("ss-detour"));
        assert_eq!(inbound.version, Some(3));
        assert_eq!(
            inbound
                .users_shadowtls
                .as_ref()
                .expect("shadowtls users should deserialize")[0]
                .name,
            "alice"
        );
        assert_eq!(
            inbound
                .shadowtls_handshake
                .as_ref()
                .expect("handshake should deserialize")
                .server,
            "handshake.example.com"
        );
        assert_eq!(
            inbound
                .shadowtls_handshake_for_server_name
                .as_ref()
                .and_then(|m| m.get("cdn.example.com"))
                .expect("handshake override should deserialize")
                .server_port,
            8443
        );
        assert_eq!(inbound.shadowtls_strict_mode, Some(true));
        assert_eq!(inbound.shadowtls_wildcard_sni.as_deref(), Some("authed"));
    }
}
