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
mod normalize;
mod outbound;
mod planned;
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
    RawCertificateIR, RawConfigRoot, RawDerpDialOptionsIR, RawDerpDomainResolverIR,
    RawDerpMeshPeerIR, RawDerpOutboundTlsOptionsIR, RawDerpStunOptionsIR, RawDerpStunOptionsObj,
    RawDerpVerifyClientUrlIR, RawDnsHostIR, RawDnsIR, RawDnsRuleIR, RawDnsServerIR,
    RawDomainResolveOptionsIR, RawEndpointIR, RawInboundTlsOptionsIR, RawLogIR, RawNtpIR,
    RawRouteIR, RawRuleIR, RawRuleSetIR, RawServiceIR, RawWireGuardPeerIR,
};
pub use route::{DomainResolveOptionsIR, RouteIR, RuleAction, RuleIR, RuleSetIR};
pub use service::{ServiceIR, ServiceType};
pub use validated::{CertificateIR, ConfigIR, LogIR, NtpIR};

/// Authentication credentials with optional environment variable support.
/// 带有可选环境变量支持的认证凭据。
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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

/// Multiplex options for inbound connections (yamux-based stream multiplexing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

/// Brutal congestion control configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BrutalIR {
    /// Upload bandwidth in Mbps.
    pub up: u64,
    /// Download bandwidth in Mbps.
    pub down: u64,
}

/// Hysteria2 Masquerade configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasqueradeFileIR {
    pub directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasqueradeProxyIR {
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MasqueradeStringIR {
    pub content: String,
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>, // simplified map
    #[serde(default)]
    pub status_code: u16,
}

// ────────────────────────────────────────────────────────────────────────────
// Service-related shared types (kept in mod.rs; used by service submodule via super::)
// ────────────────────────────────────────────────────────────────────────────

/// Inbound TLS options (Go parity: `option.InboundTLSOptions`).
/// 入站 TLS 选项（对齐 Go `option.InboundTLSOptions`）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct InboundTlsOptionsIR {
    /// Enable TLS (Go: `enabled`).
    /// 启用 TLS（Go: `enabled`）。
    #[serde(default)]
    pub enabled: bool,
    /// Server name (SNI) used for verification (client-side).
    /// 用于校验的服务器名 (SNI)（客户端）。
    #[serde(default)]
    pub server_name: Option<String>,
    /// Accept any certificate (client-side).
    /// 接受任意证书（客户端）。
    #[serde(default)]
    pub insecure: Option<bool>,
    /// ALPN protocol list.
    /// ALPN 协议列表。
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    /// Minimum TLS version (e.g. "1.2").
    /// 最小 TLS 版本（例如 "1.2"）。
    #[serde(default)]
    pub min_version: Option<String>,
    /// Maximum TLS version (e.g. "1.3").
    /// 最大 TLS 版本（例如 "1.3"）。
    #[serde(default)]
    pub max_version: Option<String>,
    /// TLS 1.0–1.2 cipher suites list.
    /// TLS 1.0–1.2 密码套件列表。
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,
    /// Inline server certificate line array (PEM).
    /// 内联服务端证书行数组（PEM）。
    #[serde(default)]
    pub certificate: Option<Vec<String>>,
    /// Server certificate path (PEM).
    /// 服务端证书路径（PEM）。
    #[serde(default)]
    pub certificate_path: Option<String>,
    /// Inline server private key line array (PEM).
    /// 内联服务端私钥行数组（PEM）。
    #[serde(default)]
    pub key: Option<Vec<String>>,
    /// Server private key path (PEM).
    /// 服务端私钥路径（PEM）。
    #[serde(default)]
    pub key_path: Option<String>,
    // ACME/ECH/Reality fields are intentionally omitted for now; they will be
    // added when the corresponding runtime integrations land.
}

impl<'de> Deserialize<'de> for InboundTlsOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawInboundTlsOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP STUN listen options (Go parity: `option.DERPSTUNListenOptions`).
/// DERP STUN 监听选项（对齐 Go `option.DERPSTUNListenOptions`）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpStunOptionsIR {
    /// Enable STUN server.
    /// 启用 STUN 服务。
    #[serde(default)]
    pub enabled: bool,
    /// Listen address.
    /// 监听地址。
    #[serde(default)]
    pub listen: Option<String>,
    /// Listen port.
    /// 监听端口。
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Bind interface (Linux).
    /// 绑定网卡（Linux）。
    #[serde(default)]
    pub bind_interface: Option<String>,
    /// Routing mark (Linux).
    /// 路由标记（Linux）。
    #[serde(default)]
    pub routing_mark: Option<u32>,
    /// Reuse address.
    /// 复用地址。
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    /// Network namespace name/path (Linux).
    /// 网络命名空间名称/路径（Linux）。
    #[serde(default)]
    pub netns: Option<String>,
}

impl<'de> Deserialize<'de> for DerpStunOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpStunOptionsIR::deserialize(deserializer).map(Into::into)
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

/// DERP Dial domain_resolver options (subset; Go parity: Dial Fields `domain_resolver`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpDomainResolverIR {
    /// DNS server tag.
    #[serde(default)]
    pub server: Option<String>,
    /// Strategy hint (parsed but not necessarily honored in runtime).
    #[serde(default)]
    pub strategy: Option<String>,
    /// Forward-compatible extra fields.
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl From<String> for DerpDomainResolverIR {
    fn from(s: String) -> Self {
        Self {
            server: Some(s),
            ..Default::default()
        }
    }
}

impl<'de> Deserialize<'de> for DerpDomainResolverIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpDomainResolverIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP Dial Fields (Go parity: shared/dial.md) used by verify_client_url and mesh_with.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpDialOptionsIR {
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<String>,
    #[serde(default)]
    pub inet6_bind_address: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub netns: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_resolver: Option<StringOrObj<DerpDomainResolverIR>>,
    /// Forward-compatible extra fields (network_strategy, etc.).
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for DerpDialOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpDialOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP verify_client_url options (Go parity: option.DERPVerifyClientURLOptions).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpVerifyClientUrlIR {
    #[serde(default)]
    pub url: String,
    #[serde(default, flatten)]
    pub dial: DerpDialOptionsIR,
}

impl From<String> for DerpVerifyClientUrlIR {
    fn from(s: String) -> Self {
        Self {
            url: s,
            ..Default::default()
        }
    }
}

impl<'de> Deserialize<'de> for DerpVerifyClientUrlIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpVerifyClientUrlIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP mesh peer outbound TLS options (minimal subset).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpOutboundTlsOptionsIR {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: Option<bool>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub ca_paths: Vec<String>,
    #[serde(default)]
    pub ca_pem: Vec<String>,
}

impl<'de> Deserialize<'de> for DerpOutboundTlsOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpOutboundTlsOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP mesh peer options (Go parity: option.DERPMeshOptions).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpMeshPeerIR {
    /// DERP server address (host or ip).
    #[serde(default)]
    pub server: String,
    /// DERP server port.
    #[serde(default)]
    pub server_port: Option<u16>,
    /// Optional hostname override for SNI/Host.
    #[serde(default)]
    pub host: Option<String>,
    /// Optional per-peer TLS options.
    #[serde(default)]
    pub tls: Option<DerpOutboundTlsOptionsIR>,
    /// Dial Fields.
    #[serde(default, flatten)]
    pub dial: DerpDialOptionsIR,
}

impl From<String> for DerpMeshPeerIR {
    fn from(s: String) -> Self {
        // Parse `host:port` shorthand when possible; keep raw as server otherwise.
        let mut out = Self {
            server: s.clone(),
            ..Default::default()
        };
        let raw = s.trim();
        if raw.is_empty() {
            return out;
        }
        // Support `[v6]:port` and `host:port`.
        if let Some(rest) = raw.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                let host = &rest[..end];
                let tail = &rest[end + 1..];
                if let Some(port_str) = tail.strip_prefix(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        out.server = host.to_string();
                        out.server_port = Some(port);
                    }
                }
                return out;
            }
        }
        if let Some((host, port_str)) = raw.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if !host.is_empty() {
                    out.server = host.to_string();
                    out.server_port = Some(port);
                }
            }
        }
        out
    }
}

impl<'de> Deserialize<'de> for DerpMeshPeerIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpMeshPeerIR::deserialize(deserializer).map(Into::into)
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
