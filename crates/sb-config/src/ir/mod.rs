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
mod outbound;
mod route;
mod service;

pub use dns::{DnsHostIR, DnsIR, DnsRuleIR, DnsServerIR};
pub use endpoint::{EndpointIR, EndpointType, WireGuardPeerIR};
pub use inbound::{
    AnyTlsUserIR, Hysteria2UserIR, HysteriaUserIR, InboundIR, InboundType, ShadowTlsHandshakeIR,
    ShadowTlsUserIR, ShadowsocksUserIR, TrojanUserIR, TuicUserIR, TunOptionsIR, VlessUserIR,
    VmessUserIR,
};
pub use outbound::{HeaderEntry, OutboundIR, OutboundType};
pub use route::{DomainResolveOptionsIR, RouteIR, RuleAction, RuleIR, RuleSetIR};
pub use service::{ServiceIR, ServiceType};

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Deserialize, Default)]
struct DerpStunOptionsObj {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    bind_interface: Option<String>,
    #[serde(default)]
    routing_mark: Option<u32>,
    #[serde(default)]
    reuse_addr: Option<bool>,
    #[serde(default)]
    netns: Option<String>,
}

impl From<DerpStunOptionsObj> for DerpStunOptionsIR {
    fn from(v: DerpStunOptionsObj) -> Self {
        Self {
            enabled: v.enabled,
            listen: v.listen,
            listen_port: v.listen_port,
            bind_interface: v.bind_interface,
            routing_mark: v.routing_mark,
            reuse_addr: v.reuse_addr,
            netns: v.netns,
        }
    }
}

impl<'de> Deserialize<'de> for DerpStunOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Bool(bool),
            Port(u16),
            Obj(DerpStunOptionsObj),
        }

        match Repr::deserialize(deserializer)? {
            Repr::Bool(enabled) => Ok(Self {
                enabled,
                ..Default::default()
            }),
            Repr::Port(port) => Ok(Self {
                enabled: true,
                listen_port: Some(port),
                ..Default::default()
            }),
            Repr::Obj(v) => Ok(v.into()),
        }
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

/// DERP Dial Fields (Go parity: shared/dial.md) used by verify_client_url and mesh_with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

/// DERP verify_client_url options (Go parity: option.DERPVerifyClientURLOptions).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

/// DERP mesh peer outbound TLS options (minimal subset).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

/// DERP mesh peer options (Go parity: option.DERPMeshOptions).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
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

/// Complete configuration intermediate representation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ConfigIR {
    /// Inbound listeners.
    #[serde(default)]
    pub inbounds: Vec<InboundIR>,
    /// Outbound proxies.
    #[serde(default)]
    pub outbounds: Vec<OutboundIR>,
    /// Routing configuration.
    #[serde(default)]
    pub route: RouteIR,
    /// Optional log configuration
    #[serde(default)]
    pub log: Option<LogIR>,
    /// Optional NTP service configuration
    #[serde(default)]
    pub ntp: Option<NtpIR>,
    /// Optional certificate configuration (global trust augmentation)
    #[serde(default)]
    pub certificate: Option<CertificateIR>,
    /// Optional DNS configuration
    #[serde(default)]
    pub dns: Option<DnsIR>,
    /// Endpoint configurations (WireGuard, Tailscale, etc.)
    #[serde(default)]
    pub endpoints: Vec<EndpointIR>,
    /// Service configurations (Resolved, DERP, SSM, etc.)
    #[serde(default)]
    pub services: Vec<ServiceIR>,
    /// Optional experimental configuration blob (schema v2 passthrough).
    ///
    /// This mirrors Go's top-level `experimental` field and allows unknown or
    /// forward-compatible options to be preserved without strong typing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<ExperimentalIR>,
}

pub mod experimental;
pub use experimental::*;

/// Certificate configuration (global)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertificateIR {
    /// Certificate store mode: "system", "mozilla", or "none"
    /// Defaults to "system" (Go parity)
    #[serde(default)]
    pub store: Option<String>,
    /// Additional CA certificate file paths (PEM)
    #[serde(default)]
    pub ca_paths: Vec<String>,
    /// Additional CA certificate PEM blocks (inline)
    #[serde(default)]
    pub ca_pem: Vec<String>,
    /// Directory path to load additional CA certificates from (recursive PEM scan)
    #[serde(default)]
    pub certificate_directory_path: Option<String>,
}

impl ConfigIR {
    /// Check if any routing rule uses negation conditions.
    ///
    /// This is used to determine if the router needs to support negation logic.
    #[must_use]
    pub fn has_any_negation(&self) -> bool {
        self.route.rules.iter().any(|r| {
            !r.not_domain.is_empty()
                || !r.not_geosite.is_empty()
                || !r.not_geoip.is_empty()
                || !r.not_ipcidr.is_empty()
                || !r.not_port.is_empty()
                || !r.not_process_name.is_empty()
                || !r.not_network.is_empty()
                || !r.not_protocol.is_empty()
                || !r.not_alpn.is_empty()
                || !r.not_wifi_ssid.is_empty()
                || !r.not_wifi_bssid.is_empty()
                || !r.not_rule_set.is_empty()
        })
    }

    /// Validate all outbound configurations.
    ///
    /// # Errors
    /// Returns a list of validation errors if any outbound configuration is invalid.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Validate REALITY configuration for all outbounds
        for outbound in &self.outbounds {
            let outbound_name = outbound.name.as_deref().unwrap_or("unnamed");

            if let Err(e) = outbound.validate_reality() {
                errors.push(e);
            }

            // Validate selector/urltest members
            if matches!(outbound.ty, OutboundType::Selector | OutboundType::UrlTest)
                && outbound.members.as_ref().is_none_or(Vec::is_empty)
            {
                errors.push(format!(
                    "outbound '{outbound_name}': selector/urltest requires at least one member"
                ));
            }

            // Validate Shadowsocks configuration
            if outbound.ty == OutboundType::Shadowsocks {
                Self::validate_shadowsocks(outbound, &mut errors);
            }

            // Validate ShadowTLS configuration
            if outbound.ty == OutboundType::Shadowtls {
                Self::validate_shadowtls(outbound, &mut errors);
            }

            // Validate TUIC configuration
            if outbound.ty == OutboundType::Tuic {
                Self::validate_tuic(outbound, &mut errors);
            }

            // Validate transport conflicts (WS/H2/HTTPUpgrade/gRPC are mutually exclusive)
            if let Some(e) = Self::validate_transport_conflicts(outbound) {
                errors.push(format!("outbound '{outbound_name}': {e}"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate Shadowsocks outbound configuration.
    fn validate_shadowsocks(outbound: &OutboundIR, errors: &mut Vec<String>) {
        let name = outbound.name.as_deref().unwrap_or("unnamed");

        if outbound.server.as_ref().is_none_or(|s| s.trim().is_empty()) {
            errors.push(format!("outbound '{name}': shadowsocks.server is required"));
        }
        if outbound.port.is_none() {
            errors.push(format!("outbound '{name}': shadowsocks.port is required"));
        }
        if outbound
            .password
            .as_ref()
            .is_none_or(|p| p.trim().is_empty())
        {
            errors.push(format!(
                "outbound '{name}': shadowsocks.password is required"
            ));
        }

        let method = outbound.method.as_deref().unwrap_or_default();
        let method_ok = matches!(
            method.to_ascii_lowercase().as_str(),
            "aes-256-gcm" | "chacha20-poly1305"
        );
        if !method_ok {
            errors.push(format!(
                "outbound '{name}': shadowsocks.method must be aes-256-gcm or chacha20-poly1305"
            ));
        }
    }

    /// Validate ShadowTLS outbound configuration.
    fn validate_shadowtls(outbound: &OutboundIR, errors: &mut Vec<String>) {
        let name = outbound.name.as_deref().unwrap_or("unnamed");

        if outbound.server.as_ref().is_none_or(|s| s.trim().is_empty()) {
            errors.push(format!("outbound '{name}': shadowtls.server is required"));
        }
        if outbound.port.is_none() {
            errors.push(format!("outbound '{name}': shadowtls.port is required"));
        }
        if outbound
            .password
            .as_ref()
            .is_none_or(|p| p.trim().is_empty())
        {
            errors.push(format!("outbound '{name}': shadowtls.password is required"));
        }

        if let Some(version) = outbound.version {
            if !(1..=3).contains(&version) {
                errors.push(format!(
                    "outbound '{name}': shadowtls.version must be 1, 2, or 3"
                ));
            }
        }
    }

    /// Validate TUIC outbound configuration.
    fn validate_tuic(outbound: &OutboundIR, errors: &mut Vec<String>) {
        let name = outbound.name.as_deref().unwrap_or("unnamed");

        if outbound.server.as_ref().is_none_or(|s| s.trim().is_empty()) {
            errors.push(format!("outbound '{name}': tuic.server is required"));
        }
        if outbound.port.is_none() {
            errors.push(format!("outbound '{name}': tuic.port is required"));
        }

        match outbound.uuid.as_ref() {
            Some(uuid) if !uuid.trim().is_empty() => {
                if uuid::Uuid::parse_str(uuid).is_err() {
                    errors.push(format!(
                        "outbound '{name}': tuic.uuid must be a valid UUID string"
                    ));
                }
            }
            _ => errors.push(format!("outbound '{name}': tuic.uuid is required")),
        }

        if outbound.token.as_ref().is_none_or(|t| t.trim().is_empty()) {
            errors.push(format!("outbound '{name}': tuic.token is required"));
        }
    }

    /// Validate transport conflicts in a single outbound IR.
    ///
    /// The application-layer transports WebSocket (ws), HTTP/2 (h2), HTTP Upgrade (httpupgrade)
    /// and gRPC (grpc) are mutually exclusive. They cannot be enabled at the same time via either
    /// explicit transport chain (e.g. transport: ["ws", "h2"]) or via hint fields
    /// (e.g. simultaneously providing `ws_*` and `h2_*` fields).
    fn validate_transport_conflicts(outbound: &OutboundIR) -> Option<String> {
        // Detect presence from explicit chain
        let mut ws = false;
        let mut h2 = false;
        let mut hup = false;
        let mut grpc = false;

        if let Some(chain) = outbound.transport.as_ref() {
            for t in chain {
                let t = t.to_ascii_lowercase();
                match t.as_str() {
                    "ws" | "websocket" => ws = true,
                    "h2" | "http2" => h2 = true,
                    "httpupgrade" | "http_upgrade" => hup = true,
                    "grpc" => grpc = true,
                    _ => {}
                }
            }
        }

        // Detect presence from hint fields
        ws |= outbound.ws_path.is_some() || outbound.ws_host.is_some();
        h2 |= outbound.h2_path.is_some() || outbound.h2_host.is_some();
        hup |= outbound.http_upgrade_path.is_some() || !outbound.http_upgrade_headers.is_empty();
        grpc |= outbound.grpc_service.is_some()
            || outbound.grpc_method.is_some()
            || outbound.grpc_authority.is_some()
            || !outbound.grpc_metadata.is_empty();

        let count = ws as u8 + h2 as u8 + hup as u8 + grpc as u8;
        if count > 1 {
            let mut kinds = Vec::new();
            if ws {
                kinds.push("ws");
            }
            if h2 {
                kinds.push("h2");
            }
            if hup {
                kinds.push("httpupgrade");
            }
            if grpc {
                kinds.push("grpc");
            }
            return Some(format!(
                "conflicting transports selected: {} (select at most one of ws/h2/httpupgrade/grpc)",
                kinds.join(", ")
            ));
        }

        None
    }
}

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
    fn config_ir_with_endpoints_and_services() {
        let data = json!({
            "inbounds": [],
            "outbounds": [],
            "route": {},
            "endpoints": [
                {
                    "type": "wireguard",
                    "tag": "wg0",
                    "wireguard_private_key": "test-key"
                }
            ],
            "services": [
                {
                    "type": "resolved",
                    "tag": "dns-svc"
                }
            ]
        });
        let config: ConfigIR = serde_json::from_value(data).unwrap();
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.endpoints[0].ty, EndpointType::Wireguard);
        assert_eq!(config.services[0].ty, ServiceType::Resolved);
    }
}

/// Log configuration (IR)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct LogIR {
    /// Log level: error|warn|info|debug|trace
    #[serde(default)]
    pub level: Option<String>,
    /// Include timestamp in logs
    #[serde(default)]
    pub timestamp: Option<bool>,
    /// Optional output format (non-standard extension): json|compact
    #[serde(default)]
    pub format: Option<String>,
    /// Disable logging entirely (Go parity: log.disabled)
    /// 完全禁用日志（Go 对齐：log.disabled）
    #[serde(default)]
    pub disabled: Option<bool>,
    /// Output destination: stdout/stderr/path (Go parity: log.output)
    /// 输出目标：stdout/stderr/路径（Go 对齐：log.output）
    #[serde(default)]
    pub output: Option<String>,
}

/// NTP service configuration (IR)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct NtpIR {
    /// Enable NTP service
    #[serde(default)]
    pub enabled: bool,
    /// NTP server hostname (without port) or host:port
    #[serde(default)]
    pub server: Option<String>,
    /// NTP server port (e.g., 123)
    #[serde(default)]
    pub server_port: Option<u16>,
    /// Sync interval in milliseconds
    #[serde(default)]
    pub interval_ms: Option<u64>,
    /// Timeout in milliseconds (optional)
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

#[cfg(test)]
mod tests_reality {
    use super::*;
    use serde_json::json;
    #[test]
    fn negation_detect() {
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            not_geoip: vec!["CN".into()],
            ..Default::default()
        });
        assert!(cfg.has_any_negation());
    }

    #[test]
    fn test_config_ir_validate_reality() {
        let mut config = ConfigIR::default();

        // Add valid outbound
        config.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("valid".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        });

        assert!(config.validate().is_ok());

        // Add invalid outbound
        config.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("invalid".to_string()),
            reality_enabled: Some(true),
            reality_public_key: None, // Missing required field
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        });

        assert!(config.validate().is_err());
        let errors = config.validate().unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("public_key is required"));
    }

    #[test]
    fn tuic_validation_reports_missing_fields() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Tuic,
            name: Some("tuic-out".to_string()),
            server: None,
            port: None,
            uuid: Some("not-a-uuid".to_string()),
            token: None,
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("tuic.server is required")));
        assert!(errors.iter().any(|e| e.contains("tuic.port is required")));
        assert!(errors
            .iter()
            .any(|e| e.contains("tuic.uuid must be a valid UUID string")));
        assert!(errors.iter().any(|e| e.contains("tuic.token is required")));
    }

    #[test]
    fn tuic_validation_accepts_complete_configuration() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Tuic,
            name: Some("tuic-out".to_string()),
            server: Some("example.com".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            token: Some("secret-token".to_string()),
            ..Default::default()
        });

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn shadowtls_validation_reports_missing_password_and_bad_version() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Shadowtls,
            name: Some("shadowtls-out".to_string()),
            server: Some("example.com".to_string()),
            port: Some(443),
            version: Some(9),
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("shadowtls.password is required")));
        assert!(errors
            .iter()
            .any(|e| e.contains("shadowtls.version must be 1, 2, or 3")));
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

    #[test]
    fn transport_conflict_detects_ws_and_h2_hints() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Vmess,
            name: Some("vmess-out".to_string()),
            ws_path: Some("/ws".to_string()),
            h2_host: Some("example.com".to_string()),
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("conflicting transports selected")));
    }

    #[test]
    fn transport_conflict_detects_chain_multiple() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("vless-out".to_string()),
            transport: Some(vec!["tls".into(), "ws".into(), "grpc".into()]),
            ..Default::default()
        });

        let result = cfg.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| e.contains("conflicting transports selected: ws, grpc")));
    }

    #[test]
    fn transport_single_ok_ws() {
        let mut cfg = ConfigIR::default();
        cfg.outbounds.push(OutboundIR {
            ty: OutboundType::Vless,
            name: Some("vless-ws".to_string()),
            ws_path: Some("/".to_string()),
            tls_sni: Some("example.com".to_string()),
            ..Default::default()
        });
        assert!(cfg.validate().is_ok());
    }
}
