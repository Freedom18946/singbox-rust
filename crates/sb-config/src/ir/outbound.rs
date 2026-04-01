//! Outbound IR types (proxy protocols, transport, TLS, DNS outbound).
//!
//! ## Deserialization (WP-30i)
//!
//! `OutboundIR` and `HeaderEntry` no longer derive `Deserialize` directly.
//! Each deserializes via its corresponding Raw bridge (`RawOutboundIR`,
//! `RawHeaderEntry`) which carries `#[serde(deny_unknown_fields)]`, so
//! unknown outbound nested fields are rejected at parse time.
//!
//! `OutboundType` is intentionally NOT Raw-ified — it stays as the validated
//! enum with lowercase serde and `ty_str()` unchanged.
//!
//! `Credentials` plus the multiplex helpers in `super::multiplex` are also
//! bridged through Raw because they are direct outbound helpers.

use serde::{Deserialize, Serialize};

use super::multiplex::MultiplexOptionsIR;
use super::raw::{RawHeaderEntry, RawOutboundIR};
use super::Credentials;

/// Outbound proxy type.
/// 出站代理类型。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutboundType {
    /// Direct connection (no proxy).
    /// 直接连接（无代理）。
    #[default]
    Direct,
    /// HTTP proxy.
    /// HTTP 代理。
    Http,
    /// SOCKS5 proxy.
    /// SOCKS5 代理。
    Socks,
    /// Block connection.
    /// 阻断连接。
    Block,
    /// Manual selector (user-selected proxy).
    /// 手动选择器（用户选择的代理）。
    Selector,
    /// Shadowsocks proxy.
    /// Shadowsocks 代理。
    Shadowsocks,
    /// ShadowTLS proxy.
    /// ShadowTLS 代理。
    Shadowtls,
    /// Automatic selector based on URL test latency.
    /// 基于 URL 测试延迟的自动选择器。
    UrlTest,
    /// Hysteria2 protocol.
    /// Hysteria2 协议。
    Hysteria2,
    /// TUIC protocol.
    /// TUIC 协议。
    Tuic,
    /// VLESS protocol.
    /// VLESS 协议。
    Vless,
    /// VMess protocol.
    /// VMess 协议。
    Vmess,
    /// Trojan protocol.
    /// Trojan 协议。
    Trojan,
    /// SSH tunnel.
    /// SSH 隧道。
    Ssh,
    /// DNS outbound (feature-gated).
    /// DNS 出站（特性开关）。
    Dns,
    /// Tor outbound.
    /// Tor 出站。
    Tor,
    /// AnyTLS/mtls outbound.
    /// AnyTLS/mtls 出站。
    Anytls,
    /// Hysteria v1 outbound.
    /// Hysteria v1 出站。
    Hysteria,
    /// WireGuard outbound.
    /// WireGuard 出站。
    Wireguard,
    /// Tailscale outbound (Rust-only, feature-gated).
    /// Tailscale 出站（Rust 扩展，特性开关）。
    Tailscale,
    /// ShadowsocksR outbound.
    /// ShadowsocksR 出站。
    ShadowsocksR,
}

impl OutboundType {
    /// Return the lowercase string name used in config/registry.
    #[must_use]
    pub fn ty_str(&self) -> &'static str {
        match self {
            OutboundType::Direct => "direct",
            OutboundType::Http => "http",
            OutboundType::Socks => "socks",
            OutboundType::Block => "block",
            OutboundType::Selector => "selector",
            OutboundType::Shadowsocks => "shadowsocks",
            OutboundType::Shadowtls => "shadowtls",
            OutboundType::UrlTest => "urltest",
            OutboundType::Hysteria2 => "hysteria2",
            OutboundType::Tuic => "tuic",
            OutboundType::Vless => "vless",
            OutboundType::Vmess => "vmess",
            OutboundType::Trojan => "trojan",
            OutboundType::Ssh => "ssh",
            OutboundType::Dns => "dns",
            OutboundType::Tor => "tor",
            OutboundType::Anytls => "anytls",
            OutboundType::Hysteria => "hysteria",
            OutboundType::Wireguard => "wireguard",
            OutboundType::Tailscale => "tailscale",
            OutboundType::ShadowsocksR => "shadowsocksr",
        }
    }
}

/// Outbound proxy configuration.
/// 出站代理配置。
///
/// Supports multiple protocols (HTTP, SOCKS, Shadowsocks, VLESS, etc.)
/// with protocol-specific fields marked as optional.
/// 支持多种协议（HTTP, SOCKS, Shadowsocks, VLESS 等），
/// 协议特定字段标记为可选。
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct OutboundIR {
    pub ty: OutboundType,
    /// Server address (IP or hostname).
    /// 服务器地址（IP 或主机名）。
    #[serde(default)]
    pub server: Option<String>,
    /// Server port.
    /// 服务器端口。
    #[serde(default)]
    pub port: Option<u16>,
    /// UDP mode: `"passthrough"` or `"socks5-upstream"`.
    /// UDP 模式：`"passthrough"` 或 `"socks5-upstream"`。
    #[serde(default)]
    pub udp: Option<String>,
    /// Named outbound (for selector/router references).
    /// 命名出站（用于选择器/路由器引用）。
    #[serde(default)]
    pub name: Option<String>,
    /// Member outbound names (for selector/urltest).
    /// 成员出站名称（用于选择器/urltest）。
    #[serde(default)]
    pub members: Option<Vec<String>>,
    /// Default member name for selector-like outbounds.
    /// 选择器类出站的默认成员名称。
    #[serde(default)]
    pub default_member: Option<String>,
    /// Method identifier (e.g., Shadowsocks cipher).
    /// 方法标识符（例如 Shadowsocks 加密）。
    #[serde(default)]
    pub method: Option<String>,
    /// Authentication credentials for upstream proxies (SOCKS/HTTP).
    /// 上游代理（SOCKS/HTTP）的认证凭据。
    #[serde(default)]
    pub credentials: Option<Credentials>,
    /// Optional outbound detour tag (Go parity: shared Dial Fields `detour`).
    /// 可选出站 detour 标签（Go 对齐：共享 Dial Fields `detour`）。
    #[serde(default)]
    pub detour: Option<String>,
    /// VLESS-specific fields
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    /// VLESS encryption parameter (e.g., "none").
    /// VLESS 加密参数（例如 "none"）。
    #[serde(default)]
    pub encryption: Option<String>,
    // Dialer options
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
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_strategy: Option<String>,
    /// Multiplex options
    #[serde(default)]
    pub multiplex: Option<MultiplexOptionsIR>,

    // Multiplex (yamux) options
    /// Maximum concurrent streams for multiplex
    /// 多路复用最大并发流数
    #[serde(default)]
    pub mux_max_streams: Option<usize>,
    /// Multiplex window size for flow control (bytes)
    /// 多路复用流量控制窗口大小（字节）
    #[serde(default)]
    pub mux_window_size: Option<u32>,
    /// Enable multiplex padding for traffic analysis resistance
    /// 启用多路复用填充以抵抗流量分析
    #[serde(default)]
    pub mux_padding: Option<bool>,
    /// Multiplex connection reuse timeout (seconds)
    /// 多路复用连接复用超时（秒）
    #[serde(default)]
    pub mux_reuse_timeout: Option<u64>,

    // VMess-specific fields
    /// VMess security/cipher (e.g., "aes-128-gcm", "chacha20-poly1305", "auto").
    /// VMess 安全/加密（例如 "aes-128-gcm", "chacha20-poly1305", "auto"）。
    #[serde(default)]
    pub security: Option<String>,
    /// VMess alterId (legacy, usually 0).
    /// VMess alterId（旧版，通常为 0）。
    #[serde(default)]
    pub alter_id: Option<u8>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    /// Transport nesting (e.g., ["tls","ws"]) for V2Ray-style transports
    /// 传输层嵌套（例如 ["tls","ws"]）用于 V2Ray 风格的传输
    #[serde(default)]
    pub transport: Option<Vec<String>>,
    /// Protocol-specific congestion control (TUIC) or flow (VLESS)
    /// 协议特定的拥塞控制 (TUIC) 或流控 (VLESS)
    #[serde(default)]
    pub congestion_control: Option<String>,
    /// TUIC authentication token
    /// TUIC 认证令牌
    #[serde(default)]
    pub token: Option<String>,
    /// Optional WebSocket path and Host header override
    /// 可选的 WebSocket 路径和 Host 头覆盖
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub ws_host: Option<String>,
    /// Optional HTTP/2 path and Host/authority override
    /// 可选的 HTTP/2 路径和 Host/authority 覆盖
    #[serde(default)]
    pub h2_path: Option<String>,
    #[serde(default)]
    pub h2_host: Option<String>,
    /// Optional gRPC service name
    /// 可选的 gRPC 服务名称
    #[serde(default)]
    pub grpc_service: Option<String>,
    /// Optional gRPC method name
    /// 可选的 gRPC 方法名称
    #[serde(default)]
    pub grpc_method: Option<String>,
    /// Optional gRPC authority (host override)
    /// 可选的 gRPC authority（主机覆盖）
    #[serde(default)]
    pub grpc_authority: Option<String>,
    /// Additional gRPC metadata headers
    /// 额外的 gRPC 元数据头
    #[serde(default)]
    pub grpc_metadata: Vec<HeaderEntry>,
    /// Optional HTTP Upgrade path
    /// 可选的 HTTP Upgrade 路径
    #[serde(default)]
    pub http_upgrade_path: Option<String>,
    /// Additional HTTP Upgrade headers
    /// 额外的 HTTP Upgrade 头
    #[serde(default)]
    pub http_upgrade_headers: Vec<HeaderEntry>,
    /// Optional TLS SNI and ALPN list
    /// 可选的 TLS SNI 和 ALPN 列表
    #[serde(default)]
    pub tls_sni: Option<String>,
    /// TLS ALPN list (Vec). Previously CSV string; standardized here.
    /// TLS ALPN 列表 (Vec)。以前是 CSV 字符串；在此标准化。
    #[serde(default)]
    pub tls_alpn: Option<Vec<String>>,
    /// Optional DNS transport override for new dns outbound
    /// 新 DNS 出站的可选 DNS 传输覆盖
    #[serde(default)]
    pub dns_transport: Option<String>,
    /// Optional TLS server name for DNS over TLS/DoQ
    /// DNS over TLS/DoQ 的可选 TLS 服务器名称
    #[serde(default)]
    pub dns_tls_server_name: Option<String>,
    /// DNS data timeout (ms)
    /// DNS 数据超时 (ms)
    #[serde(default)]
    pub dns_timeout_ms: Option<u64>,
    /// Per-query timeout (ms)
    /// 单次查询超时 (ms)
    #[serde(default)]
    pub dns_query_timeout_ms: Option<u64>,
    /// Enable EDNS0 for DNS outbound
    /// 为 DNS 出站启用 EDNS0
    #[serde(default)]
    pub dns_enable_edns0: Option<bool>,
    /// EDNS0 buffer size
    /// EDNS0 缓冲区大小
    #[serde(default)]
    pub dns_edns0_buffer_size: Option<u16>,
    /// DoH URL override
    /// DoH URL 覆盖
    #[serde(default)]
    pub dns_doh_url: Option<String>,
    /// Per-outbound TLS: additional CA files
    /// 逐出站 TLS：额外的 CA 文件
    #[serde(default)]
    pub tls_ca_paths: Vec<String>,
    /// Per-outbound TLS: additional CA PEM blocks
    /// 逐出站 TLS：额外的 CA PEM 块
    #[serde(default)]
    pub tls_ca_pem: Vec<String>,
    /// Per-outbound TLS: client certificate (path or inline PEM)
    /// 逐出站 TLS：客户端证书（路径或内联 PEM）
    #[serde(default)]
    pub tls_client_cert_path: Option<String>,
    #[serde(default)]
    pub tls_client_key_path: Option<String>,
    #[serde(default)]
    pub tls_client_cert_pem: Option<String>,
    #[serde(default)]
    pub tls_client_key_pem: Option<String>,
    /// Explicit ALPN override for transports that do not use tls_alpn (e.g., TUIC)
    /// 针对不使用 tls_alpn 的传输（例如 TUIC）的显式 ALPN 覆盖
    #[serde(default)]
    pub alpn: Option<String>,
    /// Whether to skip TLS certificate verification (TUIC)
    /// 是否跳过 TLS 证书校验 (TUIC)
    #[serde(default)]
    pub skip_cert_verify: Option<bool>,
    /// UDP relay mode for TUIC ("native" | "quic")
    /// TUIC 的 UDP 中继模式 ("native" | "quic")
    #[serde(default)]
    pub udp_relay_mode: Option<String>,

    // ==== UDP over TCP configuration ====
    /// Enable UDP over TCP transport (v1 or v2 protocol)
    /// 启用 UDP over TCP 传输（v1 或 v2 协议）
    #[serde(default)]
    pub udp_over_tcp: Option<bool>,
    /// UDP over TCP version: 1 or 2 (default: 2 for sing-box compatibility)
    /// UDP over TCP 版本：1 或 2（默认：2，与 sing-box 兼容）
    #[serde(default)]
    pub udp_over_tcp_version: Option<u8>,

    // ==== uTLS Client Fingerprinting ====
    /// uTLS client fingerprint for TLS connections
    /// (e.g., "chrome", "firefox", "safari", "ios", "edge", "random")
    /// uTLS 客户端指纹用于 TLS 连接
    #[serde(default)]
    pub utls_fingerprint: Option<String>,

    // Protocol-specific fields (ShadowsocksR)
    /// ShadowsocksR obfuscation parameter.
    /// ShadowsocksR 混淆参数。
    #[serde(default)]
    pub obfs_param: Option<String>,
    /// ShadowsocksR protocol.
    /// ShadowsocksR 协议。
    #[serde(default)]
    pub protocol: Option<String>,
    /// ShadowsocksR protocol parameter.
    /// ShadowsocksR 协议参数。
    #[serde(default)]
    pub protocol_param: Option<String>,

    // Tor fields
    /// Tor executable path (legacy/embedded usage).
    /// Tor 可执行文件路径（遗留/嵌入式用法）。
    #[serde(default)]
    pub tor_executable_path: Option<String>,
    /// Tor extra arguments.
    /// Tor 额外参数。
    #[serde(default)]
    pub tor_extra_args: Vec<String>,
    /// Tor data directory.
    /// Tor 数据目录。
    #[serde(default)]
    pub tor_data_directory: Option<String>,

    /// Whether TUIC should tunnel UDP over stream
    /// TUIC 是否应通过流隧道传输 UDP
    #[serde(default)]
    pub udp_over_stream: Option<bool>,
    /// Whether TUIC should attempt QUIC 0-RTT handshake (if supported)
    /// TUIC 是否应尝试 QUIC 0-RTT 握手（如果支持）
    #[serde(default)]
    pub zero_rtt_handshake: Option<bool>,
    /// Optional upload bandwidth limit in Mbps (Hysteria2)
    /// 可选的上传带宽限制 Mbps (Hysteria2)
    #[serde(default)]
    pub up_mbps: Option<u32>,
    /// Optional download bandwidth limit in Mbps (Hysteria2)
    /// 可选的下载带宽限制 Mbps (Hysteria2)
    #[serde(default)]
    pub down_mbps: Option<u32>,
    /// Optional obfuscation key/mode (Hysteria2)
    /// 可选的混淆密钥/模式 (Hysteria2)
    #[serde(default)]
    pub obfs: Option<String>,
    /// Optional Salamander fingerprint string (Hysteria2)
    /// 可选的 Salamander 指纹字符串 (Hysteria2)
    #[serde(default)]
    pub salamander: Option<String>,
    /// Brutal congestion control upload limit (Hysteria2)
    /// Brutal 拥塞控制上传限制 (Hysteria2)
    #[serde(default)]
    pub brutal_up_mbps: Option<u32>,
    /// Brutal congestion control download limit (Hysteria2)
    /// Brutal 拥塞控制下载限制 (Hysteria2)
    #[serde(default)]
    pub brutal_down_mbps: Option<u32>,
    /// Hysteria v1 protocol type ("udp", "wechat-video", "faketcp")
    /// Hysteria v1 协议类型 ("udp", "wechat-video", "faketcp")
    #[serde(default)]
    pub hysteria_protocol: Option<String>,
    /// Hysteria v1 authentication string
    /// Hysteria v1 认证字符串
    #[serde(default)]
    pub hysteria_auth: Option<String>,
    /// Hysteria v1 QUIC receive window for connection
    /// Hysteria v1 连接的 QUIC 接收窗口
    #[serde(default)]
    pub hysteria_recv_window_conn: Option<u64>,
    /// Hysteria v1 QUIC receive window for stream
    /// Hysteria v1 流的 QUIC 接收窗口
    #[serde(default)]
    pub hysteria_recv_window: Option<u64>,
    /// REALITY TLS configuration.
    /// REALITY TLS 配置。
    #[serde(default)]
    pub reality_enabled: Option<bool>,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub reality_server_name: Option<String>,
    /// Trojan password.
    /// Trojan 密码。
    #[serde(default)]
    pub password: Option<String>,
    /// Protocol version for versioned transports (currently used by ShadowTLS).
    /// 带版本协议的版本号（当前用于 ShadowTLS）。
    #[serde(default)]
    pub version: Option<u8>,
    // Shadowsocks plugin support
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,

    // SSH-specific fields
    /// SSH private key content or file path (when `ssh_private_key_path` is not used).
    /// SSH 私钥内容或文件路径（当未使用 `ssh_private_key_path` 时）。
    #[serde(default)]
    pub ssh_private_key: Option<String>,
    #[serde(default)]
    pub ssh_private_key_path: Option<String>,
    #[serde(default)]
    pub ssh_private_key_passphrase: Option<String>,
    #[serde(default)]
    pub ssh_host_key_verification: Option<bool>,
    #[serde(default)]
    pub ssh_known_hosts_path: Option<String>,
    #[serde(default)]
    pub ssh_connection_pool_size: Option<usize>,
    #[serde(default)]
    pub ssh_compression: Option<bool>,
    #[serde(default)]
    pub ssh_keepalive_interval: Option<u64>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u32>,

    // WireGuard-specific options (outbound)
    /// Use existing system interface (equivalent to Go's `system_interface`).
    /// 使用现有的系统接口（相当于 Go 的 `system_interface`）。
    #[serde(default)]
    pub wireguard_system_interface: Option<bool>,
    /// Preferred interface name when binding to an existing system interface.
    /// 绑定到现有系统接口时的首选接口名称。
    #[serde(default)]
    pub wireguard_interface: Option<String>,
    /// Optional list of local addresses (CIDR) associated with the interface.
    /// 与接口关联的可选本地地址列表 (CIDR)。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wireguard_local_address: Vec<String>,
    /// Preferred IPv4 source address (overrides derived local_address/env).
    /// 首选 IPv4 源地址（覆盖派生的 local_address/env）。
    #[serde(default)]
    pub wireguard_source_v4: Option<String>,
    /// Preferred IPv6 source address (overrides derived local_address/env).
    /// 首选 IPv6 源地址（覆盖派生的 local_address/env）。
    #[serde(default)]
    pub wireguard_source_v6: Option<String>,
    /// Allowed IP list for the interface (used when env vars not supplied).
    /// 接口的允许 IP 列表（当未提供环境变量时使用）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wireguard_allowed_ips: Vec<String>,
    /// Private key material (base64). Optional when provided via env vars.
    /// 私钥材料 (base64)。通过环境变量提供时可选。
    #[serde(default)]
    pub wireguard_private_key: Option<String>,
    /// Remote peer public key.
    /// 远程对等端公钥。
    #[serde(default)]
    pub wireguard_peer_public_key: Option<String>,
    /// Optional pre-shared key.
    /// 可选的预共享密钥。
    #[serde(default)]
    pub wireguard_pre_shared_key: Option<String>,
    /// Optional persistent keep-alive interval (seconds).
    /// 可选的持久保活间隔（秒）。
    #[serde(default)]
    pub wireguard_persistent_keepalive: Option<u16>,

    /// Tor SOCKS5 proxy address (default: 127.0.0.1:9050).
    /// Tor SOCKS5 代理地址（默认：127.0.0.1:9050）。
    #[serde(default)]
    pub tor_proxy_addr: Option<String>,
    // tor_executable_path, tor_extra_args, tor_data_directory already defined above
    /// Torrc configuration options (key-value pairs).
    /// Torrc 配置选项（键值对）。
    #[serde(default)]
    pub tor_options: Option<std::collections::HashMap<String, String>>,
    /// URLTest probe configuration
    /// URLTest 探测配置
    #[serde(default)]
    pub test_url: Option<String>,
    #[serde(default)]
    pub test_interval_ms: Option<u64>,
    #[serde(default)]
    pub test_timeout_ms: Option<u64>,
    #[serde(default)]
    pub test_tolerance_ms: Option<u64>,
    #[serde(default)]
    pub interrupt_exist_connections: Option<bool>,

    // AnyTLS-specific fields
    /// Optional AnyTLS padding scheme lines.
    /// 可选的 AnyTLS 填充方案行。
    #[serde(default)]
    pub anytls_padding: Option<Vec<String>>,
}

/// HTTP header entry (for gRPC metadata or HTTP Upgrade headers).
///
/// Deserialization goes through [`RawHeaderEntry`](super::raw::RawHeaderEntry)
/// which carries `#[serde(deny_unknown_fields)]` (WP-30i).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct HeaderEntry {
    /// Header key/name.
    pub key: String,
    /// Header value.
    pub value: String,
}

impl<'de> Deserialize<'de> for HeaderEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawHeaderEntry::deserialize(deserializer).map(Into::into)
    }
}

impl<'de> Deserialize<'de> for OutboundIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawOutboundIR::deserialize(deserializer).map(Into::into)
    }
}

impl OutboundIR {
    /// Return the string representation of the outbound type.
    #[must_use]
    pub fn ty_str(&self) -> &'static str {
        match self.ty {
            OutboundType::Direct => "direct",
            OutboundType::Http => "http",
            OutboundType::Socks => "socks",
            OutboundType::Block => "block",
            OutboundType::Selector => "selector",
            OutboundType::Shadowsocks => "shadowsocks",
            OutboundType::UrlTest => "urltest",
            OutboundType::Shadowtls => "shadowtls",
            OutboundType::Hysteria2 => "hysteria2",
            OutboundType::Tuic => "tuic",
            OutboundType::Vless => "vless",
            OutboundType::Vmess => "vmess",
            OutboundType::Trojan => "trojan",
            OutboundType::Ssh => "ssh",
            OutboundType::Dns => "dns",
            OutboundType::Tor => "tor",
            OutboundType::Anytls => "anytls",
            OutboundType::Hysteria => "hysteria",
            OutboundType::Wireguard => "wireguard",
            OutboundType::Tailscale => "tailscale",
            OutboundType::ShadowsocksR => "shadowsocksr",
        }
    }

    /// Validate REALITY configuration if enabled.
    ///
    /// # Errors
    /// Returns an error if REALITY is enabled but required fields are missing or malformed.
    pub fn validate_reality(&self) -> Result<(), String> {
        // Only validate if REALITY is explicitly enabled
        if let Some(true) = self.reality_enabled {
            let outbound_name = self.name.as_deref().unwrap_or("unnamed");

            // Validate public_key (must be 64 hex chars for X25519)
            if let Some(ref public_key) = self.reality_public_key {
                if !is_valid_hex(public_key) || public_key.len() != 64 {
                    return Err(format!(
                        "outbound '{outbound_name}': reality.public_key must be 64 hex characters (X25519 public key)"
                    ));
                }
            } else {
                return Err(format!(
                    "outbound '{outbound_name}': reality.public_key is required when reality is enabled"
                ));
            }

            // Validate short_id if present (0-16 hex chars, even length)
            if let Some(ref short_id) = self.reality_short_id {
                if !short_id.is_empty() {
                    if !is_valid_hex(short_id) {
                        return Err(format!(
                            "outbound '{outbound_name}': reality.short_id must be hex characters"
                        ));
                    }
                    if short_id.len() > 16 || short_id.len() % 2 != 0 {
                        return Err(format!(
                            "outbound '{outbound_name}': reality.short_id must be 0-16 hex chars (length multiple of 2)"
                        ));
                    }
                }
            }

            // Validate server_name is present
            if self
                .reality_server_name
                .as_ref()
                .is_none_or(String::is_empty)
            {
                return Err(format!(
                    "outbound '{outbound_name}': reality.server_name is required when reality is enabled"
                ));
            }
        }

        Ok(())
    }
}

/// Helper function to validate hex strings.
fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── OutboundType serde + ty_str ──────────────────────────────────────

    #[test]
    fn outbound_type_serde_all_variants() {
        let variants = [
            ("direct", OutboundType::Direct),
            ("http", OutboundType::Http),
            ("socks", OutboundType::Socks),
            ("block", OutboundType::Block),
            ("selector", OutboundType::Selector),
            ("shadowsocks", OutboundType::Shadowsocks),
            ("shadowtls", OutboundType::Shadowtls),
            ("urltest", OutboundType::UrlTest),
            ("hysteria2", OutboundType::Hysteria2),
            ("tuic", OutboundType::Tuic),
            ("vless", OutboundType::Vless),
            ("vmess", OutboundType::Vmess),
            ("trojan", OutboundType::Trojan),
            ("ssh", OutboundType::Ssh),
            ("dns", OutboundType::Dns),
            ("tor", OutboundType::Tor),
            ("anytls", OutboundType::Anytls),
            ("hysteria", OutboundType::Hysteria),
            ("wireguard", OutboundType::Wireguard),
            ("tailscale", OutboundType::Tailscale),
        ];
        for (expected_str, variant) in &variants {
            // ty_str() matches
            assert_eq!(
                variant.ty_str(),
                *expected_str,
                "ty_str mismatch for {expected_str}"
            );
            // serde roundtrip
            let json_val = serde_json::to_value(variant).unwrap();
            assert_eq!(json_val.as_str().unwrap(), *expected_str);
            let back: OutboundType = serde_json::from_value(json_val).unwrap();
            assert_eq!(&back, variant);
        }
    }

    #[test]
    fn outbound_type_shadowsocksr_serde() {
        let ty = OutboundType::ShadowsocksR;
        assert_eq!(ty.ty_str(), "shadowsocksr");
        let json_val = serde_json::to_value(&ty).unwrap();
        // Note: serde rename_all = "lowercase" produces "shadowsocksr"
        let back: OutboundType = serde_json::from_value(json_val).unwrap();
        assert_eq!(back, OutboundType::ShadowsocksR);
    }

    // ── OutboundIR basic roundtrip ───────────────────────────────────────

    #[test]
    fn outbound_type_serialization() {
        let data = json!({
            "ty": "anytls",
            "server": "example.com",
            "port": 1234
        });
        let ir: OutboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, OutboundType::Anytls);

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("ty").unwrap(), "anytls");
    }

    #[test]
    fn outbound_ir_default_roundtrip() {
        let ir = OutboundIR::default();
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::Direct);
        assert_eq!(back.server, None);
        assert_eq!(back.port, None);
    }

    // ── WireGuard roundtrip ──────────────────────────────────────────────

    #[test]
    fn wireguard_outbound_serialization() {
        let mut ir = OutboundIR {
            ty: OutboundType::Wireguard,
            name: Some("wg-out".to_string()),
            ..Default::default()
        };
        ir.wireguard_interface = Some("wg0".to_string());
        ir.wireguard_local_address = vec!["10.0.0.2/32".to_string(), "fd00::2/64".to_string()];
        ir.wireguard_allowed_ips = vec!["0.0.0.0/0".to_string()];
        ir.wireguard_persistent_keepalive = Some(25);

        let json = serde_json::to_value(&ir).unwrap();
        assert_eq!(json.get("ty").unwrap(), "wireguard");
        assert_eq!(json.get("wireguard_interface").unwrap(), "wg0");
        let local = json
            .get("wireguard_local_address")
            .and_then(|v| v.as_array())
            .expect("local addresses");
        assert_eq!(local.len(), 2);
        assert_eq!(local[0], "10.0.0.2/32");
        let allowed = json
            .get("wireguard_allowed_ips")
            .and_then(|v| v.as_array())
            .expect("allowed ips");
        assert_eq!(allowed[0], "0.0.0.0/0");

        let roundtrip: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(roundtrip.wireguard_interface.as_deref(), Some("wg0"));
        assert_eq!(roundtrip.wireguard_local_address.len(), 2);
        assert_eq!(roundtrip.wireguard_persistent_keepalive, Some(25));
    }

    // ── detour + version deserialization ──────────────────────────────────

    #[test]
    fn outbound_ir_deserializes_detour_and_shadowtls_version() {
        let outbound: OutboundIR = serde_json::from_value(json!({
            "ty": "shadowsocks",
            "name": "ss-over-stl",
            "server": "example.com",
            "port": 8388,
            "method": "aes-256-gcm",
            "password": "secret",
            "detour": "shadowtls-wrap",
            "version": 1
        }))
        .unwrap();

        assert_eq!(outbound.detour.as_deref(), Some("shadowtls-wrap"));
        assert_eq!(outbound.version, Some(1));
    }

    // ── validate_reality success/failure paths ───────────────────────────

    #[test]
    fn reality_validation_valid() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn reality_validation_missing_public_key() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: None,
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("public_key is required"));
    }

    #[test]
    fn reality_validation_invalid_public_key() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some("invalid".to_string()),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("64 hex characters"));
    }

    #[test]
    fn reality_validation_invalid_short_id() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            reality_short_id: Some("xyz".to_string()),
            reality_server_name: Some("www.apple.com".to_string()),
            ..Default::default()
        };
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("hex characters"));
    }

    #[test]
    fn reality_validation_missing_server_name() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(true),
            reality_public_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            reality_short_id: Some("01ab".to_string()),
            reality_server_name: None,
            ..Default::default()
        };
        let err = outbound.validate_reality().unwrap_err();
        assert!(err.contains("server_name is required"));
    }

    #[test]
    fn reality_validation_disabled() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            reality_enabled: Some(false),
            ..Default::default()
        };
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn reality_validation_not_set() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("test-vless".to_string()),
            ..Default::default()
        };
        assert!(outbound.validate_reality().is_ok());
    }

    // ── Transport fields roundtrip ───────────────────────────────────────

    #[test]
    fn transport_ws_fields_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Vmess,
            transport: Some(vec!["tls".into(), "ws".into()]),
            ws_path: Some("/chat".to_string()),
            ws_host: Some("ws.example.com".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.transport.as_deref(),
            Some(&["tls".to_string(), "ws".to_string()][..])
        );
        assert_eq!(back.ws_path.as_deref(), Some("/chat"));
        assert_eq!(back.ws_host.as_deref(), Some("ws.example.com"));
    }

    #[test]
    fn transport_h2_fields_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Vless,
            h2_path: Some("/h2".to_string()),
            h2_host: Some("h2.example.com".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.h2_path.as_deref(), Some("/h2"));
        assert_eq!(back.h2_host.as_deref(), Some("h2.example.com"));
    }

    #[test]
    fn transport_grpc_fields_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Vless,
            grpc_service: Some("my-svc".to_string()),
            grpc_method: Some("Method".to_string()),
            grpc_authority: Some("grpc.example.com".to_string()),
            grpc_metadata: vec![HeaderEntry {
                key: "x-custom".to_string(),
                value: "val1".to_string(),
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.grpc_service.as_deref(), Some("my-svc"));
        assert_eq!(back.grpc_metadata.len(), 1);
        assert_eq!(back.grpc_metadata[0].key, "x-custom");
    }

    #[test]
    fn transport_http_upgrade_fields_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Vmess,
            http_upgrade_path: Some("/upgrade".to_string()),
            http_upgrade_headers: vec![HeaderEntry {
                key: "Host".to_string(),
                value: "hup.example.com".to_string(),
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.http_upgrade_path.as_deref(), Some("/upgrade"));
        assert_eq!(back.http_upgrade_headers.len(), 1);
        assert_eq!(back.http_upgrade_headers[0].value, "hup.example.com");
    }

    // ── DNS outbound fields roundtrip ────────────────────────────────────

    #[test]
    fn dns_outbound_fields_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Dns,
            dns_transport: Some("udp".to_string()),
            dns_tls_server_name: Some("dns.example.com".to_string()),
            dns_timeout_ms: Some(5000),
            dns_query_timeout_ms: Some(3000),
            dns_enable_edns0: Some(true),
            dns_edns0_buffer_size: Some(4096),
            dns_doh_url: Some("https://dns.example.com/dns-query".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.dns_transport.as_deref(), Some("udp"));
        assert_eq!(back.dns_tls_server_name.as_deref(), Some("dns.example.com"));
        assert_eq!(back.dns_timeout_ms, Some(5000));
        assert_eq!(back.dns_query_timeout_ms, Some(3000));
        assert_eq!(back.dns_enable_edns0, Some(true));
        assert_eq!(back.dns_edns0_buffer_size, Some(4096));
        assert_eq!(
            back.dns_doh_url.as_deref(),
            Some("https://dns.example.com/dns-query")
        );
    }

    // ── TUIC roundtrip ───────────────────────────────────────────────────

    #[test]
    fn tuic_outbound_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Tuic,
            name: Some("tuic-out".to_string()),
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            token: Some("secret".to_string()),
            congestion_control: Some("bbr".to_string()),
            udp_relay_mode: Some("native".to_string()),
            udp_over_stream: Some(true),
            zero_rtt_handshake: Some(true),
            skip_cert_verify: Some(false),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::Tuic);
        assert_eq!(
            back.uuid.as_deref(),
            Some("12345678-1234-1234-1234-123456789abc")
        );
        assert_eq!(back.token.as_deref(), Some("secret"));
        assert_eq!(back.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(back.udp_relay_mode.as_deref(), Some("native"));
        assert_eq!(back.udp_over_stream, Some(true));
        assert_eq!(back.zero_rtt_handshake, Some(true));
    }

    // ── Hysteria v1 + v2 roundtrip ───────────────────────────────────────

    #[test]
    fn hysteria2_outbound_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Hysteria2,
            server: Some("hy2.example.com".to_string()),
            port: Some(443),
            up_mbps: Some(100),
            down_mbps: Some(200),
            obfs: Some("salamander".to_string()),
            salamander: Some("fp-string".to_string()),
            brutal_up_mbps: Some(50),
            brutal_down_mbps: Some(100),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::Hysteria2);
        assert_eq!(back.up_mbps, Some(100));
        assert_eq!(back.down_mbps, Some(200));
        assert_eq!(back.obfs.as_deref(), Some("salamander"));
        assert_eq!(back.brutal_up_mbps, Some(50));
    }

    #[test]
    fn hysteria_v1_outbound_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Hysteria,
            server: Some("hy1.example.com".to_string()),
            port: Some(443),
            up_mbps: Some(50),
            down_mbps: Some(100),
            hysteria_protocol: Some("udp".to_string()),
            hysteria_auth: Some("auth-str".to_string()),
            hysteria_recv_window_conn: Some(8388608),
            hysteria_recv_window: Some(4194304),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::Hysteria);
        assert_eq!(back.hysteria_protocol.as_deref(), Some("udp"));
        assert_eq!(back.hysteria_auth.as_deref(), Some("auth-str"));
        assert_eq!(back.hysteria_recv_window_conn, Some(8388608));
    }

    // ── Tor roundtrip ────────────────────────────────────────────────────

    #[test]
    fn tor_outbound_roundtrip() {
        let mut opts = std::collections::HashMap::new();
        opts.insert("SocksPort".to_string(), "9050".to_string());
        let ir = OutboundIR {
            ty: OutboundType::Tor,
            tor_executable_path: Some("/usr/bin/tor".to_string()),
            tor_extra_args: vec!["--quiet".to_string()],
            tor_data_directory: Some("/tmp/tor".to_string()),
            tor_proxy_addr: Some("127.0.0.1:9050".to_string()),
            tor_options: Some(opts),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::Tor);
        assert_eq!(back.tor_executable_path.as_deref(), Some("/usr/bin/tor"));
        assert_eq!(back.tor_extra_args, vec!["--quiet"]);
        assert_eq!(back.tor_proxy_addr.as_deref(), Some("127.0.0.1:9050"));
        assert!(back.tor_options.unwrap().contains_key("SocksPort"));
    }

    // ── SSH roundtrip ────────────────────────────────────────────────────

    #[test]
    fn ssh_outbound_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Ssh,
            server: Some("ssh.example.com".to_string()),
            port: Some(22),
            credentials: Some(Credentials {
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                ..Default::default()
            }),
            ssh_private_key_path: Some("/home/user/.ssh/id_rsa".to_string()),
            ssh_host_key_verification: Some(true),
            ssh_connection_pool_size: Some(4),
            ssh_compression: Some(true),
            ssh_keepalive_interval: Some(60),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::Ssh);
        assert_eq!(
            back.credentials.as_ref().unwrap().username.as_deref(),
            Some("user")
        );
        assert_eq!(back.ssh_connection_pool_size, Some(4));
        assert_eq!(back.ssh_compression, Some(true));
    }

    // ── ShadowsocksR roundtrip ───────────────────────────────────────────

    #[test]
    fn shadowsocksr_outbound_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::ShadowsocksR,
            server: Some("ssr.example.com".to_string()),
            port: Some(8388),
            method: Some("aes-256-cfb".to_string()),
            password: Some("secret".to_string()),
            obfs_param: Some("obfs-param".to_string()),
            protocol: Some("auth_aes128_md5".to_string()),
            protocol_param: Some("proto-param".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::ShadowsocksR);
        assert_eq!(back.obfs_param.as_deref(), Some("obfs-param"));
        assert_eq!(back.protocol.as_deref(), Some("auth_aes128_md5"));
        assert_eq!(back.protocol_param.as_deref(), Some("proto-param"));
    }

    // ── AnyTLS roundtrip ─────────────────────────────────────────────────

    #[test]
    fn anytls_outbound_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Anytls,
            server: Some("anytls.example.com".to_string()),
            port: Some(443),
            password: Some("pw".to_string()),
            anytls_padding: Some(vec!["0-100".to_string(), "100-200".to_string()]),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.ty, OutboundType::Anytls);
        assert_eq!(back.anytls_padding.as_ref().unwrap().len(), 2);
    }

    // ── HeaderEntry serde ────────────────────────────────────────────────

    #[test]
    fn header_entry_roundtrip() {
        let entry = HeaderEntry {
            key: "Authorization".to_string(),
            value: "Bearer token123".to_string(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json.get("key").unwrap(), "Authorization");
        assert_eq!(json.get("value").unwrap(), "Bearer token123");
        let back: HeaderEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.key, "Authorization");
        assert_eq!(back.value, "Bearer token123");
    }

    // ── TLS fields roundtrip ─────────────────────────────────────────────

    #[test]
    fn tls_fields_roundtrip() {
        let ir = OutboundIR {
            ty: OutboundType::Vless,
            tls_sni: Some("sni.example.com".to_string()),
            tls_alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            tls_ca_paths: vec!["/etc/ssl/ca.pem".to_string()],
            tls_ca_pem: vec!["-----BEGIN CERTIFICATE-----".to_string()],
            tls_client_cert_path: Some("/etc/ssl/client.pem".to_string()),
            tls_client_key_path: Some("/etc/ssl/client-key.pem".to_string()),
            utls_fingerprint: Some("chrome".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&ir).unwrap();
        let back: OutboundIR = serde_json::from_value(json).unwrap();
        assert_eq!(back.tls_sni.as_deref(), Some("sni.example.com"));
        assert_eq!(back.tls_alpn.as_ref().unwrap().len(), 2);
        assert_eq!(back.tls_ca_paths.len(), 1);
        assert_eq!(back.utls_fingerprint.as_deref(), Some("chrome"));
    }

    // ── is_valid_hex ─────────────────────────────────────────────────────

    #[test]
    fn is_valid_hex_unit() {
        assert!(is_valid_hex("0123456789abcdefABCDEF"));
        assert!(!is_valid_hex("xyz"));
        assert!(is_valid_hex(""));
    }
}
