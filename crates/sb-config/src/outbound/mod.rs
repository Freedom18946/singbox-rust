//! Outbound configuration model.
//!
//! # Raw / Validated boundary
//!
//! `serde::Deserialize` lands on **Raw** types (in the private `raw` submodule)
//! which carry `#[serde(deny_unknown_fields)]`. The public domain types below
//! are the **Validated** layer — they implement `Deserialize` via a Raw bridge
//! (`raw::Raw* → domain`) so callers can still write
//! `serde_json::from_str::<Outbound>(...)` while unknown fields are rejected at
//! the serde boundary.

mod raw;

use serde::{Deserialize, Deserializer, Serialize};

// ───────────────────────────── Outbound enum ─────────────────────────────

/// Outbound proxy configuration.
/// 出站代理配置。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Outbound {
    /// Direct connection (no proxy).
    /// 直连（无代理）。
    Direct(DirectConfig),
    /// Upstream HTTP proxy (CONNECT method).
    /// 上游 HTTP 代理（CONNECT 方法）。
    Http(HttpProxyConfig),
    /// Upstream SOCKS5 proxy.
    /// 上游 SOCKS5 代理。
    Socks5(Socks5Config),
    /// Upstream SOCKS4 proxy.
    /// 上游 SOCKS4 代理。
    Socks4(Socks4Config),
    /// VMess protocol.
    /// VMess 协议。
    Vmess(VmessConfig),
    /// VLESS protocol.
    /// VLESS 协议。
    Vless(VlessConfig),
    /// TUIC protocol.
    /// TUIC 协议。
    Tuic(TuicConfig),
    /// Manual selector (user choice).
    /// 手动选择器（用户选择）。
    Selector(SelectorConfig),
    /// Automatic selector (latency based).
    /// 自动选择器（基于延迟）。
    #[serde(rename = "urltest")]
    UrlTest(UrlTestConfig),
}

impl<'de> Deserialize<'de> for Outbound {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawOutbound::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawOutbound> for Outbound {
    fn from(r: raw::RawOutbound) -> Self {
        match r {
            raw::RawOutbound::Direct(c) => Self::Direct(c.into()),
            raw::RawOutbound::Http(c) => Self::Http(c.into()),
            raw::RawOutbound::Socks5(c) => Self::Socks5(c.into()),
            raw::RawOutbound::Socks4(c) => Self::Socks4(c.into()),
            raw::RawOutbound::Vmess(c) => Self::Vmess(c.into()),
            raw::RawOutbound::Vless(c) => Self::Vless(c.into()),
            raw::RawOutbound::Tuic(c) => Self::Tuic(c.into()),
            raw::RawOutbound::Selector(c) => Self::Selector(c.into()),
            raw::RawOutbound::UrlTest(c) => Self::UrlTest(c.into()),
        }
    }
}

// Keep for backward compatibility - alias the enum
pub type OutboundKind = Outbound;

// ───────────────────────── Per-protocol configs ──────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DirectConfig {
    pub tag: Option<String>,
}

impl<'de> Deserialize<'de> for DirectConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawDirectConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawDirectConfig> for DirectConfig {
    fn from(r: raw::RawDirectConfig) -> Self {
        Self { tag: r.tag }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpProxyConfig {
    /// Proxy server address host:port / 代理地址 host:port
    pub server: String,
    pub tag: Option<String>,
    /// Basic Auth (optional) / Basic 认证（可选）
    pub username: Option<String>,
    pub password: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration / TLS 配置
    pub tls: Option<TlsConfig>,
}

impl<'de> Deserialize<'de> for HttpProxyConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawHttpProxyConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawHttpProxyConfig> for HttpProxyConfig {
    fn from(r: raw::RawHttpProxyConfig) -> Self {
        Self {
            server: r.server,
            tag: r.tag,
            username: r.username,
            password: r.password,
            connect_timeout_sec: r.connect_timeout_sec,
            tls: r.tls.map(TlsConfig::from),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Socks5Config {
    pub server: String,
    pub tag: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration
    pub tls: Option<TlsConfig>,
}

impl<'de> Deserialize<'de> for Socks5Config {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawSocks5Config::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawSocks5Config> for Socks5Config {
    fn from(r: raw::RawSocks5Config) -> Self {
        Self {
            server: r.server,
            tag: r.tag,
            username: r.username,
            password: r.password,
            connect_timeout_sec: r.connect_timeout_sec,
            tls: r.tls.map(TlsConfig::from),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Socks4Config {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    pub tag: Option<String>,
    /// User ID for SOCKS4 authentication / SOCKS4 用户 ID
    pub user_id: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    pub connect_timeout_sec: Option<u64>,
}

impl<'de> Deserialize<'de> for Socks4Config {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawSocks4Config::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawSocks4Config> for Socks4Config {
    fn from(r: raw::RawSocks4Config) -> Self {
        Self {
            server: r.server,
            tag: r.tag,
            user_id: r.user_id,
            connect_timeout_sec: r.connect_timeout_sec,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VmessConfig {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    pub tag: Option<String>,
    /// User UUID / 用户 UUID
    pub uuid: String,
    /// Encryption method (auto, aes-128-gcm, chacha20-poly1305, none) / 加密方式
    pub security: String,
    /// AlterId (legacy, should be 0 for AEAD) / AlterId (旧版，AEAD 应为 0)
    pub alter_id: u16,
    /// Global padding / 全局填充
    pub global_padding: bool,
    /// Authenticated length / 认证长度
    pub authenticated_length: bool,
    /// Network type / 网络类型
    pub network: Option<Vec<String>>,
    /// Packet encoding / 数据包编码
    pub packet_encoding: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration / TLS 配置
    pub tls: Option<TlsConfig>,
    /// Transport configuration (WebSocket, gRPC, HTTPUpgrade) / 传输配置
    pub transport: Option<TransportConfig>,
    /// Multiplex configuration / 多路复用配置
    pub multiplex: Option<MultiplexConfig>,
}

impl<'de> Deserialize<'de> for VmessConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawVmessConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawVmessConfig> for VmessConfig {
    fn from(r: raw::RawVmessConfig) -> Self {
        Self {
            server: r.server,
            tag: r.tag,
            uuid: r.uuid,
            security: r.security,
            alter_id: r.alter_id,
            global_padding: r.global_padding,
            authenticated_length: r.authenticated_length,
            network: r.network,
            packet_encoding: r.packet_encoding,
            connect_timeout_sec: r.connect_timeout_sec,
            tls: r.tls.map(TlsConfig::from),
            transport: r.transport.map(TransportConfig::from),
            multiplex: r.multiplex.map(MultiplexConfig::from),
        }
    }
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct VlessConfig {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    pub tag: Option<String>,
    /// User UUID / 用户 UUID
    pub uuid: String,
    /// Flow control mode (xtls-rprx-vision) / 流控模式
    pub flow: Option<String>,
    /// Network type (tcp, udp) / 网络类型
    pub network: String,
    /// Packet encoding (packetaddr, xudp) / 数据包编码
    pub packet_encoding: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration / TLS 配置
    pub tls: Option<TlsConfig>,
    /// Transport configuration (WebSocket, gRPC, HTTPUpgrade) / 传输配置
    pub transport: Option<TransportConfig>,
    /// Multiplex configuration / 多路复用配置
    pub multiplex: Option<MultiplexConfig>,
}

impl<'de> Deserialize<'de> for VlessConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawVlessConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawVlessConfig> for VlessConfig {
    fn from(r: raw::RawVlessConfig) -> Self {
        Self {
            server: r.server,
            tag: r.tag,
            uuid: r.uuid,
            flow: r.flow,
            network: r.network,
            packet_encoding: r.packet_encoding,
            connect_timeout_sec: r.connect_timeout_sec,
            tls: r.tls.map(TlsConfig::from),
            transport: r.transport.map(TransportConfig::from),
            multiplex: r.multiplex.map(MultiplexConfig::from),
        }
    }
}

fn default_vless_network() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct TuicConfig {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    pub tag: Option<String>,
    /// User UUID / 用户 UUID
    pub uuid: String,
    /// Password / 密码
    pub password: String,
    /// Congestion control algorithm (bbr, cubic, new_reno) / 拥塞控制算法
    pub congestion_control: String,
    /// UDP relay mode (native, quic) / UDP 中继模式
    pub udp_relay_mode: Option<String>,
    /// UDP over Stream
    pub udp_over_stream: bool,
    /// 0-RTT Handshake / 0-RTT 握手
    pub zero_rtt_handshake: bool,
    /// Heartbeat interval (ms) / 心跳间隔 (毫秒)
    pub heartbeat: u64,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    pub connect_timeout_sec: Option<u64>,
    /// Authentication timeout in seconds (optional) / 认证超时秒（可选）
    pub auth_timeout_sec: Option<u64>,
    /// Network type / 网络类型
    pub network: Option<Vec<String>>,
    /// TLS configuration / TLS 配置
    pub tls: Option<TlsConfig>,
}

impl<'de> Deserialize<'de> for TuicConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawTuicConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawTuicConfig> for TuicConfig {
    fn from(r: raw::RawTuicConfig) -> Self {
        Self {
            server: r.server,
            tag: r.tag,
            uuid: r.uuid,
            password: r.password,
            congestion_control: r.congestion_control,
            udp_relay_mode: r.udp_relay_mode,
            udp_over_stream: r.udp_over_stream,
            zero_rtt_handshake: r.zero_rtt_handshake,
            heartbeat: r.heartbeat,
            connect_timeout_sec: r.connect_timeout_sec,
            auth_timeout_sec: r.auth_timeout_sec,
            network: r.network,
            tls: r.tls.map(TlsConfig::from),
        }
    }
}

fn default_tuic_congestion_control() -> String {
    "bbr".to_string()
}

fn default_tuic_heartbeat() -> u64 {
    10000 // 10 seconds in milliseconds
}

#[derive(Debug, Clone, Serialize)]
pub struct SelectorConfig {
    pub tag: Option<String>,
    /// Candidate outbound list (referenced by tag) / 候选出站列表（按 tag 引用）
    pub outbounds: Vec<String>,
    /// Default selected outbound (optional) / 默认选中的出站（可选）
    pub default: Option<String>,
    /// Check availability on startup / 是否在启动时检查可用性
    pub interrupt_exist_connections: bool,
}

impl<'de> Deserialize<'de> for SelectorConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawSelectorConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawSelectorConfig> for SelectorConfig {
    fn from(r: raw::RawSelectorConfig) -> Self {
        Self {
            tag: r.tag,
            outbounds: r.outbounds,
            default: r.default,
            interrupt_exist_connections: r.interrupt_exist_connections,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UrlTestConfig {
    pub tag: Option<String>,
    /// Candidate outbound list (referenced by tag) / 候选出站列表（按 tag 引用）
    pub outbounds: Vec<String>,
    /// Test URL (default http://www.gstatic.com/generate_204) / 测试 URL
    pub url: String,
    /// Test interval (seconds, default 60) / 测试间隔（秒，默认 60）
    pub interval: u64,
    /// Timeout (seconds, default 5) / 超时时间（秒，默认 5）
    pub timeout: u64,
    /// Tolerance (ms, default 50ms, switch only if latency diff > tolerance) / 容忍度（毫秒，默认 50ms）
    pub tolerance: u64,
    /// Check availability on startup / 是否在启动时检查可用性
    pub interrupt_exist_connections: bool,
}

impl<'de> Deserialize<'de> for UrlTestConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawUrlTestConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawUrlTestConfig> for UrlTestConfig {
    fn from(r: raw::RawUrlTestConfig) -> Self {
        Self {
            tag: r.tag,
            outbounds: r.outbounds,
            url: r.url,
            interval: r.interval,
            timeout: r.timeout,
            tolerance: r.tolerance,
            interrupt_exist_connections: r.interrupt_exist_connections,
        }
    }
}

fn default_url_test_url() -> String {
    "http://www.gstatic.com/generate_204".to_string()
}

fn default_url_test_interval() -> u64 {
    60
}

fn default_url_test_timeout() -> u64 {
    5
}

fn default_url_test_tolerance() -> u64 {
    50
}

// ───────────────────────── Shared / nested types ─────────────────────────

/// TLS configuration for outbound connections
/// 出站连接的 TLS 配置
#[derive(Debug, Clone, Serialize, Default)]
pub struct TlsConfig {
    /// Enable TLS / 启用 TLS
    pub enabled: bool,
    /// Server Name Indication (SNI)
    pub sni: Option<String>,
    /// Application Layer Protocol Negotiation (ALPN)
    pub alpn: Option<String>,
    /// Skip certificate verification (insecure) / 跳过证书校验（不安全）
    pub insecure: bool,
    /// REALITY TLS configuration / REALITY TLS 配置
    pub reality: Option<RealityConfig>,
    /// ECH (Encrypted Client Hello) configuration / ECH 配置
    pub ech: Option<EchConfig>,
}

impl<'de> Deserialize<'de> for TlsConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawTlsConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawTlsConfig> for TlsConfig {
    fn from(r: raw::RawTlsConfig) -> Self {
        Self {
            enabled: r.enabled,
            sni: r.sni,
            alpn: r.alpn,
            insecure: r.insecure,
            reality: r.reality.map(RealityConfig::from),
            ech: r.ech.map(EchConfig::from),
        }
    }
}

/// REALITY TLS configuration
/// REALITY TLS 配置
#[derive(Debug, Clone, Serialize)]
pub struct RealityConfig {
    /// Enable REALITY / 启用 REALITY
    pub enabled: bool,
    /// Server public key (64-character hex string) / 服务端公钥
    pub public_key: String,
    /// Short ID (0-16 character hex string) / Short ID
    pub short_id: Option<String>,
    /// Server name for SNI / SNI 服务端名称
    pub server_name: String,
}

impl<'de> Deserialize<'de> for RealityConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawRealityConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawRealityConfig> for RealityConfig {
    fn from(r: raw::RawRealityConfig) -> Self {
        Self {
            enabled: r.enabled,
            public_key: r.public_key,
            short_id: r.short_id,
            server_name: r.server_name,
        }
    }
}

/// ECH (Encrypted Client Hello) configuration
/// ECH (加密 Client Hello) 配置
#[derive(Debug, Clone, Serialize)]
pub struct EchConfig {
    /// Enable ECH / 启用 ECH
    pub enabled: bool,
    /// ECH configuration list (base64 encoded) / ECH 配置列表 (Base64 编码)
    pub config: Option<String>,
    /// Enable post-quantum signature schemes / 启用后量子签名方案
    pub pq_signature_schemes_enabled: bool,
    /// Disable dynamic record sizing / 禁用动态记录大小调整
    pub dynamic_record_sizing_disabled: Option<bool>,
}

impl<'de> Deserialize<'de> for EchConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawEchConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawEchConfig> for EchConfig {
    fn from(r: raw::RawEchConfig) -> Self {
        Self {
            enabled: r.enabled,
            config: r.config,
            pq_signature_schemes_enabled: r.pq_signature_schemes_enabled,
            dynamic_record_sizing_disabled: r.dynamic_record_sizing_disabled,
        }
    }
}

/// Transport configuration for V2Ray protocols (VMess, VLESS, Trojan)
/// V2Ray 协议 (VMess, VLESS, Trojan) 的传输配置
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
#[derive(Default)]
pub enum TransportConfig {
    /// Direct TCP connection (default)
    /// 直接 TCP 连接（默认）
    #[default]
    Tcp,
    /// WebSocket transport
    /// WebSocket 传输
    #[serde(rename = "ws")]
    WebSocket {
        /// WebSocket path / WebSocket 路径
        path: String,
        /// Custom headers / 自定义请求头
        headers: Option<std::collections::HashMap<String, String>>,
        /// Maximum message size in bytes / 最大消息大小 (字节)
        max_message_size: Option<usize>,
        /// Maximum frame size in bytes / 最大帧大小 (字节)
        max_frame_size: Option<usize>,
    },
    /// gRPC bidirectional streaming
    /// gRPC 双向流
    #[serde(rename = "grpc")]
    Grpc {
        /// Service name / 服务名称
        service_name: String,
        /// Method name / 方法名称
        method_name: String,
        /// Custom metadata / 自定义元数据
        metadata: Option<std::collections::HashMap<String, String>>,
    },
    /// HTTP/1.1 Upgrade
    /// HTTP/1.1 Upgrade
    #[serde(rename = "httpupgrade")]
    HttpUpgrade {
        /// Path / 路径
        path: String,
        /// Custom headers / 自定义请求头
        headers: Option<std::collections::HashMap<String, String>>,
    },
}

impl<'de> Deserialize<'de> for TransportConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawTransportConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawTransportConfig> for TransportConfig {
    fn from(r: raw::RawTransportConfig) -> Self {
        match r {
            raw::RawTransportConfig::Tcp => Self::Tcp,
            raw::RawTransportConfig::WebSocket(ws) => Self::WebSocket {
                path: ws.path,
                headers: ws.headers,
                max_message_size: ws.max_message_size,
                max_frame_size: ws.max_frame_size,
            },
            raw::RawTransportConfig::Grpc(g) => Self::Grpc {
                service_name: g.service_name,
                method_name: g.method_name,
                metadata: g.metadata,
            },
            raw::RawTransportConfig::HttpUpgrade(h) => Self::HttpUpgrade {
                path: h.path,
                headers: h.headers,
            },
        }
    }
}

fn default_ws_path() -> String {
    "/".to_string()
}

fn default_grpc_service() -> String {
    "TunnelService".to_string()
}

fn default_grpc_method() -> String {
    "Tunnel".to_string()
}

fn default_httpupgrade_path() -> String {
    "/".to_string()
}

/// Multiplex configuration (yamux-based stream multiplexing)
/// 多路复用配置 (基于 yamux 的流多路复用)
#[derive(Debug, Clone, Serialize)]
pub struct MultiplexConfig {
    /// Enable multiplex / 启用多路复用
    pub enabled: bool,
    /// Protocol (only "yamux" supported) / 协议 (仅支持 "yamux")
    pub protocol: String,
    /// Maximum connections in pool / 连接池最大连接数
    pub max_connections: usize,
    /// Minimum connections to keep alive / 最小保活连接数
    pub min_streams: usize,
    /// Maximum streams per connection / 单连接最大流数
    pub max_streams: usize,
    /// Padding (bytes) / 填充 (字节)
    pub padding: bool,
    /// Brutal congestion control configuration / Brutal 拥塞控制配置
    pub brutal: Option<BrutalConfig>,
}

impl<'de> Deserialize<'de> for MultiplexConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawMultiplexConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawMultiplexConfig> for MultiplexConfig {
    fn from(r: raw::RawMultiplexConfig) -> Self {
        Self {
            enabled: r.enabled,
            protocol: r.protocol,
            max_connections: r.max_connections,
            min_streams: r.min_streams,
            max_streams: r.max_streams,
            padding: r.padding,
            brutal: r.brutal.map(BrutalConfig::from),
        }
    }
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: default_multiplex_protocol(),
            max_connections: default_multiplex_max_connections(),
            min_streams: default_multiplex_min_streams(),
            max_streams: default_multiplex_max_streams(),
            padding: false,
            brutal: None,
        }
    }
}

fn default_multiplex_protocol() -> String {
    "yamux".to_string()
}

fn default_multiplex_max_connections() -> usize {
    4
}

fn default_multiplex_min_streams() -> usize {
    4
}

fn default_multiplex_max_streams() -> usize {
    16
}

/// Brutal congestion control configuration
/// Brutal 拥塞控制配置
#[derive(Debug, Clone, Serialize)]
pub struct BrutalConfig {
    /// Enable brutal congestion control / 启用 Brutal 拥塞控制
    pub enabled: bool,
    /// Upload bandwidth in Mbps / 上传带宽 (Mbps)
    pub up_mbps: u32,
    /// Download bandwidth in Mbps / 下载带宽 (Mbps)
    pub down_mbps: u32,
}

impl<'de> Deserialize<'de> for BrutalConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        raw::RawBrutalConfig::deserialize(d).map(Self::from)
    }
}

impl From<raw::RawBrutalConfig> for BrutalConfig {
    fn from(r: raw::RawBrutalConfig) -> Self {
        Self {
            enabled: r.enabled,
            up_mbps: r.up_mbps,
            down_mbps: r.down_mbps,
        }
    }
}
