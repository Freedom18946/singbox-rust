//! Outbound configuration model.

use serde::{Deserialize, Serialize};

/// Outbound proxy configuration.
/// 出站代理配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
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

// Keep for backward compatibility - alias the enum
pub type OutboundKind = Outbound;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectConfig {
    #[serde(default)]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    /// Proxy server address host:port / 代理地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// Basic Auth (optional) / Basic 认证（可选）
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration / TLS 配置
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks4Config {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// User ID for SOCKS4 authentication / SOCKS4 用户 ID
    #[serde(default)]
    pub user_id: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessConfig {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// User UUID / 用户 UUID
    pub uuid: String,
    /// Encryption method (auto, aes-128-gcm, chacha20-poly1305, none) / 加密方式
    #[serde(default = "default_vmess_security")]
    pub security: String,
    /// AlterId (legacy, should be 0 for AEAD) / AlterId (旧版，AEAD 应为 0)
    #[serde(default)]
    pub alter_id: u16,
    /// Global padding / 全局填充
    #[serde(default)]
    pub global_padding: bool,
    /// Authenticated length / 认证长度
    #[serde(default)]
    pub authenticated_length: bool,
    /// Network type / 网络类型
    #[serde(default)]
    pub network: Option<Vec<String>>,
    /// Packet encoding / 数据包编码
    #[serde(default)]
    pub packet_encoding: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration / TLS 配置
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Transport configuration (WebSocket, gRPC, HTTPUpgrade) / 传输配置
    #[serde(default)]
    pub transport: Option<TransportConfig>,
    /// Multiplex configuration / 多路复用配置
    #[serde(default)]
    pub multiplex: Option<MultiplexConfig>,
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessConfig {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// User UUID / 用户 UUID
    pub uuid: String,
    /// Flow control mode (xtls-rprx-vision) / 流控模式
    #[serde(default)]
    pub flow: Option<String>,
    /// Network type (tcp, udp) / 网络类型
    #[serde(default = "default_vless_network")]
    pub network: String,
    /// Packet encoding (packetaddr, xudp) / 数据包编码
    #[serde(default)]
    pub packet_encoding: Option<String>,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// TLS configuration / TLS 配置
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Transport configuration (WebSocket, gRPC, HTTPUpgrade) / 传输配置
    #[serde(default)]
    pub transport: Option<TransportConfig>,
    /// Multiplex configuration / 多路复用配置
    #[serde(default)]
    pub multiplex: Option<MultiplexConfig>,
}

fn default_vless_network() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicConfig {
    /// Server address host:port / 服务器地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// User UUID / 用户 UUID
    pub uuid: String,
    /// Password / 密码
    pub password: String,
    /// Congestion control algorithm (bbr, cubic, new_reno) / 拥塞控制算法
    #[serde(default = "default_tuic_congestion_control")]
    pub congestion_control: String,
    /// UDP relay mode (native, quic) / UDP 中继模式
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    /// UDP over Stream
    #[serde(default)]
    pub udp_over_stream: bool,
    /// 0-RTT Handshake / 0-RTT 握手
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    /// Heartbeat interval (ms) / 心跳间隔 (毫秒)
    #[serde(default = "default_tuic_heartbeat")]
    pub heartbeat: u64,
    /// Connection timeout in seconds (optional) / 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// Authentication timeout in seconds (optional) / 认证超时秒（可选）
    #[serde(default)]
    pub auth_timeout_sec: Option<u64>,
    /// Network type / 网络类型
    #[serde(default)]
    pub network: Option<Vec<String>>,
    /// TLS configuration / TLS 配置
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

fn default_tuic_congestion_control() -> String {
    "bbr".to_string()
}

fn default_tuic_heartbeat() -> u64 {
    10000 // 10 seconds in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorConfig {
    #[serde(default)]
    pub tag: Option<String>,
    /// Candidate outbound list (referenced by tag) / 候选出站列表（按 tag 引用）
    pub outbounds: Vec<String>,
    /// Default selected outbound (optional) / 默认选中的出站（可选）
    #[serde(default)]
    pub default: Option<String>,
    /// Check availability on startup / 是否在启动时检查可用性
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlTestConfig {
    #[serde(default)]
    pub tag: Option<String>,
    /// Candidate outbound list (referenced by tag) / 候选出站列表（按 tag 引用）
    pub outbounds: Vec<String>,
    /// Test URL (default http://www.gstatic.com/generate_204) / 测试 URL
    #[serde(default = "default_url_test_url")]
    pub url: String,
    /// Test interval (seconds, default 60) / 测试间隔（秒，默认 60）
    #[serde(default = "default_url_test_interval")]
    pub interval: u64,
    /// Timeout (seconds, default 5) / 超时时间（秒，默认 5）
    #[serde(default = "default_url_test_timeout")]
    pub timeout: u64,
    /// Tolerance (ms, default 50ms, switch only if latency diff > tolerance) / 容忍度（毫秒，默认 50ms）
    #[serde(default = "default_url_test_tolerance")]
    pub tolerance: u64,
    /// Check availability on startup / 是否在启动时检查可用性
    #[serde(default)]
    pub interrupt_exist_connections: bool,
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

/// TLS configuration for outbound connections
/// 出站连接的 TLS 配置
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// Enable TLS / 启用 TLS
    #[serde(default)]
    pub enabled: bool,
    /// Server Name Indication (SNI)
    #[serde(default)]
    pub sni: Option<String>,
    /// Application Layer Protocol Negotiation (ALPN)
    #[serde(default)]
    pub alpn: Option<String>,
    /// Skip certificate verification (insecure) / 跳过证书校验（不安全）
    #[serde(default)]
    pub insecure: bool,
    /// REALITY TLS configuration / REALITY TLS 配置
    #[serde(default)]
    pub reality: Option<RealityConfig>,
    /// ECH (Encrypted Client Hello) configuration / ECH 配置
    #[serde(default)]
    pub ech: Option<EchConfig>,
}

/// REALITY TLS configuration
/// REALITY TLS 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    /// Enable REALITY / 启用 REALITY
    #[serde(default)]
    pub enabled: bool,
    /// Server public key (64-character hex string) / 服务端公钥
    pub public_key: String,
    /// Short ID (0-16 character hex string) / Short ID
    #[serde(default)]
    pub short_id: Option<String>,
    /// Server name for SNI / SNI 服务端名称
    pub server_name: String,
}

/// ECH (Encrypted Client Hello) configuration
/// ECH (加密 Client Hello) 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EchConfig {
    /// Enable ECH / 启用 ECH
    #[serde(default)]
    pub enabled: bool,
    /// ECH configuration list (base64 encoded) / ECH 配置列表 (Base64 编码)
    #[serde(default)]
    pub config: Option<String>,
    /// Enable post-quantum signature schemes / 启用后量子签名方案
    #[serde(default)]
    pub pq_signature_schemes_enabled: bool,
    /// Disable dynamic record sizing / 禁用动态记录大小调整
    #[serde(default)]
    pub dynamic_record_sizing_disabled: Option<bool>,
}

/// Transport configuration for V2Ray protocols (VMess, VLESS, Trojan)
/// V2Ray 协议 (VMess, VLESS, Trojan) 的传输配置
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        #[serde(default = "default_ws_path")]
        path: String,
        /// Custom headers / 自定义请求头
        #[serde(default)]
        headers: Option<std::collections::HashMap<String, String>>,
        /// Maximum message size in bytes / 最大消息大小 (字节)
        #[serde(default)]
        max_message_size: Option<usize>,
        /// Maximum frame size in bytes / 最大帧大小 (字节)
        #[serde(default)]
        max_frame_size: Option<usize>,
    },
    /// gRPC bidirectional streaming
    /// gRPC 双向流
    #[serde(rename = "grpc")]
    Grpc {
        /// Service name / 服务名称
        #[serde(default = "default_grpc_service")]
        service_name: String,
        /// Method name / 方法名称
        #[serde(default = "default_grpc_method")]
        method_name: String,
        /// Custom metadata / 自定义元数据
        #[serde(default)]
        metadata: Option<std::collections::HashMap<String, String>>,
    },
    /// HTTP/1.1 Upgrade
    /// HTTP/1.1 Upgrade
    #[serde(rename = "httpupgrade")]
    HttpUpgrade {
        /// Path / 路径
        #[serde(default = "default_httpupgrade_path")]
        path: String,
        /// Custom headers / 自定义请求头
        #[serde(default)]
        headers: Option<std::collections::HashMap<String, String>>,
    },
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexConfig {
    /// Enable multiplex / 启用多路复用
    #[serde(default)]
    pub enabled: bool,
    /// Protocol (only "yamux" supported) / 协议 (仅支持 "yamux")
    #[serde(default = "default_multiplex_protocol")]
    pub protocol: String,
    /// Maximum connections in pool / 连接池最大连接数
    #[serde(default = "default_multiplex_max_connections")]
    pub max_connections: usize,
    /// Minimum connections to keep alive / 最小保活连接数
    #[serde(default = "default_multiplex_min_streams")]
    pub min_streams: usize,
    /// Maximum streams per connection / 单连接最大流数
    #[serde(default = "default_multiplex_max_streams")]
    pub max_streams: usize,
    /// Padding (bytes) / 填充 (字节)
    #[serde(default)]
    pub padding: bool,
    /// Brutal congestion control configuration / Brutal 拥塞控制配置
    #[serde(default)]
    pub brutal: Option<BrutalConfig>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrutalConfig {
    /// Enable brutal congestion control / 启用 Brutal 拥塞控制
    #[serde(default)]
    pub enabled: bool,
    /// Upload bandwidth in Mbps / 上传带宽 (Mbps)
    #[serde(default)]
    pub up_mbps: u32,
    /// Download bandwidth in Mbps / 下载带宽 (Mbps)
    #[serde(default)]
    pub down_mbps: u32,
}
