//! Outbound 配置模型
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Outbound {
    /// 直连
    Direct(DirectConfig),
    /// 上游 HTTP 代理（CONNECT）
    Http(HttpProxyConfig),
    /// 上游 SOCKS5
    Socks5(Socks5Config),
    /// VMess 协议
    Vmess(VmessConfig),
    /// VLESS 协议
    Vless(VlessConfig),
    /// TUIC 协议
    Tuic(TuicConfig),
    /// 手动选择器
    Selector(SelectorConfig),
    /// 自动选择器（基于延迟）
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
    /// 代理地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// Basic 认证（可选）
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessConfig {
    /// 服务器地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// 用户 UUID
    pub uuid: String,
    /// 加密方式 (auto, aes-128-gcm, chacha20-poly1305, none)
    #[serde(default = "default_vmess_security")]
    pub security: String,
    /// AlterId (legacy, should be 0 for AEAD)
    #[serde(default)]
    pub alter_id: u16,
    /// 全局填充
    #[serde(default)]
    pub global_padding: bool,
    /// 认证长度
    #[serde(default)]
    pub authenticated_length: bool,
    /// 网络类型
    #[serde(default)]
    pub network: Option<Vec<String>>,
    /// 数据包编码
    #[serde(default)]
    pub packet_encoding: Option<String>,
    /// 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
}

fn default_vmess_security() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessConfig {
    /// 服务器地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// 用户 UUID
    pub uuid: String,
    /// 流控模式 (xtls-rprx-vision)
    #[serde(default)]
    pub flow: Option<String>,
    /// 网络类型 (tcp, udp)
    #[serde(default = "default_vless_network")]
    pub network: String,
    /// 数据包编码 (packetaddr, xudp)
    #[serde(default)]
    pub packet_encoding: Option<String>,
    /// 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
}

fn default_vless_network() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicConfig {
    /// 服务器地址 host:port
    pub server: String,
    #[serde(default)]
    pub tag: Option<String>,
    /// 用户 UUID
    pub uuid: String,
    /// 密码
    pub password: String,
    /// 拥塞控制算法 (bbr, cubic, new_reno)
    #[serde(default = "default_tuic_congestion_control")]
    pub congestion_control: String,
    /// UDP 中继模式 (native, quic)
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    /// UDP over Stream
    #[serde(default)]
    pub udp_over_stream: bool,
    /// 0-RTT 握手
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    /// 心跳间隔 (毫秒)
    #[serde(default = "default_tuic_heartbeat")]
    pub heartbeat: u64,
    /// 建连超时秒（可选）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// 认证超时秒（可选）
    #[serde(default)]
    pub auth_timeout_sec: Option<u64>,
    /// 网络类型
    #[serde(default)]
    pub network: Option<Vec<String>>,
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
    /// 候选出站列表（按 tag 引用）
    pub outbounds: Vec<String>,
    /// 默认选中的出站（可选）
    #[serde(default)]
    pub default: Option<String>,
    /// 是否在启动时检查可用性
    #[serde(default)]
    pub interrupt_exist_connections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlTestConfig {
    #[serde(default)]
    pub tag: Option<String>,
    /// 候选出站列表（按 tag 引用）
    pub outbounds: Vec<String>,
    /// 测试 URL（默认 http://www.gstatic.com/generate_204）
    #[serde(default = "default_url_test_url")]
    pub url: String,
    /// 测试间隔（秒，默认 60）
    #[serde(default = "default_url_test_interval")]
    pub interval: u64,
    /// 超时时间（秒，默认 5）
    #[serde(default = "default_url_test_timeout")]
    pub timeout: u64,
    /// 容忍度（毫秒，默认 50ms，延迟差距小于此值不切换）
    #[serde(default = "default_url_test_tolerance")]
    pub tolerance: u64,
    /// 是否在启动时检查可用性
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
