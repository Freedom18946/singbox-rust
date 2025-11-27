//! Common types and data structures for API services
//! API 服务的通用类型和数据结构
//!
//! # Strategic Role / 战略角色
//!
//! This module defines the "contract" between the singbox-rust backend and external clients
//! (dashboards, CLIs). These structures are serialized to JSON and sent over the wire.
//! Any changes here directly affect the API compatibility.
//!
//! 本模块定义了 singbox-rust 后端与外部客户端（仪表盘、命令行工具）之间的“契约”。
//! 这些结构体被序列化为 JSON 并通过网络发送。此处的任何更改都会直接影响 API 兼容性。

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};

/// Connection information for API responses
/// API 响应的连接信息
///
/// Represents a snapshot of a connection at a specific point in time.
/// 表示特定时间点连接的快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Unique connection ID
    /// 唯一连接 ID
    pub id: String,
    /// Connection metadata
    /// 连接元数据
    pub metadata: ConnectionMetadata,
    /// Bytes uploaded
    /// 上传字节数
    pub upload: u64,
    /// Bytes downloaded
    /// 下载字节数
    pub download: u64,
    /// Connection start time (Unix timestamp in milliseconds)
    /// 连接开始时间（Unix 时间戳，毫秒）
    pub start: String,
    /// Proxy chain used for this connection
    /// 用于此连接的代理链
    pub chains: Vec<String>,
    /// Matched rule name
    /// 匹配的规则名称
    pub rule: String,
    /// Rule payload/pattern
    /// 规则载荷/模式
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
}

/// Detailed connection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMetadata {
    /// Network protocol (tcp/udp)
    /// 网络协议（tcp/udp）
    pub network: String,
    /// Connection type (HTTP/HTTPS/SOCKS5, etc.)
    /// 连接类型（HTTP/HTTPS/SOCKS5 等）
    pub r#type: String,
    /// Source IP address
    /// 源 IP 地址
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    /// Source port
    /// 源端口
    #[serde(rename = "sourcePort")]
    pub source_port: String,
    /// Destination IP address
    /// 目的 IP 地址
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    /// Destination port
    /// 目的端口
    #[serde(rename = "destinationPort")]
    pub destination_port: String,
    /// Inbound IP address
    /// 入站 IP 地址
    #[serde(rename = "inboundIP")]
    pub inbound_ip: String,
    /// Inbound port
    /// 入站端口
    #[serde(rename = "inboundPort")]
    pub inbound_port: String,
    /// Inbound adapter name
    /// 入站适配器名称
    #[serde(rename = "inboundName")]
    pub inbound_name: String,
    /// Inbound user (if applicable)
    /// 入站用户（如果适用）
    #[serde(rename = "inboundUser")]
    pub inbound_user: String,
    /// Target hostname
    /// 目标主机名
    pub host: String,
    /// DNS resolution mode
    /// DNS 解析模式
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
    /// Process UID (Unix systems)
    /// 进程 UID（Unix 系统）
    pub uid: u32,
    /// Process name
    /// 进程名称
    pub process: String,
    /// Process executable path
    /// 进程可执行文件路径
    #[serde(rename = "processPath")]
    pub process_path: String,
    /// Special proxy information
    /// 特殊代理信息
    #[serde(rename = "specialProxy")]
    pub special_proxy: String,
    /// Special rules applied
    /// 应用的特殊规则
    #[serde(rename = "specialRules")]
    pub special_rules: String,
    /// Remote destination address
    /// 远程目的地址
    #[serde(rename = "remoteDestination")]
    pub remote_destination: String,
    /// SNI host (TLS connections)
    /// SNI 主机（TLS 连接）
    #[serde(rename = "sniffHost")]
    pub sniff_host: String,
}

/// Proxy/Outbound information
/// 代理/出站信息
///
/// Used to display proxy nodes and groups in the dashboard.
/// 用于在仪表盘中显示代理节点和组。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    /// Proxy name/tag
    /// 代理名称/标签
    pub name: String,
    /// Proxy type (direct, http, socks5, vmess, etc.)
    /// 代理类型（direct, http, socks5, vmess 等）
    pub r#type: String,
    /// All available proxies (for groups)
    /// 所有可用代理（用于组）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<String>,
    /// Currently selected proxy (for groups)
    /// 当前选定的代理（用于组）
    pub now: String,
    /// Proxy health status
    /// 代理健康状态
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alive: Option<bool>,
    /// Latency in milliseconds
    /// 延迟（毫秒）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<u32>,
    /// Additional proxy metadata
    /// 额外代理元数据
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Request to select a proxy
#[derive(Debug, Deserialize)]
pub struct SelectProxyRequest {
    /// Name of the proxy to select
    /// 要选择的代理名称
    pub name: String,
}

/// Traffic statistics
/// 流量统计
///
/// Global traffic counters sent via WebSocket to update dashboard graphs.
/// 通过 WebSocket 发送的全局流量计数器，用于更新仪表盘图表。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficStats {
    /// Total bytes uploaded
    /// 总上传字节数
    pub up: u64,
    /// Total bytes downloaded
    /// 总下载字节数
    pub down: u64,
    /// Upload speed (bytes per second)
    /// 上传速度（字节/秒）
    #[serde(rename = "upSpeed")]
    pub up_speed: u64,
    /// Download speed (bytes per second)
    /// 下载速度（字节/秒）
    #[serde(rename = "downSpeed")]
    pub down_speed: u64,
    /// Timestamp when these stats were recorded
    /// 记录这些统计信息的时间戳
    pub timestamp: u64,
}

impl TrafficStats {
    /// Add traffic data to current statistics
    pub fn add_traffic(&self, upload: u64, download: u64) {
        // Note: In a real implementation, this would need proper atomic operations
        // For now, this is a placeholder for the interface
        log::trace!("Traffic update: +{} up, +{} down", upload, download);
    }
}

/// Log entry
/// 日志条目
///
/// A single log line sent via WebSocket.
/// 通过 WebSocket 发送的单行日志。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Log level (info, warn, error, debug)
    /// 日志级别（info, warn, error, debug）
    pub r#type: String,
    /// Log message
    /// 日志消息
    pub payload: String,
    /// Timestamp (Unix timestamp in milliseconds)
    /// 时间戳（Unix 时间戳，毫秒）
    pub timestamp: u64,
    /// Log source/component
    /// 日志来源/组件
    pub source: String,
    /// Associated connection ID (if applicable)
    /// 关联的连接 ID（如果适用）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
}

/// Rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule type (DOMAIN, DOMAIN-SUFFIX, IP-CIDR, etc.)
    /// 规则类型（DOMAIN, DOMAIN-SUFFIX, IP-CIDR 等）
    pub r#type: String,
    /// Rule payload/pattern
    /// 规则载荷/模式
    pub payload: String,
    /// Target proxy/action
    /// 目标代理/动作
    pub proxy: String,
    /// Rule priority/order
    /// 规则优先级/顺序
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<u32>,
}

/// Configuration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// HTTP proxy port
    /// HTTP 代理端口
    pub port: u16,
    /// SOCKS proxy port
    /// SOCKS 代理端口
    #[serde(rename = "socks-port")]
    pub socks_port: u16,
    /// HTTP proxy port (alternative field name)
    /// HTTP 代理端口（备用字段名）
    #[serde(rename = "mixed-port", skip_serializing_if = "Option::is_none")]
    pub mixed_port: Option<u16>,
    /// API server port
    /// API 服务器端口
    #[serde(rename = "controller-port", skip_serializing_if = "Option::is_none")]
    pub controller_port: Option<u16>,
    /// API server address
    /// API 服务器地址
    #[serde(
        rename = "external-controller",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_controller: Option<String>,
    /// Additional configuration
    /// 额外配置
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Provider information (for proxy/rule providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    /// Provider name
    /// 提供者名称
    pub name: String,
    /// Provider type (Proxy/Rule)
    /// 提供者类型（代理/规则）
    pub r#type: String,
    /// Vehicle type (HTTP/File)
    /// 载体类型（HTTP/文件）
    pub vehicle_type: String,
    /// Behavior (rule providers only)
    /// 行为（仅规则提供者）
    pub behavior: String,
    /// Last update time
    /// 上次更新时间
    pub updated_at: String,
    /// Subscription information
    /// 订阅信息
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_info: Option<SubscriptionInfo>,
    /// Proxies (proxy providers only)
    /// 代理（仅代理提供者）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<Proxy>,
    /// Rules (rule providers only)
    /// 规则（仅规则提供者）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

/// Subscription information for providers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionInfo {
    /// Bytes uploaded
    /// 上传字节数
    pub upload: u64,
    /// Bytes downloaded
    /// 下载字节数
    pub download: u64,
    /// Total bandwidth limit
    /// 总带宽限制
    pub total: u64,
    /// Expiration timestamp
    /// 过期时间戳
    pub expire: u64,
}

/// WebSocket message types for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    /// Traffic statistics update
    /// 流量统计更新
    #[serde(rename = "traffic")]
    Traffic(TrafficStats),
    /// Log entry
    /// 日志条目
    #[serde(rename = "log")]
    Log(LogEntry),
    /// Connection update
    /// 连接更新
    #[serde(rename = "connection")]
    Connection {
        /// Connection change type (new, closed, updated)
        /// 连接变更类型（新建、关闭、更新）
        action: String,
        /// Connection data
        /// 连接数据
        connection: Box<Connection>,
    },
    /// Heartbeat/ping message
    /// 心跳/Ping 消息
    #[serde(rename = "ping")]
    /// Client-side ping with UNIX timestamp.
    /// 带有 UNIX 时间戳的客户端 Ping。
    Ping {
        /// UNIX timestamp in milliseconds.
        /// UNIX 时间戳（毫秒）。
        timestamp: u64,
    },
    /// Response to client requests
    /// 对客户端请求的响应
    #[serde(rename = "response")]
    Response {
        /// Request ID for correlation
        /// 用于关联的请求 ID
        request_id: String,
        /// Response data
        /// 响应数据
        data: serde_json::Value,
    },
}

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Listen address for API server
    /// API 服务器监听地址
    pub listen_addr: SocketAddr,
    /// Enable CORS
    /// 启用 CORS
    pub enable_cors: bool,
    /// Allowed origins for CORS (None = allow all)
    /// 允许的 CORS 源（None = 允许所有）
    pub cors_origins: Option<Vec<String>>,
    /// API authentication token
    /// API 认证令牌
    pub auth_token: Option<String>,
    /// Enable traffic WebSocket
    /// 启用流量 WebSocket
    pub enable_traffic_ws: bool,
    /// Enable logs WebSocket
    /// 启用日志 WebSocket
    pub enable_logs_ws: bool,
    /// Traffic broadcast interval in milliseconds
    /// 流量广播间隔（毫秒）
    pub traffic_broadcast_interval_ms: u64,
    /// Log buffer size
    /// 日志缓冲区大小
    pub log_buffer_size: usize,
}
