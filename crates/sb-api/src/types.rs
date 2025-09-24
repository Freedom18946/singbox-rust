//! Common types and data structures for API services

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, time::SystemTime};

/// Connection information for API responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    /// Unique connection ID
    pub id: String,
    /// Connection metadata
    pub metadata: ConnectionMetadata,
    /// Bytes uploaded
    pub upload: u64,
    /// Bytes downloaded
    pub download: u64,
    /// Connection start time (Unix timestamp in milliseconds)
    pub start: String,
    /// Proxy chain used for this connection
    pub chains: Vec<String>,
    /// Matched rule name
    pub rule: String,
    /// Rule payload/pattern
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
}

/// Detailed connection metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionMetadata {
    /// Network protocol (tcp/udp)
    pub network: String,
    /// Connection type (HTTP/HTTPS/SOCKS5, etc.)
    pub r#type: String,
    /// Source IP address
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    /// Source port
    #[serde(rename = "sourcePort")]
    pub source_port: String,
    /// Destination IP address
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    /// Destination port
    #[serde(rename = "destinationPort")]
    pub destination_port: String,
    /// Inbound IP address
    #[serde(rename = "inboundIP")]
    pub inbound_ip: String,
    /// Inbound port
    #[serde(rename = "inboundPort")]
    pub inbound_port: String,
    /// Inbound adapter name
    #[serde(rename = "inboundName")]
    pub inbound_name: String,
    /// Inbound user (if applicable)
    #[serde(rename = "inboundUser")]
    pub inbound_user: String,
    /// Target hostname
    pub host: String,
    /// DNS resolution mode
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
    /// Process UID (Unix systems)
    pub uid: u32,
    /// Process name
    pub process: String,
    /// Process executable path
    #[serde(rename = "processPath")]
    pub process_path: String,
    /// Special proxy information
    #[serde(rename = "specialProxy")]
    pub special_proxy: String,
    /// Special rules applied
    #[serde(rename = "specialRules")]
    pub special_rules: String,
    /// Remote destination address
    #[serde(rename = "remoteDestination")]
    pub remote_destination: String,
    /// SNI host (TLS connections)
    #[serde(rename = "sniffHost")]
    pub sniff_host: String,
}

/// Proxy/Outbound information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    /// Proxy name/tag
    pub name: String,
    /// Proxy type (direct, http, socks5, vmess, etc.)
    pub r#type: String,
    /// All available proxies (for groups)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<String>,
    /// Currently selected proxy (for groups)
    pub now: String,
    /// Proxy health status
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alive: Option<bool>,
    /// Latency in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<u32>,
    /// Additional proxy metadata
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Request to select a proxy
#[derive(Debug, Deserialize)]
pub struct SelectProxyRequest {
    /// Name of the proxy to select
    pub name: String,
}

/// Traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    /// Total bytes uploaded
    pub up: u64,
    /// Total bytes downloaded
    pub down: u64,
    /// Upload speed (bytes per second)
    #[serde(rename = "upSpeed")]
    pub up_speed: u64,
    /// Download speed (bytes per second)
    #[serde(rename = "downSpeed")]
    pub down_speed: u64,
    /// Timestamp when these stats were recorded
    pub timestamp: u64,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Log level (info, warn, error, debug)
    pub r#type: String,
    /// Log message
    pub payload: String,
    /// Timestamp (Unix timestamp in milliseconds)
    pub timestamp: u64,
    /// Log source/component
    pub source: String,
    /// Associated connection ID (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
}

/// Rule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule type (DOMAIN, DOMAIN-SUFFIX, IP-CIDR, etc.)
    pub r#type: String,
    /// Rule payload/pattern
    pub payload: String,
    /// Target proxy/action
    pub proxy: String,
    /// Rule priority/order
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<u32>,
}

/// Configuration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// HTTP proxy port
    pub port: u16,
    /// SOCKS proxy port
    #[serde(rename = "socks-port")]
    pub socks_port: u16,
    /// HTTP proxy port (alternative field name)
    #[serde(rename = "mixed-port", skip_serializing_if = "Option::is_none")]
    pub mixed_port: Option<u16>,
    /// API server port
    #[serde(rename = "controller-port", skip_serializing_if = "Option::is_none")]
    pub controller_port: Option<u16>,
    /// API server address
    #[serde(
        rename = "external-controller",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_controller: Option<String>,
    /// Additional configuration
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Provider information (for proxy/rule providers)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    /// Provider name
    pub name: String,
    /// Provider type (Proxy/Rule)
    pub r#type: String,
    /// Vehicle type (HTTP/File)
    pub vehicle_type: String,
    /// Behavior (rule providers only)
    pub behavior: String,
    /// Last update time
    pub updated_at: String,
    /// Subscription information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_info: Option<SubscriptionInfo>,
    /// Proxies (proxy providers only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<Proxy>,
    /// Rules (rule providers only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

/// Subscription information for providers
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionInfo {
    /// Bytes uploaded
    pub upload: u64,
    /// Bytes downloaded
    pub download: u64,
    /// Total bandwidth limit
    pub total: u64,
    /// Expiration timestamp
    pub expire: u64,
}

/// WebSocket message types for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    /// Traffic statistics update
    #[serde(rename = "traffic")]
    Traffic(TrafficStats),
    /// Log entry
    #[serde(rename = "log")]
    Log(LogEntry),
    /// Connection update
    #[serde(rename = "connection")]
    Connection {
        /// Connection change type (new, closed, updated)
        action: String,
        /// Connection data
        connection: Connection,
    },
    /// Heartbeat/ping message
    #[serde(rename = "ping")]
    Ping { timestamp: u64 },
    /// Response to client requests
    #[serde(rename = "response")]
    Response {
        /// Request ID for correlation
        request_id: String,
        /// Response data
        data: serde_json::Value,
    },
}

/// API server configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Listen address for API server
    pub listen_addr: SocketAddr,
    /// Enable CORS
    pub enable_cors: bool,
    /// Allowed origins for CORS (None = allow all)
    pub cors_origins: Option<Vec<String>>,
    /// API authentication token
    pub auth_token: Option<String>,
    /// Enable traffic WebSocket
    pub enable_traffic_ws: bool,
    /// Enable logs WebSocket
    pub enable_logs_ws: bool,
    /// Traffic broadcast interval in milliseconds
    pub traffic_broadcast_interval_ms: u64,
    /// Log buffer size
    pub log_buffer_size: usize,
}
