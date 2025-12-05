//! Configuration format conversion utilities.
//! 配置格式转换工具。
//!
//! This module provides utilities for converting between different
//! proxy configuration formats (Clash, Surge, Quantumult, etc.) and
//! the native sing-box format.
//!
//! # Supported Formats
//!
//! - Clash YAML
//! - Surge configuration
//! - Quantumult X
//! - Shadowrocket
//! - V2Ray JSON
//! - Subscription URLs (base64)

use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use tracing::warn;

/// Supported configuration formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigFormat {
    /// Native sing-box JSON format.
    SingBox,
    /// Clash YAML format.
    Clash,
    /// Surge configuration format.
    Surge,
    /// Quantumult X format.
    QuantumultX,
    /// Shadowrocket format.
    Shadowrocket,
    /// V2Ray JSON format.
    V2Ray,
    /// Plain subscription URL list (base64 encoded).
    Subscription,
    /// Unknown format.
    Unknown,
}

impl ConfigFormat {
    /// Detect format from content.
    pub fn detect(content: &str) -> Self {
        let trimmed = content.trim();

        // Check for JSON (sing-box or v2ray)
        if trimmed.starts_with('{') {
            if trimmed.contains("\"inbounds\"") || trimmed.contains("\"outbounds\"") {
                if trimmed.contains("\"log\"") && trimmed.contains("\"dns\"") {
                    return Self::SingBox;
                }
                return Self::V2Ray;
            }
            return Self::SingBox;
        }

        // Check for YAML (Clash)
        if trimmed.starts_with("proxies:") || trimmed.contains("\nproxies:") {
            return Self::Clash;
        }
        if trimmed.starts_with("proxy-groups:") || trimmed.contains("\nproxy-groups:") {
            return Self::Clash;
        }

        // Check for Surge
        if trimmed.starts_with("[General]") || trimmed.contains("\n[Proxy]") {
            return Self::Surge;
        }

        // Check for Quantumult X
        if trimmed.starts_with("[server_local]") || trimmed.contains("\n[server_local]") {
            return Self::QuantumultX;
        }

        // Check for base64 subscription
        if is_likely_base64(trimmed) {
            return Self::Subscription;
        }

        Self::Unknown
    }

    /// Get format name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Clash => "Clash",
            Self::Surge => "Surge",
            Self::QuantumultX => "Quantumult X",
            Self::Shadowrocket => "Shadowrocket",
            Self::V2Ray => "V2Ray",
            Self::Subscription => "Subscription",
            Self::Unknown => "Unknown",
        }
    }
}

/// Check if string is likely base64 encoded.
fn is_likely_base64(s: &str) -> bool {
    if s.len() < 6 {
        return false;
    }
    // Must only contain base64 characters and common padding/whitespace
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c.is_whitespace())
}

/// Proxy node parsed from various formats.
#[derive(Debug, Clone, Default)]
pub struct ProxyNode {
    /// Node name/tag.
    pub name: String,
    /// Protocol type (ss, vmess, vless, trojan, etc.).
    pub protocol: String,
    /// Server address.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// Authentication/encryption method.
    pub method: Option<String>,
    /// Password or UUID.
    pub password: Option<String>,
    /// UUID for vmess/vless.
    pub uuid: Option<String>,
    /// Transport type (tcp, ws, grpc, etc.).
    pub transport: Option<String>,
    /// TLS enabled.
    pub tls: bool,
    /// TLS SNI.
    pub sni: Option<String>,
    /// WebSocket path.
    pub ws_path: Option<String>,
    /// WebSocket host.
    pub ws_host: Option<String>,
    /// gRPC service name.
    pub grpc_service: Option<String>,
    /// ALPN protocols.
    pub alpn: Vec<String>,
    /// Skip certificate verification.
    pub skip_cert_verify: bool,
    /// Additional options.
    pub extra: HashMap<String, String>,
}

impl ProxyNode {
    /// Create a new empty proxy node.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse from SS URI (ss://...).
    pub fn from_ss_uri(uri: &str) -> Option<Self> {
        let uri = uri.strip_prefix("ss://")?;

        // Format: base64(method:password)@server:port#name
        // Or: method:password@server:port#name (plain)
        let (main_part, name) = if let Some(idx) = uri.rfind('#') {
            let name = urlencoding::decode(&uri[idx + 1..]).ok()?.to_string();
            (&uri[..idx], name)
        } else {
            (uri, String::new())
        };

        let (userinfo, server_part) = main_part.split_once('@')?;

        // Decode userinfo if base64
        let decoded = if userinfo.contains(':') {
            userinfo.to_string()
        } else {
            let decoded = base64_decode(userinfo)?;
            String::from_utf8(decoded).ok()?
        };

        let (method, password) = decoded.split_once(':')?;
        let (server, port_str) = server_part.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;

        Some(Self {
            name: if name.is_empty() {
                format!("{}:{}", server, port)
            } else {
                name
            },
            protocol: "shadowsocks".to_string(),
            server: server.to_string(),
            port,
            method: Some(method.to_string()),
            password: Some(password.to_string()),
            ..Default::default()
        })
    }

    /// Parse from VMess URI (vmess://...).
    pub fn from_vmess_uri(uri: &str) -> Option<Self> {
        let uri = uri.strip_prefix("vmess://")?;
        let decoded = base64_decode(uri)?;
        let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;

        let obj = json.as_object()?;

        Some(Self {
            name: obj.get("ps")?.as_str()?.to_string(),
            protocol: "vmess".to_string(),
            server: obj.get("add")?.as_str()?.to_string(),
            port: obj
                .get("port")?
                .as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| obj.get("port")?.as_u64().map(|n| n as u16))?,
            uuid: Some(obj.get("id")?.as_str()?.to_string()),
            transport: obj.get("net").and_then(|v| v.as_str()).map(String::from),
            tls: obj.get("tls").and_then(|v| v.as_str()) == Some("tls"),
            sni: obj.get("sni").and_then(|v| v.as_str()).map(String::from),
            ws_path: obj.get("path").and_then(|v| v.as_str()).map(String::from),
            ws_host: obj.get("host").and_then(|v| v.as_str()).map(String::from),
            ..Default::default()
        })
    }

    /// Parse from VLESS URI (vless://...).
    pub fn from_vless_uri(uri: &str) -> Option<Self> {
        let uri = uri.strip_prefix("vless://")?;

        // Format: uuid@server:port?params#name
        let (main_part, name) = if let Some(idx) = uri.rfind('#') {
            let name = urlencoding::decode(&uri[idx + 1..]).ok()?.to_string();
            (&uri[..idx], name)
        } else {
            (uri, String::new())
        };

        let (uuid_server, params) = main_part.split_once('?').unwrap_or((main_part, ""));
        let (uuid, server_port) = uuid_server.split_once('@')?;
        let (server, port_str) = server_port.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;

        let mut node = Self {
            name: if name.is_empty() {
                format!("{}:{}", server, port)
            } else {
                name
            },
            protocol: "vless".to_string(),
            server: server.to_string(),
            port,
            uuid: Some(uuid.to_string()),
            ..Default::default()
        };

        // Parse query parameters
        for param in params.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                let value = urlencoding::decode(value).unwrap_or_default().to_string();
                match key {
                    "type" => node.transport = Some(value),
                    "security" => node.tls = value == "tls",
                    "sni" => node.sni = Some(value),
                    "path" => node.ws_path = Some(value),
                    "host" => node.ws_host = Some(value),
                    "serviceName" => node.grpc_service = Some(value),
                    "alpn" => node.alpn = value.split(',').map(String::from).collect(),
                    _ => {
                        node.extra.insert(key.to_string(), value);
                    }
                }
            }
        }

        Some(node)
    }

    /// Parse from Trojan URI (trojan://...).
    pub fn from_trojan_uri(uri: &str) -> Option<Self> {
        let uri = uri.strip_prefix("trojan://")?;

        // Format: password@server:port?params#name
        let (main_part, name) = if let Some(idx) = uri.rfind('#') {
            let name = urlencoding::decode(&uri[idx + 1..]).ok()?.to_string();
            (&uri[..idx], name)
        } else {
            (uri, String::new())
        };

        let (password_server, params) = main_part.split_once('?').unwrap_or((main_part, ""));
        let (password, server_port) = password_server.split_once('@')?;
        let (server, port_str) = server_port.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;

        let mut node = Self {
            name: if name.is_empty() {
                format!("{}:{}", server, port)
            } else {
                name
            },
            protocol: "trojan".to_string(),
            server: server.to_string(),
            port,
            password: Some(
                urlencoding::decode(password)
                    .unwrap_or_default()
                    .to_string(),
            ),
            tls: true, // Trojan always uses TLS
            ..Default::default()
        };

        // Parse query parameters
        for param in params.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                let value = urlencoding::decode(value).unwrap_or_default().to_string();
                match key {
                    "type" => node.transport = Some(value),
                    "sni" => node.sni = Some(value),
                    "path" => node.ws_path = Some(value),
                    "host" => node.ws_host = Some(value),
                    "serviceName" => node.grpc_service = Some(value),
                    "alpn" => node.alpn = value.split(',').map(String::from).collect(),
                    "allowInsecure" => node.skip_cert_verify = value == "1",
                    _ => {
                        node.extra.insert(key.to_string(), value);
                    }
                }
            }
        }

        Some(node)
    }

    /// Parse from any supported URI.
    pub fn from_uri(uri: &str) -> Option<Self> {
        let uri = uri.trim();
        if uri.starts_with("ss://") {
            Self::from_ss_uri(uri)
        } else if uri.starts_with("vmess://") {
            Self::from_vmess_uri(uri)
        } else if uri.starts_with("vless://") {
            Self::from_vless_uri(uri)
        } else if uri.starts_with("trojan://") {
            Self::from_trojan_uri(uri)
        } else {
            None
        }
    }

    /// Convert to sing-box outbound JSON.
    pub fn to_singbox_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.protocol,
            "tag": self.name,
            "server": self.server,
            "server_port": self.port,
        });

        if let Some(ref method) = self.method {
            obj["method"] = serde_json::json!(method);
        }
        if let Some(ref password) = self.password {
            obj["password"] = serde_json::json!(password);
        }
        if let Some(ref uuid) = self.uuid {
            obj["uuid"] = serde_json::json!(uuid);
        }
        if self.tls {
            obj["tls"] = serde_json::json!({
                "enabled": true,
                "server_name": self.sni.as_deref().unwrap_or(&self.server),
                "insecure": self.skip_cert_verify,
            });
        }
        if let Some(ref transport) = self.transport {
            match transport.as_str() {
                "ws" => {
                    obj["transport"] = serde_json::json!({
                        "type": "ws",
                        "path": self.ws_path.as_deref().unwrap_or("/"),
                        "headers": {
                            "Host": self.ws_host.as_deref().unwrap_or(&self.server)
                        }
                    });
                }
                "grpc" => {
                    obj["transport"] = serde_json::json!({
                        "type": "grpc",
                        "service_name": self.grpc_service.as_deref().unwrap_or("")
                    });
                }
                _ => {}
            }
        }

        obj
    }
}

/// Simple base64 decode.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // Handle URL-safe base64 and padding
    let input = input.replace('-', "+").replace('_', "/");
    let padding = (4 - input.len() % 4) % 4;
    let padded = format!("{}{}", input, "=".repeat(padding));

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for c in padded.chars() {
        if c == '=' {
            break;
        }
        let idx = ALPHABET.iter().position(|&b| b == c as u8)?;
        buffer = (buffer << 6) | (idx as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(result)
}

/// Parse subscription content (base64 encoded URI list).
pub fn parse_subscription(content: &str) -> Vec<ProxyNode> {
    let decoded = match base64_decode(content.trim()) {
        Some(d) => d,
        None => return Vec::new(),
    };

    let text = match String::from_utf8(decoded) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    text.lines()
        .filter_map(|line| ProxyNode::from_uri(line.trim()))
        .collect()
}

/// Configuration converter.
#[derive(Debug, Default)]
pub struct ConfigConverter {
    nodes: Vec<ProxyNode>,
}

impl ConfigConverter {
    /// Create a new converter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse content and detect format automatically.
    pub fn parse(&mut self, content: &str) -> ConfigFormat {
        let format = ConfigFormat::detect(content);

        match format {
            ConfigFormat::Subscription => {
                self.nodes = parse_subscription(content);
            }
            ConfigFormat::Clash => {
                self.parse_clash_yaml(content);
            }
            _ => {}
        }

        format
    }

    /// Parse Clash YAML (`proxies:` block). Falls back to inline parsing on YAML errors.
    fn parse_clash_yaml(&mut self, content: &str) {
        match serde_yaml::from_str::<serde_yaml::Value>(content) {
            Ok(doc) => {
                if let Some(proxies) = doc.get("proxies").and_then(|v| v.as_sequence()) {
                    for entry in proxies {
                        if let Some(node) = clash_entry_to_node(entry) {
                            self.nodes.push(node);
                        }
                    }
                } else {
                    warn!("Clash YAML contains no proxies section");
                }
            }
            Err(e) => {
                warn!("Failed to parse Clash YAML: {e}; falling back to inline proxy parser");
                self.parse_clash_inline(content);
            }
        }
    }

    /// Fallback parser that handles inline Clash YAML proxy lines.
    fn parse_clash_inline(&mut self, content: &str) {
        let mut in_proxies = false;

        for line in content.lines() {
            let trimmed = line.trim();

            if trimmed == "proxies:" {
                in_proxies = true;
                continue;
            }

            if in_proxies {
                if !trimmed.starts_with('-') && trimmed.contains(':') && !trimmed.starts_with('#') {
                    in_proxies = false;
                    continue;
                }

                // Parse individual proxy entry (simplified)
                if trimmed.starts_with("- {") || trimmed.starts_with("-{") {
                    if let Some(node) = self.parse_clash_proxy_line(trimmed) {
                        self.nodes.push(node);
                    }
                }
            }
        }
    }

    /// Parse a single Clash proxy line (inline YAML).
    /// Parse a single Clash proxy line.
    fn parse_clash_proxy_line(&self, line: &str) -> Option<ProxyNode> {
        let line = line.trim_start_matches('-').trim();
        let line = line.trim_start_matches('{').trim_end_matches('}');

        let mut node = ProxyNode::new();

        for part in line.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once(':') {
                let key = key.trim();
                let value = value.trim().trim_matches('"').trim_matches('\'');

                match key {
                    "name" => node.name = value.to_string(),
                    "type" => node.protocol = value.to_string(),
                    "server" => node.server = value.to_string(),
                    "port" => node.port = value.parse().unwrap_or(0),
                    "cipher" | "method" => node.method = Some(value.to_string()),
                    "password" => node.password = Some(value.to_string()),
                    "uuid" => node.uuid = Some(value.to_string()),
                    "tls" => node.tls = value == "true",
                    "sni" | "servername" => node.sni = Some(value.to_string()),
                    "network" => node.transport = Some(value.to_string()),
                    "ws-path" => node.ws_path = Some(value.to_string()),
                    "ws-headers" => {} // Skip complex parsing
                    _ => {}
                }
            }
        }

        if !node.server.is_empty() && node.port > 0 {
            if node.name.is_empty() {
                node.name = format!("{}:{}", node.server, node.port);
            }
            Some(node)
        } else {
            None
        }
    }

    /// Get parsed nodes.
    pub fn nodes(&self) -> &[ProxyNode] {
        &self.nodes
    }

    /// Convert all nodes to sing-box configuration.
    pub fn to_singbox_config(&self) -> serde_json::Value {
        let outbounds: Vec<_> = self.nodes.iter().map(|n| n.to_singbox_json()).collect();

        serde_json::json!({
            "outbounds": outbounds
        })
    }
}

fn clash_entry_to_node(entry: &YamlValue) -> Option<ProxyNode> {
    let map = entry.as_mapping()?;

    let mut node = ProxyNode::new();
    node.name = string_field(map, "name").unwrap_or_default();
    node.protocol = string_field(map, "type").unwrap_or_default();
    node.server = string_field(map, "server").unwrap_or_default();
    node.port = u16_field(map, "port").unwrap_or(0);

    // Common auth fields
    node.method = string_field(map, "cipher").or_else(|| string_field(map, "method"));
    node.password = string_field(map, "password");
    node.uuid = string_field(map, "uuid");

    // TLS and SNI
    if bool_field(map, "tls").unwrap_or(false) {
        node.tls = true;
    }
    node.skip_cert_verify = bool_field(map, "skip-cert-verify").unwrap_or(false);
    node.sni = string_field(map, "sni").or_else(|| string_field(map, "servername"));

    // Transport options
    node.transport = string_field(map, "network");
    if let Some(ws_opts) = map
        .get(&YamlValue::String("ws-opts".into()))
        .and_then(|v| v.as_mapping())
    {
        node.ws_path = string_field(ws_opts, "path");
        if let Some(headers) = ws_opts
            .get(&YamlValue::String("headers".into()))
            .and_then(|v| v.as_mapping())
        {
            if let Some(host) = headers
                .get(&YamlValue::String("Host".into()))
                .and_then(value_to_string)
            {
                node.ws_host = Some(host);
            }
        }
    }

    if let Some(alpn) = map
        .get(&YamlValue::String("alpn".into()))
        .and_then(|v| v.as_sequence())
    {
        node.alpn = alpn.iter().filter_map(value_to_string).collect();
    }

    if node.server.is_empty() || node.port == 0 {
        return None;
    }

    if node.name.is_empty() {
        node.name = format!("{}:{}", node.server, node.port);
    }

    Some(node)
}

fn string_field(map: &serde_yaml::Mapping, key: &str) -> Option<String> {
    map.get(&YamlValue::String(key.to_string()))
        .and_then(value_to_string)
}

fn u16_field(map: &serde_yaml::Mapping, key: &str) -> Option<u16> {
    map.get(&YamlValue::String(key.to_string()))
        .and_then(|v| match v {
            YamlValue::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
            YamlValue::String(s) => s.parse::<u16>().ok(),
            _ => None,
        })
}

fn bool_field(map: &serde_yaml::Mapping, key: &str) -> Option<bool> {
    map.get(&YamlValue::String(key.to_string()))
        .and_then(|v| match v {
            YamlValue::Bool(b) => Some(*b),
            YamlValue::String(s) => {
                if s.eq_ignore_ascii_case("true") {
                    Some(true)
                } else if s.eq_ignore_ascii_case("false") {
                    Some(false)
                } else {
                    None
                }
            }
            _ => None,
        })
}

fn value_to_string(v: &YamlValue) -> Option<String> {
    match v {
        YamlValue::String(s) => Some(s.clone()),
        YamlValue::Number(n) => Some(n.to_string()),
        YamlValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_detection() {
        assert_eq!(
            ConfigFormat::detect("{\"inbounds\": [], \"outbounds\": [], \"log\": {}, \"dns\": {}}"),
            ConfigFormat::SingBox
        );
        assert_eq!(
            ConfigFormat::detect("proxies:\n  - name: test"),
            ConfigFormat::Clash
        );
        assert_eq!(
            ConfigFormat::detect("[General]\n[Proxy]"),
            ConfigFormat::Surge
        );
        assert_eq!(ConfigFormat::detect("c3M6Ly8="), ConfigFormat::Subscription);
    }

    #[test]
    fn test_parse_ss_uri() {
        let uri = "ss://YWVzLTI1Ni1nY206dGVzdA==@1.2.3.4:8388#TestNode";
        let node = ProxyNode::from_ss_uri(uri);
        assert!(node.is_some());

        let node = node.unwrap();
        assert_eq!(node.protocol, "shadowsocks");
        assert_eq!(node.server, "1.2.3.4");
        assert_eq!(node.port, 8388);
        assert_eq!(node.method, Some("aes-256-gcm".to_string()));
        assert_eq!(node.password, Some("test".to_string()));
        assert_eq!(node.name, "TestNode");
    }

    #[test]
    fn test_parse_trojan_uri() {
        let uri = "trojan://password123@server.com:443?sni=example.com#MyTrojan";
        let node = ProxyNode::from_trojan_uri(uri);
        assert!(node.is_some());

        let node = node.unwrap();
        assert_eq!(node.protocol, "trojan");
        assert_eq!(node.server, "server.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.password, Some("password123".to_string()));
        assert!(node.tls);
        assert_eq!(node.sni, Some("example.com".to_string()));
        assert_eq!(node.name, "MyTrojan");
    }

    #[test]
    fn test_parse_vless_uri() {
        let uri = "vless://uuid-test@server.com:443?type=ws&security=tls&sni=example.com&path=%2Fpath#MyVless";
        let node = ProxyNode::from_vless_uri(uri);
        assert!(node.is_some());

        let node = node.unwrap();
        assert_eq!(node.protocol, "vless");
        assert_eq!(node.uuid, Some("uuid-test".to_string()));
        assert_eq!(node.transport, Some("ws".to_string()));
        assert!(node.tls);
        assert_eq!(node.ws_path, Some("/path".to_string()));
    }

    #[test]
    fn test_base64_decode() {
        let decoded = base64_decode("dGVzdA==");
        assert_eq!(decoded, Some(b"test".to_vec()));

        let decoded = base64_decode("aGVsbG8gd29ybGQ=");
        assert_eq!(decoded, Some(b"hello world".to_vec()));
    }

    #[test]
    fn test_parse_clash_yaml_proxies_section() {
        let yaml = r#"
proxies:
  - name: test-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pass
    tls: true
    sni: example.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: host.test
"#;

        let mut converter = ConfigConverter::new();
        let fmt = converter.parse(yaml);
        assert_eq!(fmt, ConfigFormat::Clash);
        let nodes = converter.nodes();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, "ss");
        assert_eq!(node.server, "1.2.3.4");
        assert_eq!(node.port, 8388);
        assert_eq!(node.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(node.password.as_deref(), Some("pass"));
        assert!(node.tls);
        assert_eq!(node.sni.as_deref(), Some("example.com"));
        assert_eq!(node.transport.as_deref(), Some("ws"));
        assert_eq!(node.ws_path.as_deref(), Some("/ws"));
        assert_eq!(node.ws_host.as_deref(), Some("host.test"));
    }

    #[test]
    fn test_to_singbox_json() {
        let node = ProxyNode {
            name: "test".to_string(),
            protocol: "shadowsocks".to_string(),
            server: "1.2.3.4".to_string(),
            port: 8388,
            method: Some("aes-256-gcm".to_string()),
            password: Some("password".to_string()),
            ..Default::default()
        };

        let json = node.to_singbox_json();
        assert_eq!(json["type"], "shadowsocks");
        assert_eq!(json["server"], "1.2.3.4");
        assert_eq!(json["server_port"], 8388);
    }
}
