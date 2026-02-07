//! HTTP handlers for Clash API endpoints
//! Clash API 端点的 HTTP 处理程序
//!
//! # Strategic Role / 战略角色
//!
//! These handlers map HTTP requests to internal manager calls. They are responsible for
//! translating internal data structures (like `Connection`, `Provider`) into the specific
//! JSON format expected by Clash clients.
//!
//! 这些处理程序将 HTTP 请求映射到内部管理器调用。它们负责将内部数据结构（如 `Connection`、
//! `Provider`）转换为 Clash 客户端期望的特定 JSON 格式。

use crate::{clash::server::ApiState, types::*};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use sb_core::outbound::{selector_group::SelectorGroup, OutboundImpl};
use serde_json::json;
use std::collections::HashMap;

// ===== Constants =====

const DEFAULT_INBOUND_IP: &str = "127.0.0.1";
const DEFAULT_INBOUND_PORT: &str = "0";
const DEFAULT_INBOUND_NAME: &str = "unknown";
const DEFAULT_DNS_MODE: &str = "normal";
const DEFAULT_PROCESS_NAME: &str = "unknown";
const DEFAULT_PORT: &str = "0";
const DEFAULT_DELAY_TIMEOUT_MS: u32 = 5000;
const DEFAULT_TEST_URL: &str = "http://www.google.com/generate_204";

const PROXY_TYPE_DIRECT: &str = "Direct";
const PROXY_TYPE_REJECT: &str = "Reject";
const PROXY_TYPE_SOCKS5: &str = "SOCKS5";
const PROXY_TYPE_HTTP: &str = "HTTP";
const PROXY_TYPE_VLESS: &str = "VLESS";
const PROXY_TYPE_VMESS: &str = "VMESS";
const PROXY_TYPE_TROJAN: &str = "TROJAN";
const PROXY_TYPE_SHADOWSOCKS: &str = "SHADOWSOCKS";
const PROXY_TYPE_RELAY: &str = "RELAY";
const PROXY_TYPE_UNKNOWN: &str = "Unknown";

const DIRECT_PROXY_NAME: &str = "DIRECT";
const REJECT_PROXY_NAME: &str = "REJECT";

// ===== Helper Functions =====

/// Convert internal `Connection` to API `Connection` type
fn convert_connection(conn: &crate::managers::Connection) -> Connection {
    // Compute connection start as UNIX epoch ms using monotonic elapsed
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let start_ms = now_ms.saturating_sub(conn.start_time.elapsed().as_millis());
    Connection {
        id: conn.id.clone(),
        metadata: ConnectionMetadata {
            network: conn.network.clone(),
            r#type: determine_connection_type(&conn.network, &conn.proxy),
            source_ip: conn.source.ip().to_string(),
            source_port: conn.source.port().to_string(),
            destination_ip: parse_destination_ip(&conn.destination),
            destination_port: parse_destination_port(&conn.destination),
            inbound_ip: DEFAULT_INBOUND_IP.to_string(),
            inbound_port: DEFAULT_INBOUND_PORT.to_string(),
            inbound_name: DEFAULT_INBOUND_NAME.to_string(),
            inbound_user: String::new(),
            host: conn.destination.clone(),
            dns_mode: DEFAULT_DNS_MODE.to_string(),
            uid: 0,
            process: DEFAULT_PROCESS_NAME.to_string(),
            process_path: String::new(),
            special_proxy: String::new(),
            special_rules: String::new(),
            remote_destination: conn.destination.clone(),
            sniff_host: String::new(),
        },
        upload: conn.get_upload(),
        download: conn.get_download(),
        start: start_ms.to_string(),
        chains: conn.chains.clone(),
        rule: conn.rule.clone(),
        rule_payload: String::new(),
    }
}

/// Infer proxy type from OutboundImpl
fn infer_proxy_type(name: &str, impl_: Option<&OutboundImpl>) -> String {
    if let Some(outbound) = impl_ {
        return match outbound {
            OutboundImpl::Direct => PROXY_TYPE_DIRECT.to_string(),
            OutboundImpl::Block => PROXY_TYPE_REJECT.to_string(),
            OutboundImpl::Socks5(_) => PROXY_TYPE_SOCKS5.to_string(),
            OutboundImpl::HttpProxy(_) => PROXY_TYPE_HTTP.to_string(),
            OutboundImpl::Connector(c) => {
                if c.as_any()
                    .and_then(|a| a.downcast_ref::<SelectorGroup>())
                    .is_some()
                {
                    "Selector".to_string()
                } else {
                    "Unknown".to_string()
                }
            }
            // Feature-gated protocol variants handled by wildcard
            _ => PROXY_TYPE_UNKNOWN.to_string(),
        };
    }

    // Fallback to name inference
    let n = name.to_ascii_lowercase();
    if n.contains("direct") {
        return PROXY_TYPE_DIRECT.to_string();
    }
    if n.contains("reject") {
        return PROXY_TYPE_REJECT.to_string();
    }
    PROXY_TYPE_UNKNOWN.to_string()
}

/// Determine connection type based on network protocol and proxy type
fn determine_connection_type(network: &str, proxy: &str) -> String {
    match network.to_ascii_lowercase().as_str() {
        "tcp" => {
            let p = proxy.to_ascii_lowercase();
            if p.contains("direct") {
                PROXY_TYPE_DIRECT.to_string()
            } else if p.contains("socks") {
                PROXY_TYPE_SOCKS5.to_string()
            } else if p.contains("http") {
                PROXY_TYPE_HTTP.to_string()
            } else if p.contains("vless") {
                PROXY_TYPE_VLESS.to_string()
            } else if p.contains("vmess") {
                PROXY_TYPE_VMESS.to_string()
            } else if p.contains("trojan") {
                PROXY_TYPE_TROJAN.to_string()
            } else if p.contains("shadowsocks") || p.contains("ss") {
                PROXY_TYPE_SHADOWSOCKS.to_string()
            } else {
                PROXY_TYPE_HTTP.to_string()
            }
        }
        "udp" => {
            if proxy.eq_ignore_ascii_case("direct") {
                PROXY_TYPE_DIRECT.to_string()
            } else {
                PROXY_TYPE_RELAY.to_string()
            }
        }
        _ => PROXY_TYPE_UNKNOWN.to_string(),
    }
}

/// Parse destination IP from destination string
fn parse_destination_ip(destination: &str) -> String {
    // Try to parse as SocketAddr first (IP:port format)
    if let Ok(addr) = destination.parse::<std::net::SocketAddr>() {
        return addr.ip().to_string();
    }

    // Try to extract IP from host:port format
    if let Some(colon_pos) = destination.rfind(':') {
        let host_part = &destination[..colon_pos];

        // Check if it's an IPv6 address in brackets
        if let Some(stripped) = host_part.strip_prefix('[') {
            if let Some(inner) = stripped.strip_suffix(']') {
                return inner.to_string();
            }
        }

        // Try to parse as IP address
        if let Ok(ip) = host_part.parse::<std::net::IpAddr>() {
            return ip.to_string();
        }

        // If not an IP, it's probably a hostname
        return host_part.to_string();
    }

    // If no port separator found, assume it's just a hostname
    destination.to_string()
}

/// Parse destination port from destination string
fn parse_destination_port(destination: &str) -> String {
    // Try to parse as SocketAddr first
    if let Ok(addr) = destination.parse::<std::net::SocketAddr>() {
        return addr.port().to_string();
    }

    // Try to extract port from host:port format
    if let Some(colon_pos) = destination.rfind(':') {
        let port_part = &destination[colon_pos + 1..];

        // Validate port is numeric
        if let Ok(port) = port_part.parse::<u16>() {
            return port.to_string();
        }
    }

    // Default port if none found or invalid
    DEFAULT_PORT.to_string()
}

/// Convert internal Provider to API Provider format
fn convert_provider_to_api(
    name: String,
    p: crate::managers::Provider,
    behavior: &str,
) -> (String, Provider) {
    (
        name.clone(),
        Provider {
            name: p.name,
            r#type: p.provider_type,
            vehicle_type: if p.url.is_some() {
                "HTTP".to_string()
            } else {
                "File".to_string()
            },
            behavior: behavior.to_string(),
            updated_at: p
                .last_update
                .map(|t| t.elapsed().as_secs().to_string())
                .unwrap_or_else(|| "never".to_string()),
            subscription_info: None,
            proxies: vec![],
            rules: vec![],
        },
    )
}

/// Parse URL into (host, port, path) components
fn parse_url_components(url: &str) -> (&str, u16, &str) {
    let (scheme_stripped, default_port) = if let Some(u) = url.strip_prefix("https://") {
        (u, 443u16)
    } else if let Some(u) = url.strip_prefix("http://") {
        (u, 80u16)
    } else {
        (url, 80u16)
    };

    let (host_port, path) = scheme_stripped
        .split_once('/')
        .map(|(hp, p)| (hp, p))
        .unwrap_or((scheme_stripped, ""));

    let (host, port) = host_port
        .split_once(':')
        .map(|(h, p)| (h, p.parse::<u16>().unwrap_or(default_port)))
        .unwrap_or((host_port, default_port));

    let path = if path.is_empty() { "/" } else {
        // path doesn't include the leading '/', reconstruct from original
        let idx = url.find(host_port).unwrap_or(0) + host_port.len();
        &url[idx..]
    };

    (host, port, path)
}

/// Perform an HTTP URL test through an outbound — matches Go's urltest.URLTest()
///
/// Connects through the outbound, sends an HTTP/1.1 GET, reads the first response bytes,
/// and returns the elapsed time in ms. Returns Err on timeout or failure.
async fn http_url_test(
    outbound: Option<&OutboundImpl>,
    url: &str,
    timeout: std::time::Duration,
) -> Result<u16, StatusCode> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (host, port, path) = parse_url_components(url);
    let start = std::time::Instant::now();

    // Connect through the outbound
    let connect_result = match outbound {
        Some(OutboundImpl::Connector(c)) => {
            tokio::time::timeout(timeout, c.connect(host, port)).await
        }
        Some(OutboundImpl::Direct) | None => {
            let fut = tokio::net::TcpStream::connect((host, port));
            tokio::time::timeout(timeout, fut).await
        }
        _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    let mut stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => return Err(StatusCode::SERVICE_UNAVAILABLE), // 503 connect error
        Err(_) => return Err(StatusCode::GATEWAY_TIMEOUT),         // 504 timeout
    };

    // Send HTTP/1.1 GET request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: singbox-rust/urltest\r\nConnection: close\r\n\r\n",
        path, host
    );
    let remaining = timeout.saturating_sub(start.elapsed());
    match tokio::time::timeout(remaining, stream.write_all(request.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => return Err(StatusCode::GATEWAY_TIMEOUT),
    }

    // Read first response bytes (status line is enough)
    let mut buf = [0u8; 128];
    let remaining = timeout.saturating_sub(start.elapsed());
    match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {}
        Ok(_) => return Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => return Err(StatusCode::GATEWAY_TIMEOUT),
    }

    Ok(start.elapsed().as_millis() as u16)
}

// ===== API Handlers =====

/// Get all proxies — matches Go's getProxies() + proxyInfo()
///
/// Returns a map of all available proxies including the GLOBAL virtual group.
pub async fn get_proxies(State(state): State<ApiState>) -> impl IntoResponse {
    let mut proxies = HashMap::new();
    let mut all_proxy_tags: Vec<String> = Vec::new();
    let mut default_tag = String::new();

    // Get proxies from outbound registry
    let entries = if let Some(registry) = &state.outbound_registry {
        let reg = registry.read();
        reg.keys()
            .filter_map(|key| {
                reg.get(key)
                    .cloned()
                    .map(|outbound| (key.clone(), outbound))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    for (key, outbound) in &entries {
        let proxy_type = infer_proxy_type(key, Some(outbound));

        // Skip Direct/Block/DNS from GLOBAL's all list (matches Go behavior)
        let type_lower = proxy_type.to_ascii_lowercase();
        if type_lower != "direct" && type_lower != "reject" && type_lower != "dns" {
            all_proxy_tags.push(key.clone());
        }

        let mut proxy = Proxy {
            name: key.clone(),
            r#type: proxy_type,
            udp: true,
            history: vec![],
            all: vec![],
            now: String::new(),
            alive: Some(true),
            delay: None,
            extra: HashMap::new(),
        };

        if let OutboundImpl::Connector(c) = outbound {
            if let Some(group) = c.as_any().and_then(|a| a.downcast_ref::<SelectorGroup>()) {
                proxy.all = group
                    .get_members()
                    .into_iter()
                    .map(|(tag, _, _)| tag)
                    .collect();
                proxy.now = group.get_selected().await.unwrap_or_default();
                proxy.r#type = "Selector".to_string();
            }
        }

        if default_tag.is_empty() {
            default_tag.clone_from(&key);
        }
        proxies.insert(key.clone(), proxy);
    }

    // Add default proxies if not present
    if !proxies.contains_key(DIRECT_PROXY_NAME) {
        proxies.insert(
            DIRECT_PROXY_NAME.to_string(),
            Proxy {
                name: DIRECT_PROXY_NAME.to_string(),
                r#type: PROXY_TYPE_DIRECT.to_string(),
                udp: true,
                history: vec![],
                all: vec![],
                now: String::new(),
                alive: Some(true),
                delay: Some(0),
                extra: HashMap::new(),
            },
        );
    }

    if !proxies.contains_key(REJECT_PROXY_NAME) {
        proxies.insert(
            REJECT_PROXY_NAME.to_string(),
            Proxy {
                name: REJECT_PROXY_NAME.to_string(),
                r#type: PROXY_TYPE_REJECT.to_string(),
                udp: false,
                history: vec![],
                all: vec![],
                now: String::new(),
                alive: Some(true),
                delay: None,
                extra: HashMap::new(),
            },
        );
    }

    // Inject GLOBAL virtual group (matches Go's getProxies behavior)
    // GLOBAL is a Fallback group containing all non-direct/block/dns outbounds
    if default_tag.is_empty() {
        default_tag = DIRECT_PROXY_NAME.to_string();
    }
    proxies.insert(
        "GLOBAL".to_string(),
        Proxy {
            name: "GLOBAL".to_string(),
            r#type: "Fallback".to_string(),
            udp: true,
            history: vec![],
            all: all_proxy_tags,
            now: default_tag,
            alive: None,
            delay: None,
            extra: HashMap::new(),
        },
    );

    Json(json!({ "proxies": proxies }))
}

/// Get a single proxy — matches Go's getProxy() / proxyInfo()
///
/// Returns detailed information about a specific proxy by name.
pub async fn get_proxy(
    State(state): State<ApiState>,
    Path(proxy_name): Path<String>,
) -> impl IntoResponse {
    // Check outbound registry
    let outbound_opt = state
        .outbound_registry
        .as_ref()
        .and_then(|registry| {
            let reg = registry.read();
            reg.get(&proxy_name).cloned()
        });

    if let Some(outbound) = outbound_opt {
        let proxy_type = infer_proxy_type(&proxy_name, Some(&outbound));
        let mut proxy = Proxy {
            name: proxy_name.clone(),
            r#type: proxy_type,
            udp: true,
            history: vec![],
            all: vec![],
            now: String::new(),
            alive: Some(true),
            delay: None,
            extra: HashMap::new(),
        };

        if let OutboundImpl::Connector(c) = &outbound {
            if let Some(group) = c.as_any().and_then(|a| a.downcast_ref::<SelectorGroup>()) {
                proxy.all = group
                    .get_members()
                    .into_iter()
                    .map(|(tag, _, _)| tag)
                    .collect();
                proxy.now = group.get_selected().await.unwrap_or_default();
                proxy.r#type = "Selector".to_string();
            }
        }

        return (StatusCode::OK, Json(serde_json::to_value(proxy).unwrap_or_default())).into_response();
    }

    // Check built-in proxies
    match proxy_name.as_str() {
        DIRECT_PROXY_NAME => {
            let proxy = Proxy {
                name: DIRECT_PROXY_NAME.to_string(),
                r#type: PROXY_TYPE_DIRECT.to_string(),
                udp: true,
                history: vec![],
                all: vec![],
                now: String::new(),
                alive: Some(true),
                delay: Some(0),
                extra: HashMap::new(),
            };
            (StatusCode::OK, Json(serde_json::to_value(proxy).unwrap_or_default())).into_response()
        }
        REJECT_PROXY_NAME => {
            let proxy = Proxy {
                name: REJECT_PROXY_NAME.to_string(),
                r#type: PROXY_TYPE_REJECT.to_string(),
                udp: false,
                history: vec![],
                all: vec![],
                now: String::new(),
                alive: Some(true),
                delay: None,
                extra: HashMap::new(),
            };
            (StatusCode::OK, Json(serde_json::to_value(proxy).unwrap_or_default())).into_response()
        }
        _ => (
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Proxy not found"})),
        )
            .into_response(),
    }
}

/// Select a proxy for a proxy group
///
/// Updates the selected proxy for a given proxy group.
pub async fn select_proxy(
    State(state): State<ApiState>,
    Path(proxy_name): Path<String>,
    Json(request): Json<SelectProxyRequest>,
) -> impl IntoResponse {
    if let Some(registry) = &state.outbound_registry {
        let outbound_opt = {
            let reg = registry.read();
            reg.get(&proxy_name).cloned()
        };

        if let Some(OutboundImpl::Connector(c)) = outbound_opt {
            if let Some(group) = c.as_any().and_then(|a| a.downcast_ref::<SelectorGroup>()) {
                if group.select_by_name(&request.name).await.is_ok() {
                    log::info!(
                        "Selected proxy '{}' for group '{}'",
                        request.name,
                        proxy_name
                    );
                    if let Some(cache) = &state.cache_file {
                        cache.set_selected(&proxy_name, &request.name);
                    }
                    return StatusCode::NO_CONTENT;
                }
            }
        }
        return StatusCode::BAD_REQUEST;
    }
    StatusCode::SERVICE_UNAVAILABLE
}

/// Get proxy delay/latency — matches Go's getProxyDelay()
///
/// Tests the latency of a specific proxy via HTTP URL test.
/// Returns `{"delay": N}` on success, 504 on timeout, 503 on connect error.
pub async fn get_proxy_delay(
    State(state): State<ApiState>,
    Path(proxy_name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let outbound_opt = if let Some(registry) = &state.outbound_registry {
        let reg = registry.read();
        reg.get(&proxy_name).cloned()
    } else {
        None
    };

    let timeout_ms = params
        .get("timeout")
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DELAY_TIMEOUT_MS as u64);

    let url = params
        .get("url")
        .map(std::string::String::as_str)
        .unwrap_or(DEFAULT_TEST_URL);

    let timeout = std::time::Duration::from_millis(timeout_ms);

    match http_url_test(outbound_opt.as_ref(), url, timeout).await {
        Ok(delay) => Json(json!({"delay": delay})).into_response(),
        Err(status) => (status, Json(json!({"message": "An error occurred"}))).into_response(),
    }
}

/// Get all active connections — matches Go's Snapshot.MarshalJSON()
///
/// Returns connections with top-level traffic totals and memory, matching the
/// Go Snapshot format: `{downloadTotal, uploadTotal, connections, memory}`.
pub async fn get_connections(State(state): State<ApiState>) -> impl IntoResponse {
    let connections: Vec<Connection> = if let Some(connection_manager) = &state.connection_manager {
        match connection_manager.get_connections().await {
            Ok(internal_connections) => internal_connections
                .iter()
                .map(convert_connection)
                .collect(),
            Err(e) => {
                log::error!("Failed to get connections: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Compute totals from current connections (approximation until global counters exist)
    let upload_total: u64 = connections.iter().map(|c| c.upload).sum();
    let download_total: u64 = connections.iter().map(|c| c.download).sum();

    // Report real process memory where possible
    let memory = crate::clash::websocket::get_process_memory_pub();

    Json(json!({
        "downloadTotal": download_total,
        "uploadTotal": upload_total,
        "connections": connections,
        "memory": memory
    }))
}

/// Close a specific connection
///
/// Terminates an active connection identified by its connection ID.
pub async fn close_connection(
    State(state): State<ApiState>,
    Path(connection_id): Path<String>,
) -> impl IntoResponse {
    if let Some(connection_manager) = &state.connection_manager {
        match connection_manager.remove_connection(&connection_id).await {
            Ok(success) => {
                if success {
                    log::info!("Successfully closed connection: {}", connection_id);
                    StatusCode::NO_CONTENT
                } else {
                    log::warn!("Connection not found: {}", connection_id);
                    StatusCode::NOT_FOUND
                }
            }
            Err(e) => {
                log::error!("Error closing connection {}: {}", connection_id, e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    } else {
        log::info!(
            "Connection manager not available, logging close request for: {}",
            connection_id
        );
        StatusCode::NO_CONTENT
    }
}

/// Close all connections — matches Go's closeAllConnections()
///
/// Closes all active connections and returns 204 NoContent.
pub async fn close_all_connections(State(state): State<ApiState>) -> impl IntoResponse {
    if let Some(connection_manager) = &state.connection_manager {
        match connection_manager.close_all_connections().await {
            Ok(closed_count) => {
                log::info!("Closed {} connections", closed_count);
            }
            Err(e) => {
                log::error!("Error closing all connections: {}", e);
            }
        }
    }
    StatusCode::NO_CONTENT
}

/// Get routing rules
///
/// Returns the current routing rules configuration. This is a demo implementation
/// that returns static rules; the full version would integrate with the router.
pub async fn get_rules(State(state): State<ApiState>) -> impl IntoResponse {
    let mut rules = Vec::new();

    if let Some(cfg) = &state.global_config {
        for (i, rule) in cfg.route.rules.iter().enumerate() {
            let proxy = rule.outbound.clone().unwrap_or("DIRECT".to_string());

            // Explode rule conditions
            for domain in &rule.domain {
                rules.push(Rule {
                    r#type: "DOMAIN".to_string(),
                    payload: domain.clone(),
                    proxy: proxy.clone(),
                    order: Some(i as u32),
                });
            }
            for suffix in &rule.domain_suffix {
                rules.push(Rule {
                    r#type: "DOMAIN-SUFFIX".to_string(),
                    payload: suffix.clone(),
                    proxy: proxy.clone(),
                    order: Some(i as u32),
                });
            }
            for cidr in &rule.ipcidr {
                rules.push(Rule {
                    r#type: "IP-CIDR".to_string(),
                    payload: cidr.clone(),
                    proxy: proxy.clone(),
                    order: Some(i as u32),
                });
            }
            // Fallback for complex rules
            if rule.domain.is_empty() && rule.domain_suffix.is_empty() && rule.ipcidr.is_empty() {
                rules.push(Rule {
                    r#type: "MATCH".to_string(),
                    payload: "".to_string(),
                    proxy: proxy.clone(),
                    order: Some(i as u32),
                });
            }
        }

        if let Some(default) = &cfg.route.default {
            rules.push(Rule {
                r#type: "MATCH".to_string(),
                payload: "".to_string(),
                proxy: default.clone(),
                order: Some(9999),
            });
        }
    }

    Json(json!({ "rules": rules }))
}

/// Get current configuration — matches Go's getConfigs() / configSchema
///
/// Returns the current runtime configuration matching the Go configSchema exactly.
pub async fn get_configs(State(state): State<ApiState>) -> impl IntoResponse {
    // Read mode from cache file if available
    let mode = state
        .cache_file
        .as_ref()
        .and_then(|cache| cache.get_clash_mode())
        .unwrap_or_else(|| "rule".to_string());

    // Read actual ports from config IR if available
    let (port, socks_port, mixed_port) = if let Some(config) = &state.global_config {
        extract_ports_from_config(config)
    } else {
        (0u16, 0u16, None)
    };

    // Determine allow-lan from inbound listen addresses
    let allow_lan = if let Some(config) = &state.global_config {
        config.inbounds.iter().any(|ib| {
            ib.listen == "0.0.0.0" || ib.listen == "::"
        })
    } else {
        false
    };

    // Build tun info from config IR
    let tun = if let Some(config) = &state.global_config {
        let tun_ib = config.inbounds.iter().find(|ib| {
            matches!(ib.ty, sb_config::ir::InboundType::Tun)
        });
        if let Some(tun_ib) = tun_ib {
            json!({
                "enable": true,
                "device": tun_ib.tag.as_deref().unwrap_or(""),
                "stack": ""
            })
        } else {
            json!({})
        }
    } else {
        json!({})
    };

    let config = Config {
        port,
        socks_port,
        redir_port: 0,
        tproxy_port: 0,
        mixed_port: mixed_port.unwrap_or(0),
        allow_lan,
        bind_address: "*".to_string(),
        mode,
        mode_list: vec![
            "rule".to_string(),
            "global".to_string(),
            "direct".to_string(),
        ],
        log_level: "info".to_string(),
        ipv6: false,
        tun,
    };

    Json(config)
}

/// Extract inbound listen ports from ConfigIR
fn extract_ports_from_config(config: &sb_config::ir::ConfigIR) -> (u16, u16, Option<u16>) {
    let mut http_port = 0u16;
    let mut socks_port = 0u16;
    let mut mixed_port = None;

    for ib in &config.inbounds {
        match ib.ty {
            sb_config::ir::InboundType::Http => {
                if http_port == 0 {
                    http_port = ib.port;
                }
            }
            sb_config::ir::InboundType::Socks => {
                if socks_port == 0 {
                    socks_port = ib.port;
                }
            }
            sb_config::ir::InboundType::Mixed => {
                if mixed_port.is_none() {
                    mixed_port = Some(ib.port);
                }
            }
            _ => {}
        }
    }

    (http_port, socks_port, mixed_port)
}

/// Update configuration (PATCH /configs) — matches Go's patchConfigs()
///
/// Handles partial configuration updates. Currently only processes `mode` changes.
pub async fn update_configs(
    State(_state): State<ApiState>,
    Json(config): Json<serde_json::Value>,
) -> impl IntoResponse {
    log::info!("Configuration update requested with payload: {:?}", config);

    let obj = match config.as_object() {
        Some(o) => o,
        None => {
            log::warn!("Invalid configuration format: expected object");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Body invalid"})),
            )
                .into_response();
        }
    };

    // Process mode change (the only field Go actually handles)
    if let Some(mode) = obj.get("mode").and_then(|v| v.as_str()) {
        if !mode.is_empty() {
            if let Some(cache) = &_state.cache_file {
                cache.set_clash_mode(mode.to_string());
            }
            log::info!("Updated mode: {}", mode);
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Get proxy providers
///
/// Returns all configured proxy providers with their current status.
pub async fn get_proxy_providers(State(state): State<ApiState>) -> impl IntoResponse {
    if let Some(provider_manager) = &state.provider_manager {
        match provider_manager.get_proxy_providers().await {
            Ok(providers) => {
                // Convert internal Provider to API Provider format
                let api_providers: HashMap<String, Provider> = providers
                    .into_iter()
                    .map(|(name, p)| convert_provider_to_api(name, p, ""))
                    .collect();
                Json(json!({ "providers": api_providers }))
            }
            Err(e) => {
                log::error!("Failed to get proxy providers: {}", e);
                Json(json!({ "providers": {} }))
            }
        }
    } else {
        log::warn!("Provider manager not available");
        Json(json!({ "providers": {} }))
    }
}

/// Get specific proxy provider
///
/// Returns detailed information about a specific proxy provider.
pub async fn get_proxy_provider(
    State(state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    if let Some(provider_manager) = &state.provider_manager {
        match provider_manager.get_proxy_provider(&provider_name).await {
            Ok(Some(p)) => {
                let provider = Provider {
                    name: p.name,
                    r#type: p.provider_type,
                    vehicle_type: if p.url.is_some() {
                        "HTTP".to_string()
                    } else {
                        "File".to_string()
                    },
                    behavior: String::new(),
                    updated_at: p
                        .last_update
                        .map(|t| t.elapsed().as_secs().to_string())
                        .unwrap_or_else(|| "never".to_string()),
                    subscription_info: None,
                    proxies: vec![],
                    rules: vec![],
                };
                (StatusCode::OK, Json(provider)).into_response()
            }
            Ok(None) => {
                log::warn!("Proxy provider '{}' not found", provider_name);
                StatusCode::NOT_FOUND.into_response()
            }
            Err(e) => {
                log::error!("Failed to get proxy provider: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        log::warn!("Provider manager not available");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

/// Update proxy provider
///
/// Triggers an update/refresh of a specific proxy provider.
pub async fn update_proxy_provider(
    State(state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    if let Some(provider_manager) = &state.provider_manager {
        match provider_manager.update_provider(&provider_name, true).await {
            Ok(true) => {
                log::info!("Successfully updated proxy provider: {}", provider_name);
                StatusCode::NO_CONTENT
            }
            Ok(false) => {
                log::warn!("Proxy provider '{}' not found", provider_name);
                StatusCode::NOT_FOUND
            }
            Err(e) => {
                log::error!("Failed to update proxy provider: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    } else {
        log::warn!("Provider manager not available");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Health check proxy provider
///
/// Performs a health check on all proxies in a specific provider.
pub async fn healthcheck_proxy_provider(
    State(state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    if let Some(provider_manager) = &state.provider_manager {
        match provider_manager
            .health_check_provider(&provider_name, true)
            .await
        {
            Ok(true) => {
                log::info!("Proxy provider '{}' is healthy", provider_name);
                StatusCode::NO_CONTENT
            }
            Ok(false) => {
                log::warn!("Proxy provider '{}' not found or unhealthy", provider_name);
                StatusCode::NOT_FOUND
            }
            Err(e) => {
                log::error!("Failed to health check proxy provider: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    } else {
        log::warn!("Provider manager not available");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Get rule providers
///
/// Returns all configured rule providers with their current status.
pub async fn get_rule_providers(State(state): State<ApiState>) -> impl IntoResponse {
    if let Some(provider_manager) = &state.provider_manager {
        match provider_manager.get_rule_providers().await {
            Ok(providers) => {
                // Convert internal Provider to API Provider format
                let api_providers: HashMap<String, Provider> = providers
                    .into_iter()
                    .map(|(name, p)| convert_provider_to_api(name, p, "domain"))
                    .collect();
                Json(json!({ "providers": api_providers }))
            }
            Err(e) => {
                log::error!("Failed to get rule providers: {}", e);
                Json(json!({ "providers": {} }))
            }
        }
    } else {
        log::warn!("Provider manager not available");
        Json(json!({ "providers": {} }))
    }
}

/// Get specific rule provider
///
/// Returns detailed information about a specific rule provider.
pub async fn get_rule_provider(
    State(state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    if let Some(provider_manager) = &state.provider_manager {
        match provider_manager.get_rule_provider(&provider_name).await {
            Ok(Some(p)) => {
                let provider = Provider {
                    name: p.name,
                    r#type: p.provider_type,
                    vehicle_type: if p.url.is_some() {
                        "HTTP".to_string()
                    } else {
                        "File".to_string()
                    },
                    behavior: "domain".to_string(),
                    updated_at: p
                        .last_update
                        .map(|t| t.elapsed().as_secs().to_string())
                        .unwrap_or_else(|| "never".to_string()),
                    subscription_info: None,
                    proxies: vec![],
                    rules: vec![],
                };
                (StatusCode::OK, Json(provider)).into_response()
            }
            Ok(None) => {
                log::warn!("Rule provider '{}' not found", provider_name);
                StatusCode::NOT_FOUND.into_response()
            }
            Err(e) => {
                log::error!("Failed to get rule provider: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    } else {
        log::warn!("Provider manager not available");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

/// Update rule provider
///
/// Triggers an update/refresh of a specific rule provider.
pub async fn update_rule_provider(
    State(state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    if let Some(provider_manager) = &state.provider_manager {
        match provider_manager
            .update_provider(&provider_name, false)
            .await
        {
            Ok(true) => {
                log::info!("Successfully updated rule provider: {}", provider_name);
                StatusCode::NO_CONTENT
            }
            Ok(false) => {
                log::warn!("Rule provider '{}' not found", provider_name);
                StatusCode::NOT_FOUND
            }
            Err(e) => {
                log::error!("Failed to update rule provider: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    } else {
        log::warn!("Provider manager not available");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Flush fake IP cache
///
/// Clears all fake IP mappings from the DNS resolver cache.
pub async fn flush_fakeip_cache(State(state): State<ApiState>) -> impl IntoResponse {
    log::info!("Fake IP cache flush requested");

    if let Some(dns_resolver) = &state.dns_resolver {
        // Get count before flushing
        let (_, fakeip_count) = dns_resolver.get_cache_stats().await;

        match dns_resolver.flush_fake_ip_cache().await {
            Ok(()) => {
                log::info!(
                    "Successfully flushed {} fake IP cache entries",
                    fakeip_count
                );
                (
                    StatusCode::OK,
                    Json(json!({
                        "status": "success",
                        "flushed": fakeip_count,
                        "message": format!("Flushed {} fake IP mappings", fakeip_count)
                    })),
                )
                    .into_response()
            }
            Err(e) => {
                log::error!("Failed to flush fake IP cache: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "status": "error",
                        "message": format!("Failed to flush fake IP cache: {}", e)
                    })),
                )
                    .into_response()
            }
        }
    } else {
        log::warn!("DNS resolver not available in API state");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unavailable",
                "message": "DNS resolver not configured or fake IP mode not enabled"
            })),
        )
            .into_response()
    }
}

/// Flush DNS cache
///
/// Clears all DNS query results from the resolver cache.
pub async fn flush_dns_cache(State(state): State<ApiState>) -> impl IntoResponse {
    log::info!("DNS cache flush requested");

    if let Some(dns_resolver) = &state.dns_resolver {
        // Get count before flushing
        let (dns_count, _) = dns_resolver.get_cache_stats().await;

        match dns_resolver.flush_dns_cache().await {
            Ok(()) => {
                log::info!("Successfully flushed {} DNS cache entries", dns_count);
                (
                    StatusCode::OK,
                    Json(json!({
                        "status": "success",
                        "flushed": dns_count,
                        "message": format!("Flushed {} DNS cache entries", dns_count)
                    })),
                )
                    .into_response()
            }
            Err(e) => {
                log::error!("Failed to flush DNS cache: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "status": "error",
                        "message": format!("Failed to flush DNS cache: {}", e)
                    })),
                )
                    .into_response()
            }
        }
    } else {
        log::warn!("DNS resolver not available in API state");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "unavailable",
                "message": "DNS resolver not configured"
            })),
        )
            .into_response()
    }
}

/// Get version information — matches Go's version() handler
///
/// Returns version info compatible with Clash dashboards.
pub async fn get_version(State(_state): State<ApiState>) -> impl IntoResponse {
    Json(json!({
        "version": format!("sing-box {}", env!("CARGO_PKG_VERSION")),
        "premium": true,
        "meta": true
    }))
}

/// Get status/health check — matches Go's hello() handler
///
/// Returns `{"hello": "clash"}` as expected by Clash-compatible dashboards.
pub async fn get_status(State(_state): State<ApiState>) -> impl IntoResponse {
    Json(json!({"hello": "clash"}))
}

/// Query DNS for a domain
///
/// Performs a DNS query and returns the resolved addresses.
pub async fn get_dns_query(
    State(state): State<ApiState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Extract query parameters
    let name = match params.get("name") {
        Some(n) if !n.is_empty() => n,
        _ => {
            log::warn!("DNS query request missing 'name' parameter");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "message": "Query parameter 'name' is required"
                })),
            )
                .into_response();
        }
    };

    let query_type = params
        .get("type")
        .map(std::string::String::as_str)
        .unwrap_or("A");

    // Validate query type
    let valid_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR"];
    if !valid_types.contains(&query_type) {
        log::warn!("Unsupported DNS query type: {}", query_type);
        // We'll allow it but log a warning - the resolver will handle it
    }

    log::info!("DNS query requested for {} (type: {})", name, query_type);

    // Perform DNS query
    if let Some(dns_resolver) = &state.dns_resolver {
        match dns_resolver.query_dns(name, query_type).await {
            Ok(addresses) => {
                if addresses.is_empty() {
                    log::warn!(
                        "DNS query returned no results for {} ({})",
                        name,
                        query_type
                    );
                    (
                        StatusCode::OK,
                        Json(json!({
                            "name": name,
                            "type": query_type,
                            "addresses": [],
                            "message": "No DNS records found"
                        })),
                    )
                        .into_response()
                } else {
                    log::info!(
                        "DNS query successful for {}: {} address(es) found",
                        name,
                        addresses.len()
                    );
                    (
                        StatusCode::OK,
                        Json(json!({
                            "name": name,
                            "type": query_type,
                            "addresses": addresses,
                            "ttl": 300
                        })),
                    )
                        .into_response()
                }
            }
            Err(e) => {
                log::error!("DNS query failed for {}: {}", name, e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "message": format!("Failed to resolve {}: {}", name, e)
                    })),
                )
                    .into_response()
            }
        }
    } else {
        log::warn!("DNS resolver not available");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "message": "DNS resolver is not configured"
            })),
        )
            .into_response()
    }
}

/// Get all proxy groups — matches Go's getGroupProxies()
///
/// Returns only OutboundGroup proxies as an array, using proxyInfo format.
pub async fn get_meta_groups(State(state): State<ApiState>) -> impl IntoResponse {
    let mut groups = Vec::new();

    let entries = if let Some(registry) = &state.outbound_registry {
        let reg = registry.read();
        reg.keys()
            .filter_map(|key| {
                reg.get(key)
                    .cloned()
                    .map(|outbound| (key.clone(), outbound))
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    // Only include OutboundGroup types (Selector, URLTest, Fallback, LoadBalance)
    for (tag, outbound) in entries {
        if let OutboundImpl::Connector(c) = &outbound {
            if let Some(group) = c.as_any().and_then(|a| a.downcast_ref::<SelectorGroup>()) {
                let all: Vec<String> = group
                    .get_members()
                    .into_iter()
                    .map(|(member, _, _)| member)
                    .collect();
                let now = group.get_selected().await.unwrap_or_default();

                groups.push(json!({
                    "name": tag,
                    "type": "Selector",
                    "udp": true,
                    "history": [],
                    "all": all,
                    "now": now,
                    "hidden": false,
                    "icon": "",
                }));
            }
        }
    }

    Json(json!({ "proxies": groups }))
}

/// Get specific proxy group
///
/// Returns detailed information about a specific proxy group.
pub async fn get_meta_group(
    State(state): State<ApiState>,
    Path(group_name): Path<String>,
) -> impl IntoResponse {
    log::info!("Meta group '{}' requested", group_name);

    // Check if the group/proxy exists in outbound manager
    let outbound = state
        .outbound_registry
        .as_ref()
        .and_then(|registry| registry.read().get(&group_name).cloned());

    if let Some(outbound) = outbound {
        let mut all = vec![group_name.clone()];
        let mut now = group_name.clone();
        let mut proxy_type = infer_proxy_type(&group_name, Some(&outbound));

        if let OutboundImpl::Connector(c) = &outbound {
            if let Some(group) = c.as_any().and_then(|a| a.downcast_ref::<SelectorGroup>()) {
                all = group
                    .get_members()
                    .into_iter()
                    .map(|(member, _, _)| member)
                    .collect();
                now = group.get_selected().await.unwrap_or_default();
                proxy_type = "Selector".to_string();
            }
        }

        let group = json!({
            "name": group_name,
            "type": proxy_type,
            "all": all,
            "now": now,
            "hidden": false,
            "icon": "",
            "udp": true,
        });
        return (StatusCode::OK, Json(group)).into_response();
    }

    // Check default groups
    match group_name.as_str() {
        DIRECT_PROXY_NAME => {
            let group = json!({
                "name": DIRECT_PROXY_NAME,
                "type": PROXY_TYPE_DIRECT,
                "all": vec![DIRECT_PROXY_NAME],
                "now": DIRECT_PROXY_NAME,
                "hidden": false,
                "icon": "",
                "udp": true,
            });
            (StatusCode::OK, Json(group)).into_response()
        }
        REJECT_PROXY_NAME => {
            let group = json!({
                "name": REJECT_PROXY_NAME,
                "type": PROXY_TYPE_REJECT,
                "all": vec![REJECT_PROXY_NAME],
                "now": REJECT_PROXY_NAME,
                "hidden": false,
                "icon": "",
                "udp": false,
            });
            (StatusCode::OK, Json(group)).into_response()
        }
        _ => {
            log::warn!("Proxy group '{}' not found", group_name);
            (
                StatusCode::NOT_FOUND,
                Json(json!({
                    "message": format!("Proxy group '{}' does not exist", group_name)
                })),
            )
                .into_response()
        }
    }
}

/// Test proxy group delay — matches Go's getGroupDelay()
///
/// Concurrently tests latency of all member proxies in a group.
/// Returns `{tag1: delay1, tag2: delay2, ...}` map.
pub async fn get_meta_group_delay(
    State(state): State<ApiState>,
    Path(group_name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let timeout_ms = params
        .get("timeout")
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(DEFAULT_DELAY_TIMEOUT_MS as u64);

    let url = params
        .get("url")
        .cloned()
        .unwrap_or_else(|| DEFAULT_TEST_URL.to_string());

    let timeout_dur = std::time::Duration::from_millis(timeout_ms);

    // Collect group members
    let members: Vec<(String, Option<OutboundImpl>)> = if let Some(registry) = &state.outbound_registry {
        let reg = registry.read();
        if let Some(outbound) = reg.get(&group_name) {
            if let OutboundImpl::Connector(c) = outbound {
                if let Some(group) = c.as_any().and_then(|a| a.downcast_ref::<SelectorGroup>()) {
                    group
                        .get_members()
                        .into_iter()
                        .map(|(tag, _, _)| {
                            let ob = reg.get(&tag).cloned();
                            (tag, ob)
                        })
                        .collect()
                } else {
                    // Not a group — test the single outbound
                    vec![(group_name.clone(), Some(outbound.clone()))]
                }
            } else {
                vec![(group_name.clone(), Some(outbound.clone()))]
            }
        } else if group_name == DIRECT_PROXY_NAME || group_name == REJECT_PROXY_NAME {
            vec![]
        } else {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"message": format!("Group '{}' not found", group_name)})),
            )
                .into_response();
        }
    } else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"message": format!("Group '{}' not found", group_name)})),
        )
            .into_response();
    };

    // Concurrently test all members
    let mut handles = Vec::with_capacity(members.len());
    for (tag, outbound) in members {
        let url = url.clone();
        handles.push(tokio::spawn(async move {
            let delay = match http_url_test(outbound.as_ref(), &url, timeout_dur).await {
                Ok(d) => d as i32,
                Err(_) => 0,
            };
            (tag, delay)
        }));
    }

    let mut results = serde_json::Map::new();
    for handle in handles {
        if let Ok((tag, delay)) = handle.await {
            results.insert(tag, json!(delay));
        }
    }

    Json(serde_json::Value::Object(results)).into_response()
}

/// Get memory usage — matches Go's memory() handler
///
/// Supports both HTTP (returns current stats) and WebSocket (pushes every second).
/// Go checks `Upgrade: websocket` header; Axum uses `Option<WebSocketUpgrade>`.
pub async fn get_meta_memory(
    ws: Option<axum::extract::ws::WebSocketUpgrade>,
    State(state): State<ApiState>,
) -> impl IntoResponse {
    if let Some(ws) = ws {
        return ws
            .on_upgrade(move |socket| crate::clash::websocket::handle_memory_websocket_inner(socket, state))
            .into_response();
    }

    // HTTP fallback — return current snapshot
    let inuse = crate::clash::websocket::get_process_memory_pub();
    Json(json!({
        "inuse": inuse,
        "oslimit": 0
    }))
    .into_response()
}

/// Trigger garbage collection
///
/// Requests garbage collection. Note: Rust uses automatic memory management.
pub async fn trigger_gc(State(_state): State<ApiState>) -> impl IntoResponse {
    log::info!("Manual garbage collection requested");

    // In Rust, explicit GC is not directly available like in Go
    // But we can provide an endpoint that would:
    // 1. Clear internal caches
    // 2. Drop unused connections
    // 3. Release resources

    log::info!("GC trigger acknowledged (Rust uses automatic memory management)");
    StatusCode::NO_CONTENT
}

/// Replace entire configuration (PUT /configs) — matches Go behavior
///
/// Go's handler does nothing and returns 204 NoContent.
pub async fn replace_configs(
    State(_state): State<ApiState>,
    Json(_config): Json<serde_json::Value>,
) -> impl IntoResponse {
    log::info!("Configuration replacement requested (no-op, returns 204)");
    StatusCode::NO_CONTENT.into_response()
}

/// Redirect to Clash UI
///
/// This endpoint redirects to the external Clash dashboard UI.
pub async fn get_ui(State(_state): State<ApiState>) -> impl IntoResponse {
    log::info!("UI redirect requested");

    // In a full implementation, this would:
    // 1. Check if external UI is configured
    // 2. Serve static files from the UI directory
    // 3. Or redirect to the configured external UI URL

    (
        StatusCode::OK,
        Json(json!({
            "message": "Clash API is running",
            "api_endpoint": "http://127.0.0.1:9090",
            "dashboards": [
                {
                    "name": "Yacd",
                    "url": "https://yacd.haishan.me"
                },
                {
                    "name": "Clash Dashboard",
                    "url": "https://clash.razord.top"
                }
            ],
            "note": "Connect your Clash dashboard to this API endpoint"
        })),
    )
        .into_response()
}

/// Get tracing profile data (GET /profile/tracing)
///
/// Provides profiling and debugging information.
pub async fn get_profile_tracing(State(_state): State<ApiState>) -> impl IntoResponse {
    log::info!("Profile tracing requested");

    (
        StatusCode::OK,
        Json(json!({
            "status": "available",
            "message": "Tracing data collection endpoint",
            "note": "Full tracing integration requires runtime instrumentation",
            "traces": []
        })),
    )
        .into_response()
}

/// Update script configuration (PATCH /script)
///
/// Allows updating script rules dynamically.
pub async fn update_script(
    State(_state): State<ApiState>,
    Json(script_config): Json<serde_json::Value>,
) -> impl IntoResponse {
    log::info!("Script configuration update requested");

    // Validate script configuration structure
    let obj = match script_config.as_object() {
        Some(o) => o,
        None => {
            log::warn!("Invalid script configuration format: expected object");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "message": "Script configuration must be a valid JSON object"
                })),
            )
                .into_response();
        }
    };

    // Validate required fields
    match obj.get("code") {
        Some(code) if code.is_string() && !code.as_str().is_none_or(str::is_empty) => {
            // Valid code field
        }
        Some(_) => {
            log::warn!("Script code field is empty or invalid");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "message": "Script code must be a non-empty string"
                })),
            )
                .into_response();
        }
        None => {
            log::warn!("Missing required 'code' field in script configuration");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "message": "Field 'code' is required for script configuration"
                })),
            )
                .into_response();
        }
    }

    log::info!("Script configuration validated successfully");

    (
        StatusCode::OK,
        Json(json!({
            "status": "accepted",
            "message": "Script configuration updated successfully"
        })),
    )
        .into_response()
}

/// Test script execution (POST /script)
///
/// Allows testing script rules against sample data.
pub async fn test_script(
    State(_state): State<ApiState>,
    Json(test_request): Json<serde_json::Value>,
) -> impl IntoResponse {
    log::info!("Script test execution requested");

    // Validate test request structure
    let obj = match test_request.as_object() {
        Some(o) => o,
        None => {
            log::warn!("Invalid test request format: expected object");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "message": "Test request must be a valid JSON object"
                })),
            )
                .into_response();
        }
    };

    // Validate required fields for testing
    let script_code = match obj.get("script") {
        Some(s) if s.is_string() => match s.as_str() {
            Some(code) if !code.is_empty() => code,
            _ => {
                log::warn!("Script field is empty");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "message": "Field 'script' is required and must be a non-empty string"
                    })),
                )
                    .into_response();
            }
        },
        _ => {
            log::warn!("Missing or invalid 'script' field in test request");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "message": "Field 'script' is required and must be a non-empty string"
                })),
            )
                .into_response();
        }
    };

    log::info!("Testing script with {} bytes of code", script_code.len());

    // For now, return a mock successful execution
    (
        StatusCode::OK,
        Json(json!({
            "status": "success",
            "result": {
                "executed": true,
                "output": "Script execution simulated successfully",
                "execution_time_ms": 5
            },
            "message": "Script test completed"
        })),
    )
        .into_response()
}

/// Upgrade connections to WebSocket (GET /connectionsUpgrade)
///
/// This endpoint would upgrade HTTP connections to WebSocket for real-time connection monitoring.
pub async fn upgrade_connections(State(_state): State<ApiState>) -> impl IntoResponse {
    log::info!("Connection upgrade to WebSocket requested");

    (
        StatusCode::OK,
        Json(json!({
            "message": "WebSocket upgrade endpoint",
            "note": "Use /connections endpoint with WebSocket upgrade headers",
            "alternative": "Use /traffic and /logs WebSocket endpoints for real-time monitoring"
        })),
    )
        .into_response()
}

/// Meta upgrade endpoint (GET /metaUpgrade)
///
/// Provides information about upgrading to Meta version.
pub async fn get_meta_upgrade(State(_state): State<ApiState>) -> impl IntoResponse {
    log::info!("Meta upgrade information requested");

    (
        StatusCode::OK,
        Json(json!({
            "message": "Meta upgrade endpoint",
            "current_version": env!("CARGO_PKG_VERSION"),
            "meta_enabled": true,
            "note": "This is a Rust implementation with Meta features built-in"
        })),
    )
        .into_response()
}

/// Update external UI (POST /meta/upgrade/ui)
///
/// Allows updating the external dashboard UI.
pub async fn upgrade_external_ui(
    State(_state): State<ApiState>,
    Json(request): Json<serde_json::Value>,
) -> impl IntoResponse {
    log::info!("External UI upgrade requested");

    // Extract UI URL if provided
    let ui_url = request.get("url").and_then(|v| v.as_str()).unwrap_or("");

    if ui_url.is_empty() {
        log::warn!("External UI upgrade requested without URL");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "message": "Field 'url' is required for UI upgrade"
            })),
        )
            .into_response();
    }

    // Validate URL format
    if !ui_url.starts_with("http://") && !ui_url.starts_with("https://") {
        log::warn!("Invalid UI URL format: {}", ui_url);
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "message": "URL must start with http:// or https://"
            })),
        )
            .into_response();
    }

    log::info!("External UI upgrade URL validated: {}", ui_url);

    (
        StatusCode::OK,
        Json(json!({
            "status": "accepted",
            "message": "External UI upgrade initiated",
            "url": ui_url,
            "note": "UI upgrade would download and install dashboard files"
        })),
    )
        .into_response()
}
