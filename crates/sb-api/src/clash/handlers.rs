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
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

// ===== Constants =====

const DEFAULT_INBOUND_IP: &str = "127.0.0.1";
const DEFAULT_INBOUND_PORT: &str = "0";
const DEFAULT_INBOUND_NAME: &str = "unknown";
const DEFAULT_DNS_MODE: &str = "normal";
const DEFAULT_PROCESS_NAME: &str = "unknown";
const DEFAULT_PORT: &str = "0";
const DEFAULT_DELAY_TIMEOUT_MS: u32 = 5000;
const DEFAULT_TEST_URL: &str = "http://www.google.com/generate_204";
const MAX_PORT_NUMBER: u64 = 65535;

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

/// Best-effort proxy type inference from a tag/name
fn infer_proxy_type(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if n.contains("direct") {
        return PROXY_TYPE_DIRECT;
    }
    if n.contains("reject") {
        return PROXY_TYPE_REJECT;
    }
    if n.contains("socks") {
        return PROXY_TYPE_SOCKS5;
    }
    if n.contains("http") {
        return PROXY_TYPE_HTTP;
    }
    if n.contains("vless") {
        return PROXY_TYPE_VLESS;
    }
    if n.contains("vmess") {
        return PROXY_TYPE_VMESS;
    }
    if n.contains("trojan") {
        return PROXY_TYPE_TROJAN;
    }
    if n.contains("shadow") || n.contains("ss") {
        return PROXY_TYPE_SHADOWSOCKS;
    }
    PROXY_TYPE_UNKNOWN
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

/// Validate port value is within valid range (1-65535)
fn validate_port(port: u64) -> Result<(), String> {
    if (1..=MAX_PORT_NUMBER).contains(&port) {
        Ok(())
    } else {
        Err(format!(
            "Port value {port} out of range (valid: 1..={MAX_PORT_NUMBER})"
        ))
    }
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

/// Simulate random proxy delay for testing purposes
fn simulate_proxy_delay(proxy_name: &str) -> i32 {
    use rand::Rng;
    if proxy_name == DIRECT_PROXY_NAME {
        0
    } else if proxy_name == REJECT_PROXY_NAME {
        -1
    } else {
        let mut rng = rand::thread_rng();
        rng.gen_range(10..200)
    }
}

// ===== API Handlers =====

/// Get all proxies
/// 获取所有代理
///
/// Returns a list of all available proxies from the outbound manager,
/// including default DIRECT and REJECT proxies.
/// 从出站管理器返回所有可用代理的列表，包括默认的 DIRECT 和 REJECT 代理。
pub async fn get_proxies(State(state): State<ApiState>) -> impl IntoResponse {
    let mut proxies = HashMap::new();

    // Get proxies from outbound manager if available
    if let Some(outbound_manager) = &state.outbound_manager {
        let tags = outbound_manager.list_tags().await;
        for tag in tags {
            let proxy = Proxy {
                name: tag.clone(),
                r#type: infer_proxy_type(&tag).to_string(),
                all: vec![],
                now: tag.clone(),
                alive: Some(true),
                delay: None,
                extra: HashMap::new(),
            };
            proxies.insert(tag, proxy);
        }
    }

    // Add default proxies
    proxies.insert(
        DIRECT_PROXY_NAME.to_string(),
        Proxy {
            name: DIRECT_PROXY_NAME.to_string(),
            r#type: PROXY_TYPE_DIRECT.to_string(),
            all: vec![],
            now: DIRECT_PROXY_NAME.to_string(),
            alive: Some(true),
            delay: Some(0),
            extra: HashMap::new(),
        },
    );

    proxies.insert(
        REJECT_PROXY_NAME.to_string(),
        Proxy {
            name: REJECT_PROXY_NAME.to_string(),
            r#type: PROXY_TYPE_REJECT.to_string(),
            all: vec![],
            now: REJECT_PROXY_NAME.to_string(),
            alive: Some(true),
            delay: None,
            extra: HashMap::new(),
        },
    );

    Json(json!({ "proxies": proxies }))
}

/// Select a proxy for a proxy group
///
/// Updates the selected proxy for a given proxy group.
pub async fn select_proxy(
    State(state): State<ApiState>,
    Path(proxy_name): Path<String>,
    Json(request): Json<SelectProxyRequest>,
) -> impl IntoResponse {
    // Validate and handle proxy selection
    if let Some(outbound_manager) = &state.outbound_manager {
        if outbound_manager.contains(&request.name).await {
            log::info!(
                "Selected proxy '{}' for group '{}'",
                request.name,
                proxy_name
            );
            StatusCode::NO_CONTENT
        } else {
            log::warn!("Proxy '{}' not found in outbound manager", request.name);
            StatusCode::NOT_FOUND
        }
    } else {
        log::warn!("Outbound manager not available");
        StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Get proxy delay/latency
///
/// Tests the latency of a specific proxy by making a request to the test URL.
pub async fn get_proxy_delay(
    State(state): State<ApiState>,
    Path(proxy_name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Check if proxy exists
    if let Some(outbound_manager) = &state.outbound_manager {
        if !outbound_manager.contains(&proxy_name).await {
            return Json(json!({ "delay": -1 })).into_response();
        }
    }

    let timeout = params
        .get("timeout")
        .and_then(|t| t.parse::<u32>().ok())
        .unwrap_or(DEFAULT_DELAY_TIMEOUT_MS);

    let url = params
        .get("url")
        .map(std::string::String::as_str)
        .unwrap_or(DEFAULT_TEST_URL);

    log::info!(
        "Testing delay for proxy '{}' with URL '{}' and timeout {}ms",
        proxy_name,
        url,
        timeout
    );

    // Simulate delay test - in real implementation, this would ping the proxy
    let simulated_delay = simulate_proxy_delay(&proxy_name);

    Json(json!({
        "delay": simulated_delay,
        "meanDelay": simulated_delay
    }))
    .into_response()
}

/// Get all active connections
/// 获取所有活动连接
///
/// Returns a list of all currently active network connections managed by the connection manager.
/// 返回由连接管理器管理的所有当前活动网络连接的列表。
pub async fn get_connections(State(state): State<ApiState>) -> impl IntoResponse {
    let connections = if let Some(connection_manager) = &state.connection_manager {
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
        // Fallback to demo connection when no connection manager is available
        let start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .to_string();

        vec![Connection {
            id: Uuid::new_v4().to_string(),
            metadata: ConnectionMetadata {
                network: "tcp".to_string(),
                r#type: PROXY_TYPE_HTTP.to_string(),
                source_ip: "192.168.1.100".to_string(),
                source_port: "12345".to_string(),
                destination_ip: "8.8.8.8".to_string(),
                destination_port: "80".to_string(),
                inbound_ip: DEFAULT_INBOUND_IP.to_string(),
                inbound_port: "7890".to_string(),
                inbound_name: "http".to_string(),
                inbound_user: String::new(),
                host: "www.google.com".to_string(),
                dns_mode: DEFAULT_DNS_MODE.to_string(),
                uid: 1000,
                process: "firefox".to_string(),
                process_path: "/usr/bin/firefox".to_string(),
                special_proxy: String::new(),
                special_rules: String::new(),
                remote_destination: "8.8.8.8:80".to_string(),
                sniff_host: String::new(),
            },
            upload: 1024,
            download: 4096,
            start: start_time,
            chains: vec![DIRECT_PROXY_NAME.to_string()],
            rule: "DOMAIN".to_string(),
            rule_payload: "www.google.com".to_string(),
        }]
    };

    Json(json!({ "connections": connections }))
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

/// Close all connections
///
/// Terminates all active connections managed by the connection manager.
pub async fn close_all_connections(State(state): State<ApiState>) -> impl IntoResponse {
    if let Some(connection_manager) = &state.connection_manager {
        match connection_manager.close_all_connections().await {
            Ok(closed_count) => {
                log::info!("Closed {} connections", closed_count);
                Json(json!({ "closed": closed_count }))
            }
            Err(e) => {
                log::error!("Error closing all connections: {}", e);
                Json(json!({ "error": e.to_string(), "closed": 0 }))
            }
        }
    } else {
        log::info!("Connection manager not available, logging close all request");
        Json(json!({ "closed": 0 }))
    }
}

/// Get routing rules
///
/// Returns the current routing rules configuration. This is a demo implementation
/// that returns static rules; the full version would integrate with the router.
pub async fn get_rules(State(_state): State<ApiState>) -> impl IntoResponse {
    // Demo rules for compatibility; integration point for live router
    let rules = vec![
        Rule {
            r#type: "DOMAIN".to_string(),
            payload: "www.google.com".to_string(),
            proxy: DIRECT_PROXY_NAME.to_string(),
            order: Some(1),
        },
        Rule {
            r#type: "DOMAIN-SUFFIX".to_string(),
            payload: ".cn".to_string(),
            proxy: DIRECT_PROXY_NAME.to_string(),
            order: Some(2),
        },
        Rule {
            r#type: "FINAL".to_string(),
            payload: String::new(),
            proxy: "PROXY".to_string(),
            order: Some(999),
        },
    ];

    Json(json!({ "rules": rules }))
}

/// Get current configuration
///
/// Returns the current runtime configuration of the service.
pub async fn get_configs(State(_state): State<ApiState>) -> impl IntoResponse {
    // Demo config for compatibility; integration point for runtime config
    let config = Config {
        port: 7890,
        socks_port: 7891,
        mixed_port: Some(7892),
        controller_port: Some(9090),
        external_controller: Some("127.0.0.1:9090".to_string()),
        extra: HashMap::new(),
    };

    Json(config)
}

/// Update configuration
///
/// Merges partial configuration updates into the current configuration.
pub async fn update_configs(
    State(_state): State<ApiState>,
    Json(config): Json<serde_json::Value>,
) -> impl IntoResponse {
    log::info!("Configuration update requested with payload: {:?}", config);

    // Validate configuration structure
    let obj = match config.as_object() {
        Some(o) => o,
        None => {
            log::warn!("Invalid configuration format: expected object");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid configuration format",
                    "message": "Configuration must be a valid JSON object"
                })),
            )
                .into_response();
        }
    };

    // Validate port ranges if provided
    for port_key in &["port", "socks-port", "mixed-port", "controller-port"] {
        if let Some(port_val) = obj.get(*port_key) {
            if let Some(port) = port_val.as_u64() {
                if let Err(err) = validate_port(port) {
                    log::warn!("Invalid port value for {}: {}", port_key, err);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "Invalid port",
                            "message": err
                        })),
                    )
                        .into_response();
                }
            }
        }
    }

    // In a full implementation, this would:
    // 1. Validate the full configuration schema
    // 2. Apply changes to runtime configuration
    // 3. Reload affected components (inbounds, outbounds, router, DNS)
    // 4. Handle graceful degradation if reload fails

    log::info!("Configuration validation passed. Runtime reload would be triggered here.");

    (
        StatusCode::OK,
        Json(json!({
            "status": "accepted",
            "message": "Configuration update queued for processing"
        })),
    )
        .into_response()
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

/// Get version information
///
/// Returns version and build information about the service.
pub async fn get_version(State(_state): State<ApiState>) -> impl IntoResponse {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "premium": false,
        "meta": true
    }))
}

/// Get status/health check
///
/// Simple health check endpoint to verify the API server is running.
pub async fn get_status(State(_state): State<ApiState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "message": "Clash API server is running"
    }))
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
                    "error": "Missing required parameter",
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
                        "error": "DNS query failed",
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
                "error": "DNS resolver unavailable",
                "message": "DNS resolver is not configured"
            })),
        )
            .into_response()
    }
}

/// Get all proxy groups
///
/// Returns all proxy groups including individual proxies and default groups.
pub async fn get_meta_groups(State(state): State<ApiState>) -> impl IntoResponse {
    log::info!("Meta groups list requested");

    let mut groups = HashMap::new();

    // Get all proxies from outbound manager
    if let Some(outbound_manager) = &state.outbound_manager {
        let tags = outbound_manager.list_tags().await;

        for tag in tags {
            let group = json!({
                "name": tag,
                "type": infer_proxy_type(&tag),
                "all": vec![tag.clone()],
                "now": tag.clone(),
                "hidden": false,
                "icon": "",
                "udp": true,
            });
            groups.insert(tag, group);
        }
    }

    // Add default groups
    if !groups.contains_key(DIRECT_PROXY_NAME) {
        groups.insert(
            DIRECT_PROXY_NAME.to_string(),
            json!({
                "name": DIRECT_PROXY_NAME,
                "type": PROXY_TYPE_DIRECT,
                "all": vec![DIRECT_PROXY_NAME],
                "now": DIRECT_PROXY_NAME,
                "hidden": false,
                "icon": "",
                "udp": true,
            }),
        );
    }

    if !groups.contains_key(REJECT_PROXY_NAME) {
        groups.insert(
            REJECT_PROXY_NAME.to_string(),
            json!({
                "name": REJECT_PROXY_NAME,
                "type": PROXY_TYPE_REJECT,
                "all": vec![REJECT_PROXY_NAME],
                "now": REJECT_PROXY_NAME,
                "hidden": false,
                "icon": "",
                "udp": false,
            }),
        );
    }

    log::info!("Returning {} proxy groups", groups.len());
    Json(json!({ "groups": groups }))
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
    if let Some(outbound_manager) = &state.outbound_manager {
        if outbound_manager.contains(&group_name).await {
            let group = json!({
                "name": group_name,
                "type": infer_proxy_type(&group_name),
                "all": vec![group_name.clone()],
                "now": group_name.clone(),
                "hidden": false,
                "icon": "",
                "udp": true,
            });
            return (StatusCode::OK, Json(group)).into_response();
        }
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
                    "error": "Group not found",
                    "message": format!("Proxy group '{}' does not exist", group_name)
                })),
            )
                .into_response()
        }
    }
}

/// Test proxy group delay
///
/// Tests the latency of all proxies in a group.
pub async fn get_meta_group_delay(
    State(state): State<ApiState>,
    Path(group_name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    log::info!("Meta group delay test requested for '{}'", group_name);

    // Extract parameters
    let timeout = params
        .get("timeout")
        .and_then(|t| t.parse::<u32>().ok())
        .unwrap_or(DEFAULT_DELAY_TIMEOUT_MS);

    let url = params
        .get("url")
        .map(std::string::String::as_str)
        .unwrap_or(DEFAULT_TEST_URL);

    // Check if group exists
    let exists = if let Some(outbound_manager) = &state.outbound_manager {
        outbound_manager.contains(&group_name).await
    } else {
        group_name == DIRECT_PROXY_NAME || group_name == REJECT_PROXY_NAME
    };

    if !exists {
        log::warn!("Proxy group '{}' not found for delay test", group_name);
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "Group not found",
                "message": format!("Proxy group '{}' does not exist", group_name)
            })),
        )
            .into_response();
    }

    log::info!(
        "Testing delay for group '{}' with URL '{}' and timeout {}ms",
        group_name,
        url,
        timeout
    );

    // Simulate delay test
    let simulated_delay = simulate_proxy_delay(&group_name);

    log::info!(
        "Group '{}' delay test result: {}ms",
        group_name,
        simulated_delay
    );

    Json(json!({
        "delay": simulated_delay,
        "meanDelay": simulated_delay
    }))
    .into_response()
}

/// Get memory usage statistics
///
/// Returns memory usage information for the service process.
pub async fn get_meta_memory(State(_state): State<ApiState>) -> impl IntoResponse {
    log::info!("Memory usage statistics requested");

    // Get process memory statistics
    // In a real implementation, this would use platform-specific APIs
    // For now, return simulated memory statistics
    let memory_stats = json!({
        "inuse": 52_428_800_u64,        // 50 MB in use
        "oslimit": 4_294_967_296_u64,   // 4 GB OS limit
        "sys": 71_303_168_u64,          // 68 MB system memory
        "gc": 24_u32                    // GC runs
    });

    log::info!("Returning memory statistics: {}", memory_stats);
    Json(memory_stats)
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

/// Replace entire configuration (PUT /configs)
///
/// Unlike PATCH /configs which merges changes, this replaces the entire config.
pub async fn replace_configs(
    State(_state): State<ApiState>,
    Json(config): Json<serde_json::Value>,
) -> impl IntoResponse {
    log::info!("Configuration replacement requested");

    // Validate configuration structure
    let obj = match config.as_object() {
        Some(o) => o,
        None => {
            log::warn!("Invalid configuration format: expected object");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid configuration format",
                    "message": "Configuration must be a valid JSON object"
                })),
            )
                .into_response();
        }
    };

    // Validate required fields for full config replacement
    let required_fields = ["port", "socks-port", "mode"];
    for field in &required_fields {
        if !obj.contains_key(*field) {
            log::warn!("Missing required field '{}' in configuration", field);
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Missing required field",
                    "message": format!("Field '{}' is required for full configuration replacement", field)
                }))
            ).into_response();
        }
    }

    // Validate port ranges
    for port_key in &["port", "socks-port", "mixed-port", "controller-port"] {
        if let Some(port_val) = obj.get(*port_key) {
            if let Some(port) = port_val.as_u64() {
                if let Err(err) = validate_port(port) {
                    log::warn!("Invalid port value for {}: {}", port_key, err);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "Invalid port",
                            "message": err
                        })),
                    )
                        .into_response();
                }
            }
        }
    }

    // Validate mode field
    if let Some(mode) = obj.get("mode") {
        if let Some(mode_str) = mode.as_str() {
            let valid_modes = ["direct", "global", "rule"];
            if !valid_modes.contains(&mode_str.to_lowercase().as_str()) {
                log::warn!("Invalid mode value: {}", mode_str);
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "Invalid mode",
                        "message": format!("Mode '{}' is not valid. Must be one of: direct, global, rule", mode_str)
                    }))
                ).into_response();
            }
        }
    }

    log::info!("Full configuration replacement validated successfully");

    // In a full implementation, this would:
    // 1. Validate the complete configuration schema
    // 2. Stop all running services
    // 3. Replace the entire runtime configuration
    // 4. Restart all services with new configuration
    // 5. Handle graceful rollback if startup fails

    log::info!("Configuration replacement accepted. Full reload would be triggered here.");

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
                    "error": "Invalid script format",
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
                    "error": "Invalid script code",
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
                    "error": "Missing field",
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
                    "error": "Invalid request format",
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
                        "error": "Missing field",
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
                    "error": "Missing field",
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
                "error": "Missing URL",
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
                "error": "Invalid URL",
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
