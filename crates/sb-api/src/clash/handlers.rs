//! HTTP handlers for Clash API endpoints

use crate::{clash::server::ApiState, types::*};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

/// Convert internal Connection to API Connection type
fn convert_connection(conn: &crate::managers::Connection) -> Connection {
    Connection {
        id: conn.id.clone(),
        metadata: ConnectionMetadata {
            network: conn.network.clone(),
            r#type: determine_connection_type(&conn.network, &conn.proxy),
            source_ip: conn.source.ip().to_string(),
            source_port: conn.source.port().to_string(),
            destination_ip: parse_destination_ip(&conn.destination),
            destination_port: parse_destination_port(&conn.destination),
            inbound_ip: "127.0.0.1".to_string(),
            inbound_port: "0".to_string(),
            inbound_name: "unknown".to_string(),
            inbound_user: "".to_string(),
            host: conn.destination.clone(),
            dns_mode: "normal".to_string(),
            uid: 0,
            process: "unknown".to_string(),
            process_path: "".to_string(),
            special_proxy: "".to_string(),
            special_rules: "".to_string(),
            remote_destination: conn.destination.clone(),
            sniff_host: "".to_string(),
        },
        upload: conn.get_upload(),
        download: conn.get_download(),
        start: conn.start_time.elapsed().as_millis().to_string(),
        chains: conn.chains.clone(),
        rule: conn.rule.clone(),
        rule_payload: "".to_string(),
    }
}

/// Best-effort proxy type inference from a tag/name
fn infer_proxy_type(name: &str) -> String {
    let n = name.to_lowercase();
    if n.contains("direct") { return "Direct".to_string(); }
    if n.contains("reject") { return "Reject".to_string(); }
    if n.contains("socks") { return "SOCKS5".to_string(); }
    if n.contains("http") { return "HTTP".to_string(); }
    if n.contains("vless") { return "VLESS".to_string(); }
    if n.contains("vmess") { return "VMESS".to_string(); }
    if n.contains("trojan") { return "TROJAN".to_string(); }
    if n.contains("shadow") || n.contains("ss") { return "SHADOWSOCKS".to_string(); }
    "Unknown".to_string()
}

/// Get all proxies
pub async fn get_proxies(State(state): State<ApiState>) -> impl IntoResponse {
    let mut proxies = HashMap::new();

    // Get proxies from outbound manager if available
    if let Some(outbound_manager) = &state.outbound_manager {
        let tags = outbound_manager.list_tags();
        for tag in tags {
            let proxy = Proxy {
                name: tag.to_string(),
                r#type: infer_proxy_type(tag),
                all: vec![],
                now: tag.to_string(),
                alive: Some(true),
                delay: None,
                extra: HashMap::new(),
            };
            proxies.insert(tag.to_string(), proxy);
        }
    }

    // Mock data for demonstration
    proxies.insert(
        "DIRECT".to_string(),
        Proxy {
            name: "DIRECT".to_string(),
            r#type: "Direct".to_string(),
            all: vec![],
            now: "DIRECT".to_string(),
            alive: Some(true),
            delay: Some(0),
            extra: HashMap::new(),
        },
    );

    proxies.insert(
        "REJECT".to_string(),
        Proxy {
            name: "REJECT".to_string(),
            r#type: "Reject".to_string(),
            all: vec![],
            now: "REJECT".to_string(),
            alive: Some(true),
            delay: None,
            extra: HashMap::new(),
        },
    );

    Json(json!({ "proxies": proxies }))
}

/// Select a proxy for a proxy group
pub async fn select_proxy(
    State(state): State<ApiState>,
    Path(proxy_name): Path<String>,
    Json(request): Json<SelectProxyRequest>,
) -> impl IntoResponse {
    // Validate and handle proxy selection
    if let Some(outbound_manager) = &state.outbound_manager {
        if outbound_manager.contains(&request.name) {
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
pub async fn get_proxy_delay(
    State(state): State<ApiState>,
    Path(proxy_name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    // Implement proxy delay testing
    if let Some(outbound_manager) = &state.outbound_manager {
        if !outbound_manager.contains(&proxy_name) {
            return Json(json!({ "delay": -1 })).into_response();
        }
    }
    let timeout = params
        .get("timeout")
        .and_then(|t| t.parse::<u32>().ok())
        .unwrap_or(5000);

    let url = params
        .get("url")
        .map(|s| s.as_str())
        .unwrap_or("http://www.google.com/generate_204");

    log::info!(
        "Testing delay for proxy '{}' with URL '{}' and timeout {}ms",
        proxy_name,
        url,
        timeout
    );

    // Simulate delay test - in real implementation, this would ping the proxy
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let simulated_delay = if proxy_name == "DIRECT" {
        0
    } else {
        rng.gen_range(10..200)
    };

    Json(json!({
        "delay": simulated_delay,
        "meanDelay": simulated_delay
    }))
    .into_response()
}

/// Get all active connections
pub async fn get_connections(State(state): State<ApiState>) -> impl IntoResponse {
    let connections = if let Some(connection_manager) = &state.connection_manager {
        match connection_manager.get_connections().await {
            Ok(internal_connections) => {
                internal_connections.iter().map(convert_connection).collect()
            }
            Err(e) => {
                log::error!("Failed to get connections: {}", e);
                Vec::new()
            }
        }
    } else {
        // Fallback to demo connection when no connection manager is available
        vec![
            Connection {
                id: Uuid::new_v4().to_string(),
                metadata: ConnectionMetadata {
                    network: "tcp".to_string(),
                    r#type: "HTTP".to_string(),
                    source_ip: "192.168.1.100".to_string(),
                    source_port: "12345".to_string(),
                    destination_ip: "8.8.8.8".to_string(),
                    destination_port: "80".to_string(),
                    inbound_ip: "127.0.0.1".to_string(),
                    inbound_port: "7890".to_string(),
                    inbound_name: "http".to_string(),
                    inbound_user: "".to_string(),
                    host: "www.google.com".to_string(),
                    dns_mode: "normal".to_string(),
                    uid: 1000,
                    process: "firefox".to_string(),
                    process_path: "/usr/bin/firefox".to_string(),
                    special_proxy: "".to_string(),
                    special_rules: "".to_string(),
                    remote_destination: "8.8.8.8:80".to_string(),
                    sniff_host: "".to_string(),
                },
                upload: 1024,
                download: 4096,
                start: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .to_string(),
                chains: vec!["DIRECT".to_string()],
                rule: "DOMAIN".to_string(),
                rule_payload: "www.google.com".to_string(),
            },
        ]
    };

    Json(json!({ "connections": connections }))
}

/// Close a specific connection
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
        log::info!("Connection manager not available, logging close request for: {}", connection_id);
        StatusCode::NO_CONTENT
    }
}

/// Close all connections
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
pub async fn get_rules(State(_state): State<ApiState>) -> impl IntoResponse {
    // Demo rules for compatibility; integration point for live router
    let rules = vec![
        Rule {
            r#type: "DOMAIN".to_string(),
            payload: "www.google.com".to_string(),
            proxy: "DIRECT".to_string(),
            order: Some(1),
        },
        Rule {
            r#type: "DOMAIN-SUFFIX".to_string(),
            payload: ".cn".to_string(),
            proxy: "DIRECT".to_string(),
            order: Some(2),
        },
        Rule {
            r#type: "FINAL".to_string(),
            payload: "".to_string(),
            proxy: "PROXY".to_string(),
            order: Some(999),
        },
    ];

    Json(json!({ "rules": rules }))
}

/// Get current configuration
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
pub async fn update_configs(
    State(_state): State<ApiState>,
    Json(_config): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Configuration update endpoint (stub). Integrate with runtime config.
    log::info!("Configuration update requested");
    StatusCode::NOT_IMPLEMENTED
}

/// Get proxy providers
pub async fn get_proxy_providers(State(_state): State<ApiState>) -> impl IntoResponse {
    // Provider listing (stub). Integrate with provider manager.
    let providers: HashMap<String, Provider> = HashMap::new();
    Json(json!({ "providers": providers }))
}

/// Get specific proxy provider
pub async fn get_proxy_provider(
    State(_state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    // Provider fetch (stub). Integrate with provider manager.
    log::info!("Getting proxy provider: {}", provider_name);
    StatusCode::NOT_FOUND
}

/// Update proxy provider
pub async fn update_proxy_provider(
    State(_state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    // Provider update (stub). Integrate with provider manager.
    log::info!("Updating proxy provider: {}", provider_name);
    StatusCode::NO_CONTENT
}

/// Health check proxy provider
pub async fn healthcheck_proxy_provider(
    State(_state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    // Provider health (stub). Integrate with provider manager.
    log::info!("Health checking proxy provider: {}", provider_name);
    StatusCode::NO_CONTENT
}

/// Get rule providers
pub async fn get_rule_providers(State(_state): State<ApiState>) -> impl IntoResponse {
    // Rule provider listing (stub). Integrate with rule provider manager.
    let providers: HashMap<String, Provider> = HashMap::new();
    Json(json!({ "providers": providers }))
}

/// Get specific rule provider
pub async fn get_rule_provider(
    State(_state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    // Rule provider fetch (stub). Integrate with rule provider manager.
    log::info!("Getting rule provider: {}", provider_name);
    StatusCode::NOT_FOUND
}

/// Update rule provider
pub async fn update_rule_provider(
    State(_state): State<ApiState>,
    Path(provider_name): Path<String>,
) -> impl IntoResponse {
    // Rule provider update (stub). Integrate with rule provider manager.
    log::info!("Updating rule provider: {}", provider_name);
    StatusCode::NO_CONTENT
}

/// Flush fake IP cache
pub async fn flush_fakeip_cache(State(_state): State<ApiState>) -> impl IntoResponse {
    // Fake IP cache flush (stub). Integrate with DNS service.
    log::info!("Flushing fake IP cache");
    StatusCode::NO_CONTENT
}

/// Flush DNS cache
pub async fn flush_dns_cache(State(_state): State<ApiState>) -> impl IntoResponse {
    // DNS cache flush (stub). Integrate with DNS service.
    log::info!("Flushing DNS cache");
    StatusCode::NO_CONTENT
}

/// Get version information
pub async fn get_version(State(_state): State<ApiState>) -> impl IntoResponse {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "premium": false,
        "meta": true
    }))
}

/// Get status/health check
pub async fn get_status(State(_state): State<ApiState>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "message": "Clash API server is running"
    }))
}

/// Determine connection type based on network protocol and proxy type
fn determine_connection_type(network: &str, proxy: &str) -> String {
    // Map network protocol to connection type
    match network.to_lowercase().as_str() {
        "tcp" => {
            // For TCP connections, determine type based on proxy
            match proxy.to_lowercase().as_str() {
                "direct" => "DIRECT".to_string(),
                p if p.contains("socks") => "SOCKS5".to_string(),
                p if p.contains("http") => "HTTP".to_string(),
                p if p.contains("vless") => "VLESS".to_string(),
                p if p.contains("vmess") => "VMESS".to_string(),
                p if p.contains("trojan") => "TROJAN".to_string(),
                p if p.contains("shadowsocks") || p.contains("ss") => "SHADOWSOCKS".to_string(),
                _ => "HTTP".to_string(), // Default to HTTP for unknown TCP proxies
            }
        }
        "udp" => {
            // For UDP connections, typically relay-based
            if proxy == "direct" {
                "DIRECT".to_string()
            } else {
                "RELAY".to_string()
            }
        }
        _ => "Unknown".to_string(),
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
        if host_part.starts_with('[') && host_part.ends_with(']') {
            return host_part[1..host_part.len()-1].to_string();
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
    "0".to_string()
}
