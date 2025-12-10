//! Clash API Server Implementation
//!
//! Provides an HTTP REST API compatible with Clash/Clash.Meta clients.
//! This module implements the external controller API for sing-box.
//!
//! ## Endpoints (Clash API v1)
//!
//! ### Configuration
//! - `GET  /configs` - Get current configuration
//! - `PATCH /configs` - Update configuration (mode, log-level, etc.)
//!
//! ### Proxies
//! - `GET  /proxies` - List all proxies and groups
//! - `GET  /proxies/:name` - Get specific proxy info
//! - `PUT  /proxies/:name` - Switch proxy in a group
//! - `GET  /proxies/:name/delay` - Test proxy latency
//!
//! ### Connections
//! - `GET  /connections` - List active connections
//! - `DELETE /connections` - Close all connections
//! - `DELETE /connections/:id` - Close specific connection
//!
//! ### Rules
//! - `GET  /rules` - List routing rules
//!
//! ### DNS
//! - `GET  /dns/query` - Query DNS
//!
//! ### Logs
//! - `GET  /logs` - WebSocket stream of logs (SSE fallback)
//!
//! ### Traffic
//! - `GET  /traffic` - WebSocket stream of traffic stats
//!
//! ### Version
//! - `GET  /version` - Get sing-box version info

use crate::context::ClashServer;
use sb_config::ir::ClashApiIR;
#[cfg(any(feature = "service_clash_api", test))]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
// use tokio::sync::oneshot;

#[cfg(feature = "service_clash_api")]
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get},
    Router,
};
#[cfg(feature = "service_clash_api")]
use tokio::sync::oneshot;

/// Clash API Server state.
#[derive(Debug, Clone)]
pub struct ClashApiState {
    /// Current Clash mode (e.g., "rule", "global", "direct")
    pub mode: Arc<parking_lot::RwLock<String>>,
    /// Authentication secret
    pub secret: Option<String>,
    /// Reference to context managers (lazy: populated at runtime)
    pub connections: Option<Arc<crate::context::ConnectionManager>>,
}

impl ClashApiState {
    fn new(cfg: &ClashApiIR) -> Self {
        Self {
            mode: Arc::new(parking_lot::RwLock::new(
                cfg.default_mode
                    .clone()
                    .unwrap_or_else(|| "rule".to_string()),
            )),
            secret: cfg.secret.clone(),
            connections: None,
        }
    }

    /// Get current Clash mode.
    pub fn get_mode(&self) -> String {
        self.mode.read().clone()
    }

    /// Set Clash mode.
    pub fn set_mode(&self, mode: String) {
        *self.mode.write() = mode;
    }
}

/// Clash API server instance.
#[derive(Debug)]
pub struct ClashApiServer {
    cfg: ClashApiIR,
    started: AtomicBool,
    state: ClashApiState,
    #[cfg(feature = "service_clash_api")]
    shutdown_tx: parking_lot::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl ClashApiServer {
    pub fn new(cfg: ClashApiIR) -> Self {
        let state = ClashApiState::new(&cfg);
        Self {
            cfg,
            started: AtomicBool::new(false),
            state,
            #[cfg(feature = "service_clash_api")]
            shutdown_tx: parking_lot::Mutex::new(None),
        }
    }

    /// Get the current Clash mode.
    pub fn get_mode(&self) -> String {
        self.state.get_mode()
    }

    /// Set the current Clash mode.
    pub fn set_mode(&self, mode: String) {
        self.state.set_mode(mode);
    }

    /// Get the listen address.
    #[cfg(any(feature = "service_clash_api", test))]
    fn listen_addr(&self) -> Option<SocketAddr> {
        self.cfg
            .external_controller
            .as_ref()
            .and_then(|addr| addr.parse().ok())
    }

    /// Create the Axum router with all Clash API endpoints.
    #[cfg(feature = "service_clash_api")]
    fn create_router(&self) -> Router {
        Router::new()
            // Version
            .route("/version", get(handlers::get_version))
            // Configuration
            .route(
                "/configs",
                get(handlers::get_configs).patch(handlers::patch_configs),
            )
            // Proxies
            .route("/proxies", get(handlers::get_proxies))
            .route(
                "/proxies/:name",
                get(handlers::get_proxy).put(handlers::switch_proxy),
            )
            .route("/proxies/:name/delay", get(handlers::get_proxy_delay))
            // Connections
            .route(
                "/connections",
                get(handlers::get_connections).delete(handlers::close_all_connections),
            )
            .route("/connections/:id", delete(handlers::close_connection))
            // Rules
            .route("/rules", get(handlers::get_rules))
            // Providers
            .route("/providers/proxies", get(handlers::get_proxy_providers))
            .route("/providers/rules", get(handlers::get_rule_providers))
            // DNS
            .route("/dns/query", get(handlers::dns_query))
            // Traffic (placeholder for WebSocket upgrade)
            .route("/traffic", get(handlers::get_traffic))
            // Logs (placeholder for WebSocket upgrade)
            .route("/logs", get(handlers::get_logs))
            .with_state(self.state.clone())
    }
}

impl ClashServer for ClashApiServer {
    fn start(&self) -> anyhow::Result<()> {
        #[cfg(not(feature = "service_clash_api"))]
        {
            self.started.store(true, Ordering::SeqCst);
            tracing::info!(
                target: "sb_core::services::clash",
                listen = ?self.cfg.external_controller,
                "Clash API server start requested (stub - enable 'service_clash_api' feature)"
            );
            Ok(())
        }

        #[cfg(feature = "service_clash_api")]
        {
            let listen_addr = match self.listen_addr() {
                Some(addr) => addr,
                None => {
                    tracing::warn!(
                        target: "sb_core::services::clash",
                        "Clash API external_controller not configured, server not started"
                    );
                    return Ok(());
                }
            };

            self.started.store(true, Ordering::SeqCst);
            let router = self.create_router();

            tracing::info!(
                target: "sb_core::services::clash",
                listen = %listen_addr,
                secret = self.cfg.secret.is_some(),
                mode = %self.state.get_mode(),
                "Starting Clash API HTTP server"
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            *self.shutdown_tx.lock() = Some(shutdown_tx);

            tokio::spawn(async move {
                let listener = match tokio::net::TcpListener::bind(listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            target: "sb_core::services::clash",
                            error = %e,
                            "Failed to bind Clash API server"
                        );
                        return;
                    }
                };

                tracing::info!(
                    target: "sb_core::services::clash",
                    listen = %listen_addr,
                    "Clash API HTTP server started"
                );

                let server = axum::serve(listener, router).with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                    tracing::info!(target: "sb_core::services::clash", "Received shutdown signal");
                });

                if let Err(e) = server.await {
                    tracing::error!(target: "sb_core::services::clash", error = %e, "Clash API server error");
                }
            });

            Ok(())
        }
    }

    fn close(&self) -> anyhow::Result<()> {
        self.started.store(false, Ordering::SeqCst);

        #[cfg(feature = "service_clash_api")]
        {
            if let Some(tx) = self.shutdown_tx.lock().take() {
                let _ = tx.send(());
            }
        }

        tracing::info!(target: "sb_core::services::clash", "Clash API server stopped");
        Ok(())
    }

    fn get_mode(&self) -> String {
        self.state.get_mode()
    }
}

/// HTTP handlers for Clash API endpoints.
#[cfg(feature = "service_clash_api")]
mod handlers {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    // ─────────────────────────────────────────────────────────────────────────
    // Response Types
    // ─────────────────────────────────────────────────────────────────────────

    #[derive(Serialize)]
    pub struct VersionResponse {
        pub version: String,
        pub meta: bool,
        pub premium: bool,
    }

    #[derive(Serialize)]
    pub struct ConfigResponse {
        pub port: u16,
        #[serde(rename = "socks-port")]
        pub socks_port: u16,
        #[serde(rename = "redir-port")]
        pub redir_port: u16,
        #[serde(rename = "tproxy-port")]
        pub tproxy_port: u16,
        #[serde(rename = "mixed-port")]
        pub mixed_port: u16,
        #[serde(rename = "allow-lan")]
        pub allow_lan: bool,
        pub mode: String,
        #[serde(rename = "log-level")]
        pub log_level: String,
        pub ipv6: bool,
    }

    #[derive(Deserialize)]
    pub struct ConfigPatch {
        mode: Option<String>,
        #[serde(rename = "log-level")]
        log_level: Option<String>,
    }

    #[derive(Serialize)]
    pub struct ProxiesResponse {
        pub proxies: HashMap<String, ProxyInfo>,
    }

    #[derive(Serialize, Clone)]
    pub struct ProxyInfo {
        pub name: String,
        #[serde(rename = "type")]
        pub proxy_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub now: Option<String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub all: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub history: Option<Vec<DelayHistory>>,
        pub udp: bool,
    }

    #[derive(Serialize, Clone)]
    pub struct DelayHistory {
        pub time: String,
        pub delay: u32,
    }

    #[derive(Deserialize)]
    pub struct DelayQuery {
        url: Option<String>,
        timeout: Option<u64>,
    }

    #[derive(Serialize)]
    pub struct DelayResponse {
        pub delay: u32,
    }

    #[derive(Serialize)]
    pub struct ConnectionsResponse {
        #[serde(rename = "downloadTotal")]
        pub download_total: u64,
        #[serde(rename = "uploadTotal")]
        pub upload_total: u64,
        pub connections: Vec<ConnectionInfo>,
    }

    #[derive(Serialize)]
    pub struct ConnectionInfo {
        pub id: String,
        pub metadata: ConnectionMetadata,
        pub upload: u64,
        pub download: u64,
        pub start: String,
        pub chains: Vec<String>,
        pub rule: String,
        #[serde(rename = "rulePayload")]
        pub rule_payload: String,
    }

    #[derive(Serialize)]
    pub struct ConnectionMetadata {
        pub network: String,
        #[serde(rename = "type")]
        pub conn_type: String,
        #[serde(rename = "sourceIP")]
        pub source_ip: String,
        #[serde(rename = "destinationIP")]
        pub destination_ip: String,
        #[serde(rename = "sourcePort")]
        pub source_port: String,
        #[serde(rename = "destinationPort")]
        pub destination_port: String,
        pub host: String,
        #[serde(rename = "dnsMode")]
        pub dns_mode: String,
        #[serde(rename = "processPath")]
        pub process_path: String,
        #[serde(rename = "specialProxy")]
        pub special_proxy: String,
    }

    #[derive(Serialize)]
    pub struct RulesResponse {
        pub rules: Vec<RuleInfo>,
    }

    #[derive(Serialize)]
    pub struct RuleInfo {
        #[serde(rename = "type")]
        pub rule_type: String,
        pub payload: String,
        pub proxy: String,
        pub size: i32,
    }

    #[derive(Serialize)]
    pub struct ProvidersResponse {
        pub providers: HashMap<String, ProviderInfo>,
    }

    #[derive(Serialize)]
    pub struct ProviderInfo {
        pub name: String,
        #[serde(rename = "type")]
        pub provider_type: String,
        #[serde(rename = "vehicleType")]
        pub vehicle_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub proxies: Option<Vec<ProxyInfo>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub rules: Option<Vec<RuleInfo>>,
        #[serde(rename = "updatedAt")]
        pub updated_at: Option<String>,
    }

    #[derive(Deserialize)]
    pub struct DnsQueryParams {
        name: String,
        #[serde(rename = "type")]
        record_type: Option<String>,
    }

    #[derive(Serialize)]
    pub struct DnsQueryResponse {
        #[serde(rename = "Status")]
        pub status: i32,
        #[serde(rename = "Answer")]
        pub answer: Vec<DnsAnswer>,
    }

    #[derive(Serialize)]
    pub struct DnsAnswer {
        #[serde(rename = "TTL")]
        pub ttl: u32,
        pub data: String,
        pub name: String,
        #[serde(rename = "type")]
        pub record_type: u16,
    }

    #[derive(Serialize)]
    pub struct TrafficResponse {
        pub up: u64,
        pub down: u64,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handler Implementations
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_version() -> Json<VersionResponse> {
        Json(VersionResponse {
            version: format!("singbox-rust {}", env!("CARGO_PKG_VERSION")),
            meta: true, // We support Meta extensions
            premium: false,
        })
    }

    pub async fn get_configs(State(state): State<ClashApiState>) -> Json<ConfigResponse> {
        Json(ConfigResponse {
            port: 0,
            socks_port: 0,
            redir_port: 0,
            tproxy_port: 0,
            mixed_port: 0,
            allow_lan: false,
            mode: state.get_mode(),
            log_level: "info".to_string(),
            ipv6: true,
        })
    }

    pub async fn patch_configs(
        State(state): State<ClashApiState>,
        Json(patch): Json<ConfigPatch>,
    ) -> StatusCode {
        if let Some(mode) = patch.mode {
            match mode.as_str() {
                "rule" | "global" | "direct" => {
                    state.set_mode(mode.clone());
                    tracing::info!(target: "sb_core::services::clash", mode = %mode, "Clash mode changed");
                }
                _ => {
                    tracing::warn!(target: "sb_core::services::clash", mode = %mode, "Invalid mode");
                    return StatusCode::BAD_REQUEST;
                }
            }
        }

        if let Some(log_level) = patch.log_level {
            tracing::info!(target: "sb_core::services::clash", level = %log_level, "Log level change requested");
            // TODO: Actually change log level via tracing-subscriber reload
        }

        StatusCode::NO_CONTENT
    }

    pub async fn get_proxies() -> Json<ProxiesResponse> {
        let mut proxies = HashMap::new();

        // Built-in proxies
        proxies.insert(
            "DIRECT".to_string(),
            ProxyInfo {
                name: "DIRECT".to_string(),
                proxy_type: "Direct".to_string(),
                now: None,
                all: vec![],
                history: None,
                udp: true,
            },
        );

        proxies.insert(
            "REJECT".to_string(),
            ProxyInfo {
                name: "REJECT".to_string(),
                proxy_type: "Reject".to_string(),
                now: None,
                all: vec![],
                history: None,
                udp: true,
            },
        );

        // TODO: Populate from OutboundManager
        // For now, return placeholder data

        Json(ProxiesResponse { proxies })
    }

    pub async fn get_proxy(Path(name): Path<String>) -> Result<Json<ProxyInfo>, StatusCode> {
        // TODO: Look up proxy from OutboundManager
        match name.as_str() {
            "DIRECT" => Ok(Json(ProxyInfo {
                name: "DIRECT".to_string(),
                proxy_type: "Direct".to_string(),
                now: None,
                all: vec![],
                history: None,
                udp: true,
            })),
            "REJECT" => Ok(Json(ProxyInfo {
                name: "REJECT".to_string(),
                proxy_type: "Reject".to_string(),
                now: None,
                all: vec![],
                history: None,
                udp: true,
            })),
            _ => Err(StatusCode::NOT_FOUND),
        }
    }

    pub async fn switch_proxy(
        Path(name): Path<String>,
        Json(body): Json<HashMap<String, String>>,
    ) -> StatusCode {
        let selected = body.get("name").cloned().unwrap_or_default();
        tracing::info!(
            target: "sb_core::services::clash",
            group = %name,
            selected = %selected,
            "Proxy switch requested"
        );
        // TODO: Actually switch the selector group
        StatusCode::NO_CONTENT
    }

    pub async fn get_proxy_delay(
        Path(name): Path<String>,
        Query(params): Query<DelayQuery>,
    ) -> Result<Json<DelayResponse>, StatusCode> {
        let url = params
            .url
            .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string());
        let timeout = params.timeout.unwrap_or(5000);

        tracing::debug!(
            target: "sb_core::services::clash",
            proxy = %name,
            url = %url,
            timeout = timeout,
            "Delay test requested"
        );

        // TODO: Perform actual delay test via OutboundManager
        // For now, return a placeholder
        Ok(Json(DelayResponse { delay: 100 }))
    }

    pub async fn get_connections(State(state): State<ClashApiState>) -> Json<ConnectionsResponse> {
        let connections = if let Some(conn_mgr) = &state.connections {
            conn_mgr
                .all()
                .iter()
                .map(|c| {
                    let parts: Vec<&str> = c.destination.split(':').collect();
                    let (host, port) = if parts.len() == 2 {
                        (parts[0].to_string(), parts[1].to_string())
                    } else {
                        (c.destination.clone(), "0".to_string())
                    };

                    ConnectionInfo {
                        id: c.id.to_string(),
                        metadata: ConnectionMetadata {
                            network: c.protocol.clone(),
                            conn_type: "".to_string(),
                            source_ip: c.source.split(':').next().unwrap_or("").to_string(),
                            destination_ip: "".to_string(),
                            source_port: c.source.split(':').last().unwrap_or("0").to_string(),
                            destination_port: port,
                            host,
                            dns_mode: "".to_string(),
                            process_path: "".to_string(),
                            special_proxy: "".to_string(),
                        },
                        upload: 0,
                        download: 0,
                        start: "".to_string(),
                        chains: vec![],
                        rule: "".to_string(),
                        rule_payload: "".to_string(),
                    }
                })
                .collect()
        } else {
            vec![]
        };

        Json(ConnectionsResponse {
            download_total: 0,
            upload_total: 0,
            connections,
        })
    }

    pub async fn close_all_connections() -> StatusCode {
        tracing::info!(target: "sb_core::services::clash", "Close all connections requested");
        // TODO: Implement connection closing via ConnectionManager
        StatusCode::NO_CONTENT
    }

    pub async fn close_connection(Path(id): Path<String>) -> StatusCode {
        tracing::info!(target: "sb_core::services::clash", id = %id, "Close connection requested");
        // TODO: Implement single connection closing
        StatusCode::NO_CONTENT
    }

    pub async fn get_rules() -> Json<RulesResponse> {
        // TODO: Get rules from Router
        Json(RulesResponse { rules: vec![] })
    }

    pub async fn get_proxy_providers() -> Json<ProvidersResponse> {
        Json(ProvidersResponse {
            providers: HashMap::new(),
        })
    }

    pub async fn get_rule_providers() -> Json<ProvidersResponse> {
        Json(ProvidersResponse {
            providers: HashMap::new(),
        })
    }

    pub async fn dns_query(Query(params): Query<DnsQueryParams>) -> Json<DnsQueryResponse> {
        tracing::debug!(
            target: "sb_core::services::clash",
            name = %params.name,
            record_type = ?params.record_type,
            "DNS query requested"
        );

        // TODO: Perform actual DNS query via DNS module
        Json(DnsQueryResponse {
            status: 0,
            answer: vec![],
        })
    }

    pub async fn get_traffic() -> Json<TrafficResponse> {
        // TODO: Return actual traffic stats, or upgrade to WebSocket
        Json(TrafficResponse { up: 0, down: 0 })
    }

    pub async fn get_logs() -> &'static str {
        // TODO: Implement WebSocket log streaming
        "Log streaming not implemented - use WebSocket connection"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clash_api_server_creation() {
        let cfg = ClashApiIR {
            external_controller: Some("127.0.0.1:9090".to_string()),
            external_ui: None,
            secret: Some("test-secret".to_string()),
            external_ui_download_url: None,
            external_ui_download_detour: None,
            default_mode: Some("rule".to_string()),
        };

        let server = ClashApiServer::new(cfg);
        assert_eq!(server.get_mode(), "rule");
        assert_eq!(
            server.listen_addr(),
            Some("127.0.0.1:9090".parse().unwrap())
        );
    }

    #[test]
    fn test_mode_switching() {
        let cfg = ClashApiIR::default();
        let server = ClashApiServer::new(cfg);

        assert_eq!(server.get_mode(), "rule");
        server.set_mode("global".to_string());
        assert_eq!(server.get_mode(), "global");
        server.set_mode("direct".to_string());
        assert_eq!(server.get_mode(), "direct");
    }
}
