//! Clash API server implementation

use crate::managers::{ConnectionManager, DnsResolver, ProviderManager};
use crate::{
    clash::{handlers, websocket},
    error::{ApiError, ApiResult},
    monitoring::MonitoringSystemHandle,
    types::ApiConfig,
};
use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use sb_core::routing::router::Router as CoreRouter;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};

/// Clash API server state shared across handlers
#[derive(Clone)]
pub struct ApiState {
    /// Configuration for the API server
    pub config: Arc<ApiConfig>,
    /// Broadcast channel for traffic statistics
    pub traffic_tx: broadcast::Sender<crate::types::TrafficStats>,
    /// Broadcast channel for log entries
    pub log_tx: broadcast::Sender<crate::types::LogEntry>,
    /// Real-time monitoring system handle
    pub monitoring: Option<MonitoringSystemHandle>,
    /// Router handle for routing decisions
    pub router: Option<Arc<CoreRouter>>,
    /// Outbound manager for proxy operations
    pub outbound_manager: Option<Arc<sb_core::outbound::manager::OutboundManager>>,
    /// Connection manager for active connection tracking
    pub connection_manager: Option<Arc<ConnectionManager>>,
    /// DNS resolver for cache operations
    pub dns_resolver: Option<Arc<DnsResolver>>,
    /// Provider manager for proxy and rule providers
    pub provider_manager: Option<Arc<ProviderManager>>,
}

impl ApiState {
    /// Create new API state
    pub fn new(
        config: ApiConfig,
    ) -> (
        Self,
        broadcast::Receiver<crate::types::TrafficStats>,
        broadcast::Receiver<crate::types::LogEntry>,
    ) {
        let (traffic_tx, traffic_rx) = broadcast::channel(1000);
        let (log_tx, log_rx) = broadcast::channel(1000);

        let state = Self {
            config: Arc::new(config),
            traffic_tx,
            log_tx,
            monitoring: None,
            router: None,
            outbound_manager: None,
            connection_manager: None,
            dns_resolver: None,
            provider_manager: None,
        };

        (state, traffic_rx, log_rx)
    }

    /// Create new API state with monitoring system
    pub fn with_monitoring(
        config: ApiConfig,
        monitoring: MonitoringSystemHandle,
    ) -> (
        Self,
        broadcast::Receiver<crate::types::TrafficStats>,
        broadcast::Receiver<crate::types::LogEntry>,
    ) {
        let (traffic_tx, traffic_rx) = broadcast::channel(1000);
        let (log_tx, log_rx) = broadcast::channel(1000);

        let state = Self {
            config: Arc::new(config),
            traffic_tx,
            log_tx,
            monitoring: Some(monitoring),
            router: None,
            outbound_manager: None,
            connection_manager: None,
            dns_resolver: None,
            provider_manager: None,
        };

        (state, traffic_rx, log_rx)
    }
}

/// Clash API server
pub struct ClashApiServer {
    state: ApiState,
    listen_addr: SocketAddr,
}

impl ClashApiServer {
    /// Create a new Clash API server
    pub fn new(config: ApiConfig) -> ApiResult<Self> {
        let listen_addr = config.listen_addr;
        let (state, _traffic_rx, _log_rx) = ApiState::new(config);

        Ok(Self { state, listen_addr })
    }

    /// Create a new Clash API server with monitoring system
    pub fn with_monitoring(
        config: ApiConfig,
        monitoring: MonitoringSystemHandle,
    ) -> ApiResult<Self> {
        let listen_addr = config.listen_addr;
        let (state, _traffic_rx, _log_rx) = ApiState::with_monitoring(config, monitoring);

        Ok(Self { state, listen_addr })
    }

    /// Start the API server
    pub async fn start(&self) -> ApiResult<()> {
        let app = self.create_app();

        log::info!("Starting Clash API server on {}", self.listen_addr);

        let listener = tokio::net::TcpListener::bind(self.listen_addr)
            .await
            .map_err(|e| {
                ApiError::configuration(format!("Failed to bind to {}: {}", self.listen_addr, e))
            })?;

        axum::serve(listener, app)
            .await
            .map_err(|e| ApiError::Internal { source: e.into() })?;

        Ok(())
    }

    /// Create the Axum router with all endpoints
    pub fn create_app(&self) -> Router {
        let mut app = Router::new()
            // Proxy management
            .route("/proxies", get(handlers::get_proxies))
            .route("/proxies/:name", put(handlers::select_proxy))
            .route("/proxies/:name/delay", get(handlers::get_proxy_delay))
            // Connection management
            .route("/connections", get(handlers::get_connections))
            .route("/connections/:id", delete(handlers::close_connection))
            .route("/connections", delete(handlers::close_all_connections))
            // Rules
            .route("/rules", get(handlers::get_rules))
            // Configuration
            .route("/configs", get(handlers::get_configs))
            .route("/configs", patch(handlers::update_configs))
            .route("/configs", put(handlers::replace_configs))
            // UI
            .route("/ui", get(handlers::get_ui))
            // Real-time WebSocket endpoints
            .route("/traffic", get(websocket::traffic_websocket))
            .route("/logs", get(websocket::logs_websocket))
            // Provider management
            .route("/providers/proxies", get(handlers::get_proxy_providers))
            .route(
                "/providers/proxies/:name",
                get(handlers::get_proxy_provider),
            )
            .route(
                "/providers/proxies/:name",
                put(handlers::update_proxy_provider),
            )
            .route(
                "/providers/proxies/:name/healthcheck",
                post(handlers::healthcheck_proxy_provider),
            )
            .route("/providers/rules", get(handlers::get_rule_providers))
            .route("/providers/rules/:name", get(handlers::get_rule_provider))
            .route(
                "/providers/rules/:name",
                put(handlers::update_rule_provider),
            )
            // Cache management
            .route("/cache/fakeip/flush", delete(handlers::flush_fakeip_cache))
            .route("/dns/flush", delete(handlers::flush_dns_cache))
            // DNS query
            .route("/dns/query", get(handlers::get_dns_query))
            // Meta endpoints
            .route("/meta/group", get(handlers::get_meta_groups))
            .route("/meta/group/:name", get(handlers::get_meta_group))
            .route(
                "/meta/group/:name/delay",
                get(handlers::get_meta_group_delay),
            )
            .route("/meta/memory", get(handlers::get_meta_memory))
            .route("/meta/gc", put(handlers::trigger_gc))
            // Script endpoints
            .route("/script", patch(handlers::update_script))
            .route("/script", post(handlers::test_script))
            // Profile/tracing endpoints
            .route("/profile/tracing", get(handlers::get_profile_tracing))
            // Upgrade endpoints
            .route("/connectionsUpgrade", get(handlers::upgrade_connections))
            .route("/metaUpgrade", get(handlers::get_meta_upgrade))
            .route("/meta/upgrade/ui", post(handlers::upgrade_external_ui))
            // Version and status
            .route("/version", get(handlers::get_version))
            .route("/", get(handlers::get_status))
            .with_state(self.state.clone());

        // Add CORS if enabled
        if self.state.config.enable_cors {
            let cors = if let Some(ref origins) = self.state.config.cors_origins {
                let mut cors_layer = CorsLayer::new();
                for origin in origins {
                    if let Ok(parsed_origin) = origin.parse::<http::HeaderValue>() {
                        cors_layer = cors_layer.allow_origin(parsed_origin);
                    } else {
                        log::warn!("Invalid CORS origin: {}", origin);
                        if let Ok(fallback) = "http://localhost:3000".parse::<http::HeaderValue>() {
                            cors_layer = cors_layer.allow_origin(fallback);
                        }
                    }
                }
                cors_layer.allow_methods(Any).allow_headers(Any)
            } else {
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any)
            };

            app = app.layer(cors);
        }

        app
    }

    /// Get a reference to the API state
    pub fn state(&self) -> &ApiState {
        &self.state
    }

    /// Broadcast a traffic statistics update
    pub fn broadcast_traffic(&self, stats: crate::types::TrafficStats) -> ApiResult<()> {
        self.state.traffic_tx.send(stats).map_err(|_| {
            ApiError::service_unavailable("No active WebSocket clients for traffic updates")
        })?;
        Ok(())
    }

    /// Broadcast a log entry
    pub fn broadcast_log(&self, log: crate::types::LogEntry) -> ApiResult<()> {
        self.state.log_tx.send(log).map_err(|_| {
            ApiError::service_unavailable("No active WebSocket clients for log updates")
        })?;
        Ok(())
    }
}
