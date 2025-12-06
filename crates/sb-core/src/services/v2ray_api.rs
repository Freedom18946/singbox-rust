//! V2Ray API Server Implementation
//!
//! Provides V2Ray-compatible API for statistics and management.
//! This module bridges the sb-core context with sb-api's V2Ray implementation.
//!
//! ## Services
//! - Stats Service: Query traffic statistics
//! - Handler Service: Manage inbound/outbound handlers
//! - Logger Service: Log streaming
//!
//! ## Endpoints
//! Stats are exposed via JSON over HTTP for simplicity.
//! Full gRPC support requires the `tonic` dependency.

use crate::context::V2RayServer;
use sb_config::ir::V2RayApiIR;
use std::collections::HashMap;
#[cfg(any(feature = "service_v2ray_api", test))]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "service_v2ray_api")]
use axum::{
    extract::{Query, State},
    response::Json,
    routing::get,
    Router,
};

#[cfg(feature = "service_v2ray_api")]
use tokio::sync::oneshot;

/// Statistics counter
#[derive(Debug, Default)]
pub struct StatCounter {
    value: AtomicU64,
}

impl StatCounter {
    /// Create a new counter with initial value
    pub fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }

    /// Get current value
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Add to counter
    pub fn add(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::SeqCst);
    }

    /// Reset counter and return previous value
    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::SeqCst)
    }
}

/// Statistics manager
#[derive(Debug, Default)]
pub struct StatsManager {
    counters: RwLock<HashMap<String, Arc<StatCounter>>>,
}

impl StatsManager {
    /// Create a new stats manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a counter
    pub async fn get_counter(&self, name: &str) -> Arc<StatCounter> {
        {
            let counters = self.counters.read().await;
            if let Some(counter) = counters.get(name) {
                return counter.clone();
            }
        }

        let mut counters = self.counters.write().await;
        counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(StatCounter::new(0)))
            .clone()
    }

    /// Get counter value by name
    pub async fn get_stat(&self, name: &str) -> Option<u64> {
        let counters = self.counters.read().await;
        counters.get(name).map(|c| c.get())
    }

    /// Query stats matching pattern
    pub async fn query_stats(&self, pattern: &str, reset: bool) -> Vec<(String, u64)> {
        let counters = self.counters.read().await;
        counters
            .iter()
            .filter(|(name, _)| pattern.is_empty() || name.contains(pattern))
            .map(|(name, counter)| {
                let value = if reset { counter.reset() } else { counter.get() };
                (name.clone(), value)
            })
            .collect()
    }

    /// Update traffic counter
    pub async fn update_traffic(&self, name: &str, bytes: u64) {
        let counter = self.get_counter(name).await;
        counter.add(bytes);
    }

    /// Initialize standard V2Ray counters
    pub async fn init_standard_counters(&self) {
        let counters = [
            "inbound>>>api>>>traffic>>>uplink",
            "inbound>>>api>>>traffic>>>downlink",
            "outbound>>>direct>>>traffic>>>uplink",
            "outbound>>>direct>>>traffic>>>downlink",
            "outbound>>>proxy>>>traffic>>>uplink",
            "outbound>>>proxy>>>traffic>>>downlink",
        ];

        for name in counters {
            self.get_counter(name).await;
        }
    }
}

/// V2Ray API server state
#[derive(Clone)]
pub struct V2RayApiState {
    stats: Arc<StatsManager>,
    enabled: bool,
}

impl std::fmt::Debug for V2RayApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2RayApiState")
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// V2Ray API server
#[derive(Debug)]
pub struct V2RayApiServer {
    cfg: V2RayApiIR,
    started: AtomicBool,
    state: V2RayApiState,
    #[cfg(feature = "service_v2ray_api")]
    shutdown_tx: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
}

impl V2RayApiServer {
    /// Create a new V2Ray API server
    pub fn new(cfg: V2RayApiIR) -> Self {
        let enabled = cfg.stats.as_ref().map(|s| s.enabled).unwrap_or(false);
        let stats = Arc::new(StatsManager::new());

        Self {
            cfg,
            started: AtomicBool::new(false),
            state: V2RayApiState { stats, enabled },
            #[cfg(feature = "service_v2ray_api")]
            shutdown_tx: parking_lot::Mutex::new(None),
        }
    }

    /// Get reference to stats manager
    pub fn stats(&self) -> &Arc<StatsManager> {
        &self.state.stats
    }

    /// Check if stats are enabled
    pub fn stats_enabled(&self) -> bool {
        self.state.enabled
    }

    /// Get listen address
    #[cfg(any(feature = "service_v2ray_api", test))]
    fn listen_addr(&self) -> Option<SocketAddr> {
        self.cfg.listen.as_ref().and_then(|addr| addr.parse().ok())
    }

    /// Create the Axum router with V2Ray API endpoints
    #[cfg(feature = "service_v2ray_api")]
    fn create_router(&self) -> Router {
        Router::new()
            .route("/v2ray.core.app.stats.command.StatsService/GetStats", get(handlers::get_stats))
            .route("/v2ray.core.app.stats.command.StatsService/QueryStats", get(handlers::query_stats))
            .route("/v2ray.core.app.stats.command.StatsService/GetSysStats", get(handlers::get_sys_stats))
            // Simplified HTTP endpoints
            .route("/api/stats", get(handlers::api_stats))
            .route("/api/stats/query", get(handlers::api_query_stats))
            .route("/api/sys", get(handlers::api_sys_stats))
            .with_state(self.state.clone())
    }
}

impl V2RayServer for V2RayApiServer {
    fn start(&self) -> anyhow::Result<()> {
        #[cfg(not(feature = "service_v2ray_api"))]
        {
            self.started.store(true, Ordering::SeqCst);
            tracing::info!(
                target: "sb_core::services::v2ray",
                listen = ?self.cfg.listen,
                stats_enabled = self.state.enabled,
                "V2Ray API server start requested (stub - enable 'service_v2ray_api' feature)"
            );
            Ok(())
        }

        #[cfg(feature = "service_v2ray_api")]
        {
            let listen_addr = match self.listen_addr() {
                Some(addr) => addr,
                None => {
                    tracing::warn!(
                        target: "sb_core::services::v2ray",
                        "V2Ray API listen address not configured, server not started"
                    );
                    return Ok(());
                }
            };

            self.started.store(true, Ordering::SeqCst);

            // Initialize standard counters
            let stats = self.state.stats.clone();
            tokio::spawn(async move {
                stats.init_standard_counters().await;
            });

            let router = self.create_router();

            tracing::info!(
                target: "sb_core::services::v2ray",
                listen = %listen_addr,
                stats_enabled = self.state.enabled,
                "Starting V2Ray API HTTP server"
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            *self.shutdown_tx.lock() = Some(shutdown_tx);

            tokio::spawn(async move {
                let listener = match tokio::net::TcpListener::bind(listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            target: "sb_core::services::v2ray",
                            error = %e,
                            "Failed to bind V2Ray API server"
                        );
                        return;
                    }
                };

                tracing::info!(
                    target: "sb_core::services::v2ray",
                    listen = %listen_addr,
                    "V2Ray API HTTP server started"
                );

                let server = axum::serve(listener, router).with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                    tracing::info!(target: "sb_core::services::v2ray", "Received shutdown signal");
                });

                if let Err(e) = server.await {
                    tracing::error!(target: "sb_core::services::v2ray", error = %e, "V2Ray API server error");
                }
            });

            Ok(())
        }
    }

    fn close(&self) -> anyhow::Result<()> {
        self.started.store(false, Ordering::SeqCst);

        #[cfg(feature = "service_v2ray_api")]
        {
            if let Some(tx) = self.shutdown_tx.lock().take() {
                let _ = tx.send(());
            }
        }

        tracing::info!(target: "sb_core::services::v2ray", "V2Ray API server stopped");
        Ok(())
    }
}

/// HTTP handlers for V2Ray API endpoints
#[cfg(feature = "service_v2ray_api")]
mod handlers {
    use super::*;
    use serde::{Deserialize, Serialize};

    // ─────────────────────────────────────────────────────────────────────────
    // Response Types (V2Ray compatible)
    // ─────────────────────────────────────────────────────────────────────────

    #[derive(Serialize)]
    pub struct Stat {
        pub name: String,
        pub value: i64,
    }

    #[derive(Serialize)]
    pub struct GetStatsResponse {
        pub stat: Option<Stat>,
    }

    #[derive(Serialize)]
    pub struct QueryStatsResponse {
        pub stat: Vec<Stat>,
    }

    #[derive(Serialize)]
    pub struct SysStatsResponse {
        #[serde(rename = "NumGoroutine")]
        pub num_goroutine: u32,
        #[serde(rename = "NumGC")]
        pub num_gc: u32,
        #[serde(rename = "Alloc")]
        pub alloc: u64,
        #[serde(rename = "TotalAlloc")]
        pub total_alloc: u64,
        #[serde(rename = "Sys")]
        pub sys: u64,
        #[serde(rename = "Mallocs")]
        pub mallocs: u64,
        #[serde(rename = "Frees")]
        pub frees: u64,
        #[serde(rename = "LiveObjects")]
        pub live_objects: u64,
        #[serde(rename = "PauseTotalNs")]
        pub pause_total_ns: u64,
        #[serde(rename = "Uptime")]
        pub uptime: u32,
    }

    #[derive(Deserialize)]
    pub struct StatsQuery {
        name: Option<String>,
        reset: Option<bool>,
    }

    #[derive(Deserialize)]
    pub struct QueryStatsQuery {
        pattern: Option<String>,
        reset: Option<bool>,
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Handler Implementations
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn get_stats(
        State(state): State<V2RayApiState>,
        Query(params): Query<StatsQuery>,
    ) -> Json<GetStatsResponse> {
        let name = params.name.unwrap_or_default();
        let reset = params.reset.unwrap_or(false);

        let stat = if let Some(value) = state.stats.get_stat(&name).await {
            if reset {
                let counter = state.stats.get_counter(&name).await;
                counter.reset();
            }
            Some(Stat {
                name,
                value: value as i64,
            })
        } else {
            None
        };

        Json(GetStatsResponse { stat })
    }

    pub async fn query_stats(
        State(state): State<V2RayApiState>,
        Query(params): Query<QueryStatsQuery>,
    ) -> Json<QueryStatsResponse> {
        let pattern = params.pattern.unwrap_or_default();
        let reset = params.reset.unwrap_or(false);

        let stats = state.stats.query_stats(&pattern, reset).await;
        let stat = stats
            .into_iter()
            .map(|(name, value)| Stat {
                name,
                value: value as i64,
            })
            .collect();

        Json(QueryStatsResponse { stat })
    }

    pub async fn get_sys_stats() -> Json<SysStatsResponse> {
        // Simulate Go runtime stats with Rust equivalents
        Json(SysStatsResponse {
            num_goroutine: tokio::runtime::Handle::current().metrics().num_workers() as u32,
            num_gc: 0, // No GC in Rust
            alloc: 0,  // Would need allocator tracking
            total_alloc: 0,
            sys: 0,
            mallocs: 0,
            frees: 0,
            live_objects: 0,
            pause_total_ns: 0,
            uptime: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0),
        })
    }

    // Simplified API endpoints
    pub async fn api_stats(
        State(state): State<V2RayApiState>,
        Query(params): Query<StatsQuery>,
    ) -> Json<GetStatsResponse> {
        get_stats(State(state), Query(params)).await
    }

    pub async fn api_query_stats(
        State(state): State<V2RayApiState>,
        Query(params): Query<QueryStatsQuery>,
    ) -> Json<QueryStatsResponse> {
        query_stats(State(state), Query(params)).await
    }

    pub async fn api_sys_stats() -> Json<SysStatsResponse> {
        get_sys_stats().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stats_manager() {
        let manager = StatsManager::new();

        // Get counter
        let counter = manager.get_counter("test>>>traffic>>>uplink").await;
        assert_eq!(counter.get(), 0);

        // Add traffic
        counter.add(1024);
        assert_eq!(counter.get(), 1024);

        // Query stats
        let stats = manager.query_stats("traffic", false).await;
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "test>>>traffic>>>uplink");
        assert_eq!(stats[0].1, 1024);

        // Reset
        let old = counter.reset();
        assert_eq!(old, 1024);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_server_creation() {
        let cfg = V2RayApiIR {
            listen: Some("127.0.0.1:10085".to_string()),
            stats: Some(sb_config::ir::StatsIR {
                enabled: true,
                inbound: true,
                outbound: true,
                users: vec![],
            }),
        };

        let server = V2RayApiServer::new(cfg);
        assert!(server.stats_enabled());
        assert_eq!(
            server.listen_addr(),
            Some("127.0.0.1:10085".parse().unwrap())
        );
    }
}
