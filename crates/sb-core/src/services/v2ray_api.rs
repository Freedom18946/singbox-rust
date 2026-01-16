//! V2Ray API Server Implementation
//!
//! Provides V2Ray-compatible API for statistics and management via gRPC.
//! This module bridges the sb-core context with sb-api's V2Ray implementation.
//!
//! ## Services
//! - Stats Service: Query traffic statistics
//!
//! ## Endpoints
//! Exposed via gRPC on the configured listen address.

use crate::context::V2RayServer;
use parking_lot::RwLock;
use sb_config::ir::{StatsIR, V2RayApiIR};
use std::collections::{HashMap, HashSet};
#[cfg(any(feature = "service_v2ray_api", test))]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "service_v2ray_api")]
use tokio::sync::oneshot;

#[cfg(feature = "service_v2ray_api")]
use tonic::{transport::Server, Request, Response, Status};

#[cfg(feature = "service_v2ray_api")]
use crate::services::v2ray::stats::command::{
    stats_service_server::{StatsService, StatsServiceServer},
    GetStatsRequest, GetStatsResponse, QueryStatsRequest, QueryStatsResponse, Stat,
    SysStatsRequest, SysStatsResponse,
};

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
#[derive(Debug)]
pub struct StatsManager {
    enabled: bool,
    created_at: Instant,
    inbounds: HashSet<String>,
    outbounds: HashSet<String>,
    users: HashSet<String>,
    track_all_inbounds: bool,
    track_all_outbounds: bool,
    counters: RwLock<HashMap<String, Arc<StatCounter>>>,
}

impl StatsManager {
    /// Create a new stats manager from config.
    pub fn new(cfg: Option<StatsIR>) -> Self {
        let cfg = cfg.unwrap_or_default();
        let track_all_inbounds = cfg.inbound.unwrap_or(false);
        let track_all_outbounds = cfg.outbound.unwrap_or(false);
        let inbounds = cfg.inbounds.into_iter().collect();
        let outbounds = cfg.outbounds.into_iter().collect();
        let users = cfg.users.into_iter().collect();

        Self {
            enabled: cfg.enabled,
            created_at: Instant::now(),
            inbounds,
            outbounds,
            users,
            track_all_inbounds,
            track_all_outbounds,
            counters: RwLock::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get or create a counter.
    pub fn get_counter(&self, name: &str) -> Arc<StatCounter> {
        if let Some(counter) = self.counters.read().get(name) {
            return counter.clone();
        }
        let mut counters = self.counters.write();
        counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(StatCounter::new(0)))
            .clone()
    }

    /// Get counter value by name.
    pub fn get_stat(&self, name: &str) -> Option<u64> {
        self.counters.read().get(name).map(|c| c.get())
    }

    /// Query stats matching patterns.
    pub fn query_stats(&self, patterns: &[String], regex: bool, reset: bool) -> Vec<(String, u64)> {
        let counters = self.counters.read();
        let mut out = Vec::new();

        let mut matchers = Vec::new();
        if regex {
            for pattern in patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    matchers.push(re);
                }
            }
        }

        for (name, counter) in counters.iter() {
            let matched = if patterns.is_empty() {
                true
            } else if regex {
                matchers.iter().any(|re| re.is_match(name))
            } else {
                patterns.iter().any(|pat| name.contains(pat))
            };

            if matched {
                let value = if reset {
                    counter.reset()
                } else {
                    counter.get()
                };
                out.push((name.clone(), value));
            }
        }

        out
    }

    fn should_track_inbound(&self, inbound: &str) -> bool {
        if !self.enabled || inbound.is_empty() {
            return false;
        }
        if self.track_all_inbounds {
            return true;
        }
        if self.inbounds.is_empty() {
            return false;
        }
        self.inbounds.contains(inbound)
    }

    fn should_track_outbound(&self, outbound: &str) -> bool {
        if !self.enabled || outbound.is_empty() {
            return false;
        }
        if self.track_all_outbounds {
            return true;
        }
        if self.outbounds.is_empty() {
            return false;
        }
        self.outbounds.contains(outbound)
    }

    fn should_track_user(&self, user: &str) -> bool {
        if !self.enabled || user.is_empty() {
            return false;
        }
        if self.users.is_empty() {
            return false;
        }
        self.users.contains(user)
    }

    pub fn traffic_recorder(
        &self,
        inbound: Option<&str>,
        outbound: Option<&str>,
        user: Option<&str>,
    ) -> Option<Arc<dyn crate::net::metered::TrafficRecorder>> {
        if !self.enabled {
            return None;
        }

        let mut uplink = Vec::new();
        let mut downlink = Vec::new();
        let mut uplink_packets = Vec::new();
        let mut downlink_packets = Vec::new();

        if let Some(tag) = inbound {
            if self.should_track_inbound(tag) {
                uplink.push(self.get_counter(&format!("inbound>>>{}>>>traffic>>>uplink", tag)));
                downlink.push(self.get_counter(&format!("inbound>>>{}>>>traffic>>>downlink", tag)));
                uplink_packets.push(self.get_counter(&format!("inbound>>>{}>>>packet>>>uplink", tag)));
                downlink_packets
                    .push(self.get_counter(&format!("inbound>>>{}>>>packet>>>downlink", tag)));
            }
        }

        if let Some(tag) = outbound {
            if self.should_track_outbound(tag) {
                uplink.push(self.get_counter(&format!("outbound>>>{}>>>traffic>>>uplink", tag)));
                downlink
                    .push(self.get_counter(&format!("outbound>>>{}>>>traffic>>>downlink", tag)));
                uplink_packets.push(self.get_counter(&format!("outbound>>>{}>>>packet>>>uplink", tag)));
                downlink_packets
                    .push(self.get_counter(&format!("outbound>>>{}>>>packet>>>downlink", tag)));
            }
        }

        if let Some(name) = user {
            if self.should_track_user(name) {
                uplink.push(self.get_counter(&format!("user>>>{}>>>traffic>>>uplink", name)));
                downlink.push(self.get_counter(&format!("user>>>{}>>>traffic>>>downlink", name)));
                uplink_packets.push(self.get_counter(&format!("user>>>{}>>>packet>>>uplink", name)));
                downlink_packets
                    .push(self.get_counter(&format!("user>>>{}>>>packet>>>downlink", name)));
            }
        }

        if uplink.is_empty() && downlink.is_empty() {
            return None;
        }

        Some(Arc::new(TrafficCounters {
            uplink,
            downlink,
            uplink_packets,
            downlink_packets,
        }))
    }

    /// Initialize standard V2Ray counters
    pub fn init_standard_counters(&self) {
        let counters = [
            "inbound>>>api>>>traffic>>>uplink",
            "inbound>>>api>>>traffic>>>downlink",
            "outbound>>>direct>>>traffic>>>uplink",
            "outbound>>>direct>>>traffic>>>downlink",
            "outbound>>>proxy>>>traffic>>>uplink",
            "outbound>>>proxy>>>traffic>>>downlink",
            "inbound>>>api>>>packet>>>uplink",
            "inbound>>>api>>>packet>>>downlink",
            "outbound>>>direct>>>packet>>>uplink",
            "outbound>>>direct>>>packet>>>downlink",
            "outbound>>>proxy>>>packet>>>uplink",
            "outbound>>>proxy>>>packet>>>downlink",
        ];

        for name in counters {
            self.get_counter(name);
        }
    }
}

#[derive(Debug)]
pub struct TrafficCounters {
    uplink: Vec<Arc<StatCounter>>,
    downlink: Vec<Arc<StatCounter>>,
    uplink_packets: Vec<Arc<StatCounter>>,
    downlink_packets: Vec<Arc<StatCounter>>,
}

impl crate::net::metered::TrafficRecorder for TrafficCounters {
    fn record_up(&self, bytes: u64) {
        for counter in &self.uplink {
            counter.add(bytes);
        }
    }

    fn record_down(&self, bytes: u64) {
        for counter in &self.downlink {
            counter.add(bytes);
        }
    }

    fn record_up_packet(&self, packets: u64) {
        for counter in &self.uplink_packets {
            counter.add(packets);
        }
    }

    fn record_down_packet(&self, packets: u64) {
        for counter in &self.downlink_packets {
            counter.add(packets);
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
        let stats = Arc::new(StatsManager::new(cfg.stats.clone()));
        let enabled = stats.enabled();

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
            let stats_manager = self.state.stats.clone();
            tokio::spawn(async move {
                stats_manager.init_standard_counters();
            });

            tracing::info!(
                target: "sb_core::services::v2ray",
                listen = %listen_addr,
                stats_enabled = self.state.enabled,
                "Starting V2Ray API gRPC server"
            );

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            *self.shutdown_tx.lock() = Some(shutdown_tx);

            // Create service implementation
            let stats_service = StatsServiceImpl {
                stats: self.state.stats.clone(),
            };

            tokio::spawn(async move {
                let serve = Server::builder()
                    .add_service(StatsServiceServer::new(stats_service))
                    .serve_with_shutdown(listen_addr, async {
                        let _ = shutdown_rx.await;
                        tracing::info!(target: "sb_core::services::v2ray", "Received shutdown signal");
                    });

                if let Err(e) = serve.await {
                    tracing::error!(
                        target: "sb_core::services::v2ray",
                        error = %e,
                        "V2Ray API server error"
                    );
                } else {
                    tracing::info!(target: "sb_core::services::v2ray", "V2Ray API server stopped");
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

        Ok(())
    }

    fn stats(&self) -> Option<Arc<StatsManager>> {
        Some(self.state.stats.clone())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// gRPC Handler Implementation
// ─────────────────────────────────────────────────────────────────────────

#[cfg(feature = "service_v2ray_api")]
#[derive(Debug)]
pub struct StatsServiceImpl {
    stats: Arc<StatsManager>,
}

#[cfg(feature = "service_v2ray_api")]
#[tonic::async_trait]
impl StatsService for StatsServiceImpl {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let req = request.into_inner();
        let name = req.name;
        let reset = req.reset;
        let value = match self.stats.get_stat(&name) {
            Some(v) => v,
            None => {
                return Err(Status::not_found(format!("stat '{}' not found", name)));
            }
        };
        if reset {
            let counter = self.stats.get_counter(&name);
            counter.reset();
        }

        Ok(Response::new(GetStatsResponse {
            stat: Some(Stat {
                name,
                value: value as i64,
            }),
        }))
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let req = request.into_inner();
        let reset = req.reset;
        let mut patterns = req.patterns;
        if patterns.is_empty() && !req.pattern.is_empty() {
            patterns.push(req.pattern);
        }

        let stats = self.stats.query_stats(&patterns, req.regexp, reset);
        let stat_list = stats
            .into_iter()
            .map(|(name, value)| Stat {
                name,
                value: value as i64,
            })
            .collect();

        Ok(Response::new(QueryStatsResponse { stat: stat_list }))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        // Best-effort runtime stats; Rust does not expose Go-equivalent counters.
        let uptime = self
            .stats
            .created_at()
            .elapsed()
            .as_secs()
            .try_into()
            .unwrap_or(u32::MAX);
        let resp = SysStatsResponse {
            num_goroutine: tokio::runtime::Handle::current().metrics().num_workers() as u32,
            num_gc: 0,
            alloc: 0,
            total_alloc: 0,
            sys: 0,
            mallocs: 0,
            frees: 0,
            live_objects: 0,
            pause_total_ns: 0,
            uptime,
        };
        Ok(Response::new(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stats_manager() {
        let manager = StatsManager::new(Some(StatsIR {
            enabled: true,
            ..Default::default()
        }));

        // Get counter
        let counter = manager.get_counter("test>>>traffic>>>uplink");
        assert_eq!(counter.get(), 0);

        // Add traffic
        counter.add(1024);
        assert_eq!(counter.get(), 1024);

        // Query stats
        let stats = manager.query_stats(&["traffic".to_string()], false, false);
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
                inbounds: vec![],
                outbounds: vec![],
                users: vec![],
                inbound: Some(true),
                outbound: Some(true),
            }),
        };

        let server = V2RayApiServer::new(cfg);
        assert!(server.stats_enabled());
        assert_eq!(
            server.listen_addr(),
            Some("127.0.0.1:10085".parse().unwrap())
        );
    }

    #[test]
    fn test_packet_counters_from_recorder() {
        let manager = StatsManager::new(Some(StatsIR {
            enabled: true,
            inbounds: vec!["dns".to_string()],
            outbounds: vec!["direct".to_string()],
            users: vec!["alice".to_string()],
            inbound: None,
            outbound: None,
        }));

        let recorder = manager
            .traffic_recorder(Some("dns"), Some("direct"), Some("alice"))
            .expect("traffic recorder expected");

        recorder.record_up(10);
        recorder.record_down(20);
        recorder.record_up_packet(2);
        recorder.record_down_packet(3);

        let uplink = 10;
        let downlink = 20;
        let up_packets = 2;
        let down_packets = 3;

        let checks = [
            ("inbound>>>dns>>>traffic>>>uplink", uplink),
            ("inbound>>>dns>>>traffic>>>downlink", downlink),
            ("outbound>>>direct>>>traffic>>>uplink", uplink),
            ("outbound>>>direct>>>traffic>>>downlink", downlink),
            ("user>>>alice>>>traffic>>>uplink", uplink),
            ("user>>>alice>>>traffic>>>downlink", downlink),
            ("inbound>>>dns>>>packet>>>uplink", up_packets),
            ("inbound>>>dns>>>packet>>>downlink", down_packets),
            ("outbound>>>direct>>>packet>>>uplink", up_packets),
            ("outbound>>>direct>>>packet>>>downlink", down_packets),
            ("user>>>alice>>>packet>>>uplink", up_packets),
            ("user>>>alice>>>packet>>>downlink", down_packets),
        ];

        for (name, expected) in checks {
            let value = manager.get_stat(name).unwrap_or(0);
            assert_eq!(value, expected, "stat mismatch for {name}");
        }
    }
}
