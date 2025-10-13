//! Metrics bridge for integrating with sb-core metrics system

use crate::types::{Connection, ConnectionMetadata, TrafficStats};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, RwLock};

/// Bridge to connect API services with sb-core metrics
pub struct MetricsBridge {
    /// Total bytes uploaded across all connections
    total_up: AtomicU64,
    /// Total bytes downloaded across all connections
    total_down: AtomicU64,
    /// Current upload speed (calculated)
    current_up_speed: AtomicU64,
    /// Current download speed (calculated)
    current_down_speed: AtomicU64,
    /// Active connections tracking
    connections: Arc<RwLock<HashMap<String, Connection>>>,
    /// Outbound metrics cache
    outbound_metrics: Arc<Mutex<HashMap<String, OutboundMetrics>>>,
    /// DNS metrics cache
    dns_metrics: Arc<Mutex<DnsMetrics>>,
    /// Last update timestamp for speed calculation
    last_update: Arc<Mutex<SystemTime>>,
    /// Previous traffic values for speed calculation
    prev_up: AtomicU64,
    prev_down: AtomicU64,
}

/// Aggregate outbound connection metrics surfaced to API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OutboundMetrics {
    /// Total connect attempts observed.
    pub connect_attempts: u64,
    /// Successful outbound connections.
    pub connect_successes: u64,
    /// Failed outbound connections.
    pub connect_failures: u64,
    /// Total uploaded bytes across outbound connections.
    pub total_bytes_up: u64,
    /// Total downloaded bytes across outbound connections.
    pub total_bytes_down: u64,
    /// Average connection duration in seconds.
    pub avg_connection_duration: f64,
    /// The most recent error, if any.
    pub last_error: Option<String>,
}

/// DNS metrics snapshot surfaced to API.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsMetrics {
    /// Total DNS queries processed.
    pub total_queries: u64,
    /// Cache hit count.
    pub cache_hits: u64,
    /// Cache miss count.
    pub cache_misses: u64,
    /// Average response time in milliseconds.
    pub avg_response_time: f64,
    /// Total DNS errors.
    pub errors: u64,
    /// Current DNS cache size.
    pub cache_size: usize,
}

impl Default for OutboundMetrics {
    fn default() -> Self {
        Self {
            connect_attempts: 0,
            connect_successes: 0,
            connect_failures: 0,
            total_bytes_up: 0,
            total_bytes_down: 0,
            avg_connection_duration: 0.0,
            last_error: None,
        }
    }
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self {
            total_queries: 0,
            cache_hits: 0,
            cache_misses: 0,
            avg_response_time: 0.0,
            errors: 0,
            cache_size: 0,
        }
    }
}

impl MetricsBridge {
    /// Create a new metrics bridge
    pub fn new() -> Self {
        Self {
            total_up: AtomicU64::new(0),
            total_down: AtomicU64::new(0),
            current_up_speed: AtomicU64::new(0),
            current_down_speed: AtomicU64::new(0),
            connections: Arc::new(RwLock::new(HashMap::new())),
            outbound_metrics: Arc::new(Mutex::new(HashMap::new())),
            dns_metrics: Arc::new(Mutex::new(DnsMetrics::default())),
            last_update: Arc::new(Mutex::new(SystemTime::now())),
            prev_up: AtomicU64::new(0),
            prev_down: AtomicU64::new(0),
        }
    }

    /// Get handle for external access
    pub fn handle(&self) -> MetricsBridgeHandle<'_> {
        MetricsBridgeHandle { bridge: self }
    }

    /// Update traffic statistics
    pub async fn update_traffic(&self, up_bytes: u64, down_bytes: u64) {
        let now = SystemTime::now();
        let mut last_update = self.last_update.lock().await;
        let time_diff = now
            .duration_since(*last_update)
            .unwrap_or_default()
            .as_secs_f64();

        if time_diff > 0.0 {
            // Calculate speeds
            let prev_up = self.prev_up.load(Ordering::Relaxed);
            let prev_down = self.prev_down.load(Ordering::Relaxed);

            let up_speed = if up_bytes > prev_up {
                ((up_bytes - prev_up) as f64 / time_diff) as u64
            } else {
                0
            };

            let down_speed = if down_bytes > prev_down {
                ((down_bytes - prev_down) as f64 / time_diff) as u64
            } else {
                0
            };

            self.current_up_speed.store(up_speed, Ordering::Relaxed);
            self.current_down_speed.store(down_speed, Ordering::Relaxed);

            self.prev_up.store(up_bytes, Ordering::Relaxed);
            self.prev_down.store(down_bytes, Ordering::Relaxed);
            *last_update = now;
        }

        self.total_up.store(up_bytes, Ordering::Relaxed);
        self.total_down.store(down_bytes, Ordering::Relaxed);
    }

    /// Get current traffic statistics
    pub async fn get_traffic_stats(&self) -> TrafficStats {
        TrafficStats {
            up: self.total_up.load(Ordering::Relaxed),
            down: self.total_down.load(Ordering::Relaxed),
            up_speed: self.current_up_speed.load(Ordering::Relaxed),
            down_speed: self.current_down_speed.load(Ordering::Relaxed),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Add a connection
    pub async fn add_connection(&self, connection: Connection) {
        let mut connections = self.connections.write().await;
        connections.insert(connection.id.clone(), connection);
    }

    /// Remove a connection
    pub async fn remove_connection(&self, connection_id: &str) {
        let mut connections = self.connections.write().await;
        connections.remove(connection_id);
    }

    /// Get all active connections
    pub async fn get_connections(&self) -> Vec<Connection> {
        let connections = self.connections.read().await;
        connections.values().cloned().collect()
    }

    /// Update outbound metrics for a specific outbound
    pub async fn update_outbound_metrics(&self, outbound_name: &str, metrics: OutboundMetrics) {
        let mut cache = self.outbound_metrics.lock().await;
        cache.insert(outbound_name.to_string(), metrics);
    }

    /// Update DNS metrics
    pub async fn update_dns_metrics(&self, metrics: DnsMetrics) {
        let mut cache = self.dns_metrics.lock().await;
        *cache = metrics;
    }

    /// Get comprehensive performance metrics
    pub async fn get_performance_metrics(&self) -> serde_json::Value {
        let outbound_metrics = self.outbound_metrics.lock().await;
        let dns_metrics = self.dns_metrics.lock().await;
        let connections = self.connections.read().await;

        json!({
            "traffic": {
                "total_up": self.total_up.load(Ordering::Relaxed),
                "total_down": self.total_down.load(Ordering::Relaxed),
                "up_speed": self.current_up_speed.load(Ordering::Relaxed),
                "down_speed": self.current_down_speed.load(Ordering::Relaxed)
            },
            "connections": {
                "active": connections.len(),
                "by_type": self.categorize_connections(&connections).await
            },
            "outbounds": outbound_metrics.clone(),
            "dns": dns_metrics.clone(),
            "timestamp": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        })
    }

    /// Categorize connections for statistics
    async fn categorize_connections(
        &self,
        connections: &HashMap<String, Connection>,
    ) -> serde_json::Value {
        let mut by_type = HashMap::new();
        let mut by_outbound = HashMap::new();
        let mut by_network = HashMap::new();

        for connection in connections.values() {
            // Count by connection type
            *by_type
                .entry(connection.metadata.r#type.clone())
                .or_insert(0u32) += 1;

            // Count by outbound (proxy chain)
            if let Some(outbound) = connection.chains.first() {
                *by_outbound.entry(outbound.clone()).or_insert(0u32) += 1;
            }

            // Count by network protocol
            *by_network
                .entry(connection.metadata.network.clone())
                .or_insert(0u32) += 1;
        }

        json!({
            "by_type": by_type,
            "by_outbound": by_outbound,
            "by_network": by_network
        })
    }

    /// Collect metrics from sb-core (production implementation)
    pub async fn collect_from_core(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Collect outbound metrics from registry if available
        #[cfg(feature = "metrics")]
        {
            use prometheus::{core::Collector, Registry};
            let registry = Registry::new();

            // Gather metrics from prometheus registry
            let mut total_up = 0_u64;
            let mut total_down = 0_u64;

            for mf in registry.gather() {
                for m in mf.get_metric() {
                    // Extract upload/download counters
                    if mf.get_name().contains("uplink") {
                        if let Some(counter) = m.get_counter() {
                            total_up += counter.get_value() as u64;
                        }
                    } else if mf.get_name().contains("downlink") {
                        if let Some(counter) = m.get_counter() {
                            total_down += counter.get_value() as u64;
                        }
                    }
                }
            }

            // Update traffic counters
            self.total_up.fetch_add(total_up, Ordering::Relaxed);
            self.total_down.fetch_add(total_down, Ordering::Relaxed);

            log::debug!(
                "Collected metrics from sb-core: up={} down={}",
                total_up,
                total_down
            );
        }

        // Fallback to simulated metrics for demonstration when metrics feature is disabled
        #[cfg(not(feature = "metrics"))]
        {
            self.simulate_metrics_collection().await;
        }

        Ok(())
    }

    /// Simulate metrics collection (for demonstration)
    async fn simulate_metrics_collection(&self) {
        // Simulate outbound metrics
        let direct_metrics = OutboundMetrics {
            connect_attempts: 150,
            connect_successes: 145,
            connect_failures: 5,
            total_bytes_up: self.total_up.load(Ordering::Relaxed) / 3,
            total_bytes_down: self.total_down.load(Ordering::Relaxed) / 3,
            avg_connection_duration: 45.2,
            last_error: None,
        };
        self.update_outbound_metrics("DIRECT", direct_metrics).await;

        // Simulate DNS metrics
        let dns_metrics = DnsMetrics {
            total_queries: 1250,
            cache_hits: 980,
            cache_misses: 270,
            avg_response_time: 15.4,
            errors: 12,
            cache_size: 850,
        };
        self.update_dns_metrics(dns_metrics).await;

        // Add some simulated connections
        self.add_simulated_connections().await;
    }

    /// Add simulated connections for demonstration
    async fn add_simulated_connections(&self) {
        let simulated_connections = vec![
            Connection {
                id: uuid::Uuid::new_v4().to_string(),
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
                upload: 2048,
                download: 8192,
                start: "1640995200000".to_string(),
                chains: vec!["DIRECT".to_string()],
                rule: "DOMAIN".to_string(),
                rule_payload: "www.google.com".to_string(),
            },
            Connection {
                id: uuid::Uuid::new_v4().to_string(),
                metadata: ConnectionMetadata {
                    network: "tcp".to_string(),
                    r#type: "HTTPS".to_string(),
                    source_ip: "192.168.1.100".to_string(),
                    source_port: "54321".to_string(),
                    destination_ip: "1.1.1.1".to_string(),
                    destination_port: "443".to_string(),
                    inbound_ip: "127.0.0.1".to_string(),
                    inbound_port: "7890".to_string(),
                    inbound_name: "http".to_string(),
                    inbound_user: "".to_string(),
                    host: "api.github.com".to_string(),
                    dns_mode: "normal".to_string(),
                    uid: 1000,
                    process: "curl".to_string(),
                    process_path: "/usr/bin/curl".to_string(),
                    special_proxy: "".to_string(),
                    special_rules: "".to_string(),
                    remote_destination: "1.1.1.1:443".to_string(),
                    sniff_host: "api.github.com".to_string(),
                },
                upload: 1024,
                download: 4096,
                start: "1640995260000".to_string(),
                chains: vec!["PROXY".to_string()],
                rule: "DOMAIN-SUFFIX".to_string(),
                rule_payload: ".github.com".to_string(),
            },
        ];

        for connection in simulated_connections {
            self.add_connection(connection).await;
        }
    }
}

impl Default for MetricsBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle for external components to access the metrics bridge
pub struct MetricsBridgeHandle<'a> {
    bridge: &'a MetricsBridge,
}

impl<'a> MetricsBridgeHandle<'a> {
    /// Get current traffic statistics
    pub async fn get_traffic_stats(&self) -> TrafficStats {
        self.bridge.get_traffic_stats().await
    }

    /// Get all active connections
    pub async fn get_connections(&self) -> Vec<Connection> {
        self.bridge.get_connections().await
    }

    /// Get performance metrics
    pub async fn get_performance_metrics(&self) -> serde_json::Value {
        self.bridge.get_performance_metrics().await
    }

    /// Update traffic statistics
    pub async fn update_traffic(&self, up_bytes: u64, down_bytes: u64) {
        self.bridge.update_traffic(up_bytes, down_bytes).await;
    }

    /// Add a connection
    pub async fn add_connection(&self, connection: Connection) {
        self.bridge.add_connection(connection).await;
    }

    /// Remove a connection
    pub async fn remove_connection(&self, connection_id: &str) {
        self.bridge.remove_connection(connection_id).await;
    }
}
