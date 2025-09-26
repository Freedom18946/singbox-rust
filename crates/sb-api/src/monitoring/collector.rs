//! Real-time data collectors for monitoring system

use crate::{
    monitoring::bridge::{DnsMetrics, MetricsBridge, OutboundMetrics},
    types::{Connection, TrafficStats},
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{broadcast, Mutex},
    time::{interval, Instant},
};

/// Traffic statistics collector with real-time updates
pub struct TrafficCollector {
    bridge: Arc<MetricsBridge>,
    is_running: Arc<AtomicBool>,
    traffic_tx: broadcast::Sender<TrafficStats>,
    update_interval: Duration,
    total_connections: AtomicU64,
    bytes_transferred: Arc<Mutex<(u64, u64)>>, // (up, down)
}

impl TrafficCollector {
    /// Create a new traffic collector
    pub fn new(bridge: Arc<MetricsBridge>) -> Self {
        let (traffic_tx, _) = broadcast::channel(1000);

        let collector = Self {
            bridge,
            is_running: Arc::new(AtomicBool::new(false)),
            traffic_tx,
            update_interval: Duration::from_millis(1000),
            total_connections: AtomicU64::new(0),
            bytes_transferred: Arc::new(Mutex::new((0, 0))),
        };

        // Touch unread field for clippy
        let _ = &collector.total_connections;

        collector
    }

    /// Start the traffic collector
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.is_running.store(true, Ordering::Relaxed);
        let bridge = self.bridge.clone();
        let traffic_tx = self.traffic_tx.clone();
        let is_running = self.is_running.clone();
        let update_interval = self.update_interval;
        let bytes_transferred = self.bytes_transferred.clone();

        tokio::spawn(async move {
            let mut interval_timer = interval(update_interval);
            let mut last_up = 0u64;
            let mut last_down = 0u64;
            let mut last_time = Instant::now();

            // Touch bytes_transferred to avoid unused variable warning
            let _ = &bytes_transferred;

            while is_running.load(Ordering::Relaxed) {
                interval_timer.tick().await;

                // Collect metrics from bridge
                if let Err(e) = bridge.collect_from_core().await {
                    log::warn!("Failed to collect metrics from core: {}", e);
                    continue;
                }

                // Get current traffic stats
                let current_stats = bridge.get_traffic_stats().await;

                // Calculate speeds if this is not the first iteration
                let now = Instant::now();
                let time_diff = now.duration_since(last_time).as_secs_f64();

                let (calculated_up_speed, calculated_down_speed) = if time_diff > 0.0 {
                    let up_speed = if current_stats.up > last_up {
                        ((current_stats.up - last_up) as f64 / time_diff) as u64
                    } else {
                        0
                    };

                    let down_speed = if current_stats.down > last_down {
                        ((current_stats.down - last_down) as f64 / time_diff) as u64
                    } else {
                        0
                    };

                    (up_speed, down_speed)
                } else {
                    (current_stats.up_speed, current_stats.down_speed)
                };

                // Create updated stats with calculated speeds
                let updated_stats = TrafficStats {
                    up: current_stats.up,
                    down: current_stats.down,
                    up_speed: calculated_up_speed,
                    down_speed: calculated_down_speed,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };

                // Broadcast the updated stats
                if let Err(_) = traffic_tx.send(updated_stats) {
                    log::debug!("No traffic subscribers, continuing collection");
                }

                // Update bridge with calculated values
                bridge
                    .update_traffic(current_stats.up, current_stats.down)
                    .await;

                // Update last values for next iteration
                last_up = current_stats.up;
                last_down = current_stats.down;
                last_time = now;

                log::trace!(
                    "Traffic stats updated: up={}, down={}, up_speed={}, down_speed={}",
                    current_stats.up,
                    current_stats.down,
                    calculated_up_speed,
                    calculated_down_speed
                );
            }

            log::info!("Traffic collector stopped");
        });

        log::info!(
            "Traffic collector started with {}ms update interval",
            update_interval.as_millis()
        );
        Ok(())
    }

    /// Stop the traffic collector
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
    }

    /// Subscribe to traffic updates
    pub fn subscribe(&self) -> broadcast::Receiver<TrafficStats> {
        self.traffic_tx.subscribe()
    }

    /// Record traffic for a specific connection
    pub async fn record_traffic(
        &self,
        up_bytes: u64,
        down_bytes: u64,
        _connection_id: Option<String>,
    ) {
        let mut bytes = self.bytes_transferred.lock().await;
        bytes.0 += up_bytes;
        bytes.1 += down_bytes;

        // Update bridge immediately for real-time updates
        self.bridge.update_traffic(bytes.0, bytes.1).await;
    }

    /// Get current traffic statistics
    pub async fn get_current_stats(&self) -> TrafficStats {
        self.bridge.get_traffic_stats().await
    }
}

/// Connection tracking collector
pub struct ConnectionCollector {
    connections: Arc<Mutex<Vec<Connection>>>,
    connection_tx: broadcast::Sender<Connection>,
    is_running: Arc<AtomicBool>,
    update_interval: Duration,
}

impl ConnectionCollector {
    /// Create a new connection collector
    pub fn new() -> Self {
        let (connection_tx, _) = broadcast::channel(1000);

        Self {
            connections: Arc::new(Mutex::new(Vec::new())),
            connection_tx,
            is_running: Arc::new(AtomicBool::new(false)),
            update_interval: Duration::from_millis(5000),
        }
    }

    /// Start the connection collector
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.is_running.store(true, Ordering::Relaxed);
        let connections = self.connections.clone();
        let connection_tx = self.connection_tx.clone();
        let is_running = self.is_running.clone();
        let update_interval = self.update_interval;

        tokio::spawn(async move {
            let mut interval_timer = interval(update_interval);

            while is_running.load(Ordering::Relaxed) {
                interval_timer.tick().await;

                // Broadcast current connections status
                let current_connections = connections.lock().await;
                for connection in current_connections.iter() {
                    if let Err(_) = connection_tx.send(connection.clone()) {
                        log::debug!("No connection subscribers");
                        break;
                    }
                }

                log::trace!(
                    "Connection status broadcasted: {} active connections",
                    current_connections.len()
                );
            }

            log::info!("Connection collector stopped");
        });

        log::info!(
            "Connection collector started with {}ms update interval",
            update_interval.as_millis()
        );
        Ok(())
    }

    /// Stop the connection collector
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
    }

    /// Subscribe to connection updates
    pub fn subscribe(&self) -> broadcast::Receiver<Connection> {
        self.connection_tx.subscribe()
    }

    /// Add a new connection
    pub async fn add_connection(&self, connection: Connection) {
        let mut connections = self.connections.lock().await;
        connections.push(connection.clone());

        // Broadcast the new connection immediately
        let _ = self.connection_tx.send(connection);

        log::debug!("Added connection: {}", connections.last().unwrap().id);
    }

    /// Remove a connection
    pub async fn remove_connection(&self, connection_id: &str) {
        let mut connections = self.connections.lock().await;
        if let Some(pos) = connections.iter().position(|c| c.id == connection_id) {
            let removed = connections.remove(pos);
            log::debug!("Removed connection: {}", removed.id);
        }
    }

    /// Get all current connections
    pub async fn get_connections(&self) -> Vec<Connection> {
        self.connections.lock().await.clone()
    }

    /// Get connection count
    pub async fn get_connection_count(&self) -> usize {
        self.connections.lock().await.len()
    }
}

/// Performance metrics collector
pub struct PerformanceCollector {
    bridge: Arc<MetricsBridge>,
    is_running: Arc<AtomicBool>,
    performance_tx: broadcast::Sender<serde_json::Value>,
    update_interval: Duration,
}

impl PerformanceCollector {
    /// Create a new performance collector
    pub fn new(bridge: Arc<MetricsBridge>) -> Self {
        let (performance_tx, _) = broadcast::channel(1000);

        Self {
            bridge,
            is_running: Arc::new(AtomicBool::new(false)),
            performance_tx,
            update_interval: Duration::from_millis(10000), // Update every 10 seconds
        }
    }

    /// Start the performance collector
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.is_running.store(true, Ordering::Relaxed);
        let bridge = self.bridge.clone();
        let performance_tx = self.performance_tx.clone();
        let is_running = self.is_running.clone();
        let update_interval = self.update_interval;

        tokio::spawn(async move {
            let mut interval_timer = interval(update_interval);

            while is_running.load(Ordering::Relaxed) {
                interval_timer.tick().await;

                // Collect comprehensive performance metrics
                let metrics = bridge.get_performance_metrics().await;

                // Broadcast performance metrics
                if let Err(_) = performance_tx.send(metrics.clone()) {
                    log::debug!("No performance metrics subscribers");
                }

                log::trace!("Performance metrics updated and broadcasted");
            }

            log::info!("Performance collector stopped");
        });

        log::info!(
            "Performance collector started with {}ms update interval",
            update_interval.as_millis()
        );
        Ok(())
    }

    /// Stop the performance collector
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
    }

    /// Subscribe to performance metrics updates
    pub fn subscribe(&self) -> broadcast::Receiver<serde_json::Value> {
        self.performance_tx.subscribe()
    }

    /// Get current performance metrics
    pub async fn get_current_metrics(&self) -> serde_json::Value {
        self.bridge.get_performance_metrics().await
    }

    /// Record outbound metrics
    pub async fn record_outbound_metrics(&self, outbound_name: &str, metrics: OutboundMetrics) {
        self.bridge
            .update_outbound_metrics(outbound_name, metrics)
            .await;
    }

    /// Record DNS metrics
    pub async fn record_dns_metrics(&self, metrics: DnsMetrics) {
        self.bridge.update_dns_metrics(metrics).await;
    }
}
