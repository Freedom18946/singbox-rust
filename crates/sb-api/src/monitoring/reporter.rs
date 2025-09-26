//! Real-time reporter for broadcasting metrics to API clients

use crate::{
    types::{Connection, LogEntry, TrafficStats},
    v2ray::simple::SimpleStat,
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::broadcast, time::interval};

/// Configuration for the real-time reporter
#[derive(Debug, Clone)]
pub struct ReportConfig {
    /// Traffic update interval in milliseconds
    pub traffic_interval_ms: u64,
    /// Log buffer size
    pub log_buffer_size: usize,
    /// Connection update interval in milliseconds
    pub connection_interval_ms: u64,
    /// Performance metrics interval in milliseconds
    pub performance_interval_ms: u64,
    /// Enable detailed logging
    pub enable_detailed_logging: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            traffic_interval_ms: 1000,
            log_buffer_size: 1000,
            connection_interval_ms: 5000,
            performance_interval_ms: 10000,
            enable_detailed_logging: false,
        }
    }
}

/// Real-time reporter that broadcasts metrics to API clients
pub struct RealtimeReporter {
    config: ReportConfig,
    is_running: AtomicBool,

    // Broadcast channels for different types of updates
    /// Channel for broadcasting traffic statistics updates
    pub traffic_tx: broadcast::Sender<TrafficStats>,
    /// Channel for broadcasting log entries
    pub log_tx: broadcast::Sender<LogEntry>,
    /// Channel for broadcasting connection updates
    pub connection_tx: broadcast::Sender<Connection>,
    v2ray_stats_tx: broadcast::Sender<SimpleStat>,

    // Internal state for V2Ray API compatibility
    v2ray_stats: Arc<tokio::sync::Mutex<std::collections::HashMap<String, i64>>>,
}

impl RealtimeReporter {
    /// Create a new real-time reporter
    pub fn new(config: ReportConfig) -> Self {
        let (traffic_tx, _) = broadcast::channel(1000);
        let (log_tx, _) = broadcast::channel(config.log_buffer_size);
        let (connection_tx, _) = broadcast::channel(1000);
        let (v2ray_stats_tx, _) = broadcast::channel(1000);

        Self {
            config,
            is_running: AtomicBool::new(false),
            traffic_tx,
            log_tx,
            connection_tx,
            v2ray_stats_tx,
            v2ray_stats: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Start the reporter with input streams from collectors
    pub async fn start(
        &self,
        traffic_rx: broadcast::Receiver<TrafficStats>,
        connection_rx: broadcast::Receiver<Connection>,
        performance_rx: broadcast::Receiver<serde_json::Value>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.is_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.is_running.store(true, Ordering::Relaxed);

        // Start traffic reporting task
        let _traffic_task = self.start_traffic_reporting(traffic_rx).await;

        // Start connection reporting task
        let _connection_task = self.start_connection_reporting(connection_rx).await;

        // Start performance reporting task
        let _performance_task = self.start_performance_reporting(performance_rx).await;

        // Start log generation task (for demonstration)
        let _log_task = self.start_log_generation().await;

        log::info!("Real-time reporter started with all reporting tasks");
        Ok(())
    }

    /// Start traffic reporting task
    async fn start_traffic_reporting(
        &self,
        mut traffic_rx: broadcast::Receiver<TrafficStats>,
    ) -> tokio::task::JoinHandle<()> {
        let traffic_tx = self.traffic_tx.clone();
        let v2ray_stats_tx = self.v2ray_stats_tx.clone();
        let v2ray_stats = self.v2ray_stats.clone();
        let is_running = Arc::new(AtomicBool::new(true));
        let config = self.config.clone();

        tokio::spawn(async move {
            while is_running.load(Ordering::Relaxed) {
                match traffic_rx.recv().await {
                    Ok(stats) => {
                        // Broadcast to Clash API clients
                        if let Err(_) = traffic_tx.send(stats.clone()) {
                            log::debug!("No Clash API traffic subscribers");
                        }

                        // Update V2Ray API stats
                        {
                            let mut v2ray_map = v2ray_stats.lock().await;
                            v2ray_map.insert(
                                "inbound>>>api>>>traffic>>>uplink".to_string(),
                                stats.up as i64,
                            );
                            v2ray_map.insert(
                                "inbound>>>api>>>traffic>>>downlink".to_string(),
                                stats.down as i64,
                            );
                            v2ray_map.insert(
                                "outbound>>>direct>>>traffic>>>uplink".to_string(),
                                stats.up as i64,
                            );
                            v2ray_map.insert(
                                "outbound>>>direct>>>traffic>>>downlink".to_string(),
                                stats.down as i64,
                            );
                        }

                        // Broadcast V2Ray stats updates
                        let v2ray_uplink = SimpleStat {
                            name: "inbound>>>api>>>traffic>>>uplink".to_string(),
                            value: stats.up as i64,
                        };
                        let v2ray_downlink = SimpleStat {
                            name: "inbound>>>api>>>traffic>>>downlink".to_string(),
                            value: stats.down as i64,
                        };

                        let _ = v2ray_stats_tx.send(v2ray_uplink);
                        let _ = v2ray_stats_tx.send(v2ray_downlink);

                        if config.enable_detailed_logging {
                            log::trace!("Traffic stats reported: up={}, down={}, up_speed={}, down_speed={}",
                                      stats.up, stats.down, stats.up_speed, stats.down_speed);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Traffic reporter lagged, skipped {} messages", skipped);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::info!("Traffic input stream closed");
                        break;
                    }
                }
            }
        })
    }

    /// Start connection reporting task
    async fn start_connection_reporting(
        &self,
        mut connection_rx: broadcast::Receiver<Connection>,
    ) -> tokio::task::JoinHandle<()> {
        let connection_tx = self.connection_tx.clone();
        let is_running = Arc::new(AtomicBool::new(true));
        let config = self.config.clone();

        tokio::spawn(async move {
            while is_running.load(Ordering::Relaxed) {
                match connection_rx.recv().await {
                    Ok(connection) => {
                        // Broadcast to Clash API clients
                        if let Err(_) = connection_tx.send(connection.clone()) {
                            log::debug!("No connection subscribers");
                        }

                        if config.enable_detailed_logging {
                            log::trace!(
                                "Connection reported: {} -> {} via {}",
                                connection.metadata.source_ip,
                                connection.metadata.destination_ip,
                                connection.chains.join("->")
                            );
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Connection reporter lagged, skipped {} messages", skipped);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::info!("Connection input stream closed");
                        break;
                    }
                }
            }
        })
    }

    /// Start performance reporting task
    async fn start_performance_reporting(
        &self,
        mut performance_rx: broadcast::Receiver<serde_json::Value>,
    ) -> tokio::task::JoinHandle<()> {
        let is_running = Arc::new(AtomicBool::new(true));
        let config = self.config.clone();

        tokio::spawn(async move {
            while is_running.load(Ordering::Relaxed) {
                match performance_rx.recv().await {
                    Ok(metrics) => {
                        // For now, just log performance metrics
                        // In a full implementation, these could be exposed via additional API endpoints
                        if config.enable_detailed_logging {
                            log::debug!(
                                "Performance metrics updated: {}",
                                serde_json::to_string_pretty(&metrics).unwrap_or_default()
                            );
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Performance reporter lagged, skipped {} messages", skipped);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::info!("Performance input stream closed");
                        break;
                    }
                }
            }
        })
    }

    /// Start log generation task (for demonstration purposes)
    async fn start_log_generation(&self) -> tokio::task::JoinHandle<()> {
        let log_tx = self.log_tx.clone();
        let is_running = Arc::new(AtomicBool::new(true));

        tokio::spawn(async move {
            let mut interval_timer = interval(Duration::from_secs(30));
            let mut counter = 0;

            while is_running.load(Ordering::Relaxed) {
                interval_timer.tick().await;
                counter += 1;

                let log_entry = LogEntry {
                    r#type: "info".to_string(),
                    payload: format!("Real-time monitoring heartbeat #{}", counter),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    source: "MonitoringSystem".to_string(),
                    connection_id: None,
                };

                if let Err(_) = log_tx.send(log_entry) {
                    log::debug!("No log subscribers");
                }
            }
        })
    }

    /// Stop the reporter
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::Relaxed);
    }

    /// Subscribe to traffic updates (for Clash API)
    pub fn subscribe_traffic(&self) -> broadcast::Receiver<TrafficStats> {
        self.traffic_tx.subscribe()
    }

    /// Subscribe to log entries (for Clash API)
    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEntry> {
        self.log_tx.subscribe()
    }

    /// Subscribe to connection updates (for Clash API)
    pub fn subscribe_connections(&self) -> broadcast::Receiver<Connection> {
        self.connection_tx.subscribe()
    }

    /// Subscribe to V2Ray stats updates
    pub fn subscribe_v2ray_stats(&self) -> broadcast::Receiver<SimpleStat> {
        self.v2ray_stats_tx.subscribe()
    }

    /// Broadcast a traffic update directly
    pub async fn broadcast_traffic(&self, stats: TrafficStats) {
        let _ = self.traffic_tx.send(stats);
    }

    /// Broadcast a log entry directly
    pub async fn broadcast_log(&self, entry: LogEntry) {
        let _ = self.log_tx.send(entry);
    }

    /// Broadcast a connection update directly
    pub async fn broadcast_connection(&self, connection: Connection) {
        let _ = self.connection_tx.send(connection);
    }

    /// Get current V2Ray stats (for V2Ray API integration)
    pub async fn get_v2ray_stats(&self) -> std::collections::HashMap<String, i64> {
        self.v2ray_stats.lock().await.clone()
    }

    /// Update V2Ray stats (for external integration)
    pub async fn update_v2ray_stat(&self, name: &str, value: i64) {
        let mut stats = self.v2ray_stats.lock().await;
        stats.insert(name.to_string(), value);

        // Broadcast the update
        let stat_update = SimpleStat {
            name: name.to_string(),
            value,
        };
        let _ = self.v2ray_stats_tx.send(stat_update);
    }

    /// Query V2Ray stats with pattern matching
    pub async fn query_v2ray_stats(&self, pattern: &str) -> Vec<SimpleStat> {
        let stats = self.v2ray_stats.lock().await;
        let mut matching_stats = Vec::new();

        for (name, value) in stats.iter() {
            if pattern.is_empty() || name.contains(pattern) {
                matching_stats.push(SimpleStat {
                    name: name.clone(),
                    value: *value,
                });
            }
        }

        matching_stats
    }
}
