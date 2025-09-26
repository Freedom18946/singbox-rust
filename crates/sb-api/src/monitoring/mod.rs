//! Real-time monitoring infrastructure for API services
//!
//! This module provides real-time data collection and broadcasting for both
//! Clash and V2Ray API services, integrating with the core metrics system.

pub mod bridge;
pub mod collector;
pub mod reporter;

pub use bridge::{MetricsBridge, MetricsBridgeHandle};
pub use collector::{ConnectionCollector, PerformanceCollector, TrafficCollector};
pub use reporter::{RealtimeReporter, ReportConfig};

use crate::types::{Connection, LogEntry, TrafficStats};
use std::sync::Arc;
use tokio::sync::broadcast;

/// Real-time monitoring system that integrates with core metrics
pub struct MonitoringSystem {
    /// Metrics bridge for collecting data from sb-core
    bridge: Arc<MetricsBridge>,
    /// Traffic statistics collector
    traffic_collector: TrafficCollector,
    /// Connection tracking collector
    connection_collector: ConnectionCollector,
    /// Performance metrics collector
    performance_collector: PerformanceCollector,
    /// Real-time reporter for API broadcasts
    reporter: RealtimeReporter,
}

impl MonitoringSystem {
    /// Create a new monitoring system
    pub fn new(config: ReportConfig) -> (Self, MonitoringSystemHandle) {
        let bridge = Arc::new(MetricsBridge::new());
        let traffic_collector = TrafficCollector::new(bridge.clone());
        let connection_collector = ConnectionCollector::new();
        let performance_collector = PerformanceCollector::new(bridge.clone());
        let reporter = RealtimeReporter::new(config);

        let system = Self {
            bridge: bridge.clone(),
            traffic_collector,
            connection_collector,
            performance_collector,
            reporter,
        };

        let handle = MonitoringSystemHandle {
            bridge: bridge.clone(),
            traffic_tx: system.reporter.traffic_tx.clone(),
            log_tx: system.reporter.log_tx.clone(),
            connection_tx: system.reporter.connection_tx.clone(),
        };

        (system, handle)
    }

    /// Start the monitoring system
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        log::info!("Starting real-time monitoring system");

        // Start all collectors
        self.traffic_collector.start().await?;
        self.connection_collector.start().await?;
        self.performance_collector.start().await?;

        // Start the reporter
        self.reporter
            .start(
                self.traffic_collector.subscribe(),
                self.connection_collector.subscribe(),
                self.performance_collector.subscribe(),
            )
            .await?;

        log::info!("Real-time monitoring system started successfully");
        Ok(())
    }

    /// Get metrics bridge handle for external components
    pub fn bridge_handle(&self) -> MetricsBridgeHandle {
        self.bridge.handle()
    }

    /// Update traffic statistics from external sources
    pub async fn update_traffic(
        &self,
        up_bytes: u64,
        down_bytes: u64,
        connection_id: Option<String>,
    ) {
        self.traffic_collector
            .record_traffic(up_bytes, down_bytes, connection_id)
            .await;
    }

    /// Record a new connection
    pub async fn record_connection(&self, connection: Connection) {
        self.connection_collector.add_connection(connection).await;
    }

    /// Record connection close
    pub async fn close_connection(&self, connection_id: &str) {
        self.connection_collector
            .remove_connection(connection_id)
            .await;
    }

    /// Record a log entry
    pub async fn log_entry(&self, entry: LogEntry) {
        self.reporter.broadcast_log(entry).await;
    }
}

/// Handle for external components to interact with the monitoring system
pub struct MonitoringSystemHandle {
    bridge: Arc<MetricsBridge>,
    traffic_tx: broadcast::Sender<TrafficStats>,
    log_tx: broadcast::Sender<LogEntry>,
    connection_tx: broadcast::Sender<Connection>,
}

impl Clone for MonitoringSystemHandle {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.clone(),
            traffic_tx: self.traffic_tx.clone(),
            log_tx: self.log_tx.clone(),
            connection_tx: self.connection_tx.clone(),
        }
    }
}

impl MonitoringSystemHandle {
    /// Subscribe to traffic statistics updates
    pub fn subscribe_traffic(&self) -> broadcast::Receiver<TrafficStats> {
        self.traffic_tx.subscribe()
    }

    /// Subscribe to log entries
    pub fn subscribe_logs(&self) -> broadcast::Receiver<LogEntry> {
        self.log_tx.subscribe()
    }

    /// Subscribe to connection updates
    pub fn subscribe_connections(&self) -> broadcast::Receiver<Connection> {
        self.connection_tx.subscribe()
    }

    /// Get metrics bridge handle
    pub fn bridge(&self) -> MetricsBridgeHandle {
        self.bridge.handle()
    }

    /// Get current traffic statistics
    pub async fn get_current_traffic(&self) -> TrafficStats {
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
}
