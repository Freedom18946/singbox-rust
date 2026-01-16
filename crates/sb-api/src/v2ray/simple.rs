//! Simplified V2Ray API implementation without protobuf dependency

use crate::{error::ApiResult, monitoring::MonitoringSystemHandle, types::ApiConfig};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, oneshot, Mutex};

/// Simplified stats data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleStat {
    /// Fully-qualified stat counter name.
    pub name: String,
    /// Current counter value.
    pub value: i64,
}

/// Simplified stats request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleStatsRequest {
    /// Stat counter name to query.
    pub name: String,
    /// Whether to reset the counter after reading.
    pub reset: bool,
}

/// Simplified stats response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleStatsResponse {
    /// Single stat entry.
    pub stat: SimpleStat,
}

/// Simplified query stats request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleQueryStatsRequest {
    /// Name substring to match (empty = all).
    pub pattern: String,
    /// Whether to reset counters after reading.
    pub reset: bool,
}

/// Simplified query stats response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleQueryStatsResponse {
    /// Matching stats list.
    pub stats: Vec<SimpleStat>,
}

/// Simple V2Ray API server implementation
pub struct SimpleV2RayApiServer {
    config: ApiConfig,
    stats: Arc<Mutex<HashMap<String, i64>>>,
    stats_broadcast: broadcast::Sender<SimpleStat>,
    monitoring: Option<MonitoringSystemHandle>,
}

impl SimpleV2RayApiServer {
    /// Create a new simple V2Ray API server
    pub fn new(config: ApiConfig) -> ApiResult<Self> {
        let mut initial_stats = HashMap::new();

        // Initialize with common V2Ray stat counters
        initial_stats.insert("inbound>>>api>>>traffic>>>uplink".to_string(), 0);
        initial_stats.insert("inbound>>>api>>>traffic>>>downlink".to_string(), 0);
        initial_stats.insert("outbound>>>direct>>>traffic>>>uplink".to_string(), 0);
        initial_stats.insert("outbound>>>direct>>>traffic>>>downlink".to_string(), 0);

        let (stats_tx, _) = broadcast::channel(1000);

        Ok(Self {
            config,
            stats: Arc::new(Mutex::new(initial_stats)),
            stats_broadcast: stats_tx,
            monitoring: None,
        })
    }

    /// Create a new simple V2Ray API server with monitoring system
    pub fn with_monitoring(
        config: ApiConfig,
        monitoring: MonitoringSystemHandle,
    ) -> ApiResult<Self> {
        let mut initial_stats = HashMap::new();

        // Initialize with common V2Ray stat counters
        initial_stats.insert("inbound>>>api>>>traffic>>>uplink".to_string(), 0);
        initial_stats.insert("inbound>>>api>>>traffic>>>downlink".to_string(), 0);
        initial_stats.insert("outbound>>>direct>>>traffic>>>uplink".to_string(), 0);
        initial_stats.insert("outbound>>>direct>>>traffic>>>downlink".to_string(), 0);

        let (stats_tx, _) = broadcast::channel(1000);

        Ok(Self {
            config,
            stats: Arc::new(Mutex::new(initial_stats)),
            stats_broadcast: stats_tx,
            monitoring: Some(monitoring),
        })
    }

    /// Start the simple V2Ray API server
    pub async fn start(&self) -> ApiResult<()> {
        // Touch unread field for clippy
        let _ = &self.monitoring;

        log::info!(
            "Starting simplified V2Ray API server on {}",
            self.config.listen_addr
        );

        // For now, just simulate the server starting
        // In a full implementation, this would start an HTTP or gRPC server

        // Simulate some stats updates
        let stats_clone = Arc::clone(&self.stats);
        let broadcast_clone = self.stats_broadcast.clone();

        let _bg = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            let mut counter = 0;

            loop {
                interval.tick().await;
                counter += 1000;

                // Update mock stats
                {
                    let mut stats = stats_clone.lock().await;
                    *stats
                        .entry("inbound>>>api>>>traffic>>>downlink".to_string())
                        .or_insert(0) += counter;
                    *stats
                        .entry("outbound>>>direct>>>traffic>>>uplink".to_string())
                        .or_insert(0) += counter / 2;
                }

                // Broadcast stats update
                let stat_update = SimpleStat {
                    name: "inbound>>>api>>>traffic>>>downlink".to_string(),
                    value: counter,
                };

                let _ = broadcast_clone.send(stat_update);

                log::debug!("V2Ray API: Updated traffic stats");
            }
        });

        log::info!("V2Ray API server started successfully");
        Ok(())
    }

    /// Start the simple V2Ray API server with a shutdown signal.
    pub async fn start_with_shutdown(&self, mut shutdown: oneshot::Receiver<()>) -> ApiResult<()> {
        let _ = &self.monitoring;

        log::info!(
            "Starting simplified V2Ray API server on {}",
            self.config.listen_addr
        );

        let stats_clone = Arc::clone(&self.stats);
        let broadcast_clone = self.stats_broadcast.clone();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut counter = 0;

        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = interval.tick() => {
                    counter += 1000;
                    {
                        let mut stats = stats_clone.lock().await;
                        *stats
                            .entry("inbound>>>api>>>traffic>>>downlink".to_string())
                            .or_insert(0) += counter;
                        *stats
                            .entry("outbound>>>direct>>>traffic>>>uplink".to_string())
                            .or_insert(0) += counter / 2;
                    }

                    let stat_update = SimpleStat {
                        name: "inbound>>>api>>>traffic>>>downlink".to_string(),
                        value: counter,
                    };

                    let _ = broadcast_clone.send(stat_update);
                    log::debug!("V2Ray API: Updated traffic stats");
                }
            }
        }

        log::info!("V2Ray API server stopped");
        Ok(())
    }

    /// Negotiate API version; returns error if unsupported
    pub fn negotiate_version(&self, version: &str) -> ApiResult<()> {
        match version {
            "v1" | "1" => Ok(()),
            other => Err(crate::error::ApiError::UnsupportedVersion {
                version: other.to_string(),
            }),
        }
    }

    /// Get stats for a specific counter
    pub async fn get_stats(&self, request: SimpleStatsRequest) -> ApiResult<SimpleStatsResponse> {
        if request.name.trim().is_empty() {
            return Err(crate::error::ApiError::InvalidField {
                field: "name".to_string(),
                message: "empty".to_string(),
            });
        }

        let mut stats = self.stats.lock().await;
        let value = stats.get(&request.name).copied().unwrap_or(0);

        // Reset the counter if requested
        if request.reset {
            stats.insert(request.name.clone(), 0);
        }

        let response = SimpleStatsResponse {
            stat: SimpleStat {
                name: request.name,
                value,
            },
        };

        Ok(response)
    }

    /// Query stats with pattern matching
    pub async fn query_stats(
        &self,
        request: SimpleQueryStatsRequest,
    ) -> ApiResult<SimpleQueryStatsResponse> {
        // basic input validation: reject overly long patterns and control chars (except whitespace)
        if request.pattern.len() > 2048
            || request
                .pattern
                .chars()
                .any(|c| (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t')
        {
            return Err(crate::error::ApiError::Parse {
                message: "invalid pattern".to_string(),
            });
        }
        let stats = self.stats.lock().await;
        let mut matching_stats = Vec::new();

        for (name, value) in stats.iter() {
            if request.pattern.is_empty() || name.contains(&request.pattern) {
                matching_stats.push(SimpleStat {
                    name: name.clone(),
                    value: *value,
                });
            }
        }

        Ok(SimpleQueryStatsResponse {
            stats: matching_stats,
        })
    }

    /// Update traffic statistics (for integration with actual traffic counters)
    pub async fn update_traffic(&self, counter_name: &str, value: i64) {
        let mut stats = self.stats.lock().await;
        *stats.entry(counter_name.to_string()).or_insert(0) += value;

        // Broadcast the update
        let stat_update = SimpleStat {
            name: counter_name.to_string(),
            value: stats[counter_name],
        };

        let _ = self.stats_broadcast.send(stat_update);
    }

    /// Subscribe to stats updates
    pub fn subscribe_stats(&self) -> broadcast::Receiver<SimpleStat> {
        self.stats_broadcast.subscribe()
    }

    /// Get all current stats
    pub async fn get_all_stats(&self) -> HashMap<String, i64> {
        self.stats.lock().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_simple_v2ray_api_creation() {
        let config = ApiConfig {
            listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            enable_cors: false,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: false,
            enable_logs_ws: false,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };

        let server = SimpleV2RayApiServer::new(config).unwrap();
        assert!(!server.get_all_stats().await.is_empty());
    }

    #[tokio::test]
    async fn test_stats_operations() {
        let config = ApiConfig {
            listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            enable_cors: false,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: false,
            enable_logs_ws: false,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };

        let server = SimpleV2RayApiServer::new(config).unwrap();

        // Test getting stats
        let request = SimpleStatsRequest {
            name: "inbound>>>api>>>traffic>>>uplink".to_string(),
            reset: false,
        };

        let response = server.get_stats(request).await.unwrap();
        assert_eq!(response.stat.name, "inbound>>>api>>>traffic>>>uplink");
        assert_eq!(response.stat.value, 0);

        // Test updating stats
        server
            .update_traffic("inbound>>>api>>>traffic>>>uplink", 1024)
            .await;

        let request = SimpleStatsRequest {
            name: "inbound>>>api>>>traffic>>>uplink".to_string(),
            reset: false,
        };

        let response = server.get_stats(request).await.unwrap();
        assert_eq!(response.stat.value, 1024);
    }

    #[tokio::test]
    async fn test_query_stats() {
        let config = ApiConfig {
            listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            enable_cors: false,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: false,
            enable_logs_ws: false,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };

        let server = SimpleV2RayApiServer::new(config).unwrap();

        // Test querying all stats
        let request = SimpleQueryStatsRequest {
            pattern: "".to_string(),
            reset: false,
        };

        let response = server.query_stats(request).await.unwrap();
        assert!(response.stats.len() >= 4); // Should have at least 4 initial stats

        // Test querying with pattern
        let request = SimpleQueryStatsRequest {
            pattern: "inbound".to_string(),
            reset: false,
        };

        let response = server.query_stats(request).await.unwrap();
        assert!(!response.stats.is_empty());
        assert!(response.stats.iter().all(|s| s.name.contains("inbound")));
    }

    #[tokio::test]
    async fn test_invalid_field_and_parse_errors() {
        let config = ApiConfig {
            listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            enable_cors: false,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: false,
            enable_logs_ws: false,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };

        let server = SimpleV2RayApiServer::new(config).unwrap();

        // Empty name should yield InvalidField
        let bad = SimpleStatsRequest {
            name: "  ".to_string(),
            reset: false,
        };
        match server.get_stats(bad).await.expect_err("must error") {
            crate::error::ApiError::InvalidField { field, .. } => assert_eq!(field, "name"),
            e => panic!("unexpected error: {e}"),
        }

        // Pattern containing control char should yield Parse
        let badq = SimpleQueryStatsRequest {
            pattern: "\u{0001}".to_string(),
            reset: false,
        };
        match server.query_stats(badq).await.expect_err("must error") {
            crate::error::ApiError::Parse { .. } => {}
            e => panic!("unexpected error: {e}"),
        }

        // Unsupported version
        match server.negotiate_version("v42").expect_err("must error") {
            crate::error::ApiError::UnsupportedVersion { version } => assert_eq!(version, "v42"),
            e => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_stats_subscription() {
        let config = ApiConfig {
            listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            enable_cors: false,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: false,
            enable_logs_ws: false,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };

        let server = SimpleV2RayApiServer::new(config).unwrap();
        let mut rx = server.subscribe_stats();

        // Update stats and check if broadcast works
        server.update_traffic("test_counter", 100).await;

        let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;

        assert!(received.is_ok());
        let stat = received.unwrap().unwrap();
        assert_eq!(stat.name, "test_counter");
        assert_eq!(stat.value, 100);
    }
}
