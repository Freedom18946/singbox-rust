//! Admin and stats ports for control plane.

use crate::errors::CoreError;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Log level for dynamic adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Admin control port.
///
/// sb-core implements this; sb-api calls it.
pub trait AdminPort: Send + Sync + 'static {
    /// Reload configuration from raw bytes.
    fn reload_config(&self, raw: Vec<u8>) -> Result<(), CoreError>;

    /// Graceful shutdown.
    fn shutdown(&self) -> Result<(), CoreError>;

    /// Set log level dynamically.
    fn set_log_level(&self, level: LogLevel) -> Result<(), CoreError>;
}

/// Connection snapshot for stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnSnapshot {
    pub session_id: u64,
    pub inbound: String,
    pub outbound: String,
    pub destination: String,
    pub start_time: SystemTime,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

/// Traffic snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficSnapshot {
    pub upload_total: u64,
    pub download_total: u64,
    pub active_connections: usize,
}

/// Stats query port.
///
/// sb-core implements this; sb-api calls it for control plane queries.
pub trait StatsPort: Send + Sync + 'static {
    /// Get all active connections.
    fn connections(&self) -> Vec<ConnSnapshot>;

    /// Get traffic summary.
    fn traffic(&self) -> TrafficSnapshot;
}
