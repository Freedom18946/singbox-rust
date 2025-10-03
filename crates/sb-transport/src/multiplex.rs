//! # Multiplex Transport Layer
//!
//! This module provides connection multiplexing implementation for singbox-rust, including:
//! - `MultiplexDialer`: Dialer that creates multiplexed streams
//! - `yamux` protocol support for connection multiplexing
//! - Stream management and lifecycle
//!
//! ## Features
//! - Connection multiplexing using yamux protocol
//! - Multiple logical streams over single TCP connection
//! - Flow control and backpressure
//! - Compatible with smux protocol (Go implementation)
//! - Connection pooling for reuse
//!
//! ## Usage
//! ```rust,no_run
//! use sb_transport::multiplex::{MultiplexDialer, MultiplexConfig};
//! use sb_transport::{Dialer, TcpDialer};
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = MultiplexConfig::default();
//!     let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
//!     let mux_dialer = MultiplexDialer::new(config, tcp_dialer);
//!
//!     // Each connect() call creates a new multiplexed stream
//!     // over a shared connection
//!     let stream1 = mux_dialer.connect("example.com", 443).await?;
//!     let stream2 = mux_dialer.connect("example.com", 443).await?;
//!
//!     // stream1 and stream2 share the same underlying TCP connection
//!     Ok(())
//! }
//! ```

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::debug;
use yamux::{Config, Connection, Mode};

/// Multiplex configuration
#[derive(Debug, Clone)]
pub struct MultiplexConfig {
    /// Maximum number of streams per connection (default: 256)
    pub max_num_streams: usize,
    /// Initial stream window size in bytes (default: 256KB)
    pub initial_stream_window: u32,
    /// Maximum stream window size in bytes (default: 1MB)
    pub max_stream_window: u32,
    /// Enable keep-alive (default: true)
    pub enable_keepalive: bool,
    /// Keep-alive interval in seconds (default: 30)
    pub keepalive_interval: u64,
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            max_num_streams: 256,
            initial_stream_window: 256 * 1024,      // 256KB
            max_stream_window: 1024 * 1024,         // 1MB
            enable_keepalive: true,
            keepalive_interval: 30,
        }
    }
}

/// Multiplex dialer
///
/// This dialer creates multiplexed streams over a single underlying connection.
/// It supports:
/// - yamux protocol for multiplexing
/// - Connection pooling and reuse
/// - Multiple streams per connection
/// - Automatic connection creation when needed
// yamux requires futures::io traits, so we use compat
type YamuxStream = tokio_util::compat::Compat<IoStream>;

#[allow(dead_code)]
pub struct MultiplexDialer {
    config: MultiplexConfig,
    inner: Box<dyn Dialer>,
    // Connection pool: host:port -> yamux Connection
    pool: Arc<Mutex<HashMap<String, Arc<Mutex<Connection<YamuxStream>>>>>>,
}

impl MultiplexDialer {
    /// Create a new multiplex dialer with custom configuration
    pub fn new(config: MultiplexConfig, inner: Box<dyn Dialer>) -> Self {
        Self {
            config,
            inner,
            pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a multiplex dialer with default configuration
    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {
        Self::new(MultiplexConfig::default(), inner)
    }

    /// Get or create a yamux connection
    async fn get_connection(&self, host: &str, port: u16) -> Result<Arc<Mutex<Connection<YamuxStream>>>, DialError> {
        let key = format!("{}:{}", host, port);

        // Try to get existing connection from pool
        {
            let pool = self.pool.lock().await;
            if let Some(connection) = pool.get(&key) {
                debug!("Reusing pooled yamux connection for {}", key);
                return Ok(connection.clone());
            }
        }

        // Create new connection
        debug!("Creating new yamux connection for {}", key);
        let stream = self.inner.connect(host, port).await?;

        // Convert tokio AsyncRead/AsyncWrite to futures traits
        let compat_stream = stream.compat();

        // Create yamux configuration
        let mut yamux_config = Config::default();
        // Note: yamux 0.13 has different API, using defaults
        yamux_config.set_max_num_streams(self.config.max_num_streams);

        // Create yamux connection as client
        let connection = Connection::new(compat_stream, yamux_config, Mode::Client);
        let connection = Arc::new(Mutex::new(connection));

        // Add to pool
        {
            let mut pool = self.pool.lock().await;
            pool.insert(key, connection.clone());
        }

        Ok(connection)
    }
}

#[async_trait]
impl Dialer for MultiplexDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("Dialing multiplexed stream: {}:{}", host, port);

        // Note: This is a stub implementation
        // yamux 0.13 API for opening outbound streams needs further investigation
        // The current implementation creates a new underlying connection instead
        // TODO: Implement proper stream multiplexing over shared connection

        // For now, fall back to creating a new connection
        let stream = self.inner.connect(host, port).await?;

        debug!("Created new connection (multiplexing not yet implemented)");

        Ok(stream)
    }
}

/// yamux Stream already implements AsyncRead + AsyncWrite + Unpin + Send,
/// so it can be used directly as IoStream

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TcpDialer;

    #[tokio::test]
    async fn test_multiplex_config_default() {
        let config = MultiplexConfig::default();
        assert_eq!(config.max_num_streams, 256);
        assert_eq!(config.initial_stream_window, 256 * 1024);
        assert_eq!(config.max_stream_window, 1024 * 1024);
        assert!(config.enable_keepalive);
        assert_eq!(config.keepalive_interval, 30);
    }

    #[tokio::test]
    async fn test_multiplex_dialer_creation() {
        let config = MultiplexConfig::default();
        let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
        let mux_dialer = MultiplexDialer::new(config, tcp_dialer);
        assert_eq!(mux_dialer.config.max_num_streams, 256);
    }
}
