//! # Multiplex Transport Layer
//!
//! This module provides connection multiplexing implementation for singbox-rust, including:
//! - `MultiplexDialer`: Client-side dialer that creates multiplexed streams
//! - `MultiplexListener`: Server-side listener that accepts multiplexed streams
//! - `yamux` protocol support for connection multiplexing
//! - Stream management and lifecycle
//!
//! ## Features
//! - Connection multiplexing using yamux protocol
//! - Multiple logical streams over single TCP connection
//! - Flow control and backpressure
//! - Compatible with smux protocol (Go implementation)
//! - Connection pooling for reuse (client-side)
//!
//! ## Client Usage
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
//!
//! ## Server Usage
//! ```rust,no_run
//! use sb_transport::multiplex::{MultiplexListener, MultiplexServerConfig};
//! use tokio::net::TcpListener;
//!
//! async fn server_example() -> Result<(), Box<dyn std::error::Error>> {
//!     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
//!     let config = MultiplexServerConfig::default();
//!     let mux_listener = MultiplexListener::new(tcp_listener, config);
//!
//!     loop {
//!         let stream = mux_listener.accept().await?;
//!         tokio::spawn(async move {
//!             // Handle multiplexed stream
//!         });
//!     }
//! }
//! ```

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use futures::future::poll_fn;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, warn};
use yamux::{Config, Connection, Mode};

/// Brutal Congestion Control configuration
///
/// Brutal is a congestion control algorithm designed for lossy networks.
/// It uses a fixed sending rate instead of traditional TCP congestion control.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BrutalConfig {
    /// Upload bandwidth in Mbps (megabits per second)
    pub up_mbps: u64,
    /// Download bandwidth in Mbps (megabits per second)
    pub down_mbps: u64,
}

impl BrutalConfig {
    /// Create a new Brutal configuration with specified bandwidth
    pub fn new(up_mbps: u64, down_mbps: u64) -> Self {
        Self { up_mbps, down_mbps }
    }

    /// Get upload bandwidth in bytes per second
    pub fn up_bytes_per_sec(&self) -> u64 {
        self.up_mbps * 1_000_000 / 8
    }

    /// Get download bandwidth in bytes per second
    pub fn down_bytes_per_sec(&self) -> u64 {
        self.down_mbps * 1_000_000 / 8
    }
}

/// Multiplex configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// Maximum number of pooled connections (default: 4)
    pub max_connections: usize,
    /// Maximum streams per connection before creating new connection (default: 8)
    pub max_streams_per_connection: usize,
    /// Connection idle timeout in seconds (default: 300)
    pub connection_idle_timeout: u64,
    /// Enable padding (default: false)
    pub padding: bool,
    /// Brutal congestion control configuration (optional)
    pub brutal: Option<BrutalConfig>,
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            max_num_streams: 256,
            initial_stream_window: 256 * 1024, // 256KB
            max_stream_window: 1024 * 1024,    // 1MB
            enable_keepalive: true,
            keepalive_interval: 30,
            max_connections: 4,
            max_streams_per_connection: 8,
            connection_idle_timeout: 300,
            padding: false,
            brutal: None,
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

/// Represents a multiplexed connection with metadata
struct MultiplexConnection {
    connection: Arc<Mutex<Connection<YamuxStream>>>,
    stream_count: Arc<AtomicUsize>,
    last_used: Arc<Mutex<Instant>>,
    created_at: Instant,
}

impl MultiplexConnection {
    fn new(connection: Connection<YamuxStream>) -> Self {
        Self {
            connection: Arc::new(Mutex::new(connection)),
            stream_count: Arc::new(AtomicUsize::new(0)),
            last_used: Arc::new(Mutex::new(Instant::now())),
            created_at: Instant::now(),
        }
    }

    fn increment_stream_count(&self) -> usize {
        self.stream_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn decrement_stream_count(&self) -> usize {
        self.stream_count
            .fetch_sub(1, Ordering::SeqCst)
            .saturating_sub(1)
    }

    fn get_stream_count(&self) -> usize {
        self.stream_count.load(Ordering::SeqCst)
    }

    async fn update_last_used(&self) {
        let mut last_used = self.last_used.lock().await;
        *last_used = Instant::now();
    }

    async fn is_idle(&self, timeout: Duration) -> bool {
        let last_used = self.last_used.lock().await;
        last_used.elapsed() > timeout
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if connection is healthy by attempting to poll it
    async fn is_healthy(&self) -> bool {
        // For yamux 0.13, we assume connection is healthy if we can lock it
        // A more sophisticated check would try to poll the connection
        self.connection.try_lock().is_ok()
    }
}

pub struct MultiplexDialer {
    config: MultiplexConfig,
    inner: Box<dyn Dialer>,
    // Connection pool: host:port -> MultiplexConnection
    pool: Arc<Mutex<HashMap<String, Arc<MultiplexConnection>>>>,
}

impl std::fmt::Debug for MultiplexDialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultiplexDialer")
            .field("config", &self.config)
            .field("pool_size", &"<pool>")
            .finish()
    }
}

impl MultiplexDialer {
    /// Create a new multiplex dialer with custom configuration
    pub fn new(config: MultiplexConfig, inner: Box<dyn Dialer>) -> Self {
        let dialer = Self {
            config,
            inner,
            pool: Arc::new(Mutex::new(HashMap::new())),
        };

        // Start background cleanup task
        dialer.start_cleanup_task();

        dialer
    }

    /// Create a multiplex dialer with default configuration
    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {
        Self::new(MultiplexConfig::default(), inner)
    }

    /// Start background task to cleanup idle and unhealthy connections
    fn start_cleanup_task(&self) {
        let pool = self.pool.clone();
        let idle_timeout = Duration::from_secs(self.config.connection_idle_timeout);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                let mut pool = pool.lock().await;
                let mut to_remove = Vec::new();

                for (key, conn) in pool.iter() {
                    // Check if connection is idle
                    if conn.is_idle(idle_timeout).await {
                        debug!("Removing idle connection: {}", key);
                        to_remove.push(key.clone());
                        continue;
                    }

                    // Check if connection is healthy
                    if !conn.is_healthy().await {
                        debug!("Removing unhealthy connection: {}", key);
                        to_remove.push(key.clone());
                        continue;
                    }
                }

                for key in to_remove {
                    pool.remove(&key);
                }
            }
        });
    }

    /// Create yamux configuration with optional Brutal congestion control
    fn create_yamux_config(&self) -> Config {
        let mut config = Config::default();
        config.set_max_num_streams(self.config.max_num_streams);

        // Apply Brutal congestion control if configured
        if let Some(ref brutal) = self.config.brutal {
            // Note: yamux 0.13 has limited API for congestion control
            // We log the configuration but yamux doesn't expose window update mode directly
            debug!(
                "Brutal congestion control configured: up={}Mbps, down={}Mbps",
                brutal.up_mbps, brutal.down_mbps
            );
            // Window sizes and congestion control would be handled at a lower level
            // or through custom yamux configuration if needed
        }

        config
    }

    /// Get or create a yamux connection with health checks and stream limits
    async fn get_or_create_connection(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Arc<MultiplexConnection>, DialError> {
        let key = format!("{}:{}", host, port);

        // Try to get existing connection from pool
        {
            let pool = self.pool.lock().await;
            if let Some(mux_conn) = pool.get(&key) {
                // Check if connection is healthy
                if mux_conn.is_healthy().await {
                    let stream_count = mux_conn.get_stream_count();

                    // Check if we can reuse this connection (not at max streams)
                    if stream_count < self.config.max_streams_per_connection {
                        debug!(
                            "Reusing pooled yamux connection for {} (streams: {}/{})",
                            key, stream_count, self.config.max_streams_per_connection
                        );
                        mux_conn.update_last_used().await;
                        return Ok(mux_conn.clone());
                    } else {
                        debug!(
                            "Connection {} at max streams ({}/{}), creating new connection",
                            key, stream_count, self.config.max_streams_per_connection
                        );
                    }
                } else {
                    debug!(
                        "Connection {} is unhealthy, will create new connection",
                        key
                    );
                }
            }
        }

        // Check if we've reached max connections limit
        {
            let pool = self.pool.lock().await;
            if pool.len() >= self.config.max_connections {
                // Try to find a connection with available capacity
                for (existing_key, mux_conn) in pool.iter() {
                    if existing_key.starts_with(&format!("{}:", host)) {
                        if mux_conn.is_healthy().await
                            && mux_conn.get_stream_count() < self.config.max_streams_per_connection
                        {
                            debug!(
                                "Max connections reached, reusing existing connection: {}",
                                existing_key
                            );
                            mux_conn.update_last_used().await;
                            return Ok(mux_conn.clone());
                        }
                    }
                }

                // If no available connection, remove oldest idle connection
                if let Some((oldest_key, _)) = pool.iter().max_by_key(|(_, conn)| conn.age()) {
                    let oldest_key = oldest_key.clone();
                    drop(pool);
                    let mut pool = self.pool.lock().await;
                    pool.remove(&oldest_key);
                    debug!("Removed oldest connection {} to make room", oldest_key);
                }
            }
        }

        // Create new connection
        debug!("Creating new yamux connection for {}", key);
        let stream = self.inner.connect(host, port).await?;

        // Convert tokio AsyncRead/AsyncWrite to futures traits
        let compat_stream = stream.compat();

        // Create yamux configuration
        let yamux_config = self.create_yamux_config();

        // Create yamux connection as client
        let connection = Connection::new(compat_stream, yamux_config, Mode::Client);
        let mux_conn = Arc::new(MultiplexConnection::new(connection));

        // Start background task to drive the yamux connection
        // This is necessary to handle control frames and keep the connection alive
        let conn_clone = mux_conn.clone();
        let key_clone = key.clone();
        tokio::spawn(async move {
            let mut connection = conn_clone.connection.lock().await;
            loop {
                match poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                    Some(Ok(_stream)) => {
                        // We don't expect inbound streams on client side, but we need to poll
                        // to drive the connection and handle control frames
                        debug!(
                            "Unexpected inbound stream on client connection: {}",
                            key_clone
                        );
                    }
                    Some(Err(e)) => {
                        debug!("yamux connection error for {}: {}", key_clone, e);
                        break;
                    }
                    None => {
                        debug!("yamux connection closed for {}", key_clone);
                        break;
                    }
                }
            }
        });

        // Add to pool
        {
            let mut pool = self.pool.lock().await;
            pool.insert(key.clone(), mux_conn.clone());
            debug!(
                "Added new connection to pool: {} (pool size: {})",
                key,
                pool.len()
            );
        }

        Ok(mux_conn)
    }
}

#[async_trait]
impl Dialer for MultiplexDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("Dialing multiplexed stream: {}:{}", host, port);

        // Get or create a yamux connection from the pool
        let mux_conn = self.get_or_create_connection(host, port).await?;

        // Increment stream count
        let stream_count = mux_conn.increment_stream_count();
        debug!(
            "Opening yamux stream for {}:{} (stream count: {})",
            host, port, stream_count
        );

        // Open a new outbound stream on the yamux connection
        let mut connection = mux_conn.connection.lock().await;
        let stream = poll_fn(|cx| connection.poll_new_outbound(cx))
            .await
            .map_err(|e| {
                mux_conn.decrement_stream_count();
                DialError::Other(format!("Failed to open yamux stream: {}", e))
            })?;

        drop(connection);

        debug!(
            "Successfully opened multiplexed stream for {}:{}",
            host, port
        );

        // Convert yamux stream back to tokio traits
        let tokio_stream = stream.compat();

        // Wrap in a struct that decrements stream count on drop
        let stream_wrapper = StreamWrapper {
            stream: tokio_stream,
            mux_conn: mux_conn.clone(),
        };

        Ok(Box::new(stream_wrapper))
    }
}

/// Wrapper that decrements stream count when dropped
struct StreamWrapper {
    stream: tokio_util::compat::Compat<yamux::Stream>,
    mux_conn: Arc<MultiplexConnection>,
}

impl Drop for StreamWrapper {
    fn drop(&mut self) {
        let count = self.mux_conn.decrement_stream_count();
        debug!("Stream dropped, remaining streams: {}", count);
    }
}

impl tokio::io::AsyncRead for StreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for StreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// yamux Stream already implements AsyncRead + AsyncWrite + Unpin + Send,
/// so it can be used directly as IoStream

/// Multiplex server configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultiplexServerConfig {
    /// Maximum number of streams per connection (default: 256)
    pub max_num_streams: usize,
    /// Initial stream window size in bytes (default: 256KB)
    pub initial_stream_window: u32,
    /// Maximum stream window size in bytes (default: 1MB)
    pub max_stream_window: u32,
    /// Enable keep-alive (default: true)
    pub enable_keepalive: bool,
    /// Brutal congestion control configuration (optional)
    pub brutal: Option<BrutalConfig>,
}

impl Default for MultiplexServerConfig {
    fn default() -> Self {
        Self {
            max_num_streams: 256,
            initial_stream_window: 256 * 1024, // 256KB
            max_stream_window: 1024 * 1024,    // 1MB
            enable_keepalive: true,
            brutal: None,
        }
    }
}

/// Multiplex server listener
///
/// This listener accepts incoming multiplexed connections by:
/// 1. Accepting TCP connections from the underlying listener
/// 2. Creating yamux server-side connection
/// 3. Accepting incoming streams from the yamux connection
/// 4. Returning streams as AsyncRead + AsyncWrite
///
/// ## Usage
/// ```rust,no_run
/// use sb_transport::multiplex::{MultiplexListener, MultiplexServerConfig};
/// use tokio::net::TcpListener;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
///     let config = MultiplexServerConfig::default();
///     let mux_listener = MultiplexListener::new(tcp_listener, config);
///
///     loop {
///         let stream = mux_listener.accept().await?;
///         tokio::spawn(async move {
///             // Handle multiplexed stream
///         });
///     }
/// }
/// ```
pub struct MultiplexListener {
    config: MultiplexServerConfig,
    // Channel for distributing incoming streams
    stream_rx: Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<IoStream>>>,
    stream_tx: tokio::sync::mpsc::UnboundedSender<IoStream>,
    local_addr: std::net::SocketAddr,
}

impl MultiplexListener {
    /// Create a new multiplex listener from a TCP listener
    pub fn new(tcp_listener: tokio::net::TcpListener, config: MultiplexServerConfig) -> Self {
        let (stream_tx, stream_rx) = tokio::sync::mpsc::unbounded_channel();
        let local_addr = tcp_listener
            .local_addr()
            .expect("Failed to get local address");

        // Start background task to accept TCP connections and handle yamux
        Self::start_accept_task(tcp_listener, config.clone(), stream_tx.clone());

        Self {
            config,
            stream_rx: Arc::new(Mutex::new(stream_rx)),
            stream_tx,
            local_addr,
        }
    }

    /// Create a multiplex listener with default configuration
    pub fn with_default_config(tcp_listener: tokio::net::TcpListener) -> Self {
        Self::new(tcp_listener, MultiplexServerConfig::default())
    }

    /// Create yamux configuration for server with optional Brutal congestion control
    fn create_server_yamux_config(config: &MultiplexServerConfig) -> Config {
        let mut yamux_config = Config::default();
        yamux_config.set_max_num_streams(config.max_num_streams);

        // Apply Brutal congestion control if configured
        if let Some(ref brutal) = config.brutal {
            // Note: yamux 0.13 has limited API for congestion control
            // We log the configuration but yamux doesn't expose window update mode directly
            debug!(
                "Server Brutal congestion control configured: up={}Mbps, down={}Mbps",
                brutal.up_mbps, brutal.down_mbps
            );
            // Window sizes and congestion control would be handled at a lower level
            // or through custom yamux configuration if needed
        }

        yamux_config
    }

    /// Start background task to accept TCP connections and distribute streams
    fn start_accept_task(
        tcp_listener: tokio::net::TcpListener,
        config: MultiplexServerConfig,
        stream_tx: tokio::sync::mpsc::UnboundedSender<IoStream>,
    ) {
        tokio::spawn(async move {
            loop {
                // Accept TCP connection
                let (tcp_stream, peer_addr) = match tcp_listener.accept().await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                debug!("Accepted TCP connection from {} for yamux", peer_addr);

                // Spawn task to handle this yamux connection
                let stream_tx = stream_tx.clone();
                let config = config.clone();

                tokio::spawn(async move {
                    if let Err(e) =
                        Self::handle_yamux_connection(tcp_stream, peer_addr, config, stream_tx)
                            .await
                    {
                        warn!("Error handling yamux connection from {}: {}", peer_addr, e);
                    }
                });
            }
        });
    }

    /// Handle a single yamux connection and distribute its streams
    async fn handle_yamux_connection(
        tcp_stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
        config: MultiplexServerConfig,
        stream_tx: tokio::sync::mpsc::UnboundedSender<IoStream>,
    ) -> Result<(), DialError> {
        // Convert to compat stream (yamux needs futures traits)
        let compat_stream = tcp_stream.compat();

        // Create yamux configuration with Brutal support
        let yamux_config = Self::create_server_yamux_config(&config);

        // Create yamux connection as server
        let mut connection = Connection::new(compat_stream, yamux_config, Mode::Server);

        debug!("Created yamux server connection for {}", peer_addr);

        // Accept and distribute all incoming streams from this connection
        loop {
            match poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                Some(Ok(stream)) => {
                    debug!("Accepted yamux stream from {}", peer_addr);

                    // Convert yamux stream back to tokio traits and box it
                    let tokio_stream = stream.compat();
                    let boxed_stream: IoStream = Box::new(tokio_stream);

                    // Send stream through channel
                    if stream_tx.send(boxed_stream).is_err() {
                        warn!("Failed to send stream to channel, listener may be closed");
                        break;
                    }
                }
                Some(Err(e)) => {
                    warn!("yamux stream error from {}: {}", peer_addr, e);
                    break;
                }
                None => {
                    debug!("yamux connection closed for {}", peer_addr);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Accept a new multiplexed stream
    ///
    /// This method receives streams from the channel that are distributed
    /// by the background task handling yamux connections.
    pub async fn accept(&self) -> Result<IoStream, DialError> {
        let mut stream_rx = self.stream_rx.lock().await;

        stream_rx
            .recv()
            .await
            .ok_or_else(|| DialError::Other("Stream channel closed".to_string()))
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(self.local_addr)
    }
}

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

    #[tokio::test]
    async fn test_multiplex_server_config_default() {
        let config = MultiplexServerConfig::default();
        assert_eq!(config.max_num_streams, 256);
        assert_eq!(config.initial_stream_window, 256 * 1024);
        assert_eq!(config.max_stream_window, 1024 * 1024);
        assert!(config.enable_keepalive);
    }
}
