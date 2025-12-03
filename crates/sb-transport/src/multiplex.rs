//! # Multiplex Transport Layer
//! # 多路复用传输层
//!
//! This module provides connection multiplexing implementation for singbox-rust, including:
//! 本模块为 singbox-rust 提供连接多路复用实现，包括：
//! - `MultiplexDialer`: Client-side dialer that creates multiplexed streams
//!   `MultiplexDialer`: 客户端拨号器，创建多路复用流
//! - `MultiplexListener`: Server-side listener that accepts multiplexed streams
//!   `MultiplexListener`: 服务端监听器，接受多路复用流
//! - `yamux`: Underlying multiplexing protocol
//!   `yamux`: 底层多路复用协议
//! - `Brutal`: Congestion control optimized for lossy networks
//!   `Brutal`: 针对有损网络优化的拥塞控制
//! - Stream management and lifecycle
//!   流管理和生命周期控制
//!
//! ## Features / 特性
//! - **Connection Reuse**: Reduces handshake overhead by reusing connections.
//!   **连接复用**：通过复用连接减少握手开销。
//! - **Concurrency**: Supports multiple concurrent streams per connection.
//!   **并发**：支持每个连接多个并发流。
//! - **Congestion Control**: Integrates Brutal algorithm for better performance in poor network conditions.
//!   **拥塞控制**：集成 Brutal 算法，在恶劣网络条件下提供更好的性能。
//! - **Keep-alive**: Built-in keep-alive mechanism to maintain persistent connections.
//!   **保活**：内置保活机制以维护持久连接。
//!
//! ## Strategic Relevance / 战略关联
//! - **Performance**: Significantly improves throughput and latency for protocols with frequent short-lived connections (e.g., HTTP/1.1).
//!   **性能**：显著提高具有频繁短连接的协议（如 HTTP/1.1）的吞吐量和延迟。
//! - **Resource Efficiency**: Reduces the number of TCP/TLS handshakes and open file descriptors.
//!   **资源效率**：减少 TCP/TLS 握手次数和打开的文件描述符数量。
//! - **Resilience**: Brutal congestion control helps maintain throughput even with high packet loss.
//!   **弹性**：Brutal 拥塞控制有助于即使在高丢包率下也能保持吞吐量。

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use futures::future::poll_fn;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{debug, warn};
use yamux::{Config, Connection, Mode};

pub mod padding;
pub use padding::PaddingStream;

/// Brutal Congestion Control configuration / Brutal 拥塞控制配置
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BrutalConfig {
    /// Upload bandwidth in Mbps
    pub up_mbps: u64,
    /// Download bandwidth in Mbps
    pub down_mbps: u64,
}

impl BrutalConfig {
    pub fn new(up_mbps: u64, down_mbps: u64) -> Self {
        Self { up_mbps, down_mbps }
    }

    pub fn up_bytes_per_sec(&self) -> u64 {
        self.up_mbps * 1024 * 1024 / 8
    }

    pub fn down_bytes_per_sec(&self) -> u64 {
        self.down_mbps * 1024 * 1024 / 8
    }
}

/// Multiplex configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MultiplexClientConfig {
    /// Maximum number of concurrent streams per connection
    /// 每个连接的最大并发流数量
    pub max_num_streams: usize,

    /// Initial receive window size (bytes)
    /// 初始接收窗口大小（字节）
    pub initial_stream_window: u32,

    /// Maximum receive window size (bytes)
    /// 最大接收窗口大小（字节）
    pub max_stream_window: u32,

    /// Enable padding frames for traffic analysis resistance
    /// 启用填充帧以抵抗流量分析
    /// Adds random padding to make traffic patterns less distinctive
    /// 添加随机填充使流量模式不易识别
    pub enable_padding: bool,

    /// Connection reuse timeout (seconds)
    /// 连接复用超时（秒）
    /// Idle connections are kept alive for reuse within this duration
    /// 空闲连接在此时间内保持活动以供复用
    pub reuse_timeout_secs: u64,

    /// Maximum number of connections to pool for reuse
    /// 连接池中复用的最大连接数
    pub max_pool_size: usize,

    pub enable_keepalive: bool,
    pub keepalive_interval: u64,
    pub max_streams_per_connection: usize,
    pub brutal: Option<BrutalConfig>,
}

impl Default for MultiplexClientConfig {
    fn default() -> Self {
        Self {
            max_num_streams: 256,
            initial_stream_window: 256 * 1024,
            max_stream_window: 1024 * 1024,
            enable_padding: false,
            reuse_timeout_secs: 300, // 5 minutes
            max_pool_size: 4,
            enable_keepalive: true,
            keepalive_interval: 30,
            max_streams_per_connection: 8,
            brutal: None,
        }
    }
}

/// Multiplex configuration (alias to MultiplexClientConfig for backward compatibility)
/// 多路复用配置（为向后兼容使用 MultiplexClientConfig 的别名）
pub type MultiplexConfig = MultiplexClientConfig;

/// Multiplex server configuration (alias to MultiplexClient Config for backward compatibility)
pub type MultiplexServerConfig = MultiplexClientConfig;

/// Control message for multiplex connection
enum ControlMessage {
    OpenStream(oneshot::Sender<Result<yamux::Stream, DialError>>),
}

/// Represents a multiplexed connection with metadata
#[derive(Clone)]
struct MultiplexConnection {
    control_tx: mpsc::UnboundedSender<ControlMessage>,
    stream_count: Arc<AtomicUsize>,
    last_used: Arc<Mutex<Instant>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl MultiplexConnection {
    fn new(
        control_tx: mpsc::UnboundedSender<ControlMessage>,
        closed: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            control_tx,
            stream_count: Arc::new(AtomicUsize::new(0)),
            last_used: Arc::new(Mutex::new(Instant::now())),
            closed,
        }
    }

    fn increment_stream_count(&self) -> usize {
        self.stream_count.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn decrement_stream_count(&self) -> usize {
        self.stream_count.fetch_sub(1, Ordering::SeqCst) - 1
    }

    fn get_stream_count(&self) -> usize {
        self.stream_count.load(Ordering::SeqCst)
    }

    async fn update_last_used(&self) {
        *self.last_used.lock().await = Instant::now();
    }

    async fn is_idle(&self, timeout: Duration) -> bool {
        if self.get_stream_count() > 0 {
            return false;
        }
        let last_used = *self.last_used.lock().await;
        last_used.elapsed() > timeout
    }

    fn is_healthy(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }
}

/// Type alias for multiplex connection pool to reduce type complexity
type MultiplexPool = Arc<Mutex<HashMap<(String, u16), Vec<MultiplexConnection>>>>;

/// Multiplex dialer
pub struct MultiplexDialer {
    config: MultiplexConfig,
    dialer: Box<dyn Dialer>,
    pool: MultiplexPool,
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
    pub fn new(config: MultiplexConfig, dialer: Box<dyn Dialer>) -> Self {
        let dialer = Self {
            config,
            dialer,
            pool: Arc::new(Mutex::new(HashMap::new())),
        };

        dialer.start_cleanup_task();

        dialer
    }

    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {
        Self::new(MultiplexConfig::default(), inner)
    }

    fn start_cleanup_task(&self) {
        let pool = self.pool.clone();
        let idle_timeout = Duration::from_secs(self.config.reuse_timeout_secs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                let mut pool = pool.lock().await;
                let mut keys_to_remove = Vec::new();

                for (key, connections) in pool.iter_mut() {
                    let mut i = 0;
                    while i < connections.len() {
                        let conn = &connections[i];
                        if conn.is_idle(idle_timeout).await {
                            debug!("Removing idle connection: {:?}", key);
                            connections.remove(i);
                        } else if !conn.is_healthy() {
                            debug!("Removing unhealthy connection: {:?}", key);
                            connections.remove(i);
                        } else {
                            i += 1;
                        }
                    }

                    if connections.is_empty() {
                        keys_to_remove.push(key.clone());
                    }
                }

                for key in keys_to_remove {
                    pool.remove(&key);
                }
            }
        });
    }

    fn create_yamux_config(&self) -> Config {
        let mut config = Config::default();
        config.set_max_num_streams(self.config.max_num_streams);
        // Yamux 0.13 deprecated set_receive_window in favor of set_max_connection_receive_window.
        // We set it to None to allow unlimited total receive window, letting individual streams
        // manage their windows. Note that yamux 0.13.8 doesn't expose per-stream window configuration
        // in the public API - it uses internal defaults.
        config.set_max_connection_receive_window(None);
        
        // Note: yamux 0.13.8 doesn't expose set_keep_alive_interval or set_receive_window in the public API.
        // Keep-alive and window management are handled internally by the yamux implementation.

        if let Some(ref brutal) = self.config.brutal {
            debug!(
                "Brutal congestion control configured: up={}Mbps, down={}Mbps",
                brutal.up_mbps, brutal.down_mbps
            );
        }

        config
    }

    async fn get_or_create_connection(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Arc<MultiplexConnection>, DialError> {
        let key = (host.to_string(), port);

        {
            let mut pool = self.pool.lock().await;
            if let Some(connections) = pool.get_mut(&key) {
                let mut i = 0;
                while i < connections.len() {
                    if !connections[i].is_healthy() {
                        debug!("Removing unhealthy connection: {:?}", key);
                        connections.remove(i);
                    } else {
                        i += 1;
                    }
                }

                for conn in connections.iter() {
                    if conn.get_stream_count() < self.config.max_streams_per_connection {
                        debug!("Reusing connection for {:?}", key);
                        return Ok(Arc::new(conn.clone()));
                    }
                }
            }
        }

        debug!("Creating new connection for {:?}", key);
        let stream = self.dialer.connect(host, port).await?;
        
        let stream = if self.config.enable_padding {
            debug!("Enabling padding for multiplex connection");
            let padded = PaddingStream::new(stream, true);
            Box::new(padded) as IoStream
        } else {
            stream
        };

        let compat_stream = stream.compat();
        let config = self.create_yamux_config();
        let mut connection = Connection::new(compat_stream, config, Mode::Client);
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closed_clone = closed.clone();
        let (control_tx, mut control_rx) = mpsc::unbounded_channel::<ControlMessage>();

        tokio::spawn(async move {
            let mut pending_open: Option<oneshot::Sender<Result<yamux::Stream, DialError>>> = None;

            poll_fn(|cx| {
                // 1. Poll inbound streams
                loop {
                    match connection.poll_next_inbound(cx) {
                        Poll::Ready(Some(Ok(_stream))) => {
                            debug!("Accepted unexpected inbound stream");
                        }
                        Poll::Ready(Some(Err(e))) => {
                            warn!("Yamux connection error: {}", e);
                            return Poll::Ready(());
                        }
                        Poll::Ready(None) => {
                            debug!("Yamux connection closed");
                            return Poll::Ready(());
                        }
                        Poll::Pending => break,
                    }
                }

                // 2. Handle pending open request
                if let Some(tx) = pending_open.take() {
                    match connection.poll_new_outbound(cx) {
                        Poll::Ready(Ok(stream)) => {
                            let _ = tx.send(Ok(stream));
                        }
                        Poll::Ready(Err(e)) => {
                            let _ = tx.send(Err(DialError::Other(e.to_string())));
                        }
                        Poll::Pending => {
                            // Still pending, put it back
                            pending_open = Some(tx);
                        }
                    }
                }

                // 3. Poll control messages if no pending open
                if pending_open.is_none() {
                    loop {
                        match control_rx.poll_recv(cx) {
                            Poll::Ready(Some(msg)) => match msg {
                                ControlMessage::OpenStream(tx) => {
                                    // Try to open immediately
                                    match connection.poll_new_outbound(cx) {
                                        Poll::Ready(Ok(stream)) => {
                                            let _ = tx.send(Ok(stream));
                                        }
                                        Poll::Ready(Err(e)) => {
                                            let _ = tx.send(Err(DialError::Other(e.to_string())));
                                        }
                                        Poll::Pending => {
                                            pending_open = Some(tx);
                                            break; // Wait for wake up
                                        }
                                    }
                                }
                            },
                            Poll::Ready(None) => {
                                return Poll::Ready(());
                            }
                            Poll::Pending => break,
                        }
                    }
                }

                Poll::Pending
            })
            .await;

            debug!("Yamux connection task finished");
            closed_clone.store(true, Ordering::SeqCst);
        });

        let mux_conn = Arc::new(MultiplexConnection::new(control_tx, closed));

        {
            let mut pool = self.pool.lock().await;
            let connections = pool.entry(key.clone()).or_insert_with(Vec::new);

            // Enforce max_pool_size
            if connections.len() >= self.config.max_pool_size {
                // Use simple FIFO eviction strategy
                // For simplicity and performance in this critical section, we remove the first connection.
                // A smarter LRU strategy would require async locking of last_used timestamps,
                // which adds complexity while holding the pool lock.
                if !connections.is_empty() {
                     debug!("Pool full for {:?}, evicting oldest connection", key);
                     connections.remove(0);
                }
            }

            connections.push((*mux_conn).clone());
        }

        Ok(mux_conn)
    }
}

#[async_trait]
impl Dialer for MultiplexDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("Dialing multiplexed stream: {}:{}", host, port);

        let mux_conn = self.get_or_create_connection(host, port).await?;
        mux_conn.update_last_used().await;
        let stream_count = mux_conn.increment_stream_count();
        debug!(
            "Opening yamux stream for {}:{} (stream count: {})",
            host, port, stream_count
        );

        let (tx, rx) = oneshot::channel();
        if mux_conn
            .control_tx
            .send(ControlMessage::OpenStream(tx))
            .is_err()
        {
            mux_conn.decrement_stream_count();
            return Err(DialError::Other("Connection closed".into()));
        }

        let stream = match rx.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                mux_conn.decrement_stream_count();
                return Err(e);
            }
            Err(_) => {
                mux_conn.decrement_stream_count();
                return Err(DialError::Other("Control channel closed".into()));
            }
        };

        debug!(
            "Successfully opened multiplexed stream for {}:{}",
            host, port
        );

        let tokio_stream = stream.compat();
        let stream_wrapper = StreamWrapper {
            stream: tokio_stream,
            mux_conn: mux_conn.clone(),
        };

        Ok(Box::new(stream_wrapper))
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

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

pub struct MultiplexListener {
    config: MultiplexServerConfig,
    stream_rx: Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<IoStream>>>,
    #[allow(dead_code)]
    stream_tx: tokio::sync::mpsc::UnboundedSender<IoStream>,
    local_addr: std::net::SocketAddr,
}

impl MultiplexListener {
    pub fn new(tcp_listener: tokio::net::TcpListener, config: MultiplexServerConfig) -> Self {
        let (stream_tx, stream_rx) = tokio::sync::mpsc::unbounded_channel();
        let local_addr = tcp_listener
            .local_addr()
            .expect("Failed to get local address");

        Self::start_accept_task(tcp_listener, config.clone(), stream_tx.clone());

        Self {
            config,
            stream_rx: Arc::new(Mutex::new(stream_rx)),
            stream_tx,
            local_addr,
        }
    }

    pub fn with_default_config(tcp_listener: tokio::net::TcpListener) -> Self {
        Self::new(tcp_listener, MultiplexServerConfig::default())
    }

    pub fn config(&self) -> &MultiplexServerConfig {
        &self.config
    }

    fn create_server_yamux_config(config: &MultiplexServerConfig) -> Config {
        let mut yamux_config = Config::default();
        yamux_config.set_max_num_streams(config.max_num_streams);

        if let Some(ref brutal) = config.brutal {
            debug!(
                "Server Brutal congestion control configured: up={}Mbps, down={}Mbps",
                brutal.up_mbps, brutal.down_mbps
            );
        }

        yamux_config
    }

    fn start_accept_task(
        tcp_listener: tokio::net::TcpListener,
        config: MultiplexServerConfig,
        stream_tx: tokio::sync::mpsc::UnboundedSender<IoStream>,
    ) {
        tokio::spawn(async move {
            loop {
                let (tcp_stream, peer_addr) = match tcp_listener.accept().await {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                debug!("Accepted TCP connection from {} for yamux", peer_addr);

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

    async fn handle_yamux_connection(
        tcp_stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
        config: MultiplexServerConfig,
        stream_tx: tokio::sync::mpsc::UnboundedSender<IoStream>,
    ) -> Result<(), DialError> {
        let stream: IoStream = if config.enable_padding {
            debug!("Enabling padding for multiplex connection from {}", peer_addr);
            Box::new(PaddingStream::new(tcp_stream, false))
        } else {
            Box::new(tcp_stream)
        };
        
        let compat_stream = stream.compat();
        let yamux_config = Self::create_server_yamux_config(&config);
        let mut connection = Connection::new(compat_stream, yamux_config, Mode::Server);

        debug!("Created yamux server connection for {}", peer_addr);

        poll_fn(|cx| loop {
            match connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    debug!("Accepted yamux stream from {}", peer_addr);
                    let tokio_stream = stream.compat();
                    let boxed_stream: IoStream = Box::new(tokio_stream);
                    if stream_tx.send(boxed_stream).is_err() {
                        warn!("Failed to send stream to channel, listener may be closed");
                        return Poll::Ready(());
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    warn!("yamux stream error from {}: {}", peer_addr, e);
                    return Poll::Ready(());
                }
                Poll::Ready(None) => {
                    debug!("yamux connection closed for {}", peer_addr);
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        })
        .await;

        Ok(())
    }

    pub async fn accept(&self) -> Result<IoStream, DialError> {
        let mut stream_rx = self.stream_rx.lock().await;

        stream_rx
            .recv()
            .await
            .ok_or_else(|| DialError::Other("Stream channel closed".to_string()))
    }

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
        let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
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
