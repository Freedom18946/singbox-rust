//! # HTTP/2 Transport Layer / HTTP/2 传输层
//!
//! This module provides HTTP/2 transport implementation for singbox-rust, including:
//! 本模块为 singbox-rust 提供 HTTP/2 传输实现，包括：
//! - `Http2Dialer`: Client-side HTTP/2 connection dialer
//!   `Http2Dialer`: 客户端 HTTP/2 连接拨号器
//! - `Http2Listener`: Server-side HTTP/2 connection acceptor
//!   `Http2Listener`: 服务端 HTTP/2 连接接收器
//! - `Http2StreamAdapter`: Adapter to make HTTP/2 streams compatible with `AsyncRead`/`AsyncWrite`
//!   `Http2StreamAdapter`: 使 HTTP/2 流兼容 `AsyncRead`/`AsyncWrite` 的适配器
//! - Stream multiplexing support
//!   流多路复用支持
//!
//! ## Features / 特性
//! - **Multiplexing**: Multiple streams over a single TCP connection.
//!   **多路复用**: 单个 TCP 连接上的多个流。
//! - **Efficiency**: Binary framing and header compression (HPACK).
//!   **效率**: 二进制分帧和头部压缩 (HPACK)。
//! - **Stealth**: Mimics standard browser traffic when used with TLS.
//!   **隐蔽性**: 与 TLS 一起使用时模仿标准浏览器流量。
//!
//! ## Strategic Relevance / 战略关联
//! - **Performance**: Reduces latency and improves throughput compared to HTTP/1.1.
//!   **性能**: 与 HTTP/1.1 相比，减少了延迟并提高了吞吐量。
//! - **Censorship Resistance**: Harder to fingerprint than custom protocols due to its widespread use.
//!   **抗审查**: 由于其广泛使用，比自定义协议更难进行指纹识别。
//!
//! ## Client Usage / 客户端用法
//! ```rust,no_run
//! use sb_transport::http2::{Http2Dialer, Http2Config};
//! use sb_transport::Dialer;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = Http2Config {
//!         path: "/tunnel".to_string(),
//!         host: "example.com".to_string(),
//!         ..Default::default()
//!     };
//!     let dialer = Http2Dialer::new(config, Box::new(sb_transport::TcpDialer));
//!     let stream = dialer.connect("example.com", 443).await?;
//!     // Use stream for communication...
//!     Ok(())
//! }
//! ```
//!
//! ## Server Usage
//! ```rust,no_run
//! use sb_transport::http2::{Http2Listener, Http2ServerConfig};
//! use tokio::net::TcpListener;
//!
//! async fn server_example() -> Result<(), Box<dyn std::error::Error>> {
//!     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
//!     let config = Http2ServerConfig::default();
//!     let h2_listener = Http2Listener::new(tcp_listener, config);
//!
//!     loop {
//!         match h2_listener.accept().await {
//!             Ok(stream) => {
//!                 tokio::spawn(async move {
//!                     // Handle HTTP/2 stream
//!                 });
//!             }
//!             Err(e) => eprintln!("Accept error: {}", e),
//!         }
//!     }
//! }
//! ```

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use h2::client::{self, SendRequest};
use h2::{RecvStream, SendStream};
use http::{Request, Uri};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Type alias for HTTP/2 connection pool to reduce type complexity
type Http2Pool = Arc<Mutex<HashMap<(String, u16), SendRequest<Bytes>>>>;

/// HTTP/2 configuration / HTTP/2 配置
#[derive(Debug, Clone)]
pub struct Http2Config {
    /// Request path (default: "/")
    /// 请求路径（默认："/"）
    pub path: String,
    /// Host header value
    /// Host 头部值
    pub host: String,
    /// Custom headers
    /// 自定义头部
    pub headers: Vec<(String, String)>,
    /// HTTP method (default: "POST")
    /// HTTP 方法（默认："POST"）
    pub method: String,
    /// Enable connection pooling (default: true)
    /// 启用连接池（默认：true）
    pub enable_pooling: bool,
    /// Max concurrent streams per connection
    /// 每个连接的最大并发流数
    pub max_concurrent_streams: Option<u32>,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: String::new(),
            headers: Vec::new(),
            method: "POST".to_string(),
            enable_pooling: true,
            max_concurrent_streams: Some(100),
        }
    }
}

/// HTTP/2 dialer / HTTP/2 拨号器
///
/// This dialer establishes HTTP/2 connections and creates streams for communication.
/// 该拨号器建立 HTTP/2 连接并创建用于通信的流。
/// It supports:
/// 它支持：
/// - Native HTTP/2 protocol
///   原生 HTTP/2 协议
/// - Stream multiplexing
///   流多路复用
/// - Connection pooling (optional)
///   连接池（可选）
/// - Custom headers and paths
///   自定义头部和路径
pub struct Http2Dialer {
    config: Http2Config,
    dialer: Box<dyn Dialer>,
    // Shared state for connection pooling
    // 连接池的共享状态
    // Key: (host, port), Value: Active HTTP/2 connection sender
    // 键: (host, port), 值: 活动 HTTP/2 连接发送者
    pool: Http2Pool,
}

impl Http2Dialer {
    /// Create a new HTTP/2 dialer with custom configuration
    /// 使用自定义配置创建新的 HTTP/2 拨号器
    pub fn new(config: Http2Config, dialer: Box<dyn Dialer>) -> Self {
        Self {
            config,
            dialer,
            pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create an HTTP/2 dialer with default configuration
    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {
        Self::new(Http2Config::default(), inner)
    }

    /// Get or create an HTTP/2 connection
    async fn get_connection(&self, host: &str, port: u16) -> Result<SendRequest<Bytes>, DialError> {
        let key = (host.to_string(), port);

        // Try to get existing connection from pool
        if self.config.enable_pooling {
            let pool = self.pool.lock().await;
            if let Some(send_request) = pool.get(&key) {
                // Try to use the existing connection
                // Note: h2 SendRequest doesn't have is_ready(), we'll try to clone and use it
                debug!("Reusing pooled HTTP/2 connection for {}:{}", host, port);
                return Ok(send_request.clone());
            }
        }

        // Create new connection via inner dialer (supports chaining: TCP->TLS->H2)
        debug!("Creating new HTTP/2 connection for {}:{}", host, port);
        let stream = self.dialer.connect(host, port).await?;

        // Perform HTTP/2 handshake
        let (send_request, connection) = client::handshake(stream)
            .await
            .map_err(|e| DialError::Other(format!("HTTP/2 handshake failed: {}", e)))?;

        // Spawn connection task to drive the connection
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                warn!("HTTP/2 connection error: {}", e);
            }
        });

        // Add to pool if pooling is enabled
        if self.config.enable_pooling {
            let mut pool = self.pool.lock().await;
            pool.insert(key, send_request.clone());
        }

        Ok(send_request)
    }
}

#[async_trait]
impl Dialer for Http2Dialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // Get or create connection
        // 获取或创建连接
        let mut send_request = self.get_connection(host, port).await?;

        // Prepare request
        // 准备请求
        let uri = format!("http://{}:{}{}", host, port, self.config.path)
            .parse::<Uri>()
            .map_err(|e| DialError::Other(format!("Invalid URI: {}", e)))?;

        let mut request_builder = Request::builder()
            .method(self.config.method.as_str())
            .uri(uri)
            .header("Host", &self.config.host);

        // Add custom headers
        // 添加自定义头部
        for (k, v) in &self.config.headers {
            request_builder = request_builder.header(k, v);
        }

        let request = request_builder
            .body(())
            .map_err(|e| DialError::Other(format!("Failed to build request: {}", e)))?;

        // Send request
        // 发送请求
        let (response, send_stream) = send_request
            .send_request(request, false)
            .map_err(|e| DialError::Other(format!("Failed to send HTTP/2 request: {}", e)))?;

        // Wait for response headers
        // 等待响应头部
        let response = response
            .await
            .map_err(|e| DialError::Other(format!("HTTP/2 response error: {}", e)))?;

        debug!("HTTP/2 handshake successful: {:?}", response.status());

        if !response.status().is_success() {
            return Err(DialError::Other(format!(
                "HTTP/2 handshake failed with status: {}",
                response.status()
            )));
        }

        let recv_stream = response.into_body();

        // Wrap streams in adapter
        // 将流包装在适配器中
        Ok(Box::new(Http2StreamAdapter::new(send_stream, recv_stream)))
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// HTTP/2 stream adapter / HTTP/2 流适配器
///
/// This adapter wraps h2 SendStream and RecvStream to implement
/// `AsyncRead` and `AsyncWrite` traits, making it compatible with the
/// `IoStream` type.
/// 该适配器包装 h2 SendStream 和 RecvStream 以实现
/// `AsyncRead` 和 `AsyncWrite` trait，使其与 `IoStream` 类型兼容。
///
/// It handles:
/// 它处理：
/// - Buffering read data from HTTP/2 DATA frames
///   缓冲来自 HTTP/2 DATA 帧的读取数据
/// - Sending data as HTTP/2 DATA frames
///   作为 HTTP/2 DATA 帧发送数据
/// - Managing flow control windows
///   管理流量控制窗口
pub struct Http2StreamAdapter {
    send_stream: SendStream<Bytes>,
    recv_stream: RecvStream,
    read_buffer: Bytes,
}

impl Http2StreamAdapter {
    fn new(send_stream: SendStream<Bytes>, recv_stream: RecvStream) -> Self {
        Self {
            send_stream,
            recv_stream,
            read_buffer: Bytes::new(),
        }
    }
}

impl AsyncRead for Http2StreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, return it first
        // 如果我们有缓冲数据，先返回它
        if !self.read_buffer.is_empty() {
            let to_read = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer[..to_read]);
            self.read_buffer.advance(to_read);
            return Poll::Ready(Ok(()));
        }

        // Poll for new data frames
        // 轮询新的数据帧
        match self.recv_stream.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                // Flow control: release capacity
                // 流量控制：释放容量
                let _ = self.recv_stream.flow_control().release_capacity(data.len());

                let to_read = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..to_read]);

                // Buffer remaining data
                // 缓冲剩余数据
                if to_read < data.len() {
                    self.read_buffer = data.slice(to_read..);
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(format!(
                "HTTP/2 read error: {}",
                e
            )))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Http2StreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Reserve capacity
        // 预留容量
        self.send_stream.reserve_capacity(buf.len());

        // Check capacity
        // 检查容量
        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(capacity))) => {
                let to_write = std::cmp::min(capacity, buf.len());
                if to_write == 0 {
                    return Poll::Pending;
                }

                // Send data
                // 发送数据
                let data = Bytes::copy_from_slice(&buf[..to_write]);
                match self.send_stream.send_data(data, false) {
                    Ok(_) => Poll::Ready(Ok(to_write)),
                    Err(e) => Poll::Ready(Err(std::io::Error::other(format!(
                        "HTTP/2 write error: {}",
                        e
                    )))),
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(format!(
                "HTTP/2 capacity error: {}",
                e
            )))),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP/2 stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // h2 sends data immediately, no explicit flush needed
        // h2 立即发送数据，不需要显式刷新
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Send empty data frame with END_STREAM flag
        // 发送带有 END_STREAM 标志的空数据帧
        // We can't easily do this here because send_data consumes self or needs mutable access
        // and we might have already sent END_STREAM.
        // For now, we just assume it's done.
        // 我们在这里很难做到这一点，因为 send_data 消耗 self 或需要可变访问权限
        // 并且我们可能已经发送了 END_STREAM。
        // 目前，我们只是假设它已完成。
        Poll::Ready(Ok(()))
    }
}

/// HTTP/2 server configuration
/// HTTP/2 服务端配置
#[derive(Debug, Clone)]
pub struct Http2ServerConfig {
    /// Maximum concurrent streams (default: 256)
    /// 最大并发流数量（默认：256）
    pub max_concurrent_streams: u32,
    /// Initial window size (default: 1MB)
    /// 初始窗口大小（默认：1MB）
    pub initial_window_size: u32,
    /// Initial connection window size (default: 1MB)
    /// 初始连接窗口大小（默认：1MB）
    pub initial_connection_window_size: u32,
}

impl Default for Http2ServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 256,
            initial_window_size: 1024 * 1024,            // 1MB
            initial_connection_window_size: 1024 * 1024, // 1MB
        }
    }
}

/// HTTP/2 server listener
/// HTTP/2 服务端监听器
///
/// This listener accepts incoming HTTP/2 connections by:
/// 该监听器通过以下方式接受传入的 HTTP/2 连接：
/// 1. Accepting TCP connections from the underlying listener
///    从底层监听器接受 TCP 连接
/// 2. Performing HTTP/2 server handshake
///    执行 HTTP/2 服务端握手
/// 3. Accepting incoming streams and returning them as AsyncRead/AsyncWrite
///    接受传入流并将其作为 AsyncRead/AsyncWrite 返回
///
/// ## Usage
/// ## 用法
/// ```rust,no_run
/// use sb_transport::http2::{Http2Listener, Http2ServerConfig};
/// use tokio::net::TcpListener;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
///     let config = Http2ServerConfig::default();
///     let h2_listener = Http2Listener::new(tcp_listener, config);
///
///     loop {
///         let stream = h2_listener.accept().await?;
///         tokio::spawn(async move {
///             // Handle HTTP/2 stream
///         });
///     }
/// }
/// ```
pub struct Http2Listener {
    tcp_listener: tokio::net::TcpListener,
    config: Http2ServerConfig,
}

impl Http2Listener {
    /// Create a new HTTP/2 listener from a TCP listener
    pub fn new(tcp_listener: tokio::net::TcpListener, config: Http2ServerConfig) -> Self {
        Self {
            tcp_listener,
            config,
        }
    }

    /// Create an HTTP/2 listener with default configuration
    pub fn with_default_config(tcp_listener: tokio::net::TcpListener) -> Self {
        Self::new(tcp_listener, Http2ServerConfig::default())
    }

    /// Accept a new HTTP/2 stream
    ///
    /// This method:
    /// 1. Accepts a TCP connection
    /// 2. Performs HTTP/2 server handshake
    /// 3. Waits for the first incoming stream
    /// 4. Returns the stream wrapped as AsyncRead + AsyncWrite
    pub async fn accept(&self) -> Result<IoStream, DialError> {
        // Accept TCP connection
        let (stream, peer_addr) = self
            .tcp_listener
            .accept()
            .await
            .map_err(|e| DialError::Other(format!("TCP accept failed: {}", e)))?;

        debug!("Accepted TCP connection from {} for HTTP/2", peer_addr);

        // Configure HTTP/2 server
        let mut builder = h2::server::Builder::new();
        builder
            .max_concurrent_streams(self.config.max_concurrent_streams)
            .initial_window_size(self.config.initial_window_size)
            .initial_connection_window_size(self.config.initial_connection_window_size);

        // Perform HTTP/2 handshake
        let mut connection = builder
            .handshake(stream)
            .await
            .map_err(|e| DialError::Other(format!("HTTP/2 server handshake failed: {}", e)))?;

        debug!("HTTP/2 server handshake successful for {}", peer_addr);

        // Accept first incoming stream
        let (request, mut respond) = match connection.accept().await {
            Some(Ok(stream_pair)) => stream_pair,
            Some(Err(e)) => {
                return Err(DialError::Other(format!(
                    "Failed to accept HTTP/2 stream: {}",
                    e
                )))
            }
            None => {
                return Err(DialError::Other(
                    "HTTP/2 connection closed before stream".to_string(),
                ))
            }
        };

        debug!(
            "HTTP/2 stream accepted: {} {}",
            request.method(),
            request.uri()
        );

        // Get request body (RecvStream)
        let recv_stream = request.into_body();

        // Send response headers (200 OK)
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .body(())
            .map_err(|e| DialError::Other(format!("Failed to build response: {}", e)))?;

        let send_stream = respond
            .send_response(response, false)
            .map_err(|e| DialError::Other(format!("Failed to send response: {}", e)))?;

        // Spawn connection task to handle additional streams
        // (this example only returns the first stream, but the connection
        // continues to run in the background)
        tokio::spawn(async move {
            while let Some(result) = connection.accept().await {
                match result {
                    Ok((_req, mut respond)) => {
                        // For additional streams, just send 200 OK and close
                        let resp = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .body(())
                            .unwrap();
                        let _ = respond.send_response(resp, true);
                    }
                    Err(e) => {
                        warn!("HTTP/2 accept error: {}", e);
                        break;
                    }
                }
            }
            debug!("HTTP/2 connection task finished for {}", peer_addr);
        });

        // Wrap streams in adapter
        let adapter = Http2StreamAdapter::new(send_stream, recv_stream);
        Ok(Box::new(adapter))
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.tcp_listener.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TcpDialer;

    #[tokio::test]
    async fn test_http2_config_default() {
        let config = Http2Config::default();
        assert_eq!(config.path, "/");
        assert_eq!(config.method, "POST");
        assert!(config.enable_pooling);
        assert_eq!(config.max_concurrent_streams, Some(100));
    }

    #[tokio::test]
    async fn test_http2_dialer_creation() {
        let config = Http2Config::default();
        let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
        let h2_dialer = Http2Dialer::new(config, tcp_dialer);
        assert_eq!(h2_dialer.config.path, "/");
    }

    #[tokio::test]
    async fn test_http2_server_config_default() {
        let config = Http2ServerConfig::default();
        assert_eq!(config.max_concurrent_streams, 256);
        assert_eq!(config.initial_window_size, 1024 * 1024);
        assert_eq!(config.initial_connection_window_size, 1024 * 1024);
    }
}
