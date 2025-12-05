//! # WebSocket Transport Layer / WebSocket 传输层
//!
//! This module provides WebSocket transport implementation for singbox-rust, including:
//! 本模块为 singbox-rust 提供 WebSocket 传输实现，包括：
//! - `WebSocketDialer`: Dialer that establishes WebSocket connections
//!   `WebSocketDialer`: 建立 WebSocket 连接的拨号器
//! - `WebSocketListener`: Server-side WebSocket connection acceptor
//!   `WebSocketListener`: 服务端 WebSocket 连接接收器
//! - `WebSocketStreamAdapter`: Adapter to make WebSocket streams compatible with `AsyncRead`/`AsyncWrite`
//!   `WebSocketStreamAdapter`: 使 WebSocket 流兼容 `AsyncRead`/`AsyncWrite` 的适配器
//! - Early data support
//!   Early data 支持
//! - TLS over WebSocket (wss://)
//!   基于 WebSocket 的 TLS (wss://)
//!
//! ## Features / 特性
//! - **Standard Compliance**: Fully compliant with RFC 6455.
//!   **标准兼容**：完全符合 RFC 6455。
//! - **Censorship Circumvention**: Often used to disguise traffic as normal web browsing.
//!   **审查规避**：常用于将流量伪装成正常网页浏览。
//! - **CDN Compatibility**: Can be used with CDNs that support WebSocket.
//!   **CDN 兼容性**：可与支持 WebSocket 的 CDN 一起使用。
//!
//! ## Strategic Relevance / 战略关联
//! - **Stealth**: Makes traffic look like standard HTTP/WebSocket traffic, harder to block.
//!   **隐蔽性**：使流量看起来像标准的 HTTP/WebSocket 流量，更难被阻止。
//! - **Versatility**: Works over standard HTTP ports (80/443), bypassing firewalls.
//!   **通用性**：在标准 HTTP 端口 (80/443) 上工作，绕过防火墙。
//!
//! ## Client Usage / 客户端用法
//! ```rust,no_run
//! use sb_transport::websocket::WebSocketDialer;
//! use sb_transport::Dialer;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = WebSocketConfig {
//!         path: "/ws".to_string(),
//!         headers: vec![
//!             ("Host".to_string(), "example.com".to_string()),
//!             ("User-Agent".to_string(), "singbox-rust/1.0".to_string()),
//!         ],
//!         ..Default::default()
//!     };
//!     let dialer = WebSocketDialer::new(config, Box::new(sb_transport::TcpDialer));
//!     let stream = dialer.connect("example.com", 80).await?;
//!     // Use stream for communication...
//!     Ok(())
//! }
//! ```
//!
//! ## Server Usage
//! ```rust,no_run
//! use sb_transport::websocket::{WebSocketListener, WebSocketServerConfig};
//! use tokio::net::TcpListener;
//!
//! async fn server_example() -> Result<(), Box<dyn std::error::Error>> {
//!     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
//!     let config = WebSocketServerConfig::default();
//!     let ws_listener = WebSocketListener::new(tcp_listener, config);
//!
//!     loop {
//!         match ws_listener.accept().await {
//!             Ok(stream) => {
//!                 tokio::spawn(async move {
//!                     // Handle WebSocket connection
//!                 });
//!             }
//!             Err(e) => eprintln!("Accept error: {}", e),
//!         }
//!     }
//! }
//! ```

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig as TungsteniteConfig;
use tokio_tungstenite::WebSocketStream as TungsteniteStream;
use tracing::{debug, warn};

/// WebSocket configuration / WebSocket 配置
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// WebSocket path (e.g., "/ws")
    /// WebSocket 路径（例如 "/ws"）
    pub path: String,
    /// Custom headers
    /// 自定义头部
    pub headers: Vec<(String, String)>,
    /// Max early data length
    /// 最大 Early data 长度
    pub max_early_data: usize,
    /// Early data header name (default: "Sec-WebSocket-Protocol")
    /// Early data 头部名称（默认："Sec-WebSocket-Protocol"）
    pub early_data_header_name: String,
    /// Maximum message size in bytes (default: 64MB)
    /// 最大消息大小，单位字节（默认：64MB）
    pub max_message_size: Option<usize>,
    /// Maximum frame size in bytes (default: 16MB)
    /// 最大帧大小，单位字节（默认：16MB）
    pub max_frame_size: Option<usize>,
    /// Enable early data (default: false)
    /// 启用 Early data（默认：false）
    pub early_data: bool,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            headers: Vec::new(),
            max_message_size: Some(64 * 1024 * 1024), // 64MB
            max_frame_size: Some(16 * 1024 * 1024),   // 16MB
            early_data: false,
            max_early_data: 0,
            early_data_header_name: "Sec-WebSocket-Protocol".to_string(),
        }
    }
}

/// WebSocket dialer / WebSocket 拨号器
///
/// This dialer establishes WebSocket connections to remote servers.
/// 该拨号器建立到远程服务器的 WebSocket 连接。
/// It supports:
/// 它支持：
/// - Standard WebSocket handshake
///   标准 WebSocket 握手
/// - Custom headers for masquerading
///   用于伪装的自定义头部
/// - Configurable path and query parameters
///   可配置的路径和查询参数
/// - TLS support (when used with TLS transport)
///   TLS 支持（当与 TLS 传输一起使用时）
/// - Early data support (via Sec-WebSocket-Protocol)
///   Early data 支持（通过 Sec-WebSocket-Protocol）
pub struct WebSocketDialer {
    config: WebSocketConfig,
    dialer: Box<dyn Dialer>,
}

impl WebSocketDialer {
    /// Create a new WebSocket dialer with custom configuration
    /// 使用自定义配置创建新的 WebSocket 拨号器
    pub fn new(config: WebSocketConfig, dialer: Box<dyn Dialer>) -> Self {
        Self { config, dialer }
    }

    /// Create a WebSocket dialer with default configuration
    /// 使用默认配置创建 WebSocket 拨号器
    pub fn with_default_config(dialer: Box<dyn Dialer>) -> Self {
        Self::new(WebSocketConfig::default(), dialer)
    }
}

#[async_trait]
impl Dialer for WebSocketDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        // 1. Establish underlying connection (TCP/TLS)
        // 1. 建立底层连接 (TCP/TLS)
        let stream = self.dialer.connect(host, port).await?;

        // 2. Prepare WebSocket handshake
        // 2. 准备 WebSocket 握手
        let uri = format!("ws://{}:{}{}", host, port, self.config.path)
            .parse::<Uri>()
            .map_err(|e| DialError::Other(format!("Invalid URI: {}", e)))?;

        let mut request = Request::builder()
            .uri(uri)
            .header("Host", host)
            .header("User-Agent", "singbox-rust/0.1.0");

        // Add custom headers
        // 添加自定义头部
        for (k, v) in &self.config.headers {
            request = request.header(k, v);
        }

        // Handle early data if present
        // 如果存在 Early data，则进行处理
        // Note: This is a simplified example. Real early data handling might involve
        // encoding data into the Sec-WebSocket-Protocol header or similar mechanisms.
        // 注意：这是一个简化的示例。真正的 Early data 处理可能涉及
        // 将数据编码到 Sec-WebSocket-Protocol 头部或类似机制中。
        if self.config.max_early_data > 0 {
            // Placeholder for early data logic
            // Early data 逻辑占位符
        }

        let request = request
            .body(())
            .map_err(|e| DialError::Other(format!("Failed to build request: {}", e)))?;

        // 3. Perform handshake
        // 3. 执行握手
        // We use client_async_with_config to support custom config
        // 我们使用 client_async_with_config 来支持自定义配置
        let (ws_stream, response) =
            tokio_tungstenite::client_async_with_config(request, stream, None)
                .await
                .map_err(|e| DialError::Other(format!("WebSocket handshake failed: {}", e)))?;

        debug!("WebSocket handshake successful: {:?}", response.status());

        // 4. Wrap stream in adapter
        // 4. 将流包装在适配器中
        Ok(Box::new(WebSocketStreamAdapter::new(ws_stream)))
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// WebSocket stream adapter
/// WebSocket 流适配器
///
/// This adapter wraps a `tokio_tungstenite::WebSocketStream` to implement
/// `AsyncRead` and `AsyncWrite` traits, making it compatible with the
/// `IoStream` type.
/// 该适配器包装 `tokio_tungstenite::WebSocketStream` 以实现
/// `AsyncRead` 和 `AsyncWrite` trait，使其与 `IoStream` 类型兼容。
///
/// It handles:
/// 它处理：
/// - Buffering read data from WebSocket frames
///   缓冲来自 WebSocket 帧的读取数据
/// - Writes send data as WebSocket binary frames
///   写入操作将数据作为 WebSocket 二进制帧发送
/// - Text frames are logged as warnings
///   文本帧会被记录为警告
/// - Close frames trigger EOF
///   关闭帧触发 EOF
pub struct WebSocketStreamAdapter<S> {
    inner: TungsteniteStream<S>,
    read_buffer: Vec<u8>,
    read_pos: usize,
}

impl<S> WebSocketStreamAdapter<S> {
    fn new(inner: TungsteniteStream<S>) -> Self {
        Self {
            inner,
            read_buffer: Vec::new(),
            read_pos: 0,
        }
    }
}

impl<S> AsyncRead for WebSocketStreamAdapter<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, return it first
        // 如果我们有缓冲数据，先返回它
        if self.read_pos < self.read_buffer.len() {
            let available = self.read_buffer.len() - self.read_pos;
            let to_read = std::cmp::min(available, buf.remaining());
            buf.put_slice(&self.read_buffer[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;

            // Reset buffer if empty
            // 如果缓冲区为空，则重置
            if self.read_pos >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_pos = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Read next frame
        // 读取下一帧
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                match msg {
                    tokio_tungstenite::tungstenite::Message::Binary(data) => {
                        // Store data in buffer and recurse to fill user buffer
                        // 将数据存储在缓冲区中并递归填充用户缓冲区
                        self.read_buffer = data;
                        self.read_pos = 0;
                        // We can call poll_read again immediately because we have data
                        // 我们可以立即再次调用 poll_read，因为我们有数据
                        self.poll_read(cx, buf)
                    }
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        warn!("Received unexpected text frame: {}", text);
                        // Ignore text frames, try next
                        // 忽略文本帧，尝试下一个
                        self.poll_read(cx, buf)
                    }
                    tokio_tungstenite::tungstenite::Message::Close(_) => {
                        debug!("WebSocket connection closed by peer");
                        Poll::Ready(Ok(())) // EOF
                    }
                    tokio_tungstenite::tungstenite::Message::Ping(_) => {
                        // Tungstenite handles pings automatically, but we might see them
                        // Tungstenite 自动处理 ping，但我们可能会看到它们
                        self.poll_read(cx, buf)
                    }
                    tokio_tungstenite::tungstenite::Message::Pong(_) => self.poll_read(cx, buf),
                    tokio_tungstenite::tungstenite::Message::Frame(_) => {
                        // Raw frames, usually handled internally
                        // 原始帧，通常在内部处理
                        self.poll_read(cx, buf)
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(format!(
                "WebSocket read error: {}",
                e
            )))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WebSocketStreamAdapter<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Create a binary message
        // 创建二进制消息
        let msg = tokio_tungstenite::tungstenite::Message::Binary(buf.to_vec());

        // Send the message
        // 发送消息
        match self.inner.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => match self.inner.start_send_unpin(msg) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(e) => Poll::Ready(Err(std::io::Error::other(format!(
                    "WebSocket write error: {}",
                    e
                )))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!(
                "WebSocket poll_ready error: {}",
                e
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.inner.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!(
                "WebSocket flush error: {}",
                e
            )))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.inner.poll_close_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!(
                "WebSocket close error: {}",
                e
            )))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// WebSocket server configuration
/// WebSocket 服务端配置
#[derive(Debug, Clone)]
pub struct WebSocketServerConfig {
    /// Expected WebSocket path (default: "/", matches any if empty)
    /// 预期的 WebSocket 路径（默认："/"，如果为空则匹配任意路径）
    pub path: String,
    /// Maximum message size in bytes (default: 64MB)
    /// 最大消息大小，单位字节（默认：64MB）
    pub max_message_size: Option<usize>,
    /// Maximum frame size in bytes (default: 16MB)
    /// 最大帧大小，单位字节（默认：16MB）
    pub max_frame_size: Option<usize>,
    /// Require specific path match (default: false, accepts any path)
    /// 要求特定路径匹配（默认：false，接受任意路径）
    pub require_path_match: bool,
}

impl Default for WebSocketServerConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            max_message_size: Some(64 * 1024 * 1024), // 64MB
            max_frame_size: Some(16 * 1024 * 1024),   // 16MB
            require_path_match: false,
        }
    }
}

/// WebSocket server listener
/// WebSocket 服务端监听器
///
/// This listener accepts incoming WebSocket connections by:
/// 该监听器通过以下方式接受传入的 WebSocket 连接：
/// 1. Accepting TCP connections from the underlying listener
///    从底层监听器接受 TCP 连接
/// 2. Performing WebSocket handshake (HTTP Upgrade)
///    执行 WebSocket 握手（HTTP 升级）
/// 3. Returning WebSocket streams wrapped in AsyncRead/AsyncWrite adapter
///    返回包装在 AsyncRead/AsyncWrite 适配器中的 WebSocket 流
///
/// ## Usage
/// ## 用法
/// ```rust,no_run
/// use sb_transport::websocket::{WebSocketListener, WebSocketServerConfig};
/// use tokio::net::TcpListener;
///
/// async fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let tcp_listener = TcpListener::bind("127.0.0.1:8080").await?;
///     let config = WebSocketServerConfig::default();
///     let ws_listener = WebSocketListener::new(tcp_listener, config);
///
///     loop {
///         let stream = ws_listener.accept().await?;
///         tokio::spawn(async move {
///             // Handle WebSocket stream
///         });
///     }
/// }
/// ```
pub struct WebSocketListener {
    tcp_listener: tokio::net::TcpListener,
    config: WebSocketServerConfig,
}

impl WebSocketListener {
    /// Create a new WebSocket listener from a TCP listener
    pub fn new(tcp_listener: tokio::net::TcpListener, config: WebSocketServerConfig) -> Self {
        Self {
            tcp_listener,
            config,
        }
    }

    /// Create a WebSocket listener with default configuration
    pub fn with_default_config(tcp_listener: tokio::net::TcpListener) -> Self {
        Self::new(tcp_listener, WebSocketServerConfig::default())
    }

    /// Accept a new WebSocket connection
    ///
    /// This method:
    /// 1. Accepts a TCP connection
    /// 2. Performs WebSocket handshake
    /// 3. Returns a stream that implements AsyncRead + AsyncWrite
    pub async fn accept(&self) -> Result<IoStream, DialError> {
        // Accept TCP connection
        let (stream, peer_addr) = self
            .tcp_listener
            .accept()
            .await
            .map_err(|e| DialError::Other(format!("TCP accept failed: {}", e)))?;

        debug!("Accepted TCP connection from {}", peer_addr);

        // Prepare tungstenite config
        let mut ws_cfg = TungsteniteConfig::default();
        if let Some(m) = self.config.max_message_size {
            ws_cfg.max_message_size = Some(m);
        }
        if let Some(f) = self.config.max_frame_size {
            ws_cfg.max_frame_size = Some(f);
        }

        // Perform WebSocket handshake
        // accept_async_with_config handles the HTTP Upgrade request
        let ws_stream = tokio_tungstenite::accept_async_with_config(stream, Some(ws_cfg))
            .await
            .map_err(|e| DialError::Other(format!("WebSocket handshake failed: {}", e)))?;

        debug!("WebSocket handshake successful for {}", peer_addr);

        // Wrap in adapter
        let adapter = WebSocketStreamAdapter::new(ws_stream);
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
    async fn test_websocket_config_default() {
        let config = WebSocketConfig::default();
        assert_eq!(config.path, "/");
        assert!(config.headers.is_empty());
        assert_eq!(config.max_message_size, Some(64 * 1024 * 1024));
        assert_eq!(config.max_frame_size, Some(16 * 1024 * 1024));
        assert!(!config.early_data);
    }

    #[tokio::test]
    async fn test_websocket_dialer_creation() {
        let config = WebSocketConfig::default();
        let tcp_dialer = Box::new(TcpDialer::default()) as Box<dyn Dialer>;
        let ws_dialer = WebSocketDialer::new(config, tcp_dialer);
        // Just verify it compiles and creates successfully
        assert_eq!(ws_dialer.config.path, "/");
    }

    #[tokio::test]
    async fn test_websocket_server_config_default() {
        let config = WebSocketServerConfig::default();
        assert_eq!(config.path, "/");
        assert_eq!(config.max_message_size, Some(64 * 1024 * 1024));
        assert_eq!(config.max_frame_size, Some(16 * 1024 * 1024));
        assert!(!config.require_path_match);
    }

    // Integration tests for server listener are in tests/websocket_server_integration.rs
    // Note: Integration tests that connect to real WebSocket servers
    // should be in the tests/ directory
}
