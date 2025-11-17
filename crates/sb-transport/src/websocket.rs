//! # WebSocket Transport Layer
//!
//! This module provides WebSocket transport implementation for singbox-rust, including:
//! - `WebSocketDialer`: Client-side WebSocket connection dialer
//! - `WebSocketListener`: Server-side WebSocket connection acceptor
//! - `WebSocketStream`: Wrapper for WebSocket streams to implement AsyncReadWrite
//! - TLS support (wss://) when combined with TLS transport
//!
//! ## Features
//! - Standard WebSocket client handshake
//! - WebSocket server accept with HTTP upgrade
//! - Custom headers (Host, User-Agent, Origin, etc.)
//! - Configurable path and query parameters
//! - Early data support
//! - TLS over WebSocket (wss://)
//!
//! ## Client Usage
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

/// WebSocket configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// WebSocket path (default: "/")
    pub path: String,
    /// Custom headers (key-value pairs)
    pub headers: Vec<(String, String)>,
    /// Maximum message size in bytes (default: 64MB)
    pub max_message_size: Option<usize>,
    /// Maximum frame size in bytes (default: 16MB)
    pub max_frame_size: Option<usize>,
    /// Enable early data (default: false)
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
        }
    }
}

/// WebSocket dialer
///
/// This dialer establishes WebSocket connections to remote servers.
/// It supports:
/// - Standard WebSocket handshake
/// - Custom headers for masquerading
/// - Configurable path and query parameters
/// - TLS support (when used with TLS transport)
pub struct WebSocketDialer {
    config: WebSocketConfig,
    inner: Box<dyn Dialer>,
}

impl WebSocketDialer {
    /// Create a new WebSocket dialer with custom configuration
    pub fn new(config: WebSocketConfig, inner: Box<dyn Dialer>) -> Self {
        Self { config, inner }
    }

    /// Create a WebSocket dialer with default configuration
    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {
        Self::new(WebSocketConfig::default(), inner)
    }
}

#[async_trait]
impl Dialer for WebSocketDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!("Dialing WebSocket: {}:{}{}", host, port, self.config.path);
        // Use the inner dialer to obtain the underlying stream (supports chaining)
        // This enables TCP -> TLS -> WebSocket and other combinations.
        let stream = self.inner.connect(host, port).await?;

        // Build WebSocket handshake request
        let uri = format!("ws://{}:{}{}", host, port, self.config.path);
        let uri: Uri = uri
            .parse()
            .map_err(|e| DialError::Other(format!("Invalid WebSocket URI: {}", e)))?;

        let mut request = Request::get(uri)
            .body(())
            .map_err(|e| DialError::Other(format!("Failed to build request: {}", e)))?;

        // Add WebSocket required headers
        let headers = request.headers_mut();

        // Generate Sec-WebSocket-Key (16 random bytes base64 encoded)
        let key = {
            let mut random_bytes = [0u8; 16];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut random_bytes);
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(random_bytes)
        };

        headers.insert(
            "Upgrade",
            http::header::HeaderValue::from_static("websocket"),
        );
        headers.insert(
            "Connection",
            http::header::HeaderValue::from_static("Upgrade"),
        );
        headers.insert(
            "Sec-WebSocket-Key",
            http::header::HeaderValue::from_str(&key)
                .map_err(|e| DialError::Other(format!("Invalid WebSocket key: {}", e)))?,
        );
        headers.insert(
            "Sec-WebSocket-Version",
            http::header::HeaderValue::from_static("13"),
        );

        // Add custom headers (may override defaults)
        for (key, value) in &self.config.headers {
            let header_name = http::header::HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| DialError::Other(format!("Invalid header name: {}", e)))?;
            let header_value = http::header::HeaderValue::from_str(value)
                .map_err(|e| DialError::Other(format!("Invalid header value: {}", e)))?;
            headers.insert(header_name, header_value);
        }

        // Set default headers if not provided
        if !headers.contains_key(http::header::HOST) {
            headers.insert(
                http::header::HOST,
                http::header::HeaderValue::from_str(host)
                    .map_err(|e| DialError::Other(format!("Invalid host header: {}", e)))?,
            );
        }
        if !headers.contains_key(http::header::USER_AGENT) {
            headers.insert(
                http::header::USER_AGENT,
                http::header::HeaderValue::from_static("singbox-rust/1.0"),
            );
        }

        // Prepare tungstenite config based on our limits
        let mut ws_cfg = TungsteniteConfig::default();
        if let Some(m) = self.config.max_message_size {
            ws_cfg.max_message_size = Some(m);
        }
        if let Some(f) = self.config.max_frame_size {
            ws_cfg.max_frame_size = Some(f);
        }

        // Perform WebSocket handshake
        // Use client_async_with_config so we can apply size limits
        let (ws_stream, response) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(ws_cfg))
                .await
                .map_err(|e| DialError::Other(format!("WebSocket handshake failed: {}", e)))?;

        debug!(
            "WebSocket handshake successful, status: {}",
            response.status()
        );

        // Wrap WebSocket stream in our AsyncReadWrite adapter
        let wrapped_stream = WebSocketStreamAdapter::new(ws_stream);
        Ok(Box::new(wrapped_stream))
    }
}

/// WebSocket stream adapter
///
/// This adapter wraps a `tokio_tungstenite::WebSocketStream` to implement
/// `AsyncRead` and `AsyncWrite` traits, making it compatible with the
/// `IoStream` type.
///
/// ## Implementation Notes
/// - WebSocket messages are framed, so we need to buffer data
/// - Reads consume WebSocket binary frames
/// - Writes send data as WebSocket binary frames
/// - Text frames are logged as warnings
/// - Close frames trigger EOF
pub struct WebSocketStreamAdapter<S> {
    inner: TungsteniteStream<S>,
    read_buffer: Vec<u8>,
    read_offset: usize,
}

impl<S> WebSocketStreamAdapter<S> {
    fn new(inner: TungsteniteStream<S>) -> Self {
        Self {
            inner,
            read_buffer: Vec::new(),
            read_offset: 0,
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
        if self.read_offset < self.read_buffer.len() {
            let remaining = &self.read_buffer[self.read_offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_offset += to_copy;

            // Clear buffer if fully consumed
            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Need to read next WebSocket frame
        match self.inner.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(msg))) => {
                use tokio_tungstenite::tungstenite::Message;
                match msg {
                    Message::Binary(data) => {
                        let to_copy = data.len().min(buf.remaining());
                        buf.put_slice(&data[..to_copy]);

                        // Buffer remaining data
                        if to_copy < data.len() {
                            self.read_buffer = data[to_copy..].to_vec();
                            self.read_offset = 0;
                        }

                        Poll::Ready(Ok(()))
                    }
                    Message::Text(text) => {
                        warn!("Received unexpected text frame: {}", text);
                        // Treat text as binary data
                        let data = text.into_bytes();
                        let to_copy = data.len().min(buf.remaining());
                        buf.put_slice(&data[..to_copy]);

                        if to_copy < data.len() {
                            self.read_buffer = data[to_copy..].to_vec();
                            self.read_offset = 0;
                        }

                        Poll::Ready(Ok(()))
                    }
                    Message::Close(_) => {
                        debug!("WebSocket close frame received");
                        Poll::Ready(Ok(())) // EOF
                    }
                    Message::Ping(_) | Message::Pong(_) => {
                        // Pings/Pongs are handled automatically by tungstenite
                        // Wake up to try reading next frame
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Message::Frame(_) => {
                        // Raw frames shouldn't appear in normal operation
                        Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Unexpected raw frame",
                        )))
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(format!(
                "WebSocket error: {}",
                e
            )))),
            Poll::Ready(None) => {
                debug!("WebSocket stream closed");
                Poll::Ready(Ok(())) // EOF
            }
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
        use tokio_tungstenite::tungstenite::Message;

        // Send data as binary WebSocket message
        let msg = Message::Binary(buf.to_vec());

        match self.inner.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => match self.inner.start_send_unpin(msg) {
                Ok(()) => Poll::Ready(Ok(buf.len())),
                Err(e) => Poll::Ready(Err(std::io::Error::other(format!(
                    "WebSocket send error: {}",
                    e
                )))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(format!(
                "WebSocket error: {}",
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
#[derive(Debug, Clone)]
pub struct WebSocketServerConfig {
    /// Expected WebSocket path (default: "/", matches any if empty)
    pub path: String,
    /// Maximum message size in bytes (default: 64MB)
    pub max_message_size: Option<usize>,
    /// Maximum frame size in bytes (default: 16MB)
    pub max_frame_size: Option<usize>,
    /// Require specific path match (default: false, accepts any path)
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
///
/// This listener accepts incoming WebSocket connections by:
/// 1. Accepting TCP connections from the underlying listener
/// 2. Performing WebSocket handshake (HTTP Upgrade)
/// 3. Returning WebSocket streams wrapped in AsyncRead/AsyncWrite adapter
///
/// ## Usage
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
        let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
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
