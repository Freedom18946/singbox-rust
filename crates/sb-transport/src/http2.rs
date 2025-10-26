//! # HTTP/2 Transport Layer
//!
//! This module provides HTTP/2 transport implementation for singbox-rust, including:
//! - `Http2Dialer`: Client-side HTTP/2 connection dialer
//! - `Http2Listener`: Server-side HTTP/2 connection acceptor
//! - `Http2Stream`: Wrapper for HTTP/2 streams to implement AsyncReadWrite
//! - Connection pooling and multiplexing support
//!
//! ## Features
//! - Native HTTP/2 transport using h2 crate
//! - Stream multiplexing over single TCP connection
//! - Connection pooling for performance (client-side)
//! - Flow control and window management
//! - TLS support when combined with TLS transport
//!
//! ## Client Usage
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
use http::{Method, Request, Uri};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// HTTP/2 configuration
#[derive(Debug, Clone)]
pub struct Http2Config {
    /// Request path (default: "/")
    pub path: String,
    /// Host header value
    pub host: String,
    /// Custom headers (key-value pairs)
    pub headers: Vec<(String, String)>,
    /// Request method (default: POST)
    pub method: String,
    /// Enable connection pooling (default: true)
    pub enable_pooling: bool,
    /// Maximum concurrent streams per connection (default: 100)
    pub max_concurrent_streams: usize,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: String::new(),
            headers: Vec::new(),
            method: "POST".to_string(),
            enable_pooling: true,
            max_concurrent_streams: 100,
        }
    }
}

/// HTTP/2 dialer
///
/// This dialer establishes HTTP/2 connections and creates streams for communication.
/// It supports:
/// - Native HTTP/2 protocol
/// - Stream multiplexing
/// - Connection pooling (optional)
/// - Custom headers and paths
pub struct Http2Dialer {
    config: Http2Config,
    inner: Box<dyn Dialer>,
    // Connection pool: host:port -> SendRequest
    pool: Arc<Mutex<std::collections::HashMap<String, SendRequest<Bytes>>>>,
}

impl Http2Dialer {
    /// Create a new HTTP/2 dialer with custom configuration
    pub fn new(config: Http2Config, inner: Box<dyn Dialer>) -> Self {
        Self {
            config,
            inner,
            pool: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Create an HTTP/2 dialer with default configuration
    pub fn with_default_config(inner: Box<dyn Dialer>) -> Self {
        Self::new(Http2Config::default(), inner)
    }

    /// Get or create an HTTP/2 connection
    async fn get_connection(&self, host: &str, port: u16) -> Result<SendRequest<Bytes>, DialError> {
        let key = format!("{}:{}", host, port);

        // Try to get existing connection from pool
        if self.config.enable_pooling {
            let pool = self.pool.lock().await;
            if let Some(send_request) = pool.get(&key) {
                // Try to use the existing connection
                // Note: h2 SendRequest doesn't have is_ready(), we'll try to clone and use it
                debug!("Reusing pooled HTTP/2 connection for {}", key);
                return Ok(send_request.clone());
            }
        }

        // Create new connection via inner dialer (supports chaining: TCP->TLS->H2)
        debug!("Creating new HTTP/2 connection for {}", key);
        let stream = self.inner.connect(host, port).await?;

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
        debug!("Dialing HTTP/2: {}:{}{}", host, port, self.config.path);

        // Get or create HTTP/2 connection
        let mut send_request = self.get_connection(host, port).await?;

        // Build HTTP/2 request
        let uri: Uri = format!("http://{}:{}{}", host, port, self.config.path)
            .parse()
            .map_err(|e| DialError::Other(format!("Invalid HTTP/2 URI: {}", e)))?;

        let method = self
            .config
            .method
            .parse::<Method>()
            .map_err(|e| DialError::Other(format!("Invalid HTTP method: {}", e)))?;

        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(http::Version::HTTP_2);

        // Add custom headers
        let headers = request
            .headers_mut()
            .ok_or_else(|| DialError::Other("Failed to get headers".to_string()))?;

        for (key, value) in &self.config.headers {
            let header_name = http::header::HeaderName::from_bytes(key.as_bytes())
                .map_err(|e| DialError::Other(format!("Invalid header name: {}", e)))?;
            let header_value = http::header::HeaderValue::from_str(value)
                .map_err(|e| DialError::Other(format!("Invalid header value: {}", e)))?;
            headers.insert(header_name, header_value);
        }

        // Set default headers if not provided
        if !headers.contains_key(http::header::HOST) {
            let host_value = if !self.config.host.is_empty() {
                &self.config.host
            } else {
                host
            };
            headers.insert(
                http::header::HOST,
                http::header::HeaderValue::from_str(host_value)
                    .map_err(|e| DialError::Other(format!("Invalid host header: {}", e)))?,
            );
        }

        let request = request
            .body(())
            .map_err(|e| DialError::Other(format!("Failed to build request: {}", e)))?;

        // Send request and get response stream
        let (response, send_stream) = send_request
            .send_request(request, false)
            .map_err(|e| DialError::Other(format!("Failed to send HTTP/2 request: {}", e)))?;

        debug!("HTTP/2 request sent, waiting for response headers");

        // Wait for response headers
        let response = response
            .await
            .map_err(|e| DialError::Other(format!("Failed to receive HTTP/2 response: {}", e)))?;

        debug!("HTTP/2 response received: {:?}", response.status());

        if !response.status().is_success() {
            return Err(DialError::Other(format!(
                "HTTP/2 response error: {}",
                response.status()
            )));
        }

        let recv_stream = response.into_body();

        // Wrap streams in our AsyncReadWrite adapter
        let wrapped_stream = Http2StreamAdapter::new(send_stream, recv_stream);
        Ok(Box::new(wrapped_stream))
    }
}

/// HTTP/2 stream adapter
///
/// This adapter wraps h2 SendStream and RecvStream to implement
/// `AsyncRead` and `AsyncWrite` traits, making it compatible with the
/// `IoStream` type.
pub struct Http2StreamAdapter {
    send_stream: SendStream<Bytes>,
    recv_stream: RecvStream,
    read_buffer: Option<Bytes>,
}

impl Http2StreamAdapter {
    fn new(send_stream: SendStream<Bytes>, recv_stream: RecvStream) -> Self {
        Self {
            send_stream,
            recv_stream,
            read_buffer: None,
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
        if let Some(data) = &mut self.read_buffer {
            if !data.is_empty() {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);
                data.advance(to_copy);

                if data.is_empty() {
                    self.read_buffer = None;
                }

                return Poll::Ready(Ok(()));
            }
        }

        // Read next data frame
        match self.recv_stream.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let data_len = data.len();
                let to_copy = data_len.min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                // Buffer remaining data
                if to_copy < data_len {
                    let mut remaining = data;
                    remaining.advance(to_copy);
                    self.read_buffer = Some(remaining);
                }

                // Release flow control window; log and continue on error
                if let Err(e) = self
                    .recv_stream
                    .flow_control()
                    .release_capacity(data_len)
                {
                    debug!("HTTP/2 release_capacity error: {}", e);
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(
                format!("HTTP/2 recv error: {}", e),
            ))),
            Poll::Ready(None) => {
                debug!("HTTP/2 stream closed");
                Poll::Ready(Ok(())) // EOF
            }
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
        // Reserve capacity in the send window
        self.send_stream.reserve_capacity(buf.len());

        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(available))) => {
                let to_send = available.min(buf.len());
                let data = Bytes::copy_from_slice(&buf[..to_send]);

                self.send_stream.send_data(data, false).map_err(|e| {
                    std::io::Error::other(
                        format!("HTTP/2 send error: {}", e),
                    )
                })?;

                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(
                format!("HTTP/2 capacity error: {}", e),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "HTTP/2 send stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // h2 handles flushing internally
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Send empty data frame with END_STREAM flag
        self.send_stream
            .send_data(Bytes::new(), true)
            .map_err(|e| {
                std::io::Error::other(
                    format!("HTTP/2 shutdown error: {}", e),
                )
            })?;

        Poll::Ready(Ok(()))
    }
}

/// HTTP/2 server configuration
#[derive(Debug, Clone)]
pub struct Http2ServerConfig {
    /// Maximum concurrent streams (default: 256)
    pub max_concurrent_streams: u32,
    /// Initial window size (default: 1MB)
    pub initial_window_size: u32,
    /// Initial connection window size (default: 1MB)
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
///
/// This listener accepts incoming HTTP/2 connections by:
/// 1. Accepting TCP connections from the underlying listener
/// 2. Performing HTTP/2 server handshake
/// 3. Accepting incoming streams and returning them as AsyncRead/AsyncWrite
///
/// ## Usage
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
        assert_eq!(config.max_concurrent_streams, 100);
    }

    #[tokio::test]
    async fn test_http2_dialer_creation() {
        let config = Http2Config::default();
        let tcp_dialer = Box::new(TcpDialer) as Box<dyn Dialer>;
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
