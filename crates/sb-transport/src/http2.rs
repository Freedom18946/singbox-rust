//! # HTTP/2 Transport Layer
//!
//! This module provides HTTP/2 transport implementation for singbox-rust, including:
//! - `Http2Dialer`: Client-side HTTP/2 connection dialer
//! - `Http2Stream`: Wrapper for HTTP/2 streams to implement AsyncReadWrite
//! - Connection pooling and multiplexing support
//!
//! ## Features
//! - Native HTTP/2 transport using h2 crate
//! - Stream multiplexing over single TCP connection
//! - Connection pooling for performance
//! - Flow control and window management
//! - TLS support when combined with TLS transport
//!
//! ## Usage
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
//!     let dialer = Http2Dialer::new(config);
//!     let stream = dialer.connect("example.com", 443).await?;
//!     // Use stream for communication...
//!     Ok(())
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
use tokio::net::TcpStream;
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
            let mut pool = self.pool.lock().await;
            if let Some(send_request) = pool.get(&key) {
                // Try to use the existing connection
                // Note: h2 SendRequest doesn't have is_ready(), we'll try to clone and use it
                debug!("Reusing pooled HTTP/2 connection for {}", key);
                return Ok(send_request.clone());
            }
        }

        // Create new connection
        debug!("Creating new HTTP/2 connection for {}", key);
        let tcp_stream = TcpStream::connect((host, port)).await?;

        // Perform HTTP/2 handshake
        let (send_request, connection) = client::handshake(tcp_stream)
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

        let method = self.config.method.parse::<Method>()
            .map_err(|e| DialError::Other(format!("Invalid HTTP method: {}", e)))?;

        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .version(http::Version::HTTP_2);

        // Add custom headers
        let headers = request.headers_mut()
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

        let request = request.body(())
            .map_err(|e| DialError::Other(format!("Failed to build request: {}", e)))?;

        // Send request and get response stream
        let (response, send_stream) = send_request
            .send_request(request, false)
            .map_err(|e| DialError::Other(format!("Failed to send HTTP/2 request: {}", e)))?;

        debug!("HTTP/2 request sent, waiting for response headers");

        // Wait for response headers
        let response = response.await
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

                // Release flow control window
                let _ = self.recv_stream.flow_control().release_capacity(data_len);

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
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

                self.send_stream
                    .send_data(data, false)
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("HTTP/2 send error: {}", e),
                        )
                    })?;

                Poll::Ready(Ok(to_send))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
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
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("HTTP/2 shutdown error: {}", e),
                )
            })?;

        Poll::Ready(Ok(()))
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
}
