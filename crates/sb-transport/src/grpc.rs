//! # gRPC Transport Layer
//!
//! This module provides gRPC transport implementation for singbox-rust, including:
//! - `GrpcDialer`: Client-side gRPC connection dialer
//! - `TunnelService`: gRPC service definition for tunneling
//! - Bidirectional streaming support
//!
//! ## Features
//! - gRPC-based transport using tonic
//! - Bidirectional streaming for full-duplex communication
//! - TLS support (when combined with TLS transport)
//! - Custom metadata/headers support
//! - HTTP/2 as underlying transport
//!
//! ## Usage
//! ```rust,no_run
//! use sb_transport::grpc::{GrpcDialer, GrpcConfig};
//! use sb_transport::Dialer;
//!
//! async fn example() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = GrpcConfig {
//!         service_name: "TunnelService".to_string(),
//!         ..Default::default()
//!     };
//!     let dialer = GrpcDialer::new(config);
//!     let stream = dialer.connect("example.com", 443).await?;
//!     // Use stream for communication...
//!     Ok(())
//! }
//! ```

use crate::dialer::{DialError, Dialer, IoStream};
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tonic::transport::{Channel, Endpoint};
use tracing::debug;

// gRPC service definition for tunnel
pub mod tunnel {
    tonic::include_proto!("tunnel");
}

/// gRPC configuration
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Service name (default: "TunnelService")
    pub service_name: String,
    /// gRPC method name (default: "Tunnel")
    pub method_name: String,
    /// Custom metadata (key-value pairs)
    pub metadata: Vec<(String, String)>,
    /// Enable TLS (default: false)
    pub enable_tls: bool,
    /// Server name for TLS (if enable_tls is true)
    pub server_name: Option<String>,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: "TunnelService".to_string(),
            method_name: "Tunnel".to_string(),
            metadata: Vec::new(),
            enable_tls: false,
            server_name: None,
        }
    }
}

/// gRPC dialer
///
/// This dialer establishes gRPC bidirectional streaming connections.
/// It supports:
/// - Bidirectional streaming over gRPC
/// - Custom service and method names
/// - Metadata for authentication/headers
/// - TLS support
pub struct GrpcDialer {
    config: GrpcConfig,
}

impl GrpcDialer {
    /// Create a new gRPC dialer with custom configuration
    pub fn new(config: GrpcConfig) -> Self {
        Self { config }
    }

    /// Create a gRPC dialer with default configuration
    pub fn with_default_config() -> Self {
        Self::new(GrpcConfig::default())
    }
}

#[async_trait]
impl Dialer for GrpcDialer {
    async fn connect(&self, host: &str, port: u16) -> Result<IoStream, DialError> {
        debug!(
            "Dialing gRPC: {}:{} (service: {}, method: {})",
            host, port, self.config.service_name, self.config.method_name
        );

        // Build endpoint URL
        let scheme = if self.config.enable_tls {
            "https"
        } else {
            "http"
        };
        let url = format!("{}://{}:{}", scheme, host, port);

        // Create gRPC channel
        let endpoint = Endpoint::from_shared(url)
            .map_err(|e| DialError::Other(format!("Invalid gRPC endpoint: {}", e)))?;

        // Configure TLS if enabled
        if self.config.enable_tls {
            let server_name = self.config.server_name.as_deref().unwrap_or(host);
            // Note: tonic 0.12 TLS configuration has changed
            // TLS is now enabled automatically when using https://
            // For more advanced TLS configuration, use the channel builder API
            debug!("TLS enabled for gRPC endpoint: {}", server_name);
        }

        let channel = endpoint
            .connect()
            .await
            .map_err(|e| DialError::Other(format!("Failed to connect to gRPC endpoint: {}", e)))?;

        debug!("gRPC channel established");

        // Create bidirectional stream adapter
        let adapter = GrpcStreamAdapter::new(channel, &self.config).await?;
        Ok(Box::new(adapter))
    }
}

/// gRPC stream adapter
///
/// This adapter wraps a gRPC bidirectional stream to implement
/// `AsyncRead` and `AsyncWrite` traits, making it compatible with the
/// `IoStream` type.
///
/// ## Implementation Notes
/// - Uses mpsc channels to bridge gRPC streaming and AsyncRead/AsyncWrite
/// - Read operations consume messages from the receive stream
/// - Write operations send messages to the send stream
/// - Handles gRPC framing automatically
pub struct GrpcStreamAdapter {
    // Channel for sending data to gRPC stream
    send_tx: mpsc::UnboundedSender<Bytes>,
    // Channel for receiving data from gRPC stream
    recv_rx: mpsc::UnboundedReceiver<Result<Bytes, tonic::Status>>,
    // Buffer for partial reads
    read_buffer: BytesMut,
}

impl GrpcStreamAdapter {
    async fn new(channel: Channel, _config: &GrpcConfig) -> Result<Self, DialError> {
        use tonic::Request;
        use tunnel::tunnel_service_client::TunnelServiceClient;
        use tunnel::{TunnelRequest, TunnelResponse};

        // Create channels for bidirectional communication
        let (send_tx, mut send_rx) = mpsc::unbounded_channel::<Bytes>();
        let (recv_tx, recv_rx) = mpsc::unbounded_channel::<Result<Bytes, tonic::Status>>();

        // Create gRPC client
        let mut client = TunnelServiceClient::new(channel);

        // Spawn task to manage the bidirectional gRPC stream
        tokio::spawn(async move {
            // Create outbound stream from send_rx channel
            let outbound_stream = async_stream::stream! {
                while let Some(data) = send_rx.recv().await {
                    yield TunnelRequest { data: data.to_vec() };
                }
                debug!("gRPC outbound stream completed");
            };

            // Establish bidirectional stream
            match client.tunnel(Request::new(outbound_stream)).await {
                Ok(response) => {
                    let mut inbound = response.into_inner();
                    debug!("gRPC bidirectional stream established");

                    // Forward inbound messages to recv_tx
                    loop {
                        match inbound.message().await {
                            Ok(Some(TunnelResponse { data })) => {
                                if let Err(e) = recv_tx.send(Ok(Bytes::from(data))) {
                                    debug!("Failed to forward gRPC message: {}", e);
                                    break;
                                }
                            }
                            Ok(None) => {
                                debug!("gRPC inbound stream closed normally");
                                break;
                            }
                            Err(status) => {
                                debug!("gRPC stream error: {}", status);
                                let _ = recv_tx.send(Err(status));
                                break;
                            }
                        }
                    }
                }
                Err(status) => {
                    debug!("Failed to establish gRPC stream: {}", status);
                    let _ = recv_tx.send(Err(status));
                }
            }
        });

        Ok(Self {
            send_tx,
            recv_rx,
            read_buffer: BytesMut::new(),
        })
    }
}

impl AsyncRead for GrpcStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, return it first
        if !self.read_buffer.is_empty() {
            let to_copy = self.read_buffer.len().min(buf.remaining());
            buf.put_slice(&self.read_buffer[..to_copy]);
            self.read_buffer.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        // Read next message from gRPC stream
        match self.recv_rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(data))) => {
                let to_copy = data.len().min(buf.remaining());
                buf.put_slice(&data[..to_copy]);

                // Buffer remaining data
                if to_copy < data.len() {
                    self.read_buffer.extend_from_slice(&data[to_copy..]);
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(status))) => Poll::Ready(Err(std::io::Error::other(
                format!("gRPC error: {}", status),
            ))),
            Poll::Ready(None) => {
                debug!("gRPC stream closed");
                Poll::Ready(Ok(())) // EOF
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for GrpcStreamAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Send data via gRPC stream
        let data = Bytes::copy_from_slice(buf);
        self.send_tx.send(data).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("Failed to send gRPC message: {}", e),
            )
        })?;

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // gRPC handles flushing internally
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Close send channel to signal end of stream
        // The channel will be dropped when GrpcStreamAdapter is dropped
        Poll::Ready(Ok(()))
    }
}

// ============================================================================
// Server-side gRPC implementation
// ============================================================================

/// gRPC server configuration
#[derive(Debug, Clone)]
pub struct GrpcServerConfig {
    /// Service name
    pub service_name: String,
    /// Method name
    pub method_name: String,
}

impl Default for GrpcServerConfig {
    fn default() -> Self {
        Self {
            service_name: "TunnelService".to_string(),
            method_name: "Tunnel".to_string(),
        }
    }
}

/// gRPC server for accepting inbound connections
///
/// This server accepts incoming gRPC bidirectional streaming connections
/// and converts them to IoStream instances for use with inbound adapters.
pub struct GrpcServer {
    config: GrpcServerConfig,
    stream_rx: std::sync::Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<IoStream>>>,
    local_addr: std::net::SocketAddr,
}

impl GrpcServer {
    /// Bind a gRPC server to the specified address
    pub async fn bind(
        bind_addr: std::net::SocketAddr,
        config: GrpcServerConfig,
    ) -> std::io::Result<Self> {
        use tokio::net::TcpListener;

        // Create TCP listener for the gRPC server
        let tcp_listener = TcpListener::bind(bind_addr).await?;
        let local_addr = tcp_listener.local_addr()?;

        // Create channel for distributing incoming streams
        let (stream_tx, stream_rx) = mpsc::unbounded_channel();

        // Clone config for the background task
        let config_clone = config.clone();

        // Start background task to accept TCP connections and handle gRPC
        tokio::spawn(async move {
            loop {
                match tcp_listener.accept().await {
                    Ok((tcp_stream, peer_addr)) => {
                        debug!("Accepted gRPC connection from {}", peer_addr);
                        let stream_tx = stream_tx.clone();
                        let config = config_clone.clone();

                        tokio::spawn(async move {
                            // TODO: Implement proper gRPC server-side handling with tonic server
                            // For now, this is a placeholder that wraps TCP stream directly
                            tracing::warn!(
                                "gRPC server-side handling not yet fully implemented for {} (service: {})",
                                peer_addr,
                                config.service_name
                            );

                            // Placeholder: wrap TCP stream directly for basic functionality
                            // In production, this should handle gRPC framing and service dispatch
                            let stream: IoStream = Box::new(tcp_stream);
                            if stream_tx.send(stream).is_err() {
                                tracing::warn!("Failed to send stream, listener may be closed");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Failed to accept gRPC connection: {}", e);
                        continue;
                    }
                }
            }
        });

        Ok(Self {
            config,
            stream_rx: std::sync::Arc::new(tokio::sync::Mutex::new(stream_rx)),
            local_addr,
        })
    }

    /// Accept a new incoming stream
    pub async fn accept(&self) -> Result<IoStream, DialError> {
        let mut stream_rx = self.stream_rx.lock().await;

        stream_rx
            .recv()
            .await
            .ok_or_else(|| DialError::Other("Stream channel closed".to_string()))
    }

    /// Get the local address this server is bound to
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(self.local_addr)
    }

    /// Get the server configuration
    pub fn config(&self) -> &GrpcServerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_grpc_config_default() {
        let config = GrpcConfig::default();
        assert_eq!(config.service_name, "TunnelService");
        assert_eq!(config.method_name, "Tunnel");
        assert!(!config.enable_tls);
        assert!(config.metadata.is_empty());
    }

    #[tokio::test]
    async fn test_grpc_dialer_creation() {
        let config = GrpcConfig::default();
        let grpc_dialer = GrpcDialer::new(config);
        assert_eq!(grpc_dialer.config.service_name, "TunnelService");
    }
}
