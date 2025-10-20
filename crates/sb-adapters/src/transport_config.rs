//! Transport configuration for protocol adapters
//!
//! This module provides transport layer abstraction for protocol adapters,
//! allowing VMess, VLESS, Trojan, and other protocols to use different
//! underlying transports (TCP, WebSocket, gRPC, HTTPUpgrade).

#[cfg(feature = "sb-transport")]
use std::sync::Arc;

/// Transport type selection
#[derive(Debug, Clone, PartialEq)]
pub enum TransportType {
    /// Direct TCP connection
    Tcp,
    /// WebSocket transport
    WebSocket,
    /// gRPC bidirectional streaming
    Grpc,
    /// HTTP/1.1 Upgrade
    HttpUpgrade,
}

impl Default for TransportType {
    fn default() -> Self {
        Self::Tcp
    }
}

/// WebSocket transport configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebSocketTransportConfig {
    /// WebSocket path (default: "/")
    pub path: String,
    /// Custom headers
    pub headers: Vec<(String, String)>,
    /// Maximum message size (default: 64MB)
    pub max_message_size: Option<usize>,
    /// Maximum frame size (default: 16MB)
    pub max_frame_size: Option<usize>,
}

impl Default for WebSocketTransportConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            headers: Vec::new(),
            max_message_size: Some(64 * 1024 * 1024),
            max_frame_size: Some(16 * 1024 * 1024),
        }
    }
}

/// gRPC transport configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GrpcTransportConfig {
    /// Service name (default: "TunnelService")
    pub service_name: String,
    /// Method name (default: "Tunnel")
    pub method_name: String,
    /// Custom metadata
    pub metadata: Vec<(String, String)>,
}

impl Default for GrpcTransportConfig {
    fn default() -> Self {
        Self {
            service_name: "TunnelService".to_string(),
            method_name: "Tunnel".to_string(),
            metadata: Vec::new(),
        }
    }
}

/// HTTPUpgrade transport configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HttpUpgradeTransportConfig {
    /// Path (default: "/")
    pub path: String,
    /// Custom headers
    pub headers: Vec<(String, String)>,
}

impl Default for HttpUpgradeTransportConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            headers: Vec::new(),
        }
    }
}

/// Transport configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TransportConfig {
    /// Direct TCP connection
    Tcp,
    /// WebSocket transport
    #[serde(rename = "ws")]
    WebSocket(WebSocketTransportConfig),
    /// gRPC transport
    Grpc(GrpcTransportConfig),
    /// HTTPUpgrade transport
    #[serde(rename = "httpupgrade")]
    HttpUpgrade(HttpUpgradeTransportConfig),
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::Tcp
    }
}

impl TransportConfig {
    /// Get transport type
    pub fn transport_type(&self) -> TransportType {
        match self {
            Self::Tcp => TransportType::Tcp,
            Self::WebSocket(_) => TransportType::WebSocket,
            Self::Grpc(_) => TransportType::Grpc,
            Self::HttpUpgrade(_) => TransportType::HttpUpgrade,
        }
    }

    /// Create a dialer for this transport configuration
    #[cfg(feature = "sb-transport")]
    pub fn create_dialer(&self) -> Box<dyn sb_transport::Dialer> {
        use sb_transport::TcpDialer;

        match self {
            Self::Tcp => Box::new(TcpDialer) as Box<dyn sb_transport::Dialer>,

            #[cfg(feature = "transport_ws")]
            Self::WebSocket(ws_config) => {
                let inner = Box::new(TcpDialer) as Box<dyn sb_transport::Dialer>;
                let config = sb_transport::websocket::WebSocketConfig {
                    path: ws_config.path.clone(),
                    headers: ws_config.headers.clone(),
                    max_message_size: ws_config.max_message_size,
                    max_frame_size: ws_config.max_frame_size,
                    early_data: false,
                };
                Box::new(sb_transport::websocket::WebSocketDialer::new(config, inner))
            }

            #[cfg(not(feature = "transport_ws"))]
            Self::WebSocket(_) => {
                tracing::error!(
                    "WebSocket transport requested but transport_ws feature not enabled"
                );
                Box::new(TcpDialer)
            }

            #[cfg(feature = "transport_grpc")]
            Self::Grpc(grpc_config) => {
                let config = sb_transport::grpc::GrpcConfig {
                    service_name: grpc_config.service_name.clone(),
                    method_name: grpc_config.method_name.clone(),
                    metadata: grpc_config.metadata.clone(),
                    enable_tls: false, // TLS will be handled separately
                    server_name: None,
                };
                Box::new(sb_transport::grpc::GrpcDialer::new(config))
            }

            #[cfg(not(feature = "transport_grpc"))]
            Self::Grpc(_) => {
                tracing::error!("gRPC transport requested but transport_grpc feature not enabled");
                Box::new(TcpDialer)
            }

            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(http_config) => {
                let inner = Box::new(TcpDialer) as Box<dyn sb_transport::Dialer>;
                let config = sb_transport::httpupgrade::HttpUpgradeConfig {
                    path: http_config.path.clone(),
                    headers: http_config.headers.clone(),
                };
                Box::new(sb_transport::httpupgrade::HttpUpgradeDialer::new(
                    config, inner,
                ))
            }

            #[cfg(not(feature = "transport_httpupgrade"))]
            Self::HttpUpgrade(_) => {
                tracing::error!(
                    "HTTPUpgrade transport requested but transport_httpupgrade feature not enabled"
                );
                Box::new(TcpDialer)
            }
        }
    }

    /// Create a dialer with TLS wrapping
    #[cfg(feature = "sb-transport")]
    pub fn create_dialer_with_tls(
        &self,
        _tls_config: &sb_transport::TlsConfig,
    ) -> Box<dyn sb_transport::Dialer> {
        let inner = self.create_dialer();

        // TlsDialer expects a concrete inner type, so we pass the Box itself
        let client_config = sb_transport::webpki_roots_config();

        Box::new(sb_transport::TlsDialer {
            inner,
            config: client_config,
            sni_override: None,
            alpn: None,
        })
    }

    /// Create a dialer with optional TLS and multiplex
    #[cfg(feature = "sb-transport")]
    pub fn create_dialer_with_layers(
        &self,
        tls_config: Option<&sb_transport::TlsConfig>,
        multiplex_config: Option<&sb_transport::multiplex::MultiplexConfig>,
    ) -> Arc<dyn sb_transport::Dialer> {
        // Start with base transport
        let dialer: Box<dyn sb_transport::Dialer> = self.create_dialer();

        // Add TLS layer if configured
        let dialer: Box<dyn sb_transport::Dialer> = if let Some(_tls_cfg) = tls_config {
            // TlsDialer expects a concrete inner type, so we pass the Box itself
            let client_config = sb_transport::webpki_roots_config();

            Box::new(sb_transport::TlsDialer {
                inner: dialer,
                config: client_config,
                sni_override: None,
                alpn: None,
            })
        } else {
            dialer
        };

        // Add multiplex layer if configured
        if let Some(mux_cfg) = multiplex_config {
            return Arc::new(sb_transport::multiplex::MultiplexDialer::new(
                mux_cfg.clone(),
                dialer,
            ));
        }

        Arc::new(dialer)
    }

    /// Create an inbound listener for this transport configuration
    ///
    /// # Arguments
    /// * `bind_addr` - The address to bind to
    ///
    /// # Returns
    /// An InboundListener that can accept connections
    pub async fn create_inbound_listener(
        &self,
        bind_addr: std::net::SocketAddr,
    ) -> Result<InboundListener, std::io::Error> {
        match self {
            Self::Tcp => {
                let listener = TcpListener::bind(bind_addr).await?;
                Ok(InboundListener::Tcp(listener))
            }

            #[cfg(feature = "transport_ws")]
            Self::WebSocket(ws_config) => {
                let tcp_listener = TcpListener::bind(bind_addr).await?;
                let server_config = sb_transport::websocket::WebSocketServerConfig {
                    path: ws_config.path.clone(),
                    max_message_size: ws_config.max_message_size,
                    max_frame_size: ws_config.max_frame_size,
                    require_path_match: false,
                };
                let ws_listener =
                    sb_transport::websocket::WebSocketListener::new(tcp_listener, server_config);
                Ok(InboundListener::WebSocket(ws_listener))
            }

            #[cfg(not(feature = "transport_ws"))]
            Self::WebSocket(_) => {
                tracing::error!("WebSocket transport requested but transport_ws feature not enabled, falling back to TCP");
                let listener = TcpListener::bind(bind_addr).await?;
                Ok(InboundListener::Tcp(listener))
            }

            #[cfg(feature = "transport_grpc")]
            Self::Grpc(grpc_config) => {
                let server_config = sb_transport::grpc::GrpcServerConfig {
                    service_name: grpc_config.service_name.clone(),
                    method_name: grpc_config.method_name.clone(),
                };
                let grpc_server =
                    sb_transport::grpc::GrpcServer::bind(bind_addr, server_config).await?;
                Ok(InboundListener::Grpc(grpc_server))
            }

            #[cfg(not(feature = "transport_grpc"))]
            Self::Grpc(_) => {
                tracing::error!("gRPC transport requested but transport_grpc feature not enabled, falling back to TCP");
                let listener = TcpListener::bind(bind_addr).await?;
                Ok(InboundListener::Tcp(listener))
            }

            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(http_config) => {
                let tcp_listener = TcpListener::bind(bind_addr).await?;
                let server_config = sb_transport::httpupgrade::HttpUpgradeServerConfig {
                    path: http_config.path.clone(),
                    upgrade_protocol: "websocket".to_string(),
                    require_path_match: false,
                };
                let http_listener = sb_transport::httpupgrade::HttpUpgradeListener::new(
                    tcp_listener,
                    server_config,
                );
                Ok(InboundListener::HttpUpgrade(http_listener))
            }

            #[cfg(not(feature = "transport_httpupgrade"))]
            Self::HttpUpgrade(_) => {
                tracing::error!("HTTPUpgrade transport requested but transport_httpupgrade feature not enabled, falling back to TCP");
                let listener = TcpListener::bind(bind_addr).await?;
                Ok(InboundListener::Tcp(listener))
            }
        }
    }
}

// ============================================================================
// Inbound transport layer support
// ============================================================================

use tokio::net::TcpListener;

/// Trait combining AsyncRead + AsyncWrite for inbound streams
pub trait InboundStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync
{
}

/// Blanket implementation for any type that satisfies the bounds
impl<T> InboundStream for T where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync
{
}

/// Wrapper to adapt AsyncReadWrite streams to InboundStream
#[cfg(feature = "sb-transport")]
#[allow(dead_code)] // Adapter is constructed under specific feature/test paths
struct InboundStreamAdapter {
    inner: sb_transport::dialer::IoStream,
}

#[cfg(feature = "sb-transport")]
impl tokio::io::AsyncRead for InboundStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "sb-transport")]
impl tokio::io::AsyncWrite for InboundStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Inbound listener that abstracts over different transport types
pub enum InboundListener {
    /// Direct TCP listener
    Tcp(TcpListener),
    /// WebSocket listener
    #[cfg(feature = "transport_ws")]
    WebSocket(sb_transport::websocket::WebSocketListener),
    /// gRPC server (future implementation)
    #[cfg(feature = "transport_grpc")]
    Grpc(sb_transport::grpc::GrpcServer),
    /// HTTPUpgrade listener (future implementation)
    #[cfg(feature = "transport_httpupgrade")]
    HttpUpgrade(sb_transport::httpupgrade::HttpUpgradeListener),
}

impl InboundListener {
    /// Accept a new connection from the listener
    ///
    /// Returns a stream that implements AsyncRead + AsyncWrite
    pub async fn accept(&self) -> Result<Box<dyn InboundStream>, std::io::Error> {
        match self {
            Self::Tcp(listener) => {
                let (stream, _peer) = listener.accept().await?;
                Ok(Box::new(stream) as Box<dyn InboundStream>)
            }

            #[cfg(feature = "transport_ws")]
            Self::WebSocket(listener) => {
                use sb_transport::dialer::DialError;
                let stream = listener.accept().await.map_err(|e| match e {
                    DialError::Io(io_err) => io_err,
                    other => std::io::Error::other(other.to_string()),
                })?;
                Ok(Box::new(InboundStreamAdapter { inner: stream }) as Box<dyn InboundStream>)
            }

            #[cfg(feature = "transport_grpc")]
            Self::Grpc(server) => {
                let stream = server
                    .accept()
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                Ok(Box::new(InboundStreamAdapter { inner: stream }) as Box<dyn InboundStream>)
            }

            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(listener) => {
                use sb_transport::dialer::DialError;
                let stream = listener.accept().await.map_err(|e| match e {
                    DialError::Io(io_err) => io_err,
                    other => std::io::Error::other(other.to_string()),
                })?;
                Ok(Box::new(InboundStreamAdapter { inner: stream }) as Box<dyn InboundStream>)
            }
        }
    }

    /// Get the local address this listener is bound to
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        match self {
            Self::Tcp(listener) => listener.local_addr(),

            #[cfg(feature = "transport_ws")]
            Self::WebSocket(listener) => listener.local_addr(),

            #[cfg(feature = "transport_grpc")]
            Self::Grpc(server) => server.local_addr(),

            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(listener) => listener.local_addr(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_type_default() {
        assert_eq!(TransportType::default(), TransportType::Tcp);
    }

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.transport_type(), TransportType::Tcp);
    }

    #[test]
    fn test_websocket_config_default() {
        let ws_config = WebSocketTransportConfig::default();
        assert_eq!(ws_config.path, "/");
        assert!(ws_config.headers.is_empty());
    }

    #[test]
    fn test_grpc_config_default() {
        let grpc_config = GrpcTransportConfig::default();
        assert_eq!(grpc_config.service_name, "TunnelService");
        assert_eq!(grpc_config.method_name, "Tunnel");
    }

    #[test]
    fn test_httpupgrade_config_default() {
        let config = HttpUpgradeTransportConfig::default();
        assert_eq!(config.path, "/");
        assert!(config.headers.is_empty());
    }

    #[cfg(feature = "sb-transport")]
    #[test]
    fn test_tcp_dialer_creation() {
        let config = TransportConfig::Tcp;
        let _dialer = config.create_dialer();
        // Just verify it compiles and creates successfully
    }
}
