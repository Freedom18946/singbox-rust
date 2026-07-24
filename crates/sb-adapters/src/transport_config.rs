//! Transport configuration for protocol adapters.
//!
//! This module provides transport layer abstraction for protocol adapters,
//! allowing VMess, VLESS, Trojan, and other protocols to use different
//! underlying transports (TCP, WebSocket, gRPC, HTTPUpgrade).
//!
//! # Features
//!
//! - **TCP**: Direct TCP connections (always available)
//! - **WebSocket**: WebSocket transport (requires `transport_ws` feature)
//! - **gRPC**: gRPC bidirectional streaming (requires `transport_grpc` feature)
//! - **HTTPUpgrade**: HTTP/1.1 Upgrade protocol (requires `transport_httpupgrade` feature)
//!
//! # Examples
//!
//! ```rust,ignore
//! use sb_adapters::transport_config::{TransportConfig, TransportType};
//!
//! let config = TransportConfig::Tcp;
//! let dialer = config.create_dialer();
//! ```

#[cfg(feature = "sb-transport")]
use std::sync::Arc;

#[cfg(feature = "sb-transport")]
struct FailedDialer {
    reason: String,
}

#[cfg(feature = "sb-transport")]
impl FailedDialer {
    fn boxed(reason: impl Into<String>) -> Box<dyn sb_transport::Dialer> {
        Box::new(Self {
            reason: reason.into(),
        })
    }
}

#[cfg(feature = "sb-transport")]
#[async_trait::async_trait]
impl sb_transport::Dialer for FailedDialer {
    async fn connect(
        &self,
        _host: &str,
        _port: u16,
    ) -> Result<sb_transport::IoStream, sb_transport::DialError> {
        Err(sb_transport::DialError::Other(self.reason.clone()))
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

/// Transport type selection.
///
/// Specifies the underlying transport protocol for proxy connections.
///
/// # Examples
///
/// ```rust,ignore
/// use sb_adapters::transport_config::TransportType;
///
/// let transport = TransportType::Tcp;
/// assert_eq!(transport, TransportType::default());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportType {
    /// Direct TCP connection.
    Tcp,

    /// WebSocket transport.
    WebSocket,

    /// gRPC bidirectional streaming.
    Grpc,

    /// HTTP/1.1 Upgrade.
    HttpUpgrade,
}

impl Default for TransportType {
    /// Returns `TransportType::Tcp` as the default.
    #[inline]
    fn default() -> Self {
        Self::Tcp
    }
}

/// WebSocket transport configuration.
///
/// # Examples
///
/// ```rust,ignore
/// use sb_adapters::transport_config::WebSocketTransportConfig;
///
/// let config = WebSocketTransportConfig {
///     path: "/v2ray".to_string(),
///     headers: vec![("Host".to_string(), "example.com".to_string())],
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebSocketTransportConfig {
    /// WebSocket path (default: "/").
    pub path: String,

    /// Custom headers to send with the WebSocket upgrade request.
    pub headers: Vec<(String, String)>,

    /// Maximum message size in bytes (default: 64MB).
    pub max_message_size: Option<usize>,

    /// Maximum frame size in bytes (default: 16MB).
    pub max_frame_size: Option<usize>,
}

impl Default for WebSocketTransportConfig {
    /// Returns default WebSocket configuration with path "/" and 64MB max message size.
    #[inline]
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
///
/// # Examples
///
/// ```rust,ignore
/// use sb_adapters::transport_config::GrpcTransportConfig;
///
/// let config = GrpcTransportConfig {
///     service_name: "MyService".to_string(),
///     method_name: "MyMethod".to_string(),
///     metadata: vec![("Authorization".to_string(), "Bearer token".to_string())],
/// };
/// ```
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
    /// Returns default gRPC configuration with TunnelService/Tunnel.
    #[inline]
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
    /// Returns default HTTPUpgrade configuration with path "/".
    #[inline]
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
    /// Returns `TransportConfig::Tcp` as the default.
    #[inline]
    fn default() -> Self {
        Self::Tcp
    }
}

impl TransportConfig {
    /// Returns the transport type of this configuration.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use sb_adapters::transport_config::{TransportConfig, TransportType};
    ///
    /// let config = TransportConfig::Tcp;
    /// assert_eq!(config.transport_type(), TransportType::Tcp);
    /// ```
    #[inline]
    #[must_use]
    pub fn transport_type(&self) -> TransportType {
        match self {
            Self::Tcp => TransportType::Tcp,
            Self::WebSocket(_) => TransportType::WebSocket,
            Self::Grpc(_) => TransportType::Grpc,
            Self::HttpUpgrade(_) => TransportType::HttpUpgrade,
        }
    }

    /// Creates a dialer for this transport configuration.
    ///
    /// Returns a dialer that fails loudly if the requested feature is absent.
    #[cfg(feature = "sb-transport")]
    #[must_use]
    pub fn create_dialer(&self) -> Box<dyn sb_transport::Dialer> {
        use sb_transport::TcpDialer;

        match self {
            Self::Tcp => Box::new(TcpDialer::default()) as Box<dyn sb_transport::Dialer>,

            #[cfg(feature = "transport_ws")]
            Self::WebSocket(ws_config) => {
                let inner = Box::new(TcpDialer::default()) as Box<dyn sb_transport::Dialer>;
                let config = sb_transport::websocket::WebSocketConfig {
                    path: ws_config.path.clone(),
                    headers: ws_config.headers.clone(),
                    max_message_size: ws_config.max_message_size,
                    max_frame_size: ws_config.max_frame_size,
                    early_data: false,
                    early_data_header_name: "Sec-WebSocket-Protocol".to_string(),
                    max_early_data: 0,
                };
                Box::new(sb_transport::websocket::WebSocketDialer::new(config, inner))
            }

            #[cfg(not(feature = "transport_ws"))]
            Self::WebSocket(_) => FailedDialer::boxed(
                "WebSocket transport requested but transport_ws feature is not enabled",
            ),

            #[cfg(feature = "transport_grpc")]
            Self::Grpc(grpc_config) => {
                let config = sb_transport::grpc::GrpcConfig {
                    service_name: grpc_config.service_name.clone(),
                    method_name: grpc_config.method_name.clone(),
                    metadata: grpc_config.metadata.clone(),
                    enable_tls: false, // TLS will be handled separately
                    server_name: None,
                    connect_timeout: std::time::Duration::from_secs(10),
                    idle_timeout: std::time::Duration::from_secs(300),
                    permit_keepalive_without_calls: true,
                    keepalive_time: Some(std::time::Duration::from_secs(20)),
                    keepalive_timeout: Some(std::time::Duration::from_secs(10)),
                };
                Box::new(sb_transport::grpc::GrpcDialer::new(config))
            }

            #[cfg(not(feature = "transport_grpc"))]
            Self::Grpc(_) => FailedDialer::boxed(
                "gRPC transport requested but transport_grpc feature is not enabled",
            ),

            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(http_config) => {
                let inner = Box::new(TcpDialer::default()) as Box<dyn sb_transport::Dialer>;
                let config = sb_transport::httpupgrade::HttpUpgradeConfig {
                    path: http_config.path.clone(),
                    headers: http_config.headers.clone(),
                    host: "".to_string(),
                };
                Box::new(sb_transport::httpupgrade::HttpUpgradeDialer::new(
                    config, inner,
                ))
            }

            #[cfg(not(feature = "transport_httpupgrade"))]
            Self::HttpUpgrade(_) => FailedDialer::boxed(
                "HTTPUpgrade transport requested but transport_httpupgrade feature is not enabled",
            ),
        }
    }

    #[cfg(all(feature = "sb-transport", feature = "transport_tls"))]
    fn tcp_with_tls(
        tls_config: &sb_transport::TlsConfig,
    ) -> Result<Box<dyn sb_transport::Dialer>, String> {
        use sb_transport::{TcpDialer, TlsConfig, TlsDialer};

        match tls_config {
            TlsConfig::Standard(config) => {
                let client_config = sb_transport::build_standard_client_config(config)
                    .map_err(|error| error.to_string())?;
                let sni_override = config
                    .server_name
                    .as_ref()
                    .filter(|name| !name.trim().is_empty())
                    .cloned();
                Ok(Box::new(TlsDialer {
                    inner: Box::new(TcpDialer::default()) as Box<dyn sb_transport::Dialer>,
                    config: client_config,
                    sni_override,
                    // ALPN is already compiled into client_config.
                    alpn: None,
                }))
            }
            #[allow(unreachable_patterns)]
            _ => Err(
                "non-standard TLS cannot be lowered through the standard V2Ray transport dialer"
                    .to_string(),
            ),
        }
    }

    #[cfg(feature = "sb-transport")]
    fn create_layered_dialer(
        &self,
        tls_config: Option<&sb_transport::TlsConfig>,
    ) -> Box<dyn sb_transport::Dialer> {
        use sb_transport::TcpDialer;

        let physical: Box<dyn sb_transport::Dialer> = match tls_config {
            #[cfg(feature = "transport_tls")]
            Some(tls_config) => match Self::tcp_with_tls(tls_config) {
                Ok(dialer) => dialer,
                Err(reason) => return FailedDialer::boxed(format!("TLS configuration: {reason}")),
            },
            #[cfg(not(feature = "transport_tls"))]
            Some(_) => {
                return FailedDialer::boxed(
                    "TLS requested but transport_tls feature is not enabled",
                )
            }
            None => Box::new(TcpDialer::default()),
        };

        match self {
            Self::Tcp => physical,
            #[cfg(feature = "transport_ws")]
            Self::WebSocket(ws_config) => {
                let config = sb_transport::websocket::WebSocketConfig {
                    path: ws_config.path.clone(),
                    headers: ws_config.headers.clone(),
                    max_message_size: ws_config.max_message_size,
                    max_frame_size: ws_config.max_frame_size,
                    early_data: false,
                    early_data_header_name: "Sec-WebSocket-Protocol".to_string(),
                    max_early_data: 0,
                };
                Box::new(sb_transport::websocket::WebSocketDialer::new(
                    config, physical,
                ))
            }
            #[cfg(not(feature = "transport_ws"))]
            Self::WebSocket(_) => FailedDialer::boxed(
                "WebSocket transport requested but transport_ws feature is not enabled",
            ),
            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(http_config) => {
                let config = sb_transport::httpupgrade::HttpUpgradeConfig {
                    path: http_config.path.clone(),
                    headers: http_config.headers.clone(),
                    host: String::new(),
                };
                Box::new(sb_transport::httpupgrade::HttpUpgradeDialer::new(
                    config, physical,
                ))
            }
            #[cfg(not(feature = "transport_httpupgrade"))]
            Self::HttpUpgrade(_) => FailedDialer::boxed(
                "HTTPUpgrade transport requested but transport_httpupgrade feature is not enabled",
            ),
            Self::Grpc(_) if tls_config.is_some() => FailedDialer::boxed(
                "standard TLS with gRPC transport is not implemented; refusing plaintext fallback",
            ),
            Self::Grpc(_) => self.create_dialer(),
        }
    }

    /// Creates TCP -> TLS -> configured V2Ray transport.
    #[cfg(feature = "sb-transport")]
    #[must_use]
    pub fn create_dialer_with_tls(
        &self,
        tls_config: &sb_transport::TlsConfig,
    ) -> Box<dyn sb_transport::Dialer> {
        self.create_layered_dialer(Some(tls_config))
    }

    /// Creates a dialer with optional TLS and multiplex layers.
    #[cfg(feature = "sb-transport")]
    #[must_use]
    pub fn create_dialer_with_layers(
        &self,
        tls_config: Option<&sb_transport::TlsConfig>,
        multiplex_config: Option<&sb_transport::multiplex::MultiplexConfig>,
    ) -> Arc<dyn sb_transport::Dialer> {
        // Physical order: TCP -> TLS -> V2Ray transport -> project yamux.
        let dialer = self.create_layered_dialer(tls_config);

        // Add multiplex layer if configured
        if let Some(mux_cfg) = multiplex_config {
            return Arc::new(sb_transport::multiplex::MultiplexDialer::new(
                mux_cfg.clone(),
                dialer,
            ));
        }

        Arc::new(dialer)
    }

    /// Creates an inbound listener for this transport configuration.
    ///
    /// Falls back to TCP if the required transport feature is not enabled.
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - The address to bind to
    ///
    /// # Returns
    ///
    /// An `InboundListener` that can accept connections.
    ///
    /// # Errors
    ///
    /// Returns an error if binding to the address fails.
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

/// Trait combining `AsyncRead` + `AsyncWrite` for inbound streams.
pub trait InboundStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Blanket implementation for any type that satisfies the bounds.
impl<T> InboundStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Wrapper to adapt `AsyncReadWrite` streams to `InboundStream`.
#[cfg(any(
    feature = "transport_ws",
    feature = "transport_grpc",
    feature = "transport_httpupgrade"
))]
struct InboundStreamAdapter {
    inner: sb_transport::dialer::IoStream,
}

#[cfg(any(
    feature = "transport_ws",
    feature = "transport_grpc",
    feature = "transport_httpupgrade"
))]
impl tokio::io::AsyncRead for InboundStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(any(
    feature = "transport_ws",
    feature = "transport_grpc",
    feature = "transport_httpupgrade"
))]
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

/// Inbound listener that abstracts over different transport types.
pub enum InboundListener {
    /// Direct TCP listener.
    Tcp(TcpListener),

    /// WebSocket listener.
    #[cfg(feature = "transport_ws")]
    WebSocket(sb_transport::websocket::WebSocketListener),

    /// gRPC server.
    #[cfg(feature = "transport_grpc")]
    Grpc(sb_transport::grpc::GrpcServer),

    /// HTTPUpgrade listener.
    #[cfg(feature = "transport_httpupgrade")]
    HttpUpgrade(sb_transport::httpupgrade::HttpUpgradeListener),
}

impl InboundListener {
    /// Accepts a new connection from the listener.
    ///
    /// Returns a stream that implements `AsyncRead + AsyncWrite`.
    ///
    /// # Errors
    ///
    /// Returns an error if accepting the connection fails.
    pub async fn accept(
        &self,
    ) -> Result<(Box<dyn InboundStream>, std::net::SocketAddr), std::io::Error> {
        match self {
            Self::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                Ok((Box::new(stream) as Box<dyn InboundStream>, peer))
            }

            #[cfg(feature = "transport_ws")]
            Self::WebSocket(listener) => {
                use sb_transport::dialer::DialError;
                let stream = listener.accept().await.map_err(|e| match e {
                    DialError::Io(io_err) => io_err,
                    other => std::io::Error::other(other.to_string()),
                })?;
                // WebSocket listener doesn't expose peer addr easily yet, use dummy
                let peer = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
                Ok((
                    Box::new(InboundStreamAdapter { inner: stream }) as Box<dyn InboundStream>,
                    peer,
                ))
            }

            #[cfg(feature = "transport_grpc")]
            Self::Grpc(server) => {
                let stream = server
                    .accept()
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                // gRPC doesn't expose peer addr easily yet, use dummy
                let peer = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
                Ok((
                    Box::new(InboundStreamAdapter { inner: stream }) as Box<dyn InboundStream>,
                    peer,
                ))
            }

            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(listener) => {
                use sb_transport::dialer::DialError;
                let stream = listener.accept().await.map_err(|e| match e {
                    DialError::Io(io_err) => io_err,
                    other => std::io::Error::other(other.to_string()),
                })?;
                // HttpUpgrade doesn't expose peer addr easily yet, use dummy
                let peer = std::net::SocketAddr::from(([0, 0, 0, 0], 0));
                Ok((
                    Box::new(InboundStreamAdapter { inner: stream }) as Box<dyn InboundStream>,
                    peer,
                ))
            }
        }
    }

    /// Returns the local address this listener is bound to.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be retrieved.
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

    #[cfg(all(feature = "sb-transport", feature = "transport_tls"))]
    #[tokio::test]
    async fn standard_tls_dialer_applies_alpn_and_version() {
        use sb_transport::{StandardTlsConfig, TlsConfig, TlsVersion};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate certificate");
        let acceptor = sb_transport::build_standard_tls_acceptor(&StandardTlsConfig {
            cert_pem: Some(cert.pem()),
            key_pem: Some(key_pair.serialize_pem()),
            alpn: vec!["h2".to_string()],
            min_version: Some(TlsVersion::V1_3),
            max_version: Some(TlsVersion::V1_3),
            ..Default::default()
        })
        .expect("server TLS config");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS server");
        let addr = listener.local_addr().expect("TLS server address");
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept TCP");
            let tls = acceptor.accept(tcp).await.expect("accept TLS");
            (
                tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec),
                tls.get_ref().1.protocol_version(),
            )
        });

        let tls = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("localhost".to_string()),
            alpn: vec!["h2".to_string()],
            insecure: true,
            min_version: Some(TlsVersion::V1_3),
            max_version: Some(TlsVersion::V1_3),
            ..Default::default()
        });
        let dialer = TransportConfig::Tcp.create_dialer_with_layers(Some(&tls), None);
        let stream = dialer
            .connect(&addr.ip().to_string(), addr.port())
            .await
            .expect("TLS dial");
        drop(stream);

        let (alpn, version) = server.await.expect("server task");
        assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
        assert_eq!(format!("{version:?}"), "Some(TLSv1_3)");
    }
}
