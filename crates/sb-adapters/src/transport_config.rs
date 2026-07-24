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
    /// HTTP Host header, independent from TLS SNI.
    pub host: Option<String>,
    /// Custom headers
    pub headers: Vec<(String, String)>,
}

impl Default for HttpUpgradeTransportConfig {
    /// Returns default HTTPUpgrade configuration with path "/".
    #[inline]
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
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

fn normalized_path(path: Option<&str>) -> String {
    let path = path.filter(|path| !path.is_empty()).unwrap_or("/");
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn selected_transport(
    tokens: Option<&[String]>,
    inferred: Option<&'static str>,
) -> Result<&'static str, String> {
    let mut selected = None;
    for token in tokens.into_iter().flatten() {
        let kind = match token.trim().to_ascii_lowercase().as_str() {
            "" | "tls" | "tcp" => continue,
            "ws" | "websocket" => "ws",
            "grpc" => "grpc",
            "httpupgrade" | "http_upgrade" => "httpupgrade",
            other => return Err(format!("unsupported V2Ray transport {other:?}")),
        };
        if selected.is_some_and(|current| current != kind) {
            return Err("multiple V2Ray application transports are not supported".to_string());
        }
        selected = Some(kind);
    }
    Ok(selected.or(inferred).unwrap_or("tcp"))
}

fn header_pairs(entries: &[sb_config::ir::HeaderEntry]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect()
}

/// Build one inbound V2Ray transport interpretation from canonical IR.
pub fn build_inbound_transport_config_from_ir(
    ir: &sb_config::ir::InboundIR,
) -> Result<TransportConfig, String> {
    build_inbound_transport_config(
        ir.transport.as_deref(),
        ir.ws_path.as_deref(),
        ir.ws_host.as_deref(),
        ir.grpc_service.as_deref(),
        ir.grpc_method.as_deref(),
        &ir.grpc_metadata,
        ir.http_upgrade_path.as_deref(),
        ir.http_upgrade_host.as_deref(),
        &ir.http_upgrade_headers,
    )
}

/// Build one inbound V2Ray transport interpretation from registry parameters.
pub fn build_inbound_transport_config_from_param(
    param: &sb_core::adapter::InboundParam,
) -> Result<TransportConfig, String> {
    build_inbound_transport_config(
        param.transport.as_deref(),
        param.ws_path.as_deref(),
        param.ws_host.as_deref(),
        param.grpc_service.as_deref(),
        param.grpc_method.as_deref(),
        &param.grpc_metadata,
        param.http_upgrade_path.as_deref(),
        param.http_upgrade_host.as_deref(),
        &param.http_upgrade_headers,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_inbound_transport_config(
    transport: Option<&[String]>,
    ws_path: Option<&str>,
    ws_host: Option<&str>,
    grpc_service: Option<&str>,
    grpc_method: Option<&str>,
    grpc_metadata: &[sb_config::ir::HeaderEntry],
    http_upgrade_path: Option<&str>,
    http_upgrade_host: Option<&str>,
    http_upgrade_headers: &[sb_config::ir::HeaderEntry],
) -> Result<TransportConfig, String> {
    let inferred = if ws_path.is_some() || ws_host.is_some() {
        Some("ws")
    } else if http_upgrade_path.is_some()
        || http_upgrade_host.is_some()
        || !http_upgrade_headers.is_empty()
    {
        Some("httpupgrade")
    } else if grpc_service.is_some() || grpc_method.is_some() || !grpc_metadata.is_empty() {
        Some("grpc")
    } else {
        None
    };
    match selected_transport(transport, inferred)? {
        "tcp" => Ok(TransportConfig::Tcp),
        "ws" => Ok(TransportConfig::WebSocket(WebSocketTransportConfig {
            path: normalized_path(ws_path),
            headers: ws_host
                .map(|host| vec![("Host".to_string(), host.to_string())])
                .unwrap_or_default(),
            ..Default::default()
        })),
        "grpc" => Ok(TransportConfig::Grpc(GrpcTransportConfig {
            service_name: grpc_service.unwrap_or("TunnelService").to_string(),
            method_name: grpc_method.unwrap_or("Tunnel").to_string(),
            metadata: header_pairs(grpc_metadata),
        })),
        "httpupgrade" => Ok(TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
            path: normalized_path(http_upgrade_path),
            host: http_upgrade_host.map(str::to_string),
            headers: header_pairs(http_upgrade_headers),
        })),
        _ => unreachable!("selected_transport returns a closed set"),
    }
}

impl TransportConfig {
    /// Go V2Ray HTTP transports advertise HTTP/1.1 when TLS ALPN is omitted.
    #[must_use]
    pub const fn default_tls_alpn(&self) -> Option<&'static str> {
        match self {
            Self::WebSocket(_) | Self::HttpUpgrade(_) => Some("http/1.1"),
            Self::Tcp | Self::Grpc(_) => None,
        }
    }

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
                    host: http_config.host.clone().unwrap_or_default(),
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
    fn try_create_layered_dialer(
        &self,
        tls_config: Option<&sb_transport::TlsConfig>,
    ) -> Result<Box<dyn sb_transport::Dialer>, String> {
        use sb_transport::TcpDialer;

        let effective_tls = tls_config.cloned().map(|mut tls| {
            let sb_transport::TlsConfig::Standard(config) = &mut tls;
            if config.alpn.is_empty() {
                if let Some(default_alpn) = self.default_tls_alpn() {
                    config.alpn.push(default_alpn.to_string());
                }
            }
            tls
        });
        let tls_config = effective_tls.as_ref();
        let physical: Box<dyn sb_transport::Dialer> = match tls_config {
            #[cfg(feature = "transport_tls")]
            Some(tls_config) => Self::tcp_with_tls(tls_config)
                .map_err(|reason| format!("TLS configuration: {reason}"))?,
            #[cfg(not(feature = "transport_tls"))]
            Some(_) => {
                return Err("TLS requested but transport_tls feature is not enabled".to_string())
            }
            None => Box::new(TcpDialer::default()),
        };

        match self {
            Self::Tcp => Ok(physical),
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
                Ok(Box::new(sb_transport::websocket::WebSocketDialer::new(
                    config, physical,
                )))
            }
            #[cfg(not(feature = "transport_ws"))]
            Self::WebSocket(_) => Err(
                "WebSocket transport requested but transport_ws feature is not enabled".to_string(),
            ),
            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(http_config) => {
                let host = http_config.host.clone().or_else(|| match tls_config {
                    Some(sb_transport::TlsConfig::Standard(config)) => config.server_name.clone(),
                    #[allow(unreachable_patterns)]
                    _ => None,
                });
                let config = sb_transport::httpupgrade::HttpUpgradeConfig {
                    path: http_config.path.clone(),
                    headers: http_config.headers.clone(),
                    host: host.unwrap_or_default(),
                };
                Ok(Box::new(sb_transport::httpupgrade::HttpUpgradeDialer::new(
                    config, physical,
                )))
            }
            #[cfg(not(feature = "transport_httpupgrade"))]
            Self::HttpUpgrade(_) => Err(
                "HTTPUpgrade transport requested but transport_httpupgrade feature is not enabled"
                    .to_string(),
            ),
            Self::Grpc(_) if tls_config.is_some() => Err(
                "standard TLS with gRPC transport is not implemented; refusing plaintext fallback"
                    .to_string(),
            ),
            Self::Grpc(_) => Ok(self.create_dialer()),
        }
    }

    #[cfg(feature = "sb-transport")]
    fn create_layered_dialer(
        &self,
        tls_config: Option<&sb_transport::TlsConfig>,
    ) -> Box<dyn sb_transport::Dialer> {
        self.try_create_layered_dialer(tls_config)
            .unwrap_or_else(|reason| FailedDialer::boxed(reason))
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
        self.try_create_dialer_with_layers(tls_config, multiplex_config)
            .unwrap_or_else(|reason| Arc::from(FailedDialer::boxed(reason)))
    }

    /// Build TCP -> optional TLS -> V2Ray transport -> optional project yamux,
    /// returning configuration failures to the production adapter builder.
    #[cfg(feature = "sb-transport")]
    pub fn try_create_dialer_with_layers(
        &self,
        tls_config: Option<&sb_transport::TlsConfig>,
        multiplex_config: Option<&sb_transport::multiplex::MultiplexConfig>,
    ) -> Result<Arc<dyn sb_transport::Dialer>, String> {
        // Physical order: TCP -> TLS -> V2Ray transport -> project yamux.
        let dialer = self.try_create_layered_dialer(tls_config)?;

        // Add multiplex layer if configured
        if let Some(mux_cfg) = multiplex_config {
            return Ok(Arc::new(sb_transport::multiplex::MultiplexDialer::new(
                mux_cfg.clone(),
                dialer,
            )));
        }

        Ok(Arc::new(dialer))
    }

    /// Creates an inbound listener for this transport configuration.
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
                    require_path_match: true,
                };
                let ws_listener =
                    sb_transport::websocket::WebSocketListener::new(tcp_listener, server_config);
                Ok(InboundListener::WebSocket(ws_listener))
            }

            #[cfg(not(feature = "transport_ws"))]
            Self::WebSocket(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "WebSocket transport requested but transport_ws feature is not enabled",
            )),

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
            Self::Grpc(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "gRPC transport requested but transport_grpc feature is not enabled",
            )),

            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(http_config) => {
                let tcp_listener = TcpListener::bind(bind_addr).await?;
                let server_config = sb_transport::httpupgrade::HttpUpgradeServerConfig {
                    path: http_config.path.clone(),
                    host: http_config.host.clone(),
                    upgrade_protocol: "websocket".to_string(),
                    require_path_match: true,
                };
                let http_listener = sb_transport::httpupgrade::HttpUpgradeListener::new(
                    tcp_listener,
                    server_config,
                );
                Ok(InboundListener::HttpUpgrade(http_listener))
            }

            #[cfg(not(feature = "transport_httpupgrade"))]
            Self::HttpUpgrade(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "HTTPUpgrade transport requested but transport_httpupgrade feature is not enabled",
            )),
        }
    }

    /// Creates an inbound listener where optional standard TLS is below the
    /// configured V2Ray transport: TCP -> TLS -> WS/HTTPUpgrade.
    #[cfg(feature = "transport_tls")]
    pub async fn create_inbound_listener_with_tls(
        &self,
        bind_addr: std::net::SocketAddr,
        tls: Option<tokio_rustls::TlsAcceptor>,
        handshake_timeout: std::time::Duration,
    ) -> Result<InboundListener, std::io::Error> {
        let Some(tls) = tls else {
            return self.create_inbound_listener(bind_addr).await;
        };
        let post_tls = match self {
            Self::Tcp => PostTlsTransport::Tcp,
            #[cfg(feature = "transport_ws")]
            Self::WebSocket(config) => {
                PostTlsTransport::WebSocket(sb_transport::websocket::WebSocketServerConfig {
                    path: config.path.clone(),
                    max_message_size: config.max_message_size,
                    max_frame_size: config.max_frame_size,
                    require_path_match: true,
                })
            }
            #[cfg(not(feature = "transport_ws"))]
            Self::WebSocket(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "WebSocket transport requested but transport_ws feature is not enabled",
                ));
            }
            Self::Grpc(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "standard TLS with gRPC inbound transport is not implemented",
                ));
            }
            #[cfg(feature = "transport_httpupgrade")]
            Self::HttpUpgrade(config) => {
                PostTlsTransport::HttpUpgrade(sb_transport::httpupgrade::HttpUpgradeServerConfig {
                    path: config.path.clone(),
                    host: config.host.clone(),
                    upgrade_protocol: "websocket".to_string(),
                    require_path_match: true,
                })
            }
            #[cfg(not(feature = "transport_httpupgrade"))]
            Self::HttpUpgrade(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "HTTPUpgrade transport requested but transport_httpupgrade feature is not enabled",
                ));
            }
        };
        let tcp_listener = TcpListener::bind(bind_addr).await?;
        Ok(InboundListener::TlsLayered {
            tcp_listener,
            tls,
            handshake_timeout,
            post_tls,
        })
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
    feature = "transport_tls",
    feature = "transport_ws",
    feature = "transport_grpc",
    feature = "transport_httpupgrade"
))]
struct InboundStreamAdapter {
    inner: sb_transport::dialer::IoStream,
}

#[cfg(any(
    feature = "transport_tls",
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
    feature = "transport_tls",
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

    /// TCP listener with TLS below an optional V2Ray HTTP transport.
    #[cfg(feature = "transport_tls")]
    TlsLayered {
        tcp_listener: TcpListener,
        tls: tokio_rustls::TlsAcceptor,
        handshake_timeout: std::time::Duration,
        post_tls: PostTlsTransport,
    },
}

#[cfg(feature = "transport_tls")]
pub enum PostTlsTransport {
    Tcp,
    #[cfg(feature = "transport_ws")]
    WebSocket(sb_transport::websocket::WebSocketServerConfig),
    #[cfg(feature = "transport_httpupgrade")]
    HttpUpgrade(sb_transport::httpupgrade::HttpUpgradeServerConfig),
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

            #[cfg(feature = "transport_tls")]
            Self::TlsLayered {
                tcp_listener,
                tls,
                handshake_timeout,
                post_tls,
            } => {
                let (tcp, peer) = tcp_listener.accept().await?;
                let tls = tokio::time::timeout(*handshake_timeout, tls.accept(tcp))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "inbound TLS handshake timed out",
                        )
                    })?
                    .map_err(|error| {
                        std::io::Error::other(format!("inbound TLS handshake failed: {error}"))
                    })?;
                let alpn = tls
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|value| String::from_utf8_lossy(value).into_owned());
                let version = tls.get_ref().1.protocol_version();
                tracing::info!(
                    %peer,
                    alpn=?alpn,
                    version=?version,
                    transport=?self.transport_name(),
                    "inbound transport TLS handshake complete"
                );
                let stream = Box::new(tls) as sb_transport::IoStream;
                let stream = match post_tls {
                    PostTlsTransport::Tcp => stream,
                    #[cfg(feature = "transport_ws")]
                    PostTlsTransport::WebSocket(config) => tokio::time::timeout(
                        *handshake_timeout,
                        sb_transport::websocket::accept_stream(stream, config),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "WebSocket handshake timed out",
                        )
                    })?
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
                    #[cfg(feature = "transport_httpupgrade")]
                    PostTlsTransport::HttpUpgrade(config) => tokio::time::timeout(
                        *handshake_timeout,
                        sb_transport::httpupgrade::accept_stream(stream, config),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "HTTPUpgrade handshake timed out",
                        )
                    })?
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
                };
                Ok((
                    Box::new(InboundStreamAdapter { inner: stream }) as Box<dyn InboundStream>,
                    peer,
                ))
            }
        }
    }

    #[cfg(feature = "transport_tls")]
    fn transport_name(&self) -> &'static str {
        match self {
            Self::TlsLayered { post_tls, .. } => match post_tls {
                PostTlsTransport::Tcp => "tcp",
                #[cfg(feature = "transport_ws")]
                PostTlsTransport::WebSocket(_) => "ws",
                #[cfg(feature = "transport_httpupgrade")]
                PostTlsTransport::HttpUpgrade(_) => "httpupgrade",
            },
            _ => "other",
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

            #[cfg(feature = "transport_tls")]
            Self::TlsLayered { tcp_listener, .. } => tcp_listener.local_addr(),
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
        assert!(config.host.is_none());
        assert!(config.headers.is_empty());
    }

    #[test]
    fn inbound_transport_builder_preserves_http_host_and_rejects_unknown() {
        let ir = sb_config::ir::InboundIR {
            transport: Some(vec!["tls".to_string(), "httpupgrade".to_string()]),
            http_upgrade_path: Some("upgrade".to_string()),
            http_upgrade_host: Some("http.virtual.test".to_string()),
            http_upgrade_headers: vec![sb_config::ir::HeaderEntry {
                key: "X-Test".to_string(),
                value: "value".to_string(),
            }],
            ..Default::default()
        };
        let TransportConfig::HttpUpgrade(config) =
            build_inbound_transport_config_from_ir(&ir).expect("HTTPUpgrade config")
        else {
            panic!("expected HTTPUpgrade");
        };
        assert_eq!(config.path, "/upgrade");
        assert_eq!(config.host.as_deref(), Some("http.virtual.test"));
        assert_eq!(config.headers, vec![("X-Test".into(), "value".into())]);

        let invalid = sb_config::ir::InboundIR {
            transport: Some(vec!["quic".to_string()]),
            ..Default::default()
        };
        assert!(build_inbound_transport_config_from_ir(&invalid)
            .unwrap_err()
            .contains("unsupported V2Ray transport"));
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

    #[cfg(all(
        feature = "sb-transport",
        feature = "transport_tls",
        feature = "transport_ws"
    ))]
    #[tokio::test]
    async fn websocket_tls_layers_before_upgrade_with_distinct_host_and_sni() {
        use sb_transport::{StandardTlsConfig, TlsConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate certificate");
        let server_tls = StandardTlsConfig {
            cert_pem: Some(cert.pem()),
            key_pem: Some(key_pair.serialize_pem()),
            alpn: vec!["http/1.1".to_string()],
            ..Default::default()
        };
        let acceptor = sb_transport::build_standard_tls_acceptor(&server_tls).expect("server TLS");
        let server_transport = TransportConfig::WebSocket(WebSocketTransportConfig {
            path: "/vmess-ws".to_string(),
            ..Default::default()
        });
        let listener = server_transport
            .create_inbound_listener_with_tls(
                "127.0.0.1:0".parse().unwrap(),
                Some(acceptor),
                std::time::Duration::from_secs(3),
            )
            .await
            .expect("layered listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("layered accept");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.expect("server read");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.expect("server write");
        });

        let client_tls = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("localhost".to_string()),
            ca_pem: vec![cert.pem()],
            alpn: vec!["http/1.1".to_string()],
            ..Default::default()
        });
        let client_transport = TransportConfig::WebSocket(WebSocketTransportConfig {
            path: "/vmess-ws".to_string(),
            headers: vec![("Host".to_string(), "ws.virtual.test".to_string())],
            ..Default::default()
        });
        let dialer = client_transport.create_dialer_with_tls(&client_tls);
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            dialer.connect(&addr.ip().to_string(), addr.port()),
        )
        .await
        .expect("TLS WebSocket dial timeout")
        .expect("TLS WebSocket dial");
        stream.write_all(b"ping").await.expect("client write");
        let mut response = [0_u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .expect("client read timeout")
        .expect("client read");
        assert_eq!(&response, b"pong");
        tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .expect("server task timeout")
            .expect("server task");
    }

    #[cfg(all(
        feature = "sb-transport",
        feature = "transport_tls",
        feature = "transport_httpupgrade"
    ))]
    #[tokio::test]
    async fn httpupgrade_tls_layers_before_upgrade_with_distinct_host_and_sni() {
        use sb_transport::{StandardTlsConfig, TlsConfig};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("generate certificate");
        let acceptor = sb_transport::build_standard_tls_acceptor(&StandardTlsConfig {
            cert_pem: Some(cert.pem()),
            key_pem: Some(key_pair.serialize_pem()),
            alpn: vec!["http/1.1".to_string()],
            ..Default::default()
        })
        .expect("server TLS");
        let server_transport = TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
            path: "/vmess-upgrade".to_string(),
            host: Some("http.virtual.test".to_string()),
            headers: Vec::new(),
        });
        let listener = server_transport
            .create_inbound_listener_with_tls(
                "127.0.0.1:0".parse().unwrap(),
                Some(acceptor),
                std::time::Duration::from_secs(3),
            )
            .await
            .expect("layered listener");
        let addr = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("layered accept");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.expect("server read");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.expect("server write");
        });

        let client_tls = TlsConfig::Standard(StandardTlsConfig {
            server_name: Some("localhost".to_string()),
            ca_pem: vec![cert.pem()],
            alpn: vec!["http/1.1".to_string()],
            ..Default::default()
        });
        let client_transport = TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
            path: "/vmess-upgrade".to_string(),
            host: Some("http.virtual.test".to_string()),
            headers: Vec::new(),
        });
        let dialer = client_transport.create_dialer_with_tls(&client_tls);
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            dialer.connect(&addr.ip().to_string(), addr.port()),
        )
        .await
        .expect("TLS HTTPUpgrade dial timeout")
        .expect("TLS HTTPUpgrade dial");
        stream.write_all(b"ping").await.expect("client write");
        let mut response = [0_u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_exact(&mut response),
        )
        .await
        .expect("client read timeout")
        .expect("client read");
        assert_eq!(&response, b"pong");
        tokio::time::timeout(std::time::Duration::from_secs(3), server)
            .await
            .expect("server task timeout")
            .expect("server task");
    }
}
