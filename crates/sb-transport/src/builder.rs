//! Transport chain builder
//!
//! Provides a simple builder to compose transport layers in order, e.g.:
//! TCP -> TLS -> WebSocket, or TCP -> TLS -> HTTP/2, etc.
//!
//! Example:
//! ```rust,no_run
//! use std::sync::Arc;
//! use sb_transport::builder::TransportBuilder;
//! use sb_transport::TcpDialer;
//!
//! # #[cfg(feature = "transport_tls")]
//! # async fn demo() {
//! let base = Box::new(TcpDialer) as Box<dyn sb_transport::Dialer>;
//! let tls_cfg = sb_transport::tls::smoke_empty_roots_config();
//! let dialer = TransportBuilder::with_inner(base)
//!     .tls(tls_cfg, None, None)
//!     // .websocket(sb_transport::websocket::WebSocketConfig::default())
//!     .build();
//! let _ = dialer; // use as Box<dyn Dialer>
//! # }
//! ```

use crate::dialer::Dialer;

/// Builder for composing transport layers into a single `Dialer`.
pub struct TransportBuilder {
    inner: Box<dyn Dialer>,
}

impl TransportBuilder {
    /// Start a builder from an existing dialer
    pub fn with_inner(inner: Box<dyn Dialer>) -> Self {
        Self { inner }
    }

    /// Start a builder from a TCP dialer
    pub fn tcp() -> Self {
        Self {
            inner: Box::new(crate::dialer::TcpDialer),
        }
    }

    /// Wrap with TLS layer (requires `transport_tls` feature)
    #[cfg(feature = "transport_tls")]
    pub fn tls(
        self,
        config: std::sync::Arc<rustls::ClientConfig>,
        sni_override: Option<String>,
        alpn: Option<Vec<Vec<u8>>>,
    ) -> Self {
        let dialer = crate::tls::TlsDialer {
            inner: self.inner,
            config,
            sni_override,
            alpn,
        };
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Wrap with WebSocket layer (requires `transport_ws` feature)
    #[cfg(feature = "transport_ws")]
    pub fn websocket(self, config: crate::websocket::WebSocketConfig) -> Self {
        let dialer = crate::websocket::WebSocketDialer::new(config, self.inner);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Wrap with HTTP/2 layer (requires `transport_h2` feature)
    #[cfg(feature = "transport_h2")]
    pub fn http2(self, config: crate::http2::Http2Config) -> Self {
        let dialer = crate::http2::Http2Dialer::new(config, self.inner);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Wrap with HTTPUpgrade layer (requires `transport_httpupgrade` feature)
    #[cfg(feature = "transport_httpupgrade")]
    pub fn http_upgrade(self, config: crate::httpupgrade::HttpUpgradeConfig) -> Self {
        let dialer = crate::httpupgrade::HttpUpgradeDialer::new(config, self.inner);
        Self { inner: Box::new(dialer) }
    }

    /// Wrap with Multiplex (yamux) layer (requires `transport_mux` feature)
    #[cfg(feature = "transport_mux")]
    pub fn multiplex(self, config: crate::multiplex::MultiplexConfig) -> Self {
        let dialer = crate::multiplex::MultiplexDialer::new(config, self.inner);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Switch to gRPC transport (requires `transport_grpc` feature)
    /// Note: gRPC establishes its own HTTP/2 channel; previous layers are ignored.
    #[cfg(feature = "transport_grpc")]
    pub fn grpc(self, config: crate::grpc::GrpcConfig) -> Self {
        let dialer = crate::grpc::GrpcDialer::new(config);
        Self { inner: Box::new(dialer) }
    }

    /// Return the composed dialer
    pub fn build(self) -> Box<dyn Dialer> {
        self.inner
    }
}
