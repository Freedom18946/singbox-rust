//! # Transport Chain Builder / 传输链构建器
//!
//! Provides a simple builder to compose transport layers in order, e.g.:
//! 提供一个简单的构建器来按顺序组合传输层，例如：
//! TCP -> TLS -> WebSocket, or TCP -> TLS -> HTTP/2, etc.
//! TCP -> TLS -> WebSocket，或 TCP -> TLS -> HTTP/2 等。
//!
//! ## Strategic Relevance / 战略关联
//! - **Composition**: Allows flexible composition of transport layers without complex nesting.
//!   **组合**: 允许灵活组合传输层，而无需复杂的嵌套。
//! - **Type Safety**: Ensures that layers are composed in a valid order (e.g., TLS wraps TCP).
//!   **类型安全**: 确保层按有效顺序组合（例如，TLS 包装 TCP）。
//!
//! ## Example / 示例
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
/// 用于将传输层组合成单个 `Dialer` 的构建器。
pub struct TransportBuilder {
    inner: Box<dyn Dialer>,
}

impl TransportBuilder {
    /// Start a builder from an existing dialer
    /// 从现有的拨号器开始构建
    #[must_use]
    pub fn with_inner(inner: Box<dyn Dialer>) -> Self {
        Self { inner }
    }

    /// Start a builder from a TCP dialer
    /// 从 TCP 拨号器开始构建
    #[must_use]
    pub fn tcp() -> Self {
        Self {
            inner: Box::new(crate::dialer::TcpDialer {
                bind_interface: None,
                bind_v4: None,
                bind_v6: None,
                routing_mark: None,
                reuse_addr: false,
                connect_timeout: None,
                tcp_fast_open: false,
                tcp_multi_path: false,
                udp_fragment: false,
            }),
        }
    }

    /// Set bind interface (if underlying dialer is TCP)
    pub fn bind_interface(mut self, interface: String) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.bind_interface = Some(interface);
        }
        self
    }

    /// Set IPv4 bind address (if underlying dialer is TCP)
    pub fn bind_v4(mut self, addr: std::net::Ipv4Addr) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.bind_v4 = Some(addr);
        }
        self
    }

    /// Set IPv6 bind address (if underlying dialer is TCP)
    pub fn bind_v6(mut self, addr: std::net::Ipv6Addr) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.bind_v6 = Some(addr);
        }
        self
    }

    /// Set routing mark (if underlying dialer is TCP)
    pub fn routing_mark(mut self, mark: u32) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.routing_mark = Some(mark);
        }
        self
    }

    /// Set reuse address (if underlying dialer is TCP)
    pub fn reuse_addr(mut self, reuse: bool) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.reuse_addr = reuse;
        }
        self
    }

    /// Set connect timeout (if underlying dialer is TCP)
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.connect_timeout = Some(timeout);
        }
        self
    }

    /// Set TCP Fast Open (if underlying dialer is TCP)
    pub fn tcp_fast_open(mut self, enable: bool) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.tcp_fast_open = enable;
        }
        self
    }

    /// Set TCP Multi-Path (if underlying dialer is TCP)
    pub fn tcp_multi_path(mut self, enable: bool) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.tcp_multi_path = enable;
        }
        self
    }

    /// Set UDP Fragment (if underlying dialer is TCP - note: this might be a misnomer in sb-core usage but adding for compatibility)
    pub fn udp_fragment(mut self, enable: bool) -> Self {
        if let Some(tcp) = self
            .inner
            .as_any_mut()
            .downcast_mut::<crate::dialer::TcpDialer>()
        {
            tcp.udp_fragment = enable;
        }
        self
    }

    /// Wrap with TLS layer (requires `transport_tls` feature)
    /// 包装 TLS 层（需要 `transport_tls` 特性）
    #[cfg(feature = "transport_tls")]
    #[must_use]
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
    /// 包装 WebSocket 层（需要 `transport_ws` 特性）
    #[cfg(feature = "transport_ws")]
    #[must_use]
    pub fn websocket(self, config: crate::websocket::WebSocketConfig) -> Self {
        let dialer = crate::websocket::WebSocketDialer::new(config, self.inner);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Wrap with HTTP/2 layer (requires `transport_h2` feature)
    /// 包装 HTTP/2 层（需要 `transport_h2` 特性）
    #[cfg(feature = "transport_h2")]
    #[must_use]
    pub fn http2(self, config: crate::http2::Http2Config) -> Self {
        let dialer = crate::http2::Http2Dialer::new(config, self.inner);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Wrap with HTTPUpgrade layer (requires `transport_httpupgrade` feature)
    /// 包装 HTTPUpgrade 层（需要 `transport_httpupgrade` 特性）
    #[cfg(feature = "transport_httpupgrade")]
    #[must_use]
    pub fn http_upgrade(self, config: crate::httpupgrade::HttpUpgradeConfig) -> Self {
        let dialer = crate::httpupgrade::HttpUpgradeDialer::new(config, self.inner);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Wrap with Multiplex (yamux) layer (requires `transport_mux` feature)
    /// 包装多路复用 (yamux) 层（需要 `transport_mux` 特性）
    #[cfg(feature = "transport_mux")]
    #[must_use]
    pub fn multiplex(self, config: crate::multiplex::MultiplexConfig) -> Self {
        let dialer = crate::multiplex::MultiplexDialer::new(config, self.inner);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Switch to gRPC transport (requires `transport_grpc` feature)
    /// 切换到 gRPC 传输（需要 `transport_grpc` 特性）
    ///
    /// Note: gRPC establishes its own HTTP/2 channel; previous layers are ignored.
    /// 注意：gRPC 建立自己的 HTTP/2 通道；先前的层将被忽略。
    #[cfg(feature = "transport_grpc")]
    #[must_use]
    pub fn grpc(self, config: crate::grpc::GrpcConfig) -> Self {
        let dialer = crate::grpc::GrpcDialer::new(config);
        Self {
            inner: Box::new(dialer),
        }
    }

    /// Return the composed dialer
    /// 返回组合后的拨号器
    #[must_use]
    pub fn build(self) -> Box<dyn Dialer> {
        self.inner
    }
}
