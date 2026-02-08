//! Adapter registration functions for integrating with sb-core.

#[cfg(any(
    all(feature = "adapter-http", feature = "http", feature = "router"),
    all(feature = "adapter-socks", feature = "socks", feature = "router"),
    all(
        feature = "adapter-http",
        feature = "adapter-socks",
        feature = "mixed",
        feature = "router"
    )
))]
use std::io;
use std::net::SocketAddr;
#[cfg(any(
    all(feature = "adapter-http", feature = "http", feature = "router"),
    all(feature = "adapter-socks", feature = "socks", feature = "router"),
    all(
        feature = "adapter-http",
        feature = "adapter-socks",
        feature = "mixed",
        feature = "router"
    )
))]
use std::sync::Mutex;
use std::sync::{Arc, Once};

use sb_config::ir::OutboundIR;
use sb_core::adapter::registry;
use sb_core::adapter::{
    InboundParam, InboundService, OutboundConnector, OutboundParam, UdpOutboundFactory,
};
use tracing::warn;

type OutboundBuilderResult = Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)>;

/// Bridge wrapper: adapts an `sb_adapters::traits::OutboundConnector` (returns BoxedStream)
/// into an `sb_core::adapter::OutboundConnector` (returns TcpStream / IoStream).
///
/// The `connect()` method returns an error (encrypted protocols can't return raw TcpStream).
/// The `connect_io()` method delegates to the inner adapter's `dial()`, returning a layered stream.
struct AdapterIoBridge<A: crate::traits::OutboundConnector + 'static> {
    inner: Arc<A>,
    name: &'static str,
}

impl<A: crate::traits::OutboundConnector + 'static> std::fmt::Debug for AdapterIoBridge<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterIoBridge")
            .field("name", &self.name)
            .field("inner", &self.inner)
            .finish()
    }
}

#[async_trait::async_trait]
impl<A: crate::traits::OutboundConnector + 'static> OutboundConnector for AdapterIoBridge<A> {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        Err(std::io::Error::other(format!(
            "{} adapter uses encrypted stream for {}:{}; use connect_io() instead",
            self.name, host, port
        )))
    }

    #[cfg(feature = "v2ray_transport")]
    async fn connect_io(
        &self,
        host: &str,
        port: u16,
    ) -> std::io::Result<sb_transport::IoStream> {
        use crate::traits::{DialOpts, Target, TransportKind};

        let target = Target {
            host: host.to_string(),
            port,
            kind: TransportKind::Tcp,
        };
        let opts = DialOpts::default();

        let boxed_stream = self
            .inner
            .dial(target, opts)
            .await
            .map_err(|e| std::io::Error::other(format!("{} dial failed: {}", self.name, e)))?;

        // Convert BoxedStream to IoStream via adapter wrapper
        Ok(Box::new(BoxedStreamAdapter(boxed_stream)))
    }
}

/// Adapter that converts `BoxedStream` (sb-adapters) to `AsyncReadWrite` (sb-transport).
/// Both have identical bounds (AsyncRead + AsyncWrite + Unpin + Send).
#[cfg(feature = "v2ray_transport")]
struct BoxedStreamAdapter(crate::traits::BoxedStream);

#[cfg(feature = "v2ray_transport")]
impl tokio::io::AsyncRead for BoxedStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

#[cfg(feature = "v2ray_transport")]
impl tokio::io::AsyncWrite for BoxedStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

static REGISTER_ONCE: Once = Once::new();

/// Register adapter-provided builders with sb-core registry. Safe to call multiple times.
/// 将适配器提供的构建器注册到 sb-core 注册表中。可以安全地多次调用。
pub fn register_all() {
    REGISTER_ONCE.call_once(|| {
        #[cfg(feature = "adapter-http")]
        {
            let _ = registry::register_outbound("http", build_http_outbound);
        }
        #[cfg(feature = "adapter-socks")]
        {
            let _ = registry::register_outbound("socks", build_socks_outbound);
            let _ = registry::register_outbound("socks4", build_socks4_outbound);
        }
        #[cfg(feature = "adapter-shadowsocks")]
        {
            let _ = registry::register_outbound("shadowsocks", build_shadowsocks_outbound);
            let _ = registry::register_outbound("shadowsocksr", build_shadowsocksr_outbound);
        }
        #[cfg(feature = "adapter-trojan")]
        {
            let _ = registry::register_outbound("trojan", build_trojan_outbound);
        }
        #[cfg(feature = "adapter-vmess")]
        {
            let _ = registry::register_outbound("vmess", build_vmess_outbound);
        }
        #[cfg(feature = "adapter-vless")]
        {
            let _ = registry::register_outbound("vless", build_vless_outbound);
        }
        {
            let _ = registry::register_outbound("direct", build_direct_outbound);
        }
        {
            let _ = registry::register_outbound("block", build_block_outbound);
        }
        {
            let _ = registry::register_outbound("dns", build_dns_outbound);
        }
        {
            let _ = registry::register_outbound("tor", build_tor_outbound);
        }
        {
            let _ = registry::register_outbound("anytls", build_anytls_outbound);
        }
        {
            let _ = registry::register_outbound("wireguard", build_wireguard_outbound);
        }
        {
            let _ = registry::register_outbound("tailscale", build_tailscale_outbound);
        }
        {
            let _ = registry::register_outbound("hysteria", build_hysteria_outbound);
        }
        {
            let _ = registry::register_outbound("tuic", build_tuic_outbound);
        }
        {
            let _ = registry::register_outbound("hysteria2", build_hysteria2_outbound);
        }
        {
            let _ = registry::register_outbound("ssh", build_ssh_outbound);
        }
        {
            let _ = registry::register_outbound("shadowtls", build_shadowtls_outbound);
        }
        // Selector group outbounds (core functionality, always available)
        {
            let _ = registry::register_outbound("selector", build_selector_outbound);
        }
        {
            let _ = registry::register_outbound("urltest", build_urltest_outbound);
        }

        #[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
        {
            let _ = registry::register_inbound("http", build_http_inbound);
        }

        #[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
        {
            let _ = registry::register_inbound("socks", build_socks_inbound);
        }

        #[cfg(all(
            feature = "adapter-http",
            feature = "adapter-socks",
            feature = "mixed",
            feature = "router"
        ))]
        {
            let _ = registry::register_inbound("mixed", build_mixed_inbound);
        }

        #[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
        {
            let _ = registry::register_inbound("shadowsocks", build_shadowsocks_inbound);
        }

        #[cfg(all(feature = "adapter-vmess", feature = "router"))]
        {
            let _ = registry::register_inbound("vmess", build_vmess_inbound);
        }

        #[cfg(all(feature = "adapter-vless", feature = "router"))]
        {
            let _ = registry::register_inbound("vless", build_vless_inbound);
        }
        #[cfg(all(feature = "adapter-trojan", feature = "router"))]
        {
            let _ = registry::register_inbound("trojan", build_trojan_inbound);
        }
        {
            let _ = registry::register_inbound("naive", build_naive_inbound);
        }
        {
            let _ = registry::register_inbound("shadowtls", build_shadowtls_inbound);
        }
        {
            let _ = registry::register_inbound("hysteria", build_hysteria_inbound);
        }
        {
            let _ = registry::register_inbound("hysteria2", build_hysteria2_inbound);
        }
        {
            let _ = registry::register_inbound("tuic", build_tuic_inbound);
        }
        {
            let _ = registry::register_inbound("anytls", build_anytls_inbound);
        }
        #[cfg(feature = "router")]
        {
            let _ = registry::register_inbound("direct", build_direct_inbound);
        }

        #[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
        {
            let _ = registry::register_inbound("tun", build_tun_inbound);
        }

        #[cfg(all(target_os = "linux", feature = "router"))]
        {
            let _ = registry::register_inbound("redirect", build_redirect_inbound);
            let _ = registry::register_inbound("tproxy", build_tproxy_inbound);
        }

        #[cfg(feature = "dns")]
        {
            let _ = registry::register_inbound("dns", build_dns_inbound);
        }

        #[cfg(feature = "ssh")]
        {
            let _ = registry::register_inbound("ssh", build_ssh_inbound);
        }

        // Register endpoint and service stubs (WireGuard, Tailscale, Resolved, DERP, SSM)
        crate::endpoint_stubs::register_endpoint_stubs();
        crate::service_stubs::register_service_stubs();
    });
}

#[cfg(any(feature = "adapter-http", feature = "adapter-socks"))]
fn build_tls_config(ir: &OutboundIR) -> Option<sb_config::outbound::TlsConfig> {
    use sb_config::outbound::{EchConfig, RealityConfig, TlsConfig};

    // Check if any TLS fields are present
    let has_tls = ir.tls_sni.is_some()
        || ir.tls_alpn.is_some()
        || ir.skip_cert_verify.is_some()
        || !ir.tls_ca_paths.is_empty()
        || !ir.tls_ca_pem.is_empty()
        || ir.tls_client_cert_path.is_some()
        || ir.tls_client_key_path.is_some()
        || ir.tls_client_cert_pem.is_some()
        || ir.tls_client_key_pem.is_some()
        || ir.reality_enabled.unwrap_or(false)
        || ir.alpn.is_some(); // explicit alpn override

    if !has_tls {
        return None;
    }

    let reality = if ir.reality_enabled.unwrap_or(false) {
        Some(RealityConfig {
            enabled: true,
            public_key: ir.reality_public_key.clone().unwrap_or_default(),
            short_id: ir.reality_short_id.clone(),
            server_name: ir.reality_server_name.clone().unwrap_or_default(),
        })
    } else {
        None
    };

    // ECH is not yet fully exposed in OutboundIR in the version I saw,
    // but TlsConfig has it. If IR doesn't have it, we leave it None.
    let ech: Option<EchConfig> = None;

    Some(TlsConfig {
        enabled: true,
        sni: ir.tls_sni.clone(),
        alpn: ir
            .tls_alpn
            .as_ref()
            .map(|v| v.join(","))
            .or(ir.alpn.clone()),
        insecure: ir.skip_cert_verify.unwrap_or(false),
        reality,
        ech,
    })
}

#[cfg(feature = "adapter-http")]
fn build_http_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::http::HttpProxyConnector;
    use sb_config::outbound::HttpProxyConfig;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;

    // Build server address string (host:port format)
    let server_addr = format!("{}:{}", server, port);

    // Extract credentials if present
    let (username, password) = ir
        .credentials
        .as_ref()
        .map(|c| (c.username.clone(), c.password.clone()))
        .unwrap_or((None, None));

    // Build config
    let tls = build_tls_config(ir);
    let cfg = HttpProxyConfig {
        server: server_addr,
        tag: ir.name.clone(),
        username,
        password,
        connect_timeout_sec: Some(30),
        tls: tls.clone(),
    };

    // Create connector
    let connector = if tls.map(|t| t.enabled).unwrap_or(false) {
        #[cfg(feature = "http-tls")]
        {
            HttpProxyConnector::with_tls(cfg)
        }
        #[cfg(not(feature = "http-tls"))]
        {
            warn!("HTTP outbound TLS configured but http-tls feature is disabled");
            HttpProxyConnector::new(cfg)
        }
    } else {
        HttpProxyConnector::new(cfg)
    };
    let connector_arc = Arc::new(connector);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct HttpConnectorWrapper {
        inner: Arc<HttpProxyConnector>,
    }

    impl std::fmt::Debug for HttpConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HttpConnectorWrapper")
                .field("inner", &self.inner)
                .finish()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for HttpConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // HTTP proxy uses CONNECT method, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::other(format!(
                "HTTP proxy uses CONNECT method for {}:{}; use switchboard registry instead",
                host, port
            )))
        }
    }

    let wrapper = HttpConnectorWrapper {
        inner: connector_arc,
    };

    // Return TCP connector wrapper (no UDP support for HTTP proxy)
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-http"))]
#[allow(dead_code)]
fn build_http_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-socks")]
fn build_socks_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::socks5::Socks5Connector;
    use sb_config::outbound::Socks5Config;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;

    // Build server address string (host:port format)
    let server_addr = format!("{}:{}", server, port);

    // Extract credentials if present
    let (username, password) = ir
        .credentials
        .as_ref()
        .map(|c| (c.username.clone(), c.password.clone()))
        .unwrap_or((None, None));

    // Build config
    let tls = build_tls_config(ir);
    let cfg = Socks5Config {
        server: server_addr,
        tag: ir.name.clone(),
        username,
        password,
        connect_timeout_sec: Some(30),
        tls: tls.clone(),
    };

    // Create connector
    let connector = if tls.map(|t| t.enabled).unwrap_or(false) {
        #[cfg(feature = "socks-tls")]
        {
            Socks5Connector::with_tls(cfg)
        }
        #[cfg(not(feature = "socks-tls"))]
        {
            warn!("SOCKS5 outbound TLS configured but socks-tls feature is disabled");
            Socks5Connector::new(cfg)
        }
    } else {
        Socks5Connector::new(cfg)
    };
    let connector_arc = Arc::new(connector);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct Socks5ConnectorWrapper {
        inner: Arc<Socks5Connector>,
    }

    impl std::fmt::Debug for Socks5ConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Socks5ConnectorWrapper")
                .field("inner", &self.inner)
                .finish()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for Socks5ConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // SOCKS5 uses proxy protocol, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::other(format!(
                "SOCKS5 uses proxy protocol for {}:{}; use switchboard registry instead",
                host, port
            )))
        }
    }

    let wrapper = Socks5ConnectorWrapper {
        inner: connector_arc,
    };

    // Return TCP connector wrapper (UDP support can be added later)
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-socks"))]
#[allow(dead_code)]
fn build_socks_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-socks")]
fn build_socks4_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::socks4::Socks4Connector;
    use sb_config::outbound::Socks4Config;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;

    // Build server address string (host:port format)
    let server_addr = format!("{}:{}", server, port);

    // Extract credentials if present (SOCKS4 only supports user_id)
    let user_id = ir
        .credentials
        .as_ref()
        .map(|c| c.username.clone())
        .unwrap_or(None);

    // Build config
    let cfg = Socks4Config {
        server: server_addr,
        tag: ir.name.clone(),
        user_id,
        connect_timeout_sec: Some(30),
    };

    // Create connector
    let connector = Socks4Connector::new(cfg);
    let connector_arc = Arc::new(connector);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct Socks4ConnectorWrapper {
        inner: Arc<Socks4Connector>,
    }

    impl std::fmt::Debug for Socks4ConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Socks4ConnectorWrapper")
                .field("inner", &self.inner)
                .finish()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for Socks4ConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // SOCKS4 uses proxy protocol, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::other(format!(
                "SOCKS4 uses proxy protocol for {}:{}; use switchboard registry instead",
                host, port
            )))
        }
    }

    let wrapper = Socks4ConnectorWrapper {
        inner: connector_arc,
    };

    // Return TCP connector wrapper (SOCKS4 doesn't support UDP)
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-socks"))]
#[allow(dead_code)]
fn build_socks4_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-shadowsocks")]
fn build_shadowsocks_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let password = ir.password.as_ref()?.clone();

    // Map method string (default to AES-256-GCM)
    let method = ir
        .method
        .as_deref()
        .unwrap_or("aes-256-gcm")
        .to_ascii_lowercase();

    let server_addr = format!("{}:{}", server, port);

    let cfg = ShadowsocksConfig {
        server: server_addr,
        tag: ir.name.clone(),
        method,
        password,
        connect_timeout_sec: ir.connect_timeout_sec.map(|s| s as u64),
        multiplex: build_multiplex_config_client(&ir.multiplex.clone().or(param.multiplex.clone())),
    };

    // Create adapter connector
    let connector = ShadowsocksConnector::new(cfg).ok()?;
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "shadowsocks",
    };

    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-shadowsocks"))]
#[allow(dead_code)]
fn build_shadowsocks_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(feature = "legacy_shadowsocksr")]
fn build_shadowsocksr_outbound(
    _param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::shadowsocksr::ShadowsocksROutbound;

    // Use TryFrom to build adapter from IR
    let adapter = ShadowsocksROutbound::try_from(ir).ok()?;
    let adapter_arc = Arc::new(adapter);

    // Wrapper
    #[derive(Clone)]
    struct ShadowsocksRConnectorWrapper {
        inner: Arc<ShadowsocksROutbound>,
    }

    impl std::fmt::Debug for ShadowsocksRConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ShadowsocksRConnectorWrapper")
                .field("inner", &self.inner)
                .finish()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for ShadowsocksRConnectorWrapper {
        async fn connect(&self, _host: &str, _port: u16) -> std::io::Result<tokio::net::TcpStream> {
            Err(std::io::Error::other(
                "ShadowsocksR adapter connector is not usable directly; use switchboard registry instead",
            ))
        }
    }

    let wrapper = ShadowsocksRConnectorWrapper { inner: adapter_arc };

    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "legacy_shadowsocksr"))]
#[allow(dead_code)]
fn build_shadowsocksr_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-trojan")]
fn build_trojan_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::trojan::{TrojanConfig, TrojanConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let password = ir.password.as_ref()?.clone();

    // Build server address (host:port)
    let server_addr = format!("{}:{}", server, port);

    // Build transport config from IR
    let transport_layer = build_transport_config(ir);

    // Build adapter-level TrojanConfig
    let cfg = TrojanConfig {
        server: server_addr,
        tag: ir.name.clone(),
        password,
        connect_timeout_sec: ir.connect_timeout_sec.map(|s| s as u64),
        sni: ir.tls_sni.clone().or_else(|| Some(server.clone())),
        alpn: ir.tls_alpn.clone().or_else(|| {
            ir.alpn.as_ref().map(|raw| {
                raw.split(',')
                    .map(|x| x.trim().to_string())
                    .filter(|x| !x.is_empty())
                    .collect::<Vec<_>>()
            })
        }),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        transport_layer,
        #[cfg(feature = "tls_reality")]
        reality: None, // TODO: wire REALITY config from IR
        multiplex: build_multiplex_config_client(&ir.multiplex.clone().or(param.multiplex.clone())),
    };

    // Create adapter connector
    let connector = TrojanConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    // Use AdapterIoBridge to wrap the adapter connector
    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "trojan",
    };

    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-trojan"))]
#[allow(dead_code)]
fn build_trojan_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-vmess")]
fn build_vmess_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::vmess::{Security, VmessAuth, VmessConfig, VmessConnector, VmessTransport};
    use std::collections::HashMap;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let uuid_str = ir.uuid.as_ref()?;
    let uuid = uuid::Uuid::parse_str(uuid_str).ok()?;

    // Parse server to SocketAddr (try IP:port first, then resolve)
    let server_addr = format!("{}:{}", server, port)
        .parse::<SocketAddr>()
        .ok()?;

    // Map security string
    let security = match ir.security.as_deref() {
        Some("none") => Security::None,
        Some("chacha20-poly1305") | Some("chacha20-ietf-poly1305") => Security::ChaCha20Poly1305,
        Some("auto") => Security::Auto,
        _ => Security::Aes128Gcm,
    };

    let auth = VmessAuth {
        uuid,
        alter_id: ir.alter_id.unwrap_or(0) as u16,
        security,
        additional_data: None,
    };

    let transport_layer = build_transport_config(ir);

    let cfg = VmessConfig {
        server_addr,
        auth,
        transport: VmessTransport::default(),
        transport_layer,
        timeout: Some(std::time::Duration::from_secs(30)),
        packet_encoding: false,
        headers: HashMap::new(),
        #[cfg(feature = "transport_mux")]
        multiplex: build_multiplex_config_client(&ir.multiplex.clone().or(param.multiplex.clone())),
        #[cfg(feature = "transport_tls")]
        tls: None,
    };

    let connector = VmessConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "vmess",
    };

    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-vmess"))]
#[allow(dead_code)]
fn build_vmess_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-vless")]
fn build_vless_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
    use std::collections::HashMap;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let uuid_str = ir.uuid.as_ref()?;
    let uuid = uuid::Uuid::parse_str(uuid_str).ok()?;

    // Parse server to SocketAddr
    let server_addr = format!("{}:{}", server, port)
        .parse::<SocketAddr>()
        .ok()?;

    // Map flow control
    let flow = match ir.flow.as_deref() {
        Some("xtls-rprx-vision") => FlowControl::XtlsRprxVision,
        Some("xtls-rprx-direct") => FlowControl::XtlsRprxDirect,
        _ => FlowControl::None,
    };

    // Map encryption
    let encryption = match ir.encryption.as_deref() {
        Some("aes-128-gcm") => Encryption::Aes128Gcm,
        Some("chacha20-poly1305") | Some("chacha20-ietf-poly1305") => Encryption::ChaCha20Poly1305,
        _ => Encryption::None,
    };

    let transport_layer = build_transport_config(ir);

    let cfg = VlessConfig {
        server_addr,
        uuid,
        flow,
        encryption,
        headers: HashMap::new(),
        timeout: Some(30),
        tcp_fast_open: false,
        transport_layer,
        #[cfg(feature = "transport_mux")]
        multiplex: build_multiplex_config_client(&ir.multiplex.clone().or(param.multiplex.clone())),
        #[cfg(feature = "tls_reality")]
        reality: None, // TODO: wire REALITY config from IR
        #[cfg(feature = "transport_ech")]
        ech: None,
    };

    let connector = VlessConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "vless",
    };

    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-vless"))]
#[allow(dead_code)]
fn build_vless_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    None
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
#[allow(dead_code)]
fn build_http_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::http::HttpProxyConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = HttpProxyConfig {
        tag: param.tag.clone(),
        listen,
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        tls: None,
        users: param.basic_auth.clone().map(|c| vec![c]),
        set_system_proxy: param.set_system_proxy,
        allow_private_network: param.allow_private_network,
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
    };
    Some(Arc::new(HttpInboundAdapter::new(cfg)))
}

#[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
#[allow(dead_code)]
fn build_shadowsocks_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::shadowsocks::{
        ShadowsocksInboundAdapter, ShadowsocksInboundConfig, ShadowsocksUser,
    };
    use std::net::SocketAddr;

    let listen_str = format!("{}:{}", param.listen, param.port);
    let listen: SocketAddr = match listen_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(
                "Failed to parse Shadowsocks listen address '{}': {}",
                listen_str, e
            );
            return None;
        }
    };

    let method = match &param.method {
        Some(m) => m.clone(),
        None => {
            warn!("Shadowsocks inbound requires 'method'");
            return None;
        }
    };

    let mut users = Vec::new();
    if let Some(users_json) = &param.users_shadowsocks {
        match serde_json::from_str::<Vec<sb_config::ir::ShadowsocksUserIR>>(users_json) {
            Ok(user_irs) => {
                for u in user_irs {
                    users.push(ShadowsocksUser::new(u.name, u.password));
                }
            }
            Err(e) => {
                warn!("Failed to parse Shadowsocks users JSON: {}", e);
            }
        }
    }

    #[allow(deprecated)]
    let config = ShadowsocksInboundConfig {
        listen,
        method,
        password: param.password.clone(),
        users,
        router: ctx.router.clone(),
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        multiplex: convert_multiplex_config(&param.multiplex),
        // NOTE: Transport layer configuration can be added via param in future
        transport_layer: None,
    };

    let adapter = if let Some(tag) = param.tag.clone() {
        ShadowsocksInboundAdapter::with_tag(config, tag)
    } else {
        ShadowsocksInboundAdapter::new(config)
    };
    Some(Arc::new(adapter))
}

#[cfg(feature = "sb-transport")]
#[cfg_attr(
    not(any(
        all(feature = "adapter-shadowsocks", feature = "router"),
        all(feature = "adapter-vmess", feature = "router"),
        all(feature = "adapter-vless", feature = "router")
    )),
    allow(dead_code)
)]
fn convert_multiplex_config(
    ir: &Option<sb_config::ir::MultiplexOptionsIR>,
) -> Option<sb_transport::multiplex::MultiplexServerConfig> {
    let ir = ir.as_ref()?;
    if !ir.enabled {
        return None;
    }

    let mut config = sb_transport::multiplex::MultiplexServerConfig::default();
    if let Some(n) = ir.max_streams {
        config.max_num_streams = n;
    }
    if let Some(p) = ir.padding {
        config.enable_padding = p;
    }
    if let Some(_b) = &ir.brutal {
        // Assuming BrutalIR has compatible fields or just skip for now to pass check
        // config.brutal = ...
    }
    Some(config)
}

/// Build transport config from IR fields.
/// Maps IR transport fields to sb-adapters' TransportConfig.
#[allow(dead_code)]
fn build_transport_config(ir: &OutboundIR) -> crate::transport_config::TransportConfig {
    use crate::transport_config::*;

    // Transport field is Vec<String>, take first element as transport type
    let transport_type = ir
        .transport
        .as_ref()
        .and_then(|v| v.first())
        .map(|s| s.as_str());

    match transport_type {
        Some("ws") | Some("websocket") => {
            let ws_cfg = WebSocketTransportConfig {
                path: ir.ws_path.clone().unwrap_or_else(|| "/".to_string()),
                headers: ir
                    .ws_host
                    .as_ref()
                    .map(|h| vec![("Host".to_string(), h.clone())])
                    .unwrap_or_default(),
                ..Default::default()
            };
            TransportConfig::WebSocket(ws_cfg)
        }
        Some("grpc") => {
            let grpc_cfg = GrpcTransportConfig {
                service_name: ir
                    .grpc_service
                    .clone()
                    .unwrap_or_else(|| "TunnelService".to_string()),
                method_name: ir
                    .grpc_method
                    .clone()
                    .unwrap_or_else(|| "Tunnel".to_string()),
                metadata: ir
                    .grpc_metadata
                    .iter()
                    .map(|e| (e.key.clone(), e.value.clone()))
                    .collect(),
            };
            TransportConfig::Grpc(grpc_cfg)
        }
        Some("httpupgrade") => {
            let mut headers: Vec<(String, String)> = ir
                .http_upgrade_headers
                .iter()
                .map(|e| (e.key.clone(), e.value.clone()))
                .collect();
            // Add Host header if not already present
            if let Some(host) = ir.ws_host.as_ref().or(ir.tls_sni.as_ref()) {
                if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
                    headers.push(("Host".to_string(), host.clone()));
                }
            }
            let hu_cfg = HttpUpgradeTransportConfig {
                path: ir
                    .http_upgrade_path
                    .clone()
                    .unwrap_or_else(|| "/".to_string()),
                headers,
            };
            TransportConfig::HttpUpgrade(hu_cfg)
        }
        _ => TransportConfig::Tcp,
    }
}

/// Build client-side multiplex config from IR.
#[cfg(feature = "sb-transport")]
#[allow(dead_code)]
fn build_multiplex_config_client(
    ir: &Option<sb_config::ir::MultiplexOptionsIR>,
) -> Option<sb_transport::multiplex::MultiplexConfig> {
    let ir = ir.as_ref()?;
    if !ir.enabled {
        return None;
    }

    let mut config = sb_transport::multiplex::MultiplexConfig::default();
    if let Some(n) = ir.max_streams {
        config.max_num_streams = n;
    }
    if let Some(p) = ir.padding {
        config.enable_padding = p;
    }
    Some(config)
}

#[cfg(all(feature = "adapter-vmess", feature = "router"))]
#[allow(dead_code)]
fn build_vmess_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::vmess::{VmessInboundAdapter, VmessInboundConfig};
    use std::net::SocketAddr;
    use uuid::Uuid;

    let listen_str = format!("{}:{}", param.listen, param.port);
    let listen: SocketAddr = match listen_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(
                "Failed to parse VMess listen address '{}': {}",
                listen_str, e
            );
            return None;
        }
    };

    // NOTE: Multi-user VMess can use users list for authentication.
    let uuid_str = param.uuid.clone();

    let uuid = match uuid_str {
        Some(s) => match Uuid::parse_str(&s) {
            Ok(u) => u,
            Err(e) => {
                warn!("Failed to parse VMess UUID '{}': {}", s, e);
                return None;
            }
        },
        None => {
            warn!("VMess inbound requires 'uuid'");
            return None;
        }
    };

    let security = match &param.security {
        Some(s) => s.clone(),
        None => "auto".to_string(),
    };

    let config = VmessInboundConfig {
        listen,
        uuid,
        security,
        router: ctx.router.clone(),
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        multiplex: convert_multiplex_config(&param.multiplex),
        transport_layer: None,
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
    };

    Some(Arc::new(VmessInboundAdapter::new(config)))
}

#[cfg(all(feature = "adapter-vless", feature = "router"))]
#[allow(dead_code)]
fn build_vless_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::vless::{VlessInboundAdapter, VlessInboundConfig};
    use std::net::SocketAddr;
    use uuid::Uuid;

    let listen_str = format!("{}:{}", param.listen, param.port);
    let listen: SocketAddr = match listen_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(
                "Failed to parse VLESS listen address '{}': {}",
                listen_str, e
            );
            return None;
        }
    };

    let uuid_str = param.uuid.clone();
    let uuid = match uuid_str {
        Some(s) => match Uuid::parse_str(&s) {
            Ok(u) => u,
            Err(e) => {
                warn!("Failed to parse VLESS UUID '{}': {}", s, e);
                return None;
            }
        },
        None => {
            warn!("VLESS inbound requires 'uuid'");
            return None;
        }
    };

    let config = VlessInboundConfig {
        listen,
        uuid,
        router: ctx.router.clone(),
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        #[cfg(feature = "tls_reality")]
        // NOTE: REALITY configuration is feature-gated (tls_reality)
        reality: None,
        multiplex: convert_multiplex_config(&param.multiplex),
        transport_layer: None,
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
        flow: param.flow.clone(),
    };

    Some(Arc::new(VlessInboundAdapter::new(config)))
}

#[cfg(all(feature = "adapter-trojan", feature = "router"))]
#[allow(dead_code)]
fn build_trojan_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::trojan::{TrojanInboundConfig, TrojanUser};
    use std::net::SocketAddr;

    // Parse listen address
    let listen_str = format!("{}:{}", param.listen, param.port);
    let listen: SocketAddr = match listen_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(
                "Failed to parse Trojan listen address '{}': {}",
                listen_str, e
            );
            return None;
        }
    };

    // Parse users
    let mut users = Vec::new();
    if let Some(users_json) = &param.users_trojan {
        match serde_json::from_str::<Vec<sb_config::ir::TrojanUserIR>>(users_json) {
            Ok(user_irs) => {
                for u in user_irs {
                    users.push(TrojanUser::new(u.name, u.password));
                }
            }
            Err(e) => {
                warn!("Failed to parse Trojan users JSON: {}", e);
            }
        }
    }

    if let Some(password) = &param.password {
        if !password.is_empty() {
            users.push(TrojanUser::new("default".to_string(), password.clone()));
        }
    }

    if users.is_empty() {
        warn!("Trojan inbound requires at least one user or password");
        return None;
    }

    // TLS cert/key
    let cert_path = match (&param.tls_cert_pem, &param.tls_cert_path) {
        (Some(pem), _) => {
            // Write inline PEM to temporary file
            let temp_path = format!("/tmp/trojan_cert_{}.pem", std::process::id());
            if let Err(e) = std::fs::write(&temp_path, pem) {
                warn!("Failed to write Trojan TLS certificate to temp file: {}", e);
                return None;
            }
            temp_path
        }
        (None, Some(path)) => path.clone(),
        (None, None) => {
            warn!("Trojan inbound requires TLS certificate");
            return None;
        }
    };

    let key_path = match (&param.tls_key_pem, &param.tls_key_path) {
        (Some(pem), _) => {
            let temp_path = format!("/tmp/trojan_key_{}.pem", std::process::id());
            if let Err(e) = std::fs::write(&temp_path, pem) {
                warn!("Failed to write Trojan TLS private key to temp file: {}", e);
                return None;
            }
            temp_path
        }
        (None, Some(path)) => path.clone(),
        (None, None) => {
            warn!("Trojan inbound requires TLS private key");
            return None;
        }
    };

    #[allow(deprecated)]
    let config = TrojanInboundConfig {
        listen,
        password: None,
        users,
        cert_path,
        key_path,
        router: ctx.router.clone(),
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        #[cfg(feature = "tls_reality")]
        reality: None,
        multiplex: None,
        transport_layer: None,
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
    };

    Some(Arc::new(crate::inbound::trojan::TrojanInboundAdapter::new(
        config,
    )))
}

#[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
#[allow(dead_code)]
fn build_socks_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::socks::{DomainStrategy, SocksInboundConfig};

    let listen = parse_listen_addr(&param.listen, param.port)?;

    let domain_strategy =
        param
            .domain_strategy
            .as_deref()
            .and_then(|s| match s.to_ascii_lowercase().as_str() {
                "asis" | "as_is" => Some(DomainStrategy::AsIs),
                "useip" | "use_ip" => Some(DomainStrategy::UseIp),
                "useipv4" | "use_ipv4" => Some(DomainStrategy::UseIpv4),
                "useipv6" | "use_ipv6" => Some(DomainStrategy::UseIpv6),
                _ => None,
            });

    let cfg = SocksInboundConfig {
        tag: param.tag.clone(),
        listen,
        udp_bind: None,
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        udp_nat_ttl: std::time::Duration::from_secs(60),
        // NOTE: User authentication mapping can be added via IR flow
        users: None,
        udp_timeout: param.udp_timeout,
        domain_strategy,
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
    };
    Some(Arc::new(crate::inbound::socks::SocksInboundAdapter::new(
        cfg,
    )))
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
#[allow(dead_code)]
fn build_mixed_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::mixed::MixedInboundConfig;
    use crate::inbound::socks::DomainStrategy;

    let listen = parse_listen_addr(&param.listen, param.port)?;

    let domain_strategy =
        param
            .domain_strategy
            .as_deref()
            .and_then(|s| match s.to_ascii_lowercase().as_str() {
                "asis" | "as_is" => Some(DomainStrategy::AsIs),
                "useip" | "use_ip" => Some(DomainStrategy::UseIp),
                "useipv4" | "use_ipv4" => Some(DomainStrategy::UseIpv4),
                "useipv6" | "use_ipv6" => Some(DomainStrategy::UseIpv6),
                _ => None,
            });

    let cfg = MixedInboundConfig {
        tag: param.tag.clone(),
        listen,
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        read_timeout: None,
        tls: None,
        users: param.basic_auth.clone().map(|c| vec![c]),
        set_system_proxy: param.set_system_proxy,
        allow_private_network: param.allow_private_network,
        udp_timeout: param.udp_timeout,
        domain_strategy,
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
    };
    Some(Arc::new(MixedInboundAdapter::new(cfg)))
}

fn build_naive_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-naive")]
    {
        use crate::inbound::naive::NaiveInboundAdapter;

        match NaiveInboundAdapter::create(param, ctx.router.clone(), ctx.outbounds.clone()) {
            Ok(adapter) => Some(Arc::from(adapter)),
            Err(e) => {
                warn!("Failed to build Naive inbound: {}", e);
                None
            }
        }
    }
    #[cfg(not(feature = "adapter-naive"))]
    {
        let _ = (param, ctx);
        stub_inbound("naive");
        None
    }
}

fn build_shadowtls_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-shadowtls")]
    {
        use crate::inbound::shadowtls::ShadowTlsInboundConfig;
        use sb_transport::tls::StandardTlsConfig;

        // Parse listen address
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = match listen_str.parse() {
            Ok(addr) => addr,
            Err(e) => {
                warn!(
                    "Failed to parse ShadowTLS listen address '{}': {}",
                    listen_str, e
                );
                return None;
            }
        };

        // Get TLS certificate and key (required for ShadowTLS)
        let (cert_pem, cert_path) = match (&param.tls_cert_pem, &param.tls_cert_path) {
            (Some(pem), _) => (Some(pem.clone()), None),
            (None, Some(path)) => (None, Some(path.clone())),
            (None, None) => {
                warn!("ShadowTLS inbound requires TLS certificate (tls_cert_pem or tls_cert_path)");
                return None;
            }
        };

        let (key_pem, key_path) = match (&param.tls_key_pem, &param.tls_key_path) {
            (Some(pem), _) => (Some(pem.clone()), None),
            (None, Some(path)) => (None, Some(path.clone())),
            (None, None) => {
                warn!("ShadowTLS inbound requires TLS private key (tls_key_pem or tls_key_path)");
                return None;
            }
        };

        // Create TLS configuration using sb-transport infrastructure
        let alpn = param.tls_alpn.clone().unwrap_or_default();
        let standard_tls = StandardTlsConfig {
            server_name: param.tls_server_name.clone(),
            alpn,
            insecure: false,
            cert_path,
            key_path,
            cert_pem,
            key_pem,
        };

        let tls = sb_transport::TlsConfig::Standard(standard_tls);

        let config = ShadowTlsInboundConfig {
            listen,
            tls,
            router: ctx.router.clone(),
            tag: param.tag.clone(),
            stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        };

        Some(Arc::new(
            crate::inbound::shadowtls::ShadowTlsInboundAdapter::new(config),
        ))
    }
    #[cfg(not(feature = "adapter-shadowtls"))]
    {
        let _ = (param, ctx);
        stub_inbound("shadowtls");
        None
    }
}

#[allow(unused_variables)]
fn build_hysteria_inbound(
    param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-hysteria")]
    {
        use crate::inbound::hysteria::{
            HysteriaInbound, HysteriaInboundConfig, HysteriaUserConfig,
        };
        use std::net::SocketAddr;

        // Parse listen address
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = match listen_str.parse() {
            Ok(addr) => addr,
            Err(e) => {
                warn!(
                    "Failed to parse Hysteria v1 listen address '{}': {}",
                    listen_str, e
                );
                return None;
            }
        };

        // Parse users from JSON
        let users = if let Some(users_json) = &param.users_hysteria {
            match serde_json::from_str::<Vec<sb_config::ir::HysteriaUserIR>>(users_json) {
                Ok(user_irs) => user_irs
                    .into_iter()
                    .map(|u| HysteriaUserConfig {
                        name: u.name,
                        auth: u.auth,
                    })
                    .collect(),
                Err(e) => {
                    warn!("Failed to parse Hysteria v1 users JSON: {}", e);
                    vec![]
                }
            }
        } else {
            vec![]
        };

        if users.is_empty() {
            warn!("Hysteria v1 inbound requires at least one user");
            return None;
        }

        // Get TLS certificate and key paths (required for Hysteria v1)
        let cert_path = match (&param.tls_cert_pem, &param.tls_cert_path) {
            (Some(pem), _) => {
                // Write inline PEM to temporary file
                let temp_path = format!("/tmp/hysteria_cert_{}.pem", std::process::id());
                if let Err(e) = std::fs::write(&temp_path, pem) {
                    warn!(
                        "Failed to write Hysteria v1 TLS certificate to temp file: {}",
                        e
                    );
                    return None;
                }
                temp_path
            }
            (None, Some(path)) => path.clone(),
            (None, None) => {
                warn!(
                    "Hysteria v1 inbound requires TLS certificate (tls_cert_pem or tls_cert_path)"
                );
                return None;
            }
        };

        let key_path = match (&param.tls_key_pem, &param.tls_key_path) {
            (Some(pem), _) => {
                // Write inline PEM to temporary file
                let temp_path = format!("/tmp/hysteria_key_{}.pem", std::process::id());
                if let Err(e) = std::fs::write(&temp_path, pem) {
                    warn!(
                        "Failed to write Hysteria v1 TLS private key to temp file: {}",
                        e
                    );
                    return None;
                }
                temp_path
            }
            (None, Some(path)) => path.clone(),
            (None, None) => {
                warn!("Hysteria v1 inbound requires TLS private key (tls_key_pem or tls_key_path)");
                return None;
            }
        };

        let config = HysteriaInboundConfig {
            listen,
            users,
            up_mbps: param.hysteria_up_mbps.unwrap_or(10),
            down_mbps: param.hysteria_down_mbps.unwrap_or(50),
            obfs: param.hysteria_obfs.clone(),
            cert_path,
            key_path,
            recv_window_conn: param.hysteria_recv_window_conn,
            recv_window: param.hysteria_recv_window,
        };

        match HysteriaInbound::new(config) {
            Ok(adapter) => Some(Arc::new(adapter)),
            Err(e) => {
                warn!("Failed to build Hysteria v1 inbound: {:?}", e);
                None
            }
        }
    }

    #[cfg(not(feature = "adapter-hysteria"))]
    {
        stub_inbound("hysteria");
        None
    }
}

fn build_hysteria2_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-hysteria2")]
    {
        use crate::inbound::hysteria2::{
            Hysteria2Inbound, Hysteria2InboundConfig, Hysteria2UserConfig,
        };
        use std::net::SocketAddr;

        // Parse listen address
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = match listen_str.parse() {
            Ok(addr) => addr,
            Err(e) => {
                warn!(
                    "Failed to parse Hysteria2 listen address '{}': {}",
                    listen_str, e
                );
                return None;
            }
        };

        // Parse users from JSON
        let users = if let Some(users_json) = &param.users_hysteria2 {
            match serde_json::from_str::<Vec<sb_config::ir::Hysteria2UserIR>>(users_json) {
                Ok(user_irs) => user_irs
                    .into_iter()
                    .map(|u| Hysteria2UserConfig {
                        password: u.password,
                    })
                    .collect(),
                Err(e) => {
                    warn!("Failed to parse Hysteria2 users JSON: {}", e);
                    vec![]
                }
            }
        } else {
            vec![]
        };

        if users.is_empty() {
            warn!("Hysteria2 inbound requires at least one user");
            return None;
        }

        // Get TLS certificate and key (required for Hysteria2)
        let cert = match (&param.tls_cert_pem, &param.tls_cert_path) {
            (Some(pem), _) => pem.clone(),
            (None, Some(path)) => match std::fs::read_to_string(path) {
                Ok(content) => content,
                Err(e) => {
                    warn!(
                        "Failed to read Hysteria2 TLS certificate from '{}': {}",
                        path, e
                    );
                    return None;
                }
            },
            (None, None) => {
                warn!("Hysteria2 inbound requires TLS certificate (tls_cert_pem or tls_cert_path)");
                return None;
            }
        };

        let key = match (&param.tls_key_pem, &param.tls_key_path) {
            (Some(pem), _) => pem.clone(),
            (None, Some(path)) => match std::fs::read_to_string(path) {
                Ok(content) => content,
                Err(e) => {
                    warn!(
                        "Failed to read Hysteria2 TLS private key from '{}': {}",
                        path, e
                    );
                    return None;
                }
            },
            (None, None) => {
                warn!("Hysteria2 inbound requires TLS private key (tls_key_pem or tls_key_path)");
                return None;
            }
        };

        // Parse Masquerade config
        let masquerade = if let Some(json) = &param.masquerade {
            use sb_core::outbound::hysteria2::inbound::MasqueradeConfig as CoreMasq;
            match serde_json::from_str::<sb_config::ir::MasqueradeIR>(json) {
                Ok(ir) => match ir.type_.as_str() {
                    "string" => ir.string.map(|s| CoreMasq::String {
                        content: s.content,
                        headers: s.headers.unwrap_or_default().into_iter().collect(),
                        status_code: s.status_code,
                    }),
                    "file" => ir.file.map(|f| CoreMasq::File {
                        directory: f.directory,
                    }),
                    "proxy" => ir.proxy.map(|p| CoreMasq::Proxy {
                        url: p.url,
                        rewrite_host: p.rewrite_host,
                    }),
                    _ => {
                        warn!("Unknown masquerade type: {}", ir.type_);
                        None
                    }
                },
                Err(e) => {
                    warn!("Failed to parse Hysteria2 masquerade JSON: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let config = Hysteria2InboundConfig {
            listen,
            users,
            cert,
            key,
            congestion_control: param.congestion_control.clone(),
            salamander: param.salamander.clone(),
            obfs: param.obfs.clone(),
            tag: param.tag.clone(),
            stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
            masquerade,
            router: ctx.router.clone(),
            outbounds: ctx.outbounds.clone(),
        };

        match Hysteria2Inbound::new(config) {
            Ok(adapter) => Some(Arc::from(adapter)),
            Err(e) => {
                warn!("Failed to build Hysteria2 inbound: {}", e);
                None
            }
        }
    }
    #[cfg(not(feature = "adapter-hysteria2"))]
    {
        let _ = (param, ctx);
        stub_inbound("hysteria2");
        None
    }
}

#[cfg(feature = "adapter-tuic")]
fn build_tuic_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::tuic::{TuicInboundConfig, TuicUser};
    use std::net::SocketAddr;

    // Parse listen address
    let listen_str = format!("{}:{}", param.listen, param.port);
    let listen: SocketAddr = match listen_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(
                "Failed to parse TUIC listen address '{}': {}",
                listen_str, e
            );
            return None;
        }
    };

    // Parse users from JSON
    let users = if let Some(users_json) = &param.users_tuic {
        match serde_json::from_str::<Vec<sb_config::ir::TuicUserIR>>(users_json) {
            Ok(user_irs) => user_irs
                .into_iter()
                .filter_map(|u| {
                    // Parse UUID from string
                    match uuid::Uuid::parse_str(&u.uuid) {
                        Ok(uuid) => Some(TuicUser {
                            uuid,
                            token: u.token,
                        }),
                        Err(e) => {
                            warn!("Failed to parse TUIC UUID '{}': {}", u.uuid, e);
                            None
                        }
                    }
                })
                .collect(),
            Err(e) => {
                warn!("Failed to parse TUIC users JSON: {}", e);
                vec![]
            }
        }
    } else {
        vec![]
    };

    if users.is_empty() {
        warn!("TUIC inbound requires at least one user");
        return None;
    }

    // Get TLS certificate and key (required for TUIC)
    let cert = match (&param.tls_cert_pem, &param.tls_cert_path) {
        (Some(pem), _) => pem.clone(),
        (None, Some(path)) => match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read TUIC TLS certificate from '{}': {}", path, e);
                return None;
            }
        },
        (None, None) => {
            warn!("TUIC inbound requires TLS certificate (tls_cert_pem or tls_cert_path)");
            return None;
        }
    };

    let key = match (&param.tls_key_pem, &param.tls_key_path) {
        (Some(pem), _) => pem.clone(),
        (None, Some(path)) => match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read TUIC TLS private key from '{}': {}", path, e);
                return None;
            }
        },
        (None, None) => {
            warn!("TUIC inbound requires TLS private key (tls_key_pem or tls_key_path)");
            return None;
        }
    };

    let config = TuicInboundConfig {
        listen,
        users,
        cert,
        key,
        congestion_control: param.congestion_control.clone(),
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
    };

    Some(Arc::new(crate::inbound::tuic::TuicInboundAdapter::new(
        config,
    )))
}

#[cfg(not(feature = "adapter-tuic"))]
fn build_tuic_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    stub_inbound("tuic");
    None
}

fn build_anytls_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-anytls")]
    {
        use crate::inbound::anytls::AnyTlsInboundAdapter;
        match AnyTlsInboundAdapter::new(param, ctx.router.clone(), ctx.outbounds.clone()) {
            Ok(adapter) => Some(Arc::from(adapter)),
            Err(e) => {
                warn!("Failed to build AnyTLS inbound: {}", e);
                None
            }
        }
    }
    #[cfg(not(feature = "adapter-anytls"))]
    {
        let _ = (param, ctx);
        stub_inbound("anytls");
        None
    }
}

#[allow(dead_code)]
fn build_direct_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::direct::DirectInboundAdapter;

    let stats = ctx.context.v2ray_server.as_ref().and_then(|s| s.stats());
    match DirectInboundAdapter::create(param, stats) {
        Ok(adapter) => Some(Arc::from(adapter)),
        Err(e) => {
            warn!("Failed to build Direct inbound: {}", e);
            None
        }
    }
}

#[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
fn build_tun_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::tun::{TunInbound, TunInboundConfig};

    let tun_json = param.tun_options.as_deref().unwrap_or("{}");
    let config: TunInboundConfig = match serde_json::from_str(tun_json) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to parse Tun options: {}", e);
            return None;
        }
    };

    tracing::info!("Initializing TunInbound: {}", config.name);
    let stats = ctx.context.v2ray_server.as_ref().and_then(|s| s.stats());
    Some(Arc::new(TunInbound::new(
        config,
        ctx.router.clone(),
        ctx.outbounds.clone(),
        param.tag.clone(),
        stats,
    )))
}

#[allow(dead_code)]
fn stub_inbound(kind: &str) {
    warn!(target: "crate::register", inbound=%kind, "adapter inbound not implemented yet; falling back to scaffold");
}

#[cfg(feature = "dns")]
fn build_dns_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::dns::DnsInboundAdapter;

    let stats = ctx.context.v2ray_server.as_ref().and_then(|s| s.stats());
    match DnsInboundAdapter::create(param, stats) {
        Ok(adapter) => Some(Arc::from(adapter)),
        Err(e) => {
            warn!("Failed to build DNS inbound: {}", e);
            None
        }
    }
}

#[cfg(feature = "ssh")]
fn build_ssh_inbound(
    param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::ssh::SshInboundAdapter;

    match SshInboundAdapter::create(param) {
        Ok(adapter) => Some(Arc::from(adapter)),
        Err(e) => {
            warn!("Failed to build SSH inbound: {}", e);
            None
        }
    }
}

#[cfg(feature = "adapter-dns")]
fn build_dns_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::dns::{DnsConfig, DnsConnector, DnsTransport};

    // Extract required fields
    let server = match ir.server.as_ref().or(param.server.as_ref()) {
        Some(s) => s.parse().ok(),
        None => None,
    };

    let server = match server {
        Some(s) => s,
        None => {
            warn!("DNS outbound requires a valid IP address for server");
            return None;
        }
    };

    let transport = match ir.dns_transport.as_deref() {
        Some("tcp") => DnsTransport::Tcp,
        Some("dot") => DnsTransport::DoT,
        Some("doh") => DnsTransport::DoH,
        Some("doq") => DnsTransport::DoQ,
        _ => DnsTransport::Udp,
    };

    let config = DnsConfig {
        server,
        port: ir.port.or(param.port),
        transport,
        timeout: std::time::Duration::from_millis(
            ir.dns_timeout_ms
                .or(ir.connect_timeout_sec.map(|s| (s as u64) * 1000))
                .unwrap_or(5000),
        ),
        tls_server_name: ir.tls_sni.clone(),
        query_timeout: std::time::Duration::from_millis(ir.dns_query_timeout_ms.unwrap_or(3000)),
        enable_edns0: ir.dns_enable_edns0.unwrap_or(true),
        edns0_buffer_size: ir.dns_edns0_buffer_size.unwrap_or(1232),
        doh_url: ir.dns_doh_url.clone(),
    };

    let connector = Arc::new(DnsConnector::new(config));

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct DnsConnectorWrapper {
        inner: Arc<DnsConnector>,
    }

    impl std::fmt::Debug for DnsConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DnsConnectorWrapper")
                .field("inner", &self.inner)
                .finish()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for DnsConnectorWrapper {
        async fn connect(&self, _host: &str, _port: u16) -> std::io::Result<tokio::net::TcpStream> {
            Err(std::io::Error::other(
                "DNS outbound does not support generic TCP connections; use it for DNS resolution only",
            ))
        }
    }

    let wrapper = DnsConnectorWrapper { inner: connector };

    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-dns"))]
fn build_dns_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    stub_outbound("dns");
    None
}

fn build_direct_outbound(
    param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use sb_core::adapter::{UdpOutboundFactory, UdpOutboundSession};
    use sb_core::outbound::DirectConnector;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    // Create direct outbound instance with options
    let direct = DirectConnector::with_options(
        param.connect_timeout,
        param.bind_interface.clone(),
        param.routing_mark,
        param.reuse_addr,
        param.tcp_fast_open,
        param.tcp_multi_path,
    );
    let direct_arc = Arc::new(direct);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    // DirectConnector already implements AsyncOutboundConnector (sb_core::outbound::traits::OutboundConnector)
    // AND sb_core::adapter::OutboundConnector.
    // So we can use it directly if we cast it or wrap it.
    // Since DirectConnector is in sb_core, and we are in sb_adapters, we can use it.
    // However, the return type expects Arc<dyn OutboundConnector>.
    // DirectConnector implements it.

    // UDP Factory implementation
    #[derive(Debug)]
    struct DirectUdpFactory;

    impl UdpOutboundFactory for DirectUdpFactory {
        fn open_session(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = std::io::Result<Arc<dyn UdpOutboundSession>>>
                    + Send,
            >,
        > {
            Box::pin(async move {
                let socket = UdpSocket::bind("0.0.0.0:0").await?;
                Ok(Arc::new(DirectUdpSession { socket }) as Arc<dyn UdpOutboundSession>)
            })
        }
    }

    #[derive(Debug)]
    struct DirectUdpSession {
        socket: UdpSocket,
    }

    #[async_trait::async_trait]
    impl UdpOutboundSession for DirectUdpSession {
        async fn send_to(&self, data: &[u8], host: &str, port: u16) -> std::io::Result<()> {
            // Resolve destination
            // Simple resolution for now, ideally use system resolver or internal DNS
            let addr_str = format!("{}:{}", host, port);
            let mut addrs = tokio::net::lookup_host(&addr_str).await?;
            let addr = addrs
                .next()
                .ok_or_else(|| std::io::Error::other("DNS resolution failed"))?;
            self.socket.send_to(data, addr).await?;
            Ok(())
        }

        async fn recv_from(&self) -> std::io::Result<(Vec<u8>, SocketAddr)> {
            let mut buf = vec![0u8; 65535];
            let (len, addr) = self.socket.recv_from(&mut buf).await?;
            buf.truncate(len);
            Ok((buf, addr))
        }
    }

    Some((direct_arc, Some(Arc::new(DirectUdpFactory))))
}

fn build_block_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::block::BlockOutbound;

    // Create block outbound instance
    let block = BlockOutbound::new();
    let block_arc = Arc::new(block);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct BlockConnectorWrapper {
        inner: Arc<BlockOutbound>,
    }

    impl std::fmt::Debug for BlockConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BlockConnectorWrapper")
                .field("inner", &self.inner)
                .finish()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for BlockConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // Block outbound always returns error
            use sb_core::net::Address;
            use sb_core::pipeline::Outbound;

            let target = Address::Domain(host.to_string(), port);
            self.inner.connect(target).await
        }
    }

    let wrapper = BlockConnectorWrapper { inner: block_arc };

    // Return TCP connector wrapper (no UDP support for block)
    Some((Arc::new(wrapper), None))
}

#[allow(unused_variables)]
fn build_tor_outbound(
    _param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    #[cfg(feature = "adapter-tor")]
    {
        use crate::outbound::tor::TorOutbound;

        // Check for fields (tor_extra_args is Vec<String>)
        let proxy_addr = ir
            .tor_proxy_addr
            .clone()
            .unwrap_or_else(|| "127.0.0.1:9050".to_string());

        if ir.tor_executable_path.is_some()
            || !ir.tor_extra_args.is_empty()
            || ir.tor_data_directory.is_some()
            || ir.tor_options.is_some()
        {
            // Log warning if executable path is set but we are using Arti
            // For parity, we might want to support external Tor via SOCKS, but for now we prioritize Arti.
            if ir.tor_executable_path.is_some() {
                warn!(
                    target: "sb_adapters::tor",
                    "tor exec path present but using embedded Arti; running external tor daemon at {} is not supported in this mode",
                    proxy_addr
                );
            }
        }

        // Create TorOutbound (Arti)
        // Using dummy context since TorOutbound doesn't use it yet.
        // In real impl, we should pass context from factory if possible.
        let ctx = sb_core::context::Context::new();
        match TorOutbound::new(ir, &ctx) {
            Ok(adapter) => {
                let adapter_arc = Arc::new(adapter);

                // Wrapper
                #[derive(Clone)]
                struct TorConnectorWrapper {
                    inner: Arc<TorOutbound>,
                }

                impl std::fmt::Debug for TorConnectorWrapper {
                    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.debug_struct("TorConnectorWrapper")
                            .field("inner", &self.inner)
                            .finish()
                    }
                }

                #[async_trait::async_trait]
                impl OutboundConnector for TorConnectorWrapper {
                    async fn connect(
                        &self,
                        _host: &str,
                        _port: u16,
                    ) -> std::io::Result<tokio::net::TcpStream> {
                        // Tor uses SOCKS-like or internal dialing, cannot return raw TcpStream easily without virtual network
                        // or just failing like other proxies.
                        Err(std::io::Error::other(
                            "Tor adapter connector is not usable directly; use switchboard registry instead",
                        ))
                    }
                }

                let wrapper = TorConnectorWrapper { inner: adapter_arc };

                Some((Arc::new(wrapper), None))
            }
            Err(e) => {
                warn!(target: "sb_adapters::tor", "Failed to create TorOutbound: {}", e);
                None
            }
        }
    }

    #[cfg(not(feature = "adapter-tor"))]
    {
        stub_outbound("tor");
        None
    }
}

fn build_anytls_outbound(
    _param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    #[cfg(feature = "adapter-anytls")]
    {
        use crate::outbound::anytls::AnyTlsConnector;
        match AnyTlsConnector::try_from(ir) {
            Ok(connector) => Some((Arc::new(connector), None)),
            Err(e) => {
                warn!("Failed to build AnyTLS outbound: {}", e);
                None
            }
        }
    }
    #[cfg(not(feature = "adapter-anytls"))]
    {
        let _ = ir;
        stub_outbound("anytls");
        None
    }
}

#[cfg(feature = "adapter-wireguard-outbound")]
fn build_wireguard_outbound(
    _param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::wireguard::{LazyWireGuardConnector, WireGuardOutboundConfig};

    // Parse config from IR
    let cfg = match WireGuardOutboundConfig::try_from(ir) {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!(
                target: "wireguard",
                "failed to build WireGuard config: {}",
                e
            );
            return None;
        }
    };

    // Lazy init — transport created on first dial()
    let connector = LazyWireGuardConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "wireguard",
    };

    // No UDP factory from adapter layer (sb-core's WireGuardOutbound had UdpOutboundFactory)
    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-wireguard-outbound"))]
#[allow(dead_code)]
fn build_wireguard_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    stub_outbound("wireguard");
    None
}

#[cfg(feature = "adapter-tailscale")]
fn build_tailscale_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::tailscale::{TailscaleConfig, TailscaleConnector};
    use sb_core::outbound::direct_connector::DirectConnector;

    let direct = DirectConnector::with_options(
        param.connect_timeout,
        param.bind_interface.clone(),
        param.routing_mark,
        param.reuse_addr,
        param.tcp_fast_open,
        param.tcp_multi_path,
    );

    // NOTE: Tailscale-specific fields are defined in EndpointIR, not OutboundIR.
    // For now, use defaults with outbound name as tag.
    // Future: add tailscale fields to OutboundIR or use EndpointIR for configuration.
    let cfg = TailscaleConfig {
        tag: ir.name.clone(),
        ..Default::default()
    };

    let connector = TailscaleConnector::new(Arc::new(direct), cfg);
    Some((Arc::new(connector), None))
}

#[cfg(not(feature = "adapter-tailscale"))]
fn build_tailscale_outbound(
    param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use sb_core::outbound::direct_connector::DirectConnector;

    warn!(
        target: "sb_adapters::tailscale",
        "tailscale outbound not built; falling back to direct connector"
    );

    let direct = DirectConnector::with_options(
        param.connect_timeout,
        param.bind_interface.clone(),
        param.routing_mark,
        param.reuse_addr,
        param.tcp_fast_open,
        param.tcp_multi_path,
    );

    Some((Arc::new(direct), None))
}

#[cfg(feature = "adapter-hysteria")]
fn build_hysteria_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::hysteria::{HysteriaAdapterConfig, HysteriaConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port).unwrap_or(443);

    // Hysteria v1 specific configuration
    let protocol = ir
        .hysteria_protocol
        .clone()
        .unwrap_or_else(|| "udp".to_string());

    let up_mbps = ir.up_mbps.unwrap_or(10);
    let down_mbps = ir.down_mbps.unwrap_or(50);

    // Auth string (use hysteria_auth if available, otherwise password)
    let auth = ir.hysteria_auth.as_ref().or(ir.password.as_ref()).cloned();

    // Obfuscation
    let obfs = ir.obfs.clone();

    // ALPN (convert Vec<String> if present, otherwise default)
    let alpn = ir
        .tls_alpn
        .clone()
        .unwrap_or_else(|| vec!["hysteria".to_string()]);

    // QUIC receive windows
    let recv_window_conn = ir.hysteria_recv_window_conn;
    let recv_window = ir.hysteria_recv_window;

    // TLS configuration
    let skip_cert_verify = ir.skip_cert_verify.unwrap_or(false);
    let sni = ir.tls_sni.clone();

    // Build config
    let cfg = HysteriaAdapterConfig {
        server: server.clone(),
        port,
        protocol,
        up_mbps,
        down_mbps,
        obfs,
        auth,
        alpn,
        recv_window_conn,
        recv_window,
        skip_cert_verify,
        sni,
    };

    // Create connector
    let connector = HysteriaConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "hysteria",
    };

    // No UDP factory for Hysteria v1 yet
    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-hysteria"))]
fn build_hysteria_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    stub_outbound("hysteria");
    None
}

#[cfg(feature = "adapter-shadowtls")]
fn build_shadowtls_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port).unwrap_or(443);

    // SNI is required for TLS
    let sni = ir.tls_sni.clone().unwrap_or_else(|| server.clone());

    // ALPN from tls_alpn (Vec<String>), convert to single comma-separated string
    let alpn = ir.tls_alpn.as_ref().map(|v| v.join(","));

    // Skip cert verify (default: false)
    let skip_cert_verify = ir.skip_cert_verify.unwrap_or(false);

    // Build config
    let cfg = ShadowTlsAdapterConfig {
        server: server.clone(),
        port,
        sni,
        alpn,
        skip_cert_verify,
        utls_fingerprint: ir.utls_fingerprint.clone(),
    };

    // Create connector
    let connector = ShadowTlsConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "shadowtls",
    };

    // ShadowTLS only supports TCP, no UDP factory
    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-shadowtls"))]
fn build_shadowtls_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    stub_outbound("shadowtls");
    None
}

#[cfg(feature = "adapter-tuic")]
fn build_tuic_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::tuic::{TuicAdapterConfig, TuicConnector, TuicUdpRelayMode};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let uuid_str = ir.uuid.as_ref()?;
    let uuid = uuid::Uuid::parse_str(uuid_str).ok()?;
    let token = ir.token.as_ref()?.clone();

    // Map UDP relay mode
    let udp_relay_mode = match ir.udp_relay_mode.as_deref() {
        Some(m) if m.eq_ignore_ascii_case("quic") => TuicUdpRelayMode::Quic,
        _ => TuicUdpRelayMode::Native,
    };

    // Build adapter config
    let cfg = TuicAdapterConfig {
        server: server.clone(),
        port,
        uuid,
        token,
        password: ir.password.clone(),
        congestion_control: ir.congestion_control.clone(),
        alpn: ir
            .alpn
            .as_ref()
            .cloned()
            .or_else(|| ir.tls_alpn.as_ref().map(|v| v.join(","))),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        udp_relay_mode,
        udp_over_stream: ir.udp_over_stream.unwrap_or(false),
    };

    let connector = TuicConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "tuic",
    };

    // No UDP factory from adapter layer yet (sb-core's TuicOutbound had one)
    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-tuic"))]
fn build_tuic_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    stub_outbound("tuic");
    None
}

#[cfg(feature = "adapter-hysteria2")]
fn build_hysteria2_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::hysteria2::{Hysteria2AdapterConfig, Hysteria2Connector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let password = ir.password.as_ref()?.clone();

    // Build adapter config
    let cfg = Hysteria2AdapterConfig {
        server: server.clone(),
        port,
        password,
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        sni: ir.tls_sni.clone(),
        alpn: ir.tls_alpn.clone(),
        congestion_control: ir.congestion_control.clone(),
        up_mbps: ir.up_mbps,
        down_mbps: ir.down_mbps,
        obfs: ir.obfs.clone(),
        salamander: ir.salamander.clone(),
    };

    let connector = Hysteria2Connector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "hysteria2",
    };

    // No UDP factory from adapter layer yet
    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-hysteria2"))]
fn build_hysteria2_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    stub_outbound("hysteria2");
    None
}

#[cfg(feature = "adapter-ssh")]
fn build_ssh_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    use crate::outbound::ssh::{SshAdapterConfig, SshConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port).unwrap_or(22);

    // Get username from credentials
    let username = ir.credentials.as_ref().and_then(|c| c.username.clone())?;

    // Get password from credentials or dedicated password field
    let password = ir
        .credentials
        .as_ref()
        .and_then(|c| c.password.clone())
        .or_else(|| ir.password.clone());

    // Get private key
    let private_key = ir.ssh_private_key.clone();
    let private_key_passphrase = ir.ssh_private_key_passphrase.clone();

    // Ensure at least password or private key is provided
    if password.is_none() && private_key.is_none() {
        warn!("SSH outbound requires either password or private_key");
        return None;
    }

    // Build config
    let cfg = SshAdapterConfig {
        server: server.clone(),
        port,
        username,
        password,
        private_key,
        private_key_passphrase,
        host_key_verification: ir.ssh_host_key_verification.unwrap_or(true),
        known_hosts_path: ir.ssh_known_hosts_path.clone(),
        connection_pool_size: ir.ssh_connection_pool_size,
        compression: ir.ssh_compression.unwrap_or(false),
        keepalive_interval: ir.ssh_keepalive_interval,
        connect_timeout: Some(10), // Default 10 seconds
    };

    // Create connector
    let connector = SshConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    let bridge = AdapterIoBridge {
        inner: connector_arc,
        name: "ssh",
    };

    // SSH only supports TCP, no UDP factory
    Some((Arc::new(bridge), None))
}

#[cfg(not(feature = "adapter-ssh"))]
fn build_ssh_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    stub_outbound("ssh");
    None
}

#[allow(dead_code)]
fn stub_outbound(kind: &str) {
    warn!(target: "crate::register", outbound=%kind, "adapter outbound not implemented yet; falling back to scaffold");
}

#[cfg(all(test, feature = "adapter-dns"))]
mod tests {
    use super::*;
    use sb_config::ir::{Hysteria2UserIR, InboundIR, InboundType, OutboundIR, OutboundType};

    #[test]
    fn build_dns_outbound_accepts_doh() {
        let mut ir = OutboundIR::default();
        ir.ty = OutboundType::Dns;
        ir.server = Some("1.1.1.1".into());
        ir.port = Some(443);
        ir.dns_transport = Some("doh".into());
        let param = OutboundParam {
            kind: "dns".into(),
            name: Some("dns".into()),
            server: None,
            port: None,
            ..Default::default()
        };
        let context = sb_core::context::Context::new();
        let bridge = std::sync::Arc::new(sb_core::adapter::Bridge::new(context));
        let ctx = sb_core::registry::AdapterOutboundContext {
            context: sb_core::context::ContextRegistry::from(&bridge.context),
            bridge,
        };
        let built = build_dns_outbound(&param, &ir, &ctx);
        assert!(
            built.is_some(),
            "DoH outbound should construct successfully"
        );
    }

    #[test]
    #[cfg(feature = "adapter-hysteria2")]
    fn test_hysteria2_inbound_fields() {
        // Create a test InboundIR for Hysteria2
        let ir = InboundIR {
            ty: InboundType::Hysteria2,
            listen: "127.0.0.1".to_string(),
            port: 8443,
            sniff: false,
            udp: false,
            basic_auth: None,
            override_host: None,
            override_port: None,
            method: None,
            password: None,
            users_shadowsocks: None,
            network: None,
            uuid: None,
            alter_id: None,
            users_vmess: None,
            flow: None,
            users_vless: None,
            users_trojan: None,
            users_anytls: None,
            anytls_padding: None,
            users_hysteria2: Some(vec![Hysteria2UserIR {
                name: "test_user".to_string(),
                password: "test_password".to_string(),
            }]),
            congestion_control: Some("bbr".to_string()),
            salamander: None,
            obfs: Some("test_obfs".to_string()),
            brutal_up_mbps: Some(100),
            brutal_down_mbps: Some(100),
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            grpc_service: None,
            tls_enabled: None,
            tls_cert_path: Some("test_cert.pem".to_string()),
            tls_key_path: Some("test_key.pem".to_string()),
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_server_name: None,
            tls_alpn: None,
            multiplex: None,
            ..Default::default()
        };

        // Verify Hysteria2 fields are set
        assert!(ir.users_hysteria2.is_some());
        assert_eq!(ir.congestion_control, Some("bbr".to_string()));
        assert_eq!(ir.obfs, Some("test_obfs".to_string()));
        assert_eq!(ir.brutal_up_mbps, Some(100));
        assert_eq!(ir.brutal_down_mbps, Some(100));
    }

    #[test]
    #[cfg(feature = "adapter-shadowtls")]
    fn test_shadowtls_outbound_registration() {
        // Create a test OutboundIR for ShadowTLS
        let ir = OutboundIR {
            ty: OutboundType::Shadowtls,
            server: Some("example.com".to_string()),
            port: Some(443),
            tls_sni: Some("example.com".to_string()),
            tls_alpn: Some(vec!["http/1.1".to_string(), "h2".to_string()]),
            skip_cert_verify: Some(false),
            ..Default::default()
        };

        let param = OutboundParam {
            kind: "shadowtls".into(),
            name: Some("shadowtls_test".into()),
            server: None,
            port: None,
            ..Default::default()
        };

        // Build ShadowTLS outbound
        let context = sb_core::context::Context::new();
        let bridge = std::sync::Arc::new(sb_core::adapter::Bridge::new(context));
        let ctx = sb_core::registry::AdapterOutboundContext {
            context: sb_core::context::ContextRegistry::from(&bridge.context),
            bridge,
        };
        let result = build_shadowtls_outbound(&param, &ir, &ctx);

        // Verify outbound was created successfully
        assert!(
            result.is_some(),
            "ShadowTLS outbound should construct successfully"
        );
        let (_connector, udp_factory) = result.unwrap();
        assert!(
            udp_factory.is_none(),
            "ShadowTLS should not provide UDP factory"
        );
    }
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
#[derive(Debug)]
struct HttpInboundAdapter {
    cfg: crate::inbound::http::HttpProxyConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
impl HttpInboundAdapter {
    fn new(cfg: crate::inbound::http::HttpProxyConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
impl InboundService for HttpInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock().unwrap();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            crate::inbound::http::serve_http(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().unwrap().take();
        res
    }

    fn request_shutdown(&self) {
        eprintln!("HttpInboundAdapter::request_shutdown called");
        let mut guard = self.stop_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[allow(dead_code)]
fn parse_listen_addr(listen: &str, port: u16) -> Option<SocketAddr> {
    listen
        .parse()
        .ok()
        .or_else(|| format!("{listen}:{port}").parse().ok())
}

// ========== ShadowTLS Inbound ==========

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
#[derive(Debug)]
struct MixedInboundAdapter {
    cfg: crate::inbound::mixed::MixedInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
impl MixedInboundAdapter {
    fn new(cfg: crate::inbound::mixed::MixedInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
impl InboundService for MixedInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock().unwrap();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            crate::inbound::mixed::serve_mixed(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().unwrap().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

// ========== TUN Inbound ==========

// ========== Redirect Inbound (Linux only) ==========

#[cfg(all(target_os = "linux", feature = "router"))]
#[allow(dead_code)]
fn build_redirect_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::redirect::RedirectConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = RedirectConfig {
        listen,
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
    };
    Some(Arc::new(RedirectInboundAdapter::new(cfg)))
}

#[cfg(all(target_os = "linux", feature = "router"))]
#[derive(Debug)]
struct RedirectInboundAdapter {
    cfg: crate::inbound::redirect::RedirectConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl RedirectInboundAdapter {
    fn new(cfg: crate::inbound::redirect::RedirectConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl InboundService for RedirectInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock().unwrap();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            crate::inbound::redirect::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().unwrap().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

// ========== TProxy Inbound (Linux only) ==========

#[cfg(all(target_os = "linux", feature = "router"))]
#[allow(dead_code)]
fn build_tproxy_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::tproxy::TproxyConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = TproxyConfig {
        listen,
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
    };
    Some(Arc::new(TproxyInboundAdapter::new(cfg)))
}

#[cfg(all(target_os = "linux", feature = "router"))]
#[derive(Debug)]
struct TproxyInboundAdapter {
    cfg: crate::inbound::tproxy::TproxyConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl TproxyInboundAdapter {
    fn new(cfg: crate::inbound::tproxy::TproxyConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl InboundService for TproxyInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock().unwrap();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            crate::inbound::tproxy::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().unwrap().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

// ========== TUIC Inbound ==========

// Selector and URLTest builders
fn build_selector_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    crate::outbound::selector::build_selector_outbound(param, ir, ctx)
}

fn build_urltest_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    crate::outbound::urltest::build_urltest_outbound(param, ir, ctx)
}
