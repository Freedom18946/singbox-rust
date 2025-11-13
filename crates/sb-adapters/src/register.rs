use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::io;
use parking_lot::Mutex;

use sb_config::ir::OutboundIR;
use sb_core::adapter::registry;
use sb_core::adapter::{
    InboundParam, InboundService, OutboundConnector, OutboundParam, UdpOutboundFactory,
};
use tracing::warn;

static REGISTER_ONCE: Once = Once::new();

/// Register adapter-provided builders with sb-core registry. Safe to call multiple times.
pub fn register_all() {
    REGISTER_ONCE.call_once(|| {
        #[cfg(feature = "adapter-http")]
        {
            let _ = registry::register_outbound("http", build_http_outbound);
        }
        #[cfg(feature = "adapter-socks")]
        {
            let _ = registry::register_outbound("socks", build_socks_outbound);
        }
        #[cfg(feature = "adapter-shadowsocks")]
        {
            let _ = registry::register_outbound("shadowsocks", build_shadowsocks_outbound);
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
    });
}

#[cfg(feature = "adapter-http")]
fn build_http_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    use crate::outbound::http::HttpProxyConnector;
    use sb_config::outbound::HttpProxyConfig;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;

    // Build server address string (host:port format)
    let server_addr = format!("{}:{}", server, port);

    // Extract credentials if present
    let (username, password) = ir.credentials.as_ref()
        .map(|c| (c.username.clone(), c.password.clone()))
        .unwrap_or((None, None));

    // Build config
    let cfg = HttpProxyConfig {
        server: server_addr,
        tag: ir.name.clone(),
        username,
        password,
        connect_timeout_sec: Some(30),
        tls: None, // TODO: Add TLS support from IR
    };

    // Create connector
    let connector = HttpProxyConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct HttpConnectorWrapper {
        inner: Arc<HttpProxyConnector>,
    }

    impl std::fmt::Debug for HttpConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HttpConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for HttpConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // HTTP proxy uses CONNECT method, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HTTP proxy uses CONNECT method for {}:{}; use switchboard registry instead", host, port),
            ))
        }
    }

    let wrapper = HttpConnectorWrapper {
        inner: connector_arc,
    };

    // Return TCP connector wrapper (no UDP support for HTTP proxy)
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-http"))]
fn build_http_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(feature = "adapter-socks")]
fn build_socks_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    use crate::outbound::socks5::Socks5Connector;
    use sb_config::outbound::Socks5Config;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;

    // Build server address string (host:port format)
    let server_addr = format!("{}:{}", server, port);

    // Extract credentials if present
    let (username, password) = ir.credentials.as_ref()
        .map(|c| (c.username.clone(), c.password.clone()))
        .unwrap_or((None, None));

    // Build config
    let cfg = Socks5Config {
        server: server_addr,
        tag: ir.name.clone(),
        username,
        password,
        connect_timeout_sec: Some(30),
        tls: None, // TODO: Add TLS support from IR
    };

    // Create connector
    let connector = Socks5Connector::new(cfg);
    let connector_arc = Arc::new(connector);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct Socks5ConnectorWrapper {
        inner: Arc<Socks5Connector>,
    }

    impl std::fmt::Debug for Socks5ConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Socks5ConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for Socks5ConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // SOCKS5 uses proxy protocol, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("SOCKS5 uses proxy protocol for {}:{}; use switchboard registry instead", host, port),
            ))
        }
    }

    let wrapper = Socks5ConnectorWrapper {
        inner: connector_arc,
    };

    // Return TCP connector wrapper (UDP support can be added later)
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-socks"))]
fn build_socks_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(all(feature = "adapter-shadowsocks", feature = "out_ss"))]
fn build_shadowsocks_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    use sb_core::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksOutbound};
    use sb_core::outbound::crypto_types::OutboundTcp;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let method = ir.method.as_ref()?.clone();
    let password = ir.password.as_ref()?.clone();

    // Build config
    let cfg = ShadowsocksConfig {
        server: server.clone(),
        port,
        method,
        password,
        plugin: ir.plugin.clone(),
        plugin_opts: ir.plugin_opts.clone(),
    };

    // Create outbound
    let outbound = ShadowsocksOutbound::new(cfg);
    let outbound_arc = Arc::new(outbound);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct ShadowsocksConnectorWrapper {
        inner: Arc<ShadowsocksOutbound>,
    }

    impl std::fmt::Debug for ShadowsocksConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ShadowsocksConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for ShadowsocksConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // Shadowsocks uses encrypted stream, cannot return TcpStream directly
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Shadowsocks uses encrypted stream; use switchboard registry instead",
            ))
        }
    }

    let wrapper = ShadowsocksConnectorWrapper {
        inner: outbound_arc.clone(),
    };

    // Return TCP connector wrapper and UDP factory
    Some((
        Arc::new(wrapper),
        Some(outbound_arc as Arc<dyn UdpOutboundFactory>),
    ))
}

#[cfg(not(all(feature = "adapter-shadowsocks", feature = "out_ss")))]
fn build_shadowsocks_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(all(feature = "adapter-trojan", feature = "out_trojan"))]
fn build_trojan_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    use sb_core::outbound::trojan::{TrojanConfig, TrojanOutbound};
    use sb_core::outbound::crypto_types::OutboundTcp;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let password = ir.password.as_ref()?.clone();

    // Build config
    let cfg = TrojanConfig {
        server: server.clone(),
        port,
        password,
        sni: ir.tls_sni.clone(),
        alpn: ir
            .tls_alpn
            .clone()
            .or_else(|| {
                ir.alpn.as_ref().map(|raw| {
                    raw.split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect::<Vec<_>>()
                })
            }),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        tls_ca_paths: ir.tls_ca_paths.clone(),
        tls_ca_pem: ir.tls_ca_pem.clone(),
    };

    // Create outbound
    let outbound = TrojanOutbound::new(cfg).ok()?;
    let outbound_arc = Arc::new(outbound);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct TrojanConnectorWrapper {
        inner: Arc<TrojanOutbound>,
    }

    impl std::fmt::Debug for TrojanConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TrojanConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for TrojanConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // Trojan uses encrypted stream, cannot return TcpStream directly
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Trojan uses encrypted stream; use switchboard registry instead",
            ))
        }
    }

    let wrapper = TrojanConnectorWrapper {
        inner: outbound_arc.clone(),
    };

    // Return TCP connector wrapper and UDP factory
    Some((
        Arc::new(wrapper),
        Some(outbound_arc as Arc<dyn UdpOutboundFactory>),
    ))
}

#[cfg(not(all(feature = "adapter-trojan", feature = "out_trojan")))]
fn build_trojan_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(all(feature = "adapter-vmess", feature = "out_vmess"))]
fn build_vmess_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    use sb_core::outbound::vmess::{VmessConfig, VmessOutbound};
    use sb_core::outbound::crypto_types::OutboundTcp;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let uuid_str = ir.uuid.as_ref()?;
    let uuid = uuid::Uuid::parse_str(uuid_str).ok()?;

    // Build config
    let cfg = VmessConfig {
        server: server.clone(),
        port,
        id: uuid,
        security: ir
            .security
            .clone()
            .unwrap_or_else(|| "aes-128-gcm".to_string()),
        alter_id: ir.alter_id.unwrap_or(0),
        transport: ir.transport.clone(),
        ws_path: ir.ws_path.clone(),
        ws_host: ir.ws_host.clone(),
        h2_path: ir.h2_path.clone(),
        h2_host: ir.h2_host.clone(),
        tls_sni: ir.tls_sni.clone(),
        tls_alpn: ir.tls_alpn.clone(),
        grpc_service: ir.grpc_service.clone(),
        grpc_method: ir.grpc_method.clone(),
        grpc_authority: ir.grpc_authority.clone(),
        grpc_metadata: ir.grpc_metadata.iter().map(|e| (e.key.clone(), e.value.clone())).collect(),
        http_upgrade_path: ir.http_upgrade_path.clone(),
        http_upgrade_headers: ir.http_upgrade_headers.iter().map(|e| (e.key.clone(), e.value.clone())).collect(),
    };

    // Create outbound
    let outbound = VmessOutbound::new(cfg).ok()?;
    let outbound_arc = Arc::new(outbound);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct VmessConnectorWrapper {
        inner: Arc<VmessOutbound>,
    }

    impl std::fmt::Debug for VmessConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("VmessConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for VmessConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // VMess uses encrypted stream, cannot return TcpStream directly
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "VMess uses encrypted stream; use switchboard registry instead",
            ))
        }
    }

    let wrapper = VmessConnectorWrapper {
        inner: outbound_arc.clone(),
    };

    // Return TCP connector wrapper (VMess doesn't support UDP factory yet)
    Some((
        Arc::new(wrapper),
        None,
    ))
}

#[cfg(not(all(feature = "adapter-vmess", feature = "out_vmess")))]
fn build_vmess_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(all(feature = "adapter-vless", feature = "out_vless"))]
fn build_vless_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    use sb_core::outbound::vless::{VlessConfig, VlessOutbound};
    use sb_core::outbound::crypto_types::OutboundTcp;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let uuid_str = ir.uuid.as_ref()?;
    let uuid = uuid::Uuid::parse_str(uuid_str).ok()?;

    // Build config
    let cfg = VlessConfig {
        server: server.clone(),
        port,
        uuid,
        flow: ir.flow.clone(),
        encryption: ir.encryption.clone(),
        transport: ir.transport.clone(),
        ws_path: ir.ws_path.clone(),
        ws_host: ir.ws_host.clone(),
        h2_path: ir.h2_path.clone(),
        h2_host: ir.h2_host.clone(),
        tls_sni: ir.tls_sni.clone(),
        tls_alpn: ir.tls_alpn.clone(),
        grpc_service: ir.grpc_service.clone(),
        grpc_method: ir.grpc_method.clone(),
        grpc_authority: ir.grpc_authority.clone(),
        grpc_metadata: ir.grpc_metadata.iter().map(|e| (e.key.clone(), e.value.clone())).collect(),
        http_upgrade_path: ir.http_upgrade_path.clone(),
        http_upgrade_headers: ir.http_upgrade_headers.iter().map(|e| (e.key.clone(), e.value.clone())).collect(),
    };

    // Create outbound
    let outbound = VlessOutbound::new(cfg).ok()?;
    let outbound_arc = Arc::new(outbound);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct VlessConnectorWrapper {
        inner: Arc<VlessOutbound>,
    }

    impl std::fmt::Debug for VlessConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("VlessConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for VlessConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // VLESS uses encrypted stream, cannot return TcpStream directly
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "VLESS uses encrypted stream; use switchboard registry instead",
            ))
        }
    }

    let wrapper = VlessConnectorWrapper {
        inner: outbound_arc.clone(),
    };

    // Return TCP connector wrapper (VLESS doesn't support UDP factory yet)
    Some((
        Arc::new(wrapper),
        None,
    ))
}

#[cfg(not(all(feature = "adapter-vless", feature = "out_vless")))]
fn build_vless_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
fn build_http_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::http::HttpProxyConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = HttpProxyConfig {
        listen,
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        tls: None,
    };
    Some(Arc::new(HttpInboundAdapter::new(cfg)))
}

#[cfg(not(all(feature = "adapter-http", feature = "http", feature = "router")))]
fn build_http_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
fn build_shadowsocks_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = ShadowsocksInboundConfig {
        listen,
        method: param.name.clone().unwrap_or_else(|| "aes-256-gcm".into()),
        password: param.password.clone().unwrap_or_else(|| "password".into()),
        router: ctx.router.clone(),
        multiplex: None,
        transport_layer: None,
    };
    Some(Arc::new(ShadowsocksInboundAdapter::new(cfg)))
}

#[cfg(not(all(feature = "adapter-shadowsocks", feature = "router")))]
fn build_shadowsocks_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(feature = "adapter-vmess", feature = "router"))]
fn build_vmess_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::vmess::VmessInboundConfig;
    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = VmessInboundConfig {
        listen,
        uuid: param.uuid.clone()?.parse().ok()?,
        security: param
            .credentials
            .as_ref()
            .and_then(|c| c.password.clone())
            .unwrap_or_else(|| "aes-128-gcm".into()),
        router: ctx.router.clone(),
        multiplex: None,
        transport_layer: None,
    };
    Some(Arc::new(VmessInboundAdapter::new(cfg)))
}

#[cfg(not(all(feature = "adapter-vmess", feature = "router")))]
fn build_vmess_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(feature = "adapter-vless", feature = "router"))]
fn build_vless_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::vless::VlessInboundConfig;
    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = VlessInboundConfig {
        listen,
        uuid: param.uuid.clone()?.parse().ok()?,
        flow: None,
        encryption: Some("none".into()),
        router: ctx.router.clone(),
        multiplex: None,
        transport_layer: None,
    };
    Some(Arc::new(VlessInboundAdapter::new(cfg)))
}

#[cfg(not(all(feature = "adapter-vless", feature = "router")))]
fn build_vless_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(feature = "adapter-trojan", feature = "router"))]
fn build_trojan_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::trojan::TrojanInboundConfig;
    let cfg = TrojanInboundConfig::default();
    Some(Arc::new(TrojanInboundAdapter::new(cfg)))
}

#[cfg(not(all(feature = "adapter-trojan", feature = "router")))]
fn build_trojan_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
fn build_socks_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::socks::SocksInboundConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = SocksInboundConfig {
        listen,
        udp_bind: None,
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        udp_nat_ttl: Duration::from_secs(60),
    };
    Some(Arc::new(SocksInboundAdapter::new(cfg)))
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
fn build_mixed_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::mixed::MixedInboundConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = MixedInboundConfig {
        listen,
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        read_timeout: None,
        tls: None,
    };
    Some(Arc::new(MixedInboundAdapter::new(cfg)))
}

#[cfg(not(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
)))]
fn build_mixed_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(not(all(feature = "adapter-socks", feature = "socks", feature = "router")))]
fn build_socks_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

fn build_naive_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-naive")]
    {
        use crate::inbound::naive::NaiveInboundAdapter;

        match NaiveInboundAdapter::new(param, ctx.router.clone()) {
            Ok(adapter) => Some(Arc::from(adapter)),
            Err(e) => {
                warn!("Failed to build Naive inbound: {}", e);
                None
            }
        }
    }
    #[cfg(not(feature = "adapter-naive"))]
    {
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
                warn!("Failed to parse ShadowTLS listen address '{}': {}", listen_str, e);
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
        };

        Some(Arc::new(ShadowTlsInboundAdapter::new(config)))
    }
    #[cfg(not(feature = "adapter-shadowtls"))]
    {
        stub_inbound("shadowtls");
        None
    }
}

fn build_hysteria_inbound(
    param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-hysteria")]
    {
        use crate::inbound::hysteria::{HysteriaInbound, HysteriaInboundConfig, HysteriaUserConfig};
        use std::net::SocketAddr;

        // Parse listen address
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = match listen_str.parse() {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Failed to parse Hysteria v1 listen address '{}': {}", listen_str, e);
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
                    warn!("Failed to write Hysteria v1 TLS certificate to temp file: {}", e);
                    return None;
                }
                temp_path
            }
            (None, Some(path)) => path.clone(),
            (None, None) => {
                warn!("Hysteria v1 inbound requires TLS certificate (tls_cert_pem or tls_cert_path)");
                return None;
            }
        };

        let key_path = match (&param.tls_key_pem, &param.tls_key_path) {
            (Some(pem), _) => {
                // Write inline PEM to temporary file
                let temp_path = format!("/tmp/hysteria_key_{}.pem", std::process::id());
                if let Err(e) = std::fs::write(&temp_path, pem) {
                    warn!("Failed to write Hysteria v1 TLS private key to temp file: {}", e);
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
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    #[cfg(feature = "adapter-hysteria2")]
    {
        use crate::inbound::hysteria2::{Hysteria2Inbound, Hysteria2InboundConfig, Hysteria2UserConfig};
        use std::net::SocketAddr;

        // Parse listen address
        let listen_str = format!("{}:{}", param.listen, param.port);
        let listen: SocketAddr = match listen_str.parse() {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Failed to parse Hysteria2 listen address '{}': {}", listen_str, e);
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
            (None, Some(path)) => {
                match std::fs::read_to_string(path) {
                    Ok(content) => content,
                    Err(e) => {
                        warn!("Failed to read Hysteria2 TLS certificate from '{}': {}", path, e);
                        return None;
                    }
                }
            }
            (None, None) => {
                warn!("Hysteria2 inbound requires TLS certificate (tls_cert_pem or tls_cert_path)");
                return None;
            }
        };

        let key = match (&param.tls_key_pem, &param.tls_key_path) {
            (Some(pem), _) => pem.clone(),
            (None, Some(path)) => {
                match std::fs::read_to_string(path) {
                    Ok(content) => content,
                    Err(e) => {
                        warn!("Failed to read Hysteria2 TLS private key from '{}': {}", path, e);
                        return None;
                    }
                }
            }
            (None, None) => {
                warn!("Hysteria2 inbound requires TLS private key (tls_key_pem or tls_key_path)");
                return None;
            }
        };

        let config = Hysteria2InboundConfig {
            listen,
            users,
            cert,
            key,
            congestion_control: param.congestion_control.clone(),
            salamander: param.salamander.clone(),
            obfs: param.obfs.clone(),
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
        stub_inbound("hysteria2");
        None
    }
}

#[cfg(feature = "adapter-tuic")]
fn build_tuic_inbound(
    param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::tuic::{TuicInboundConfig, TuicUser};
    use std::net::SocketAddr;

    // Parse listen address
    let listen_str = format!("{}:{}", param.listen, param.port);
    let listen: SocketAddr = match listen_str.parse() {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Failed to parse TUIC listen address '{}': {}", listen_str, e);
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
        (None, Some(path)) => {
            match std::fs::read_to_string(path) {
                Ok(content) => content,
                Err(e) => {
                    warn!("Failed to read TUIC TLS certificate from '{}': {}", path, e);
                    return None;
                }
            }
        }
        (None, None) => {
            warn!("TUIC inbound requires TLS certificate (tls_cert_pem or tls_cert_path)");
            return None;
        }
    };

    let key = match (&param.tls_key_pem, &param.tls_key_path) {
        (Some(pem), _) => pem.clone(),
        (None, Some(path)) => {
            match std::fs::read_to_string(path) {
                Ok(content) => content,
                Err(e) => {
                    warn!("Failed to read TUIC TLS private key from '{}': {}", path, e);
                    return None;
                }
            }
        }
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
    };

    Some(Arc::new(TuicInboundAdapter::new(config)))
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
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    stub_inbound("anytls");
    None
}

fn build_direct_inbound(
    param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use crate::inbound::direct::DirectInboundAdapter;

    match DirectInboundAdapter::new(param) {
        Ok(adapter) => Some(Arc::from(adapter)),
        Err(e) => {
            warn!("Failed to build Direct inbound: {}", e);
            None
        }
    }
}

fn stub_inbound(kind: &str) {
    warn!(target: "sb_adapters::register", inbound=%kind, "adapter inbound not implemented yet; falling back to scaffold");
}

#[cfg(feature = "adapter-dns")]
fn build_dns_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    // TODO: Architecture mismatch - DnsConnector implements sb_adapters::traits::OutboundConnector
    // but this function needs sb_core::adapter::OutboundConnector. Needs adapter wrapper or trait unification.
    warn!("DNS outbound temporarily disabled due to trait architecture mismatch");
    None
}

#[cfg(not(feature = "adapter-dns"))]
fn build_dns_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("dns");
    None
}

fn build_direct_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    use crate::outbound::direct::DirectOutbound;

    // Create direct outbound instance
    let direct = DirectOutbound::new();
    let direct_arc = Arc::new(direct);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct DirectConnectorWrapper {
        inner: Arc<DirectOutbound>,
    }

    impl std::fmt::Debug for DirectConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DirectConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for DirectConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // Direct outbound connects directly to target
            use sb_core::net::Address;
            use sb_core::pipeline::Outbound;

            let target = if host.parse::<std::net::IpAddr>().is_ok() {
                Address::Ip(format!("{}:{}", host, port).parse().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("Invalid socket address: {}", e))
                })?)
            } else {
                Address::Domain(host.to_string(), port)
            };

            self.inner.connect(target).await
        }
    }

    let wrapper = DirectConnectorWrapper {
        inner: direct_arc,
    };

    // Return TCP connector wrapper (no UDP support for direct)
    Some((Arc::new(wrapper), None))
}

fn build_block_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
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
                .finish_non_exhaustive()
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

    let wrapper = BlockConnectorWrapper {
        inner: block_arc,
    };

    // Return TCP connector wrapper (no UDP support for block)
    Some((Arc::new(wrapper), None))
}

fn build_tor_outbound(
    _param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    #[cfg(feature = "adapter-socks")]
    {
        use crate::outbound::socks5::Socks5Connector;
        use sb_config::outbound::Socks5Config;

        // Default Tor SOCKS5 proxy address
        let default_tor_proxy = "127.0.0.1:9050".to_string();

    // Get Tor proxy address from IR, fall back to default
    let proxy_addr = ir.tor_proxy_addr.as_ref()
        .unwrap_or(&default_tor_proxy);

    // Create SOCKS5 config (Tor doesn't require authentication by default)
    let config = Socks5Config {
        server: proxy_addr.clone(),
        tag: ir.name.clone(),
        username: None,  // Tor SOCKS5 doesn't use auth
        password: None,
        connect_timeout_sec: Some(30),
        tls: None,  // Tor SOCKS5 doesn't use TLS
    };

    let connector = Socks5Connector::new(config);
    let connector_arc = Arc::new(connector);

    // Wrapper that implements OutboundConnector trait
    // Note: Tor uses SOCKS5 proxy protocol and should be used via switchboard registry
    #[derive(Clone)]
    struct TorConnectorWrapper {
        inner: Arc<Socks5Connector>,
    }

    impl std::fmt::Debug for TorConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TorConnectorWrapper")
                .field("proxy", &"127.0.0.1:9050")
                .finish()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for TorConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // Tor uses SOCKS5 proxy protocol, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Tor uses SOCKS5 proxy protocol for {}:{}; use switchboard registry instead", host, port),
            ))
        }
    }

    let wrapper = TorConnectorWrapper {
        inner: connector_arc,
    };

    // Return TCP connector wrapper (UDP over Tor can be added later)
    Some((Arc::new(wrapper), None))
    }

    #[cfg(not(feature = "adapter-socks"))]
    {
        stub_outbound("tor");
        None
    }
}

fn build_anytls_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("anytls");
    None
}

fn build_wireguard_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("wireguard");
    None
}

#[cfg(feature = "adapter-hysteria")]
fn build_hysteria_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    use crate::outbound::hysteria::{HysteriaAdapterConfig, HysteriaConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port).unwrap_or(443);

    // Hysteria v1 specific configuration
    let protocol = ir.hysteria_protocol.as_ref()
        .map(|s| s.clone())
        .unwrap_or_else(|| "udp".to_string());

    let up_mbps = ir.up_mbps.unwrap_or(10);
    let down_mbps = ir.down_mbps.unwrap_or(50);

    // Auth string (use hysteria_auth if available, otherwise password)
    let auth = ir.hysteria_auth.as_ref()
        .or(ir.password.as_ref())
        .cloned();

    // Obfuscation
    let obfs = ir.obfs.clone();

    // ALPN (convert Vec<String> if present, otherwise default)
    let alpn = ir.tls_alpn.as_ref()
        .map(|v| v.clone())
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

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct HysteriaConnectorWrapper {
        inner: Arc<HysteriaConnector>,
    }

    impl std::fmt::Debug for HysteriaConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HysteriaConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for HysteriaConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // Hysteria v1 uses QUIC stream, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Hysteria v1 uses QUIC stream for {}:{}; use switchboard registry instead", host, port),
            ))
        }
    }

    let wrapper = HysteriaConnectorWrapper {
        inner: connector_arc,
    };

    // No UDP factory for Hysteria v1 yet (can be added later if needed)
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-hysteria"))]
fn build_hysteria_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("hysteria");
    None
}

#[cfg(feature = "adapter-shadowtls")]
fn build_shadowtls_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    use crate::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port).unwrap_or(443);

    // SNI is required for TLS
    let sni = ir.tls_sni.as_ref()
        .map(|s| s.clone())
        .unwrap_or_else(|| server.clone());

    // ALPN from tls_alpn (Vec<String>), convert to single comma-separated string
    let alpn = ir.tls_alpn.as_ref()
        .map(|v| v.join(","));

    // Skip cert verify (default: false)
    let skip_cert_verify = ir.skip_cert_verify.unwrap_or(false);

    // Build config
    let cfg = ShadowTlsAdapterConfig {
        server: server.clone(),
        port,
        sni,
        alpn,
        skip_cert_verify,
    };

    // Create connector
    let connector = ShadowTlsConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct ShadowTlsConnectorWrapper {
        inner: Arc<ShadowTlsConnector>,
    }

    impl std::fmt::Debug for ShadowTlsConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ShadowTlsConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for ShadowTlsConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // ShadowTLS uses encrypted TLS stream, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("ShadowTLS uses encrypted TLS stream for {}:{}; use switchboard registry instead", host, port),
            ))
        }
    }

    let wrapper = ShadowTlsConnectorWrapper {
        inner: connector_arc,
    };

    // ShadowTLS only supports TCP, no UDP factory
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-shadowtls"))]
fn build_shadowtls_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("shadowtls");
    None
}

#[cfg(feature = "out_tuic")]
fn build_tuic_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    use sb_core::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};
    use sb_core::outbound::crypto_types::OutboundTcp;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let uuid_str = ir.uuid.as_ref()?;
    let uuid = uuid::Uuid::parse_str(uuid_str).ok()?;
    let token = ir.token.as_ref()?.clone();

    // Map UDP relay mode
    let relay_mode = match ir.udp_relay_mode.as_deref() {
        Some(m) if m.eq_ignore_ascii_case("quic") => UdpRelayMode::Quic,
        _ => UdpRelayMode::Native,
    };

    // Build config
    let cfg = TuicConfig {
        server: server.clone(),
        port,
        uuid,
        token,
        password: ir.password.clone(),
        congestion_control: ir.congestion_control.clone(),
        alpn: ir.alpn.clone().or_else(|| ir.tls_alpn.clone()),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        sni: ir.tls_sni.clone(),
        tls_ca_paths: ir.tls_ca_paths.clone(),
        tls_ca_pem: ir.tls_ca_pem.clone(),
        udp_relay_mode: relay_mode,
        udp_over_stream: ir.udp_over_stream.unwrap_or(false),
        zero_rtt_handshake: ir.zero_rtt_handshake.unwrap_or(false),
    };

    // Create outbound
    let outbound = TuicOutbound::new(cfg).ok()?;
    let outbound_arc = Arc::new(outbound);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct TuicConnectorWrapper {
        inner: Arc<TuicOutbound>,
    }

    impl std::fmt::Debug for TuicConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TuicConnectorWrapper").finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for TuicConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // TUIC is QUIC-based, cannot return TcpStream directly
            // This is a fundamental architecture limitation
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "TUIC is QUIC-based and cannot provide TcpStream; use switchboard registry instead"
            ))
        }
    }

    let wrapper = TuicConnectorWrapper {
        inner: outbound_arc.clone(),
    };

    // Return both TCP connector and UDP factory
    Some((Arc::new(wrapper), Some(outbound_arc as Arc<dyn UdpOutboundFactory>)))
}

#[cfg(not(feature = "out_tuic"))]
fn build_tuic_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("tuic");
    None
}

#[cfg(feature = "out_hysteria2")]
fn build_hysteria2_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    use sb_core::outbound::hysteria2::{BrutalConfig, Hysteria2Config, Hysteria2Outbound};
    use sb_core::outbound::crypto_types::OutboundTcp;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let password = ir.password.as_ref()?.clone();

    // Build brutal config if both up/down specified
    let brutal = match (ir.brutal_up_mbps, ir.brutal_down_mbps) {
        (Some(up), Some(down)) => Some(BrutalConfig {
            up_mbps: up,
            down_mbps: down,
        }),
        _ => None,
    };

    // Parse ALPN list
    let alpn_list = ir.tls_alpn.clone();

    // Build config
    let cfg = Hysteria2Config {
        server: server.clone(),
        port,
        password,
        congestion_control: ir.congestion_control.clone(),
        up_mbps: ir.up_mbps,
        down_mbps: ir.down_mbps,
        obfs: ir.obfs.clone(),
        skip_cert_verify: ir.skip_cert_verify.unwrap_or(false),
        sni: ir.tls_sni.clone(),
        alpn: alpn_list,
        salamander: ir.salamander.clone(),
        brutal,
        tls_ca_paths: ir.tls_ca_paths.clone(),
        tls_ca_pem: ir.tls_ca_pem.clone(),
        zero_rtt_handshake: ir.zero_rtt_handshake.unwrap_or(false),
    };

    // Create outbound
    let outbound = Hysteria2Outbound::new(cfg).ok()?;
    let outbound_arc = Arc::new(outbound);

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct Hysteria2ConnectorWrapper {
        inner: Arc<Hysteria2Outbound>,
    }

    impl std::fmt::Debug for Hysteria2ConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Hysteria2ConnectorWrapper").finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for Hysteria2ConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // Hysteria2 is QUIC-based, cannot return TcpStream directly
            // This is a fundamental architecture limitation
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Hysteria2 is QUIC-based and cannot provide TcpStream; use switchboard registry instead"
            ))
        }
    }

    let wrapper = Hysteria2ConnectorWrapper {
        inner: outbound_arc.clone(),
    };

    // Return both TCP connector and UDP factory
    Some((Arc::new(wrapper), Some(outbound_arc as Arc<dyn UdpOutboundFactory>)))
}

#[cfg(not(feature = "out_hysteria2"))]
fn build_hysteria2_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("hysteria2");
    None
}

#[cfg(feature = "adapter-ssh")]
fn build_ssh_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    use crate::outbound::ssh::{SshAdapterConfig, SshConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port).unwrap_or(22);

    // Get username from credentials
    let username = ir.credentials.as_ref()
        .and_then(|c| c.username.clone())?;

    // Get password from credentials or dedicated password field
    let password = ir.credentials.as_ref()
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

    // Wrapper connector that implements sb_core::adapter::OutboundConnector
    #[derive(Clone)]
    struct SshConnectorWrapper {
        inner: Arc<SshConnector>,
    }

    impl std::fmt::Debug for SshConnectorWrapper {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SshConnectorWrapper")
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl OutboundConnector for SshConnectorWrapper {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            // SSH uses tunnel proxy protocol, cannot return raw TcpStream
            // Use switchboard registry instead
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("SSH uses tunnel proxy for {}:{}; use switchboard registry instead", host, port),
            ))
        }
    }

    let wrapper = SshConnectorWrapper {
        inner: connector_arc,
    };

    // SSH only supports TCP, no UDP factory
    Some((Arc::new(wrapper), None))
}

#[cfg(not(feature = "adapter-ssh"))]
fn build_ssh_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("ssh");
    None
}

fn stub_outbound(kind: &str) {
    warn!(target: "sb_adapters::register", outbound=%kind, "adapter outbound not implemented yet; falling back to scaffold");
}

#[cfg(all(test, feature = "adapter-dns"))]
mod tests {
    use super::*;
    use sb_config::ir::{OutboundIR, OutboundType};

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
        let built = build_dns_outbound(&param, &ir);
        assert!(built.is_some(), "DoH outbound should construct successfully");
    }
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
struct HttpInboundAdapter {
    cfg: sb_adapters::inbound::http::HttpProxyConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
impl HttpInboundAdapter {
    fn new(cfg: sb_adapters::inbound::http::HttpProxyConfig) -> Self {
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
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::http::serve_http(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
struct SocksInboundAdapter {
    cfg: sb_adapters::inbound::socks::SocksInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
impl SocksInboundAdapter {
    fn new(cfg: sb_adapters::inbound::socks::SocksInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
impl InboundService for SocksInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::socks::serve_socks(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

fn parse_listen_addr(listen: &str, port: u16) -> Option<SocketAddr> {
    listen
        .parse()
        .ok()
        .or_else(|| format!("{listen}:{port}").parse().ok())
}

#[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
struct TunInboundAdapter {
    inner: sb_adapters::inbound::tun::TunInbound,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-vmess", feature = "router"))]
struct VmessInboundAdapter {
    cfg: sb_adapters::inbound::vmess::VmessInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-vmess", feature = "router"))]
impl VmessInboundAdapter {
    fn new(cfg: sb_adapters::inbound::vmess::VmessInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-vmess", feature = "router"))]
impl InboundService for VmessInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::vmess::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(all(feature = "adapter-vless", feature = "router"))]
struct VlessInboundAdapter {
    cfg: sb_adapters::inbound::vless::VlessInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-vless", feature = "router"))]
impl VlessInboundAdapter {
    fn new(cfg: sb_adapters::inbound::vless::VlessInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-vless", feature = "router"))]
impl InboundService for VlessInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::vless::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
impl TunInboundAdapter {
    fn new(inner: sb_adapters::inbound::tun::TunInbound) -> Self {
        Self {
            inner,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
impl InboundService for TunInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let inbound = self.inner.clone();
        let res = rt.block_on(async move {
            tokio::select! {
                biased;
                _ = rx.recv() => Ok(()),
                r = inbound.run() => r,
            }
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(all(feature = "adapter-trojan", feature = "router"))]
struct TrojanInboundAdapter {
    cfg: sb_adapters::inbound::trojan::TrojanInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-trojan", feature = "router"))]
impl TrojanInboundAdapter {
    fn new(cfg: sb_adapters::inbound::trojan::TrojanInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-trojan", feature = "router"))]
impl InboundService for TrojanInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::trojan::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

// ========== ShadowTLS Inbound ==========

#[cfg(feature = "adapter-shadowtls")]
#[derive(Debug)]
struct ShadowTlsInboundAdapter {
    cfg: crate::inbound::shadowtls::ShadowTlsInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(feature = "adapter-shadowtls")]
impl ShadowTlsInboundAdapter {
    fn new(cfg: crate::inbound::shadowtls::ShadowTlsInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl InboundService for ShadowTlsInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            crate::inbound::shadowtls::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
struct MixedInboundAdapter {
    cfg: sb_adapters::inbound::mixed::MixedInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
impl MixedInboundAdapter {
    fn new(cfg: sb_adapters::inbound::mixed::MixedInboundConfig) -> Self {
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
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::mixed::serve_mixed(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
struct ShadowsocksInboundAdapter {
    cfg: sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
impl ShadowsocksInboundAdapter {
    fn new(cfg: sb_adapters::inbound::shadowsocks::ShadowsocksInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
impl InboundService for ShadowsocksInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::shadowsocks::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

// ========== TUN Inbound ==========

#[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
fn build_tun_inbound(
    _param: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::tun::{TunInbound, TunInboundConfig};

    let cfg = TunInboundConfig::default();
    let inbound = TunInbound::new(cfg, ctx.router.clone());
    Some(Arc::new(TunInboundAdapter::new(inbound)))
}

#[cfg(not(all(feature = "adapter-tun", feature = "tun", feature = "router")))]
fn build_tun_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
impl InboundService for TunInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        self.inner.serve()
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
        }
    }
}

// ========== Redirect Inbound (Linux only) ==========

#[cfg(all(target_os = "linux", feature = "router"))]
fn build_redirect_inbound(
    param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::redirect::RedirectConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = RedirectConfig { listen };
    Some(Arc::new(RedirectInboundAdapter::new(cfg)))
}

#[cfg(not(all(target_os = "linux", feature = "router")))]
fn build_redirect_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(target_os = "linux", feature = "router"))]
struct RedirectInboundAdapter {
    cfg: sb_adapters::inbound::redirect::RedirectConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl RedirectInboundAdapter {
    fn new(cfg: sb_adapters::inbound::redirect::RedirectConfig) -> Self {
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
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::redirect::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

// ========== TProxy Inbound (Linux only) ==========

#[cfg(all(target_os = "linux", feature = "router"))]
fn build_tproxy_inbound(
    param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    use sb_adapters::inbound::tproxy::TproxyConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = TproxyConfig { listen };
    Some(Arc::new(TproxyInboundAdapter::new(cfg)))
}

#[cfg(not(all(target_os = "linux", feature = "router")))]
fn build_tproxy_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(all(target_os = "linux", feature = "router"))]
struct TproxyInboundAdapter {
    cfg: sb_adapters::inbound::tproxy::TproxyConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl TproxyInboundAdapter {
    fn new(cfg: sb_adapters::inbound::tproxy::TproxyConfig) -> Self {
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
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::tproxy::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

// ========== TUIC Inbound ==========

#[cfg(feature = "adapter-tuic")]
#[derive(Debug)]
struct TuicInboundAdapter {
    cfg: crate::inbound::tuic::TuicInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(feature = "adapter-tuic")]
impl TuicInboundAdapter {
    fn new(cfg: crate::inbound::tuic::TuicInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

#[cfg(feature = "adapter-tuic")]
impl InboundService for TuicInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Runtime::new().map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            crate::inbound::tuic::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::{Hysteria2UserIR, InboundIR, InboundType, OutboundType};

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
        let result = build_shadowtls_outbound(&param, &ir);

        // Verify outbound was created successfully
        assert!(result.is_some(), "ShadowTLS outbound should construct successfully");
        let (_connector, udp_factory) = result.unwrap();
        assert!(udp_factory.is_none(), "ShadowTLS should not provide UDP factory");
    }
}
