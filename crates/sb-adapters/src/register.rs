use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

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
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    // TODO: Architecture mismatch - HttpProxyConnector implements sb_adapters::traits::OutboundConnector
    // but this function needs sb_core::adapter::OutboundConnector. Needs adapter wrapper or trait unification.
    warn!("HTTP outbound temporarily disabled due to trait architecture mismatch");
    None
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
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    // TODO: Architecture mismatch - Socks5Connector implements sb_adapters::traits::OutboundConnector
    // but this function needs sb_core::adapter::OutboundConnector. Needs adapter wrapper or trait unification.
    warn!("SOCKS outbound temporarily disabled due to trait architecture mismatch");
    None
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

#[cfg(feature = "adapter-shadowsocks")]
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

#[cfg(not(feature = "adapter-shadowsocks"))]
fn build_shadowsocks_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(feature = "adapter-trojan")]
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
        alpn: ir.alpn.clone().or_else(|| ir.tls_alpn.clone()),
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

#[cfg(not(feature = "adapter-trojan"))]
fn build_trojan_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(feature = "adapter-vmess")]
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
        tls_alpn: ir.tls_alpn.clone().map(|s| s.split(',').map(|s| s.trim().to_string()).collect()),
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

#[cfg(not(feature = "adapter-vmess"))]
fn build_vmess_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    None
}

#[cfg(feature = "adapter-vless")]
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
        tls_alpn: ir.tls_alpn.clone().map(|s| s.split(',').map(|s| s.trim().to_string()).collect()),
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

#[cfg(not(feature = "adapter-vless"))]
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
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    stub_inbound("naive");
    None
}

fn build_shadowtls_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    stub_inbound("shadowtls");
    None
}

fn build_hysteria_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    stub_inbound("hysteria");
    None
}

fn build_hysteria2_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    stub_inbound("hysteria2");
    None
}

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

fn build_tor_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("tor");
    None
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

fn build_hysteria_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> Option<(Arc<dyn OutboundConnector>, Option<Arc<dyn UdpOutboundFactory>>)> {
    stub_outbound("hysteria");
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
    let alpn_list = ir
        .tls_alpn
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        });

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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::http::serve_http(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::socks::serve_socks(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::vmess::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::vless::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
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
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::trojan::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::mixed::serve_mixed(cfg, rx, None)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::shadowsocks::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::redirect::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
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
            let mut guard = self.stop_tx.lock().map_err(io::Error::other)?;
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async {
            sb_adapters::inbound::tproxy::serve(cfg, rx)
                .await
                .map_err(io::Error::other)
        });
        let _ = self.stop_tx.lock().map_err(io::Error::other)?.take();
        res
    }

    fn request_shutdown(&self) {
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
        }
    }
}
