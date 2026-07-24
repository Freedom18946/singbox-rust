//! Protocol builders used by adapter registry façade.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Once};

use sb_config::ir::OutboundIR;
use sb_core::adapter::{registry, InboundParam, InboundTaskDriver, OutboundParam};
use tracing::warn;

type CanonicalOutboundBuilderResult = Option<Arc<dyn sb_types::Outbound>>;

#[allow(dead_code)] // Callers are feature-gated inbound builders.
fn inbound_auth_users(param: &InboundParam) -> Option<Vec<sb_config::ir::Credentials>> {
    param
        .users
        .clone()
        .or_else(|| param.basic_auth.clone().map(|user| vec![user]))
}

macro_rules! canonical_inbound_builder {
    ($canonical:ident, $driver:ident) => {
        fn $canonical(
            param: &InboundParam,
            context: &registry::AdapterInboundContext,
        ) -> Option<Arc<dyn sb_types::Inbound>> {
            $driver(param, context).map(|driver| {
                sb_core::adapter::manage_inbound(
                    driver,
                    param.kind.clone(),
                    param
                        .tag
                        .clone()
                        .unwrap_or_else(|| format!("{}-inbound", param.kind)),
                )
            })
        }
    };
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
canonical_inbound_builder!(canonical_build_http_inbound, build_http_inbound);
#[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
canonical_inbound_builder!(canonical_build_socks_inbound, build_socks_inbound);
#[cfg(all(
    feature = "adapter-http",
    feature = "adapter-socks",
    feature = "mixed",
    feature = "router"
))]
canonical_inbound_builder!(canonical_build_mixed_inbound, build_mixed_inbound);
#[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
canonical_inbound_builder!(
    canonical_build_shadowsocks_inbound,
    build_shadowsocks_inbound
);
#[cfg(all(feature = "adapter-vmess", feature = "router"))]
canonical_inbound_builder!(canonical_build_vmess_inbound, build_vmess_inbound);
#[cfg(all(feature = "adapter-vless", feature = "router"))]
canonical_inbound_builder!(canonical_build_vless_inbound, build_vless_inbound);
#[cfg(all(feature = "adapter-trojan", feature = "router"))]
canonical_inbound_builder!(canonical_build_trojan_inbound, build_trojan_inbound);
canonical_inbound_builder!(canonical_build_naive_inbound, build_naive_inbound);
canonical_inbound_builder!(canonical_build_shadowtls_inbound, build_shadowtls_inbound);
canonical_inbound_builder!(canonical_build_hysteria_inbound, build_hysteria_inbound);
canonical_inbound_builder!(canonical_build_hysteria2_inbound, build_hysteria2_inbound);
canonical_inbound_builder!(canonical_build_tuic_inbound, build_tuic_inbound);
canonical_inbound_builder!(canonical_build_anytls_inbound, build_anytls_inbound);
canonical_inbound_builder!(canonical_build_direct_inbound, build_direct_inbound);
#[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
canonical_inbound_builder!(canonical_build_tun_inbound, build_tun_inbound);
#[cfg(all(target_os = "linux", feature = "redirect", feature = "router"))]
canonical_inbound_builder!(canonical_build_redirect_inbound, build_redirect_inbound);
#[cfg(all(target_os = "linux", feature = "tproxy", feature = "router"))]
canonical_inbound_builder!(canonical_build_tproxy_inbound, build_tproxy_inbound);
#[cfg(feature = "dns")]
canonical_inbound_builder!(canonical_build_dns_inbound, build_dns_inbound);
#[cfg(feature = "ssh")]
canonical_inbound_builder!(canonical_build_ssh_inbound, build_ssh_inbound);

fn canonicalize_outbound_result(
    result: CanonicalOutboundBuilderResult,
    _param: &OutboundParam,
    _ir: &OutboundIR,
) -> CanonicalOutboundBuilderResult {
    result
}

#[derive(Debug)]
#[allow(dead_code)] // Shared invalid-config fallback for optional outbound builders.
struct InvalidConfigConnector {
    protocol: &'static str,
    reason: Arc<str>,
}

impl InvalidConfigConnector {
    #[allow(dead_code)] // Referenced only when optional outbound features are enabled.
    fn new(protocol: &'static str, reason: impl Into<Arc<str>>) -> Self {
        Self {
            protocol,
            reason: reason.into(),
        }
    }
}

impl sb_types::Outbound for InvalidConfigConnector {
    fn r#type(&self) -> &str {
        self.protocol
    }
    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(self.protocol)
    }
    fn network(&self) -> &[sb_types::NetworkKind] {
        crate::outbound::TCP
    }
    fn dial<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::InvalidConfig,
                format!(
                    "{} outbound is disabled due to invalid config: {}",
                    self.protocol, self.reason
                ),
            ))
        })
    }
    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async move {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::InvalidConfig,
                format!(
                    "{} outbound is disabled due to invalid config: {}",
                    self.protocol, self.reason
                ),
            ))
        })
    }
}

#[allow(dead_code)] // Shared by optional outbound builders under feature-gated code paths.
fn invalid_config_outbound(
    protocol: &'static str,
    reason: impl Into<Arc<str>>,
) -> CanonicalOutboundBuilderResult {
    Some(Arc::new(InvalidConfigConnector::new(protocol, reason)))
}

#[allow(dead_code)] // Shared by optional outbound builders under feature-gated code paths.
fn invalid_outbound_config_reason(
    protocol: &'static str,
    outbound: &str,
    detail: impl std::fmt::Display,
) -> Arc<str> {
    format!(
        "{protocol} outbound config is invalid for outbound '{outbound}'; silent builder failure is disabled; fix the config explicitly: {detail}"
    )
    .into()
}

/// Reason string for a long-tail outbound whose Cargo feature is not compiled in.
///
/// Used by the feature-disabled stub branches of long-tail outbound builders
/// (tor / tailscale / shadowsocksr — CAL-18). Instead of returning `None` (which
/// the bridge turns into a generic "no outbound builder available" log line and
/// silently skips the outbound, surfacing downstream as a misleading "outbound not
/// found"), these branches register an [`InvalidConfigConnector`] carrying this
/// reason, so any dial through the outbound fails loudly with the missing feature
/// name and a concrete next step.
#[allow(dead_code)] // Referenced only when the matching long-tail feature is OFF.
fn unsupported_outbound_feature_reason(feature: &str) -> Arc<str> {
    format!(
        "this long-tail protocol is not compiled into this binary; it requires the '{feature}' cargo feature (excluded from the default/parity build). Rebuild with that feature enabled (e.g. --features {feature}) or remove this outbound from the config"
    )
    .into()
}

#[allow(dead_code)] // Shared by optional outbound builders under feature-gated code paths.
fn parse_required_outbound_uuid(
    protocol: &'static str,
    outbound: &str,
    value: Option<&String>,
) -> Result<Option<uuid::Uuid>, Arc<str>> {
    match value {
        Some(raw) => uuid::Uuid::parse_str(raw).map(Some).map_err(|err| {
            format!(
                "{protocol} outbound uuid '{raw}' is invalid for outbound '{outbound}'; silent uuid parse fallback is disabled; fix the config explicitly: {err}"
            )
            .into()
        }),
        None => Ok(None),
    }
}

#[allow(dead_code)]
fn parse_required_outbound_ip_addr(
    protocol: &'static str,
    field: &'static str,
    outbound: &str,
    value: Option<&String>,
) -> Result<Option<IpAddr>, Arc<str>> {
    match value {
        Some(raw) => raw.parse::<IpAddr>().map(Some).map_err(|err| {
            format!(
                "{protocol} outbound {field} '{raw}' is invalid for outbound '{outbound}'; silent ip parse fallback is disabled; fix the config explicitly: {err}"
            )
            .into()
        }),
        None => Ok(None),
    }
}

#[allow(dead_code)] // Shared by optional outbound builders under feature-gated code paths.
fn parse_required_outbound_socket_addr(
    protocol: &'static str,
    outbound: &str,
    server: &str,
    port: u16,
) -> Result<(String, u16), Arc<str>> {
    let server = server.trim();
    if server.is_empty() {
        return Err(format!(
            "{protocol} outbound server is empty for outbound '{outbound}'; silent endpoint fallback is disabled; fix the config explicitly"
        )
        .into());
    }
    if port == 0 {
        return Err(format!(
            "{protocol} outbound port '0' is invalid for outbound '{outbound}'; silent endpoint fallback is disabled; fix the config explicitly"
        )
        .into());
    }
    Ok((server.to_string(), port))
}

static REGISTER_ONCE: Once = Once::new();

fn populate_default_registry(snapshot: &mut registry::RegistrySnapshot) {
    #[cfg(feature = "adapter-http")]
    {
        let _ = snapshot.register_outbound("http", build_http_outbound);
    }
    #[cfg(feature = "adapter-socks")]
    {
        let _ = snapshot.register_outbound("socks", build_socks_outbound);
        let _ = snapshot.register_outbound("socks4", build_socks4_outbound);
    }
    #[cfg(feature = "adapter-shadowsocks")]
    {
        let _ = snapshot.register_outbound("shadowsocks", build_shadowsocks_outbound);
        let _ = snapshot.register_outbound("shadowsocksr", build_shadowsocksr_outbound);
    }
    #[cfg(feature = "adapter-trojan")]
    {
        let _ = snapshot.register_outbound("trojan", build_trojan_outbound);
    }
    #[cfg(feature = "adapter-vmess")]
    {
        let _ = snapshot.register_outbound("vmess", build_vmess_outbound);
    }
    #[cfg(feature = "adapter-vless")]
    {
        let _ = snapshot.register_outbound("vless", build_vless_outbound);
    }
    {
        let _ = snapshot.register_outbound("direct", build_direct_outbound);
    }
    {
        let _ = snapshot.register_outbound("block", build_block_outbound);
    }
    {
        let _ = snapshot.register_outbound("dns", build_dns_outbound);
    }
    {
        let _ = snapshot.register_outbound("tor", build_tor_outbound);
    }
    {
        let _ = snapshot.register_outbound("anytls", build_anytls_outbound);
    }
    {
        let _ = snapshot.register_outbound("wireguard", build_wireguard_outbound);
    }
    {
        let _ = snapshot.register_outbound("tailscale", build_tailscale_outbound_canonical);
    }
    {
        let _ = snapshot.register_outbound("hysteria", build_hysteria_outbound);
    }
    {
        let _ = snapshot.register_outbound("tuic", build_tuic_outbound);
    }
    {
        let _ = snapshot.register_outbound("hysteria2", build_hysteria2_outbound);
    }
    {
        let _ = snapshot.register_outbound("ssh", build_ssh_outbound);
    }
    {
        let _ = snapshot.register_outbound("shadowtls", build_shadowtls_outbound);
    }
    // Selector group outbounds (core functionality, always available)
    {
        let _ = snapshot.register_outbound("selector", build_selector_outbound_canonical);
    }
    {
        let _ = snapshot.register_outbound("urltest", build_urltest_outbound_canonical);
    }

    #[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
    {
        let _ = snapshot.register_inbound("http", canonical_build_http_inbound);
    }

    #[cfg(all(feature = "adapter-socks", feature = "socks", feature = "router"))]
    {
        let _ = snapshot.register_inbound("socks", canonical_build_socks_inbound);
    }

    #[cfg(all(
        feature = "adapter-http",
        feature = "adapter-socks",
        feature = "mixed",
        feature = "router"
    ))]
    {
        let _ = snapshot.register_inbound("mixed", canonical_build_mixed_inbound);
    }

    #[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
    {
        let _ = snapshot.register_inbound("shadowsocks", canonical_build_shadowsocks_inbound);
    }

    #[cfg(all(feature = "adapter-vmess", feature = "router"))]
    {
        let _ = snapshot.register_inbound("vmess", canonical_build_vmess_inbound);
    }

    #[cfg(all(feature = "adapter-vless", feature = "router"))]
    {
        let _ = snapshot.register_inbound("vless", canonical_build_vless_inbound);
    }
    #[cfg(all(feature = "adapter-trojan", feature = "router"))]
    {
        let _ = snapshot.register_inbound("trojan", canonical_build_trojan_inbound);
    }
    {
        let _ = snapshot.register_inbound("naive", canonical_build_naive_inbound);
    }
    {
        let _ = snapshot.register_inbound("shadowtls", canonical_build_shadowtls_inbound);
    }
    {
        let _ = snapshot.register_inbound("hysteria", canonical_build_hysteria_inbound);
    }
    {
        let _ = snapshot.register_inbound("hysteria2", canonical_build_hysteria2_inbound);
    }
    {
        let _ = snapshot.register_inbound("tuic", canonical_build_tuic_inbound);
    }
    {
        let _ = snapshot.register_inbound("anytls", canonical_build_anytls_inbound);
    }
    #[cfg(feature = "router")]
    {
        let _ = snapshot.register_inbound("direct", canonical_build_direct_inbound);
    }

    #[cfg(all(feature = "adapter-tun", feature = "tun", feature = "router"))]
    {
        let _ = snapshot.register_inbound("tun", canonical_build_tun_inbound);
    }

    #[cfg(all(target_os = "linux", feature = "redirect", feature = "router"))]
    {
        let _ = snapshot.register_inbound("redirect", canonical_build_redirect_inbound);
    }

    #[cfg(all(target_os = "linux", feature = "tproxy", feature = "router"))]
    {
        let _ = snapshot.register_inbound("tproxy", canonical_build_tproxy_inbound);
    }

    #[cfg(feature = "dns")]
    {
        let _ = snapshot.register_inbound("dns", canonical_build_dns_inbound);
    }

    #[cfg(feature = "ssh")]
    {
        let _ = snapshot.register_inbound("ssh", canonical_build_ssh_inbound);
    }
}

/// Build the default adapter registry snapshot for product startup paths.
pub fn build_default_registry() -> registry::RegistrySnapshot {
    let mut snapshot = registry::RegistrySnapshot::new();
    populate_default_registry(&mut snapshot);
    snapshot
}

/// Register adapter-provided builders with sb-core registry. Safe to call multiple times.
/// 将适配器提供的构建器注册到 sb-core 注册表中。可以安全地多次调用。
pub fn register_all() {
    REGISTER_ONCE.call_once(|| {
        let snapshot = build_default_registry();
        registry::install_snapshot(&snapshot);
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

#[cfg(feature = "tls_reality")]
fn build_reality_client_config(
    ir: &OutboundIR,
    fallback_target: &str,
) -> Option<sb_tls::RealityClientConfig> {
    if !ir.reality_enabled.unwrap_or(false) {
        return None;
    }

    let public_key = ir.reality_public_key.clone()?;
    let server_name = ir
        .reality_server_name
        .clone()
        .or_else(|| ir.tls_sni.clone())
        .unwrap_or_else(|| fallback_target.to_string());

    Some(sb_tls::RealityClientConfig {
        target: server_name.clone(),
        server_name,
        public_key,
        short_id: ir.reality_short_id.clone(),
        fingerprint: ir
            .utls_fingerprint
            .clone()
            .unwrap_or_else(|| "chrome".to_string()),
        alpn: ir.tls_alpn.clone().unwrap_or_default(),
    })
}

#[cfg(feature = "adapter-http")]
fn build_http_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
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

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-http"))]
#[allow(dead_code)]
fn build_http_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-socks")]
fn build_socks_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
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

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-socks"))]
#[allow(dead_code)]
fn build_socks_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-socks")]
fn build_socks4_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
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

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-socks"))]
#[allow(dead_code)]
fn build_socks4_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-shadowsocks")]
fn build_shadowsocks_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::shadowsocks::{ShadowsocksConfig, ShadowsocksConnector};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let password = ir.password.as_ref()?.clone();
    let outbound_name = ir.name.as_deref().unwrap_or("shadowsocks");

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
        detour: ir.detour.clone(),
        multiplex: build_multiplex_config_client(&ir.multiplex.clone().or(param.multiplex.clone())),
    };

    // Create adapter connector
    let connector = match ShadowsocksConnector::new(cfg) {
        Ok(connector) => connector,
        Err(err) => {
            let reason = invalid_outbound_config_reason("shadowsocks", outbound_name, &err);
            warn!("{reason}");
            return canonicalize_outbound_result(
                invalid_config_outbound("shadowsocks", reason),
                param,
                ir,
            );
        }
    };
    let connector_arc = Arc::new(connector);

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-shadowsocks"))]
#[allow(dead_code)]
fn build_shadowsocks_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    None
}

#[cfg(feature = "legacy_shadowsocksr")]
fn build_shadowsocksr_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::shadowsocksr::ShadowsocksROutbound;

    // Use TryFrom to build adapter from IR
    let outbound_name = ir.name.as_deref().unwrap_or("shadowsocksr");
    let adapter = match ShadowsocksROutbound::try_from(ir) {
        Ok(adapter) => adapter,
        Err(err) => {
            let reason = invalid_outbound_config_reason("shadowsocksr", outbound_name, &err);
            warn!("{reason}");
            return canonicalize_outbound_result(
                invalid_config_outbound("shadowsocksr", reason),
                param,
                ir,
            );
        }
    };
    let adapter_arc = Arc::new(adapter);

    Some(adapter_arc)
}

#[cfg(not(feature = "legacy_shadowsocksr"))]
#[allow(dead_code)]
fn build_shadowsocksr_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    canonicalize_outbound_result(
        invalid_config_outbound(
            "shadowsocksr",
            unsupported_outbound_feature_reason("legacy_shadowsocksr"),
        ),
        param,
        ir,
    )
}

#[cfg(feature = "adapter-trojan")]
fn build_trojan_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
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
        detour: ir.detour.clone(),
        transport_layer,
        #[cfg(feature = "tls_reality")]
        reality: build_reality_client_config(ir, server),
        multiplex: build_multiplex_config_client(&ir.multiplex.clone().or(param.multiplex.clone())),
    };

    // Create adapter connector
    let connector = TrojanConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-trojan"))]
#[allow(dead_code)]
fn build_trojan_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-vmess")]
fn build_vmess_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::vmess::{
        Security, VmessAuth, VmessConfig, VmessConnector, VmessTransport,
    };
    use std::collections::HashMap;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let outbound_name = ir.name.as_deref().unwrap_or("vmess");
    let uuid = match parse_required_outbound_uuid("vmess", outbound_name, ir.uuid.as_ref()) {
        Ok(Some(uuid)) => uuid,
        Ok(None) => return None,
        Err(reason) => {
            warn!("{reason}");
            return canonicalize_outbound_result(
                invalid_config_outbound("vmess", reason),
                param,
                ir,
            );
        }
    };

    let (server, port) =
        match parse_required_outbound_socket_addr("vmess", outbound_name, server, port) {
            Ok(endpoint) => endpoint,
            Err(reason) => {
                warn!("{reason}");
                return canonicalize_outbound_result(
                    invalid_config_outbound("vmess", reason),
                    param,
                    ir,
                );
            }
        };

    // Match sing-vmess names exactly. Unknown values must not silently become AES.
    let security = match ir.security.as_deref().unwrap_or("auto") {
        "" | "auto" => Security::Auto,
        "none" => Security::None,
        "zero" => Security::Zero,
        "aes-128-gcm" => Security::Aes128Gcm,
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => Security::ChaCha20Poly1305,
        unsupported => {
            let reason =
                format!("vmess outbound {outbound_name:?}: unsupported security {unsupported:?}");
            warn!("{reason}");
            return canonicalize_outbound_result(
                invalid_config_outbound("vmess", reason),
                param,
                ir,
            );
        }
    };

    let auth = VmessAuth {
        uuid,
        alter_id: ir.alter_id.unwrap_or(0) as u16,
        security,
        additional_data: None,
    };

    let transport_layer = build_transport_config(ir);

    #[cfg(feature = "transport_tls")]
    let tls = match crate::standard_tls::lower_vmess_outbound_tls(ir) {
        Ok(tls) => tls,
        Err(reason) => {
            warn!("{reason}");
            return canonicalize_outbound_result(
                invalid_config_outbound("vmess", reason),
                param,
                ir,
            );
        }
    };

    let cfg = VmessConfig {
        tag: ir.name.clone().or_else(|| param.name.clone()),
        server,
        port,
        auth,
        transport: VmessTransport::default(),
        transport_layer,
        timeout: Some(std::time::Duration::from_secs(30)),
        packet_encoding: false,
        headers: HashMap::new(),
        #[cfg(feature = "transport_mux")]
        multiplex: build_multiplex_config_client(&ir.multiplex.clone().or(param.multiplex.clone())),
        #[cfg(feature = "transport_tls")]
        tls,
    };

    let connector = VmessConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-vmess"))]
#[allow(dead_code)]
fn build_vmess_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    None
}

#[cfg(feature = "adapter-vless")]
fn build_vless_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::vless::{Encryption, FlowControl, VlessConfig, VlessConnector};
    use std::collections::HashMap;

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let outbound_name = ir.name.as_deref().unwrap_or("vless");
    let uuid = match parse_required_outbound_uuid("vless", outbound_name, ir.uuid.as_ref()) {
        Ok(Some(uuid)) => uuid,
        Ok(None) => return None,
        Err(reason) => {
            warn!("{reason}");
            return canonicalize_outbound_result(
                invalid_config_outbound("vless", reason),
                param,
                ir,
            );
        }
    };

    let (server, port) =
        match parse_required_outbound_socket_addr("vless", outbound_name, server, port) {
            Ok(endpoint) => endpoint,
            Err(reason) => {
                warn!("{reason}");
                return canonicalize_outbound_result(
                    invalid_config_outbound("vless", reason),
                    param,
                    ir,
                );
            }
        };

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
        tag: ir.name.clone().or_else(|| param.name.clone()),
        server: server.clone(),
        port,
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
        reality: build_reality_client_config(ir, &server),
        #[cfg(feature = "transport_ech")]
        ech: None,
    };

    let connector = VlessConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-vless"))]
#[allow(dead_code)]
fn build_vless_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    None
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
#[allow(dead_code)]
fn build_http_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
    use crate::inbound::http::HttpProxyConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = HttpProxyConfig {
        tag: param.tag.clone(),
        listen,
        router: ctx.router.clone(),
        outbounds: ctx.outbounds.clone(),
        tls: None,
        users: inbound_auth_users(param),
        set_system_proxy: param.set_system_proxy,
        allow_private_network: param.allow_private_network,
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        conn_tracker: ctx.context.conn_tracker.clone(),
        active_connections: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sniff: param.sniff,
        sniff_override_destination: param.sniff_override_destination,
    };
    Some(Arc::new(crate::inbound::http::HttpInboundDriver::new(cfg)))
}

#[cfg(all(feature = "adapter-shadowsocks", feature = "router"))]
#[allow(dead_code)]
fn build_shadowsocks_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
        conn_tracker: ctx.context.conn_tracker.clone(),
        multiplex: convert_multiplex_config(&param.multiplex),
        // NOTE: Transport layer configuration can be added via param in future
        transport_layer: None,
    };

    let adapter = if let Some(tag) = param.tag.clone() {
        ShadowsocksInboundAdapter::with_tag(config, tag)
    } else {
        ShadowsocksInboundAdapter::new(config)
    };
    let adapter = Arc::new(adapter);
    crate::inbound::shadowsocks::register_detour_inbound(
        param
            .tag
            .clone()
            .unwrap_or_else(|| "shadowsocks".to_string()),
        &adapter,
    );
    #[cfg(feature = "service_ssmapi")]
    {
        use sb_core::service::ssm::{register_managed_ssm_server, ManagedSSMServer};

        let tag = ManagedSSMServer::tag(adapter.as_ref()).to_string();
        if !tag.trim().is_empty() {
            let srv: Arc<dyn ManagedSSMServer> = adapter.clone();
            register_managed_ssm_server(&tag, Arc::downgrade(&srv));
        }
    }
    Some(adapter)
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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

    let tls = match crate::standard_tls::lower_vmess_inbound_tls_options(param.tls.as_ref()) {
        Ok(Some(config)) => match sb_transport::build_standard_tls_acceptor(&config) {
            Ok(acceptor) => Some(acceptor),
            Err(error) => {
                warn!("VMess inbound TLS config invalid: {error}");
                return None;
            }
        },
        Ok(None) => None,
        Err(error) => {
            warn!("{error}");
            return None;
        }
    };

    let config = VmessInboundConfig {
        listen,
        uuid,
        security,
        router: ctx.router.clone(),
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        conn_tracker: ctx.context.conn_tracker.clone(),
        multiplex: convert_multiplex_config(&param.multiplex),
        transport_layer: None,
        fallback: None,
        fallback_for_alpn: std::collections::HashMap::new(),
        tls,
        tls_handshake_timeout: std::time::Duration::from_secs(10),
    };

    Some(Arc::new(VmessInboundAdapter::new(config)))
}

#[cfg(all(feature = "adapter-vless", feature = "router"))]
#[allow(dead_code)]
fn build_vless_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
        conn_tracker: ctx.context.conn_tracker.clone(),
        #[cfg(feature = "tls_reality")]
        reality: match param.reality.as_ref() {
            Some(reality) => {
                let max_time_difference = match reality.max_time_difference.as_deref() {
                    Some(raw) => match humantime::parse_duration(raw) {
                        Ok(value) => Some(value),
                        Err(error) => {
                            warn!(error=%error, "invalid VLESS REALITY max_time_difference");
                            return None;
                        }
                    },
                    None => None,
                };
                let config = sb_tls::RealityServerConfig {
                    target: reality.target.clone(),
                    server_names: reality.server_names.clone(),
                    private_key: reality.private_key.clone(),
                    short_ids: reality.short_ids.clone(),
                    handshake_timeout: reality.handshake_timeout,
                    max_time_difference,
                    enable_fallback: true,
                };
                if let Err(error) = config.validate() {
                    warn!(error=%error, "invalid VLESS REALITY configuration");
                    return None;
                }
                Some(config)
            }
            None => None,
        },
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
        conn_tracker: ctx.context.conn_tracker.clone(),
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
        users: inbound_auth_users(param),
        udp_timeout: param.udp_timeout,
        domain_strategy,
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        conn_tracker: ctx.context.conn_tracker.clone(),
        sniff: param.sniff,
        sniff_override_destination: param.sniff_override_destination,
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
        users: inbound_auth_users(param),
        set_system_proxy: param.set_system_proxy,
        allow_private_network: param.allow_private_network,
        udp_timeout: param.udp_timeout,
        domain_strategy,
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        conn_tracker: ctx.context.conn_tracker.clone(),
        sniff: param.sniff,
        sniff_override_destination: param.sniff_override_destination,
    };
    Some(Arc::new(crate::inbound::mixed::MixedInboundDriver::new(
        cfg,
    )))
}

fn build_naive_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
    #[cfg(feature = "adapter-shadowtls")]
    {
        use crate::inbound::shadowtls::{
            ShadowTlsHandshakeConfig, ShadowTlsInboundConfig, ShadowTlsUser,
            ShadowTlsWildcardSniMode,
        };

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

        let detour = match param.detour.as_ref().filter(|tag| !tag.is_empty()) {
            Some(tag) => tag.clone(),
            None => {
                warn!("ShadowTLS inbound requires detour to a chained inbound");
                return None;
            }
        };

        let version = param.shadowtls_version.unwrap_or(1);
        if !(1..=3).contains(&version) {
            warn!("ShadowTLS inbound version {version} is unsupported");
            return None;
        }

        let users = match param.users_shadowtls.as_deref() {
            Some(raw) => match serde_json::from_str::<Vec<ShadowTlsUser>>(raw) {
                Ok(users) => users,
                Err(err) => {
                    warn!("Failed to parse ShadowTLS users: {err}");
                    return None;
                }
            },
            None => Vec::new(),
        };

        let handshake = match param.shadowtls_handshake.as_deref() {
            Some(raw) => match serde_json::from_str::<ShadowTlsHandshakeConfig>(raw) {
                Ok(cfg) => Some(cfg),
                Err(err) => {
                    warn!("Failed to parse ShadowTLS handshake target: {err}");
                    return None;
                }
            },
            None => None,
        };

        let handshake_for_server_name = match param.shadowtls_handshake_for_server_name.as_deref() {
            Some(raw) => {
                match serde_json::from_str::<
                    std::collections::HashMap<String, ShadowTlsHandshakeConfig>,
                >(raw)
                {
                    Ok(cfg) => cfg,
                    Err(err) => {
                        warn!("Failed to parse ShadowTLS handshake overrides: {err}");
                        return None;
                    }
                }
            }
            None => std::collections::HashMap::new(),
        };

        if version == 2
            && param
                .password
                .as_deref()
                .filter(|value| !value.is_empty())
                .is_none()
        {
            warn!("ShadowTLS inbound v2 requires password");
            return None;
        }

        if version == 3 && users.is_empty() {
            warn!("ShadowTLS inbound v3 requires users");
            return None;
        }

        let wildcard_sni =
            match ShadowTlsWildcardSniMode::parse(param.shadowtls_wildcard_sni.as_deref()) {
                Ok(mode) => mode,
                Err(err) => {
                    warn!("{err}");
                    return None;
                }
            };

        let config = ShadowTlsInboundConfig {
            listen,
            detour,
            version,
            password: param.password.clone(),
            users,
            handshake,
            handshake_for_server_name,
            strict_mode: param.shadowtls_strict_mode.unwrap_or(false),
            wildcard_sni,
            tag: param.tag.clone(),
            tls: None,
            router: Some(ctx.router.clone()),
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
    _ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
            match serde_json::from_str::<sb_config::ir::MasqueradeIR>(json) {
                Ok(ir) => match ir.type_.as_str() {
                    "string" => {
                        ir.string
                            .map(|s| crate::inbound::hysteria2::MasqueradeConfig::String {
                                content: s.content,
                                headers: s.headers.unwrap_or_default().into_iter().collect(),
                                status_code: s.status_code,
                            })
                    }
                    "file" => ir
                        .file
                        .map(|f| crate::inbound::hysteria2::MasqueradeConfig::File {
                            directory: f.directory,
                        }),
                    "proxy" => {
                        ir.proxy
                            .map(|p| crate::inbound::hysteria2::MasqueradeConfig::Proxy {
                                url: p.url,
                                rewrite_host: p.rewrite_host,
                            })
                    }
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
            conn_tracker: ctx.context.conn_tracker.clone(),
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
        conn_tracker: ctx.context.conn_tracker.clone(),
    };

    Some(Arc::new(crate::inbound::tuic::TuicInboundAdapter::new(
        config,
    )))
}

#[cfg(not(feature = "adapter-tuic"))]
fn build_tuic_inbound(
    _param: &InboundParam,
    _ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
    stub_inbound("tuic");
    None
}

fn build_anytls_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
    let inbound = match TunInbound::try_new(
        config,
        ctx.router.clone(),
        ctx.outbounds.clone(),
        param.tag.clone(),
        stats,
        param.sniff,
        param.sniff_override_destination,
    ) {
        Ok(inbound) => inbound,
        Err(error) => {
            tracing::error!(
                inbound = %param.tag.as_deref().unwrap_or("tun"),
                error = %error,
                "failed to prepare TUN runtime backend"
            );
            return None;
        }
    };
    Some(Arc::new(inbound))
}

#[allow(dead_code)]
fn stub_inbound(kind: &str) {
    warn!(target: "crate::register", inbound=%kind, "adapter inbound is not compiled into this build");
}

#[cfg(feature = "dns")]
fn build_dns_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
    _ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
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
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::dns::{DnsConfig, DnsConnector, DnsTransport};

    // Extract required fields
    let outbound_name = ir
        .name
        .as_deref()
        .or(param.name.as_deref())
        .unwrap_or("dns");
    let server = match parse_required_outbound_ip_addr(
        "dns",
        "server",
        outbound_name,
        ir.server.as_ref().or(param.server.as_ref()),
    ) {
        Ok(Some(server)) => server,
        Ok(None) => {
            warn!("DNS outbound requires a valid IP address for server");
            return None;
        }
        Err(reason) => {
            warn!("{reason}");
            return canonicalize_outbound_result(invalid_config_outbound("dns", reason), param, ir);
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

    let tag = ir
        .name
        .clone()
        .or_else(|| param.name.clone())
        .unwrap_or_else(|| "dns".to_string());
    let connector = Arc::new(DnsConnector::with_tag(config, tag));
    Some(connector)
}

#[cfg(not(feature = "adapter-dns"))]
fn build_dns_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    stub_outbound("dns");
    None
}

fn build_direct_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    if param.bind_interface.is_some()
        || param.routing_mark.is_some()
        || param.reuse_addr.is_some()
        || param.tcp_fast_open.is_some()
        || param.tcp_multi_path.is_some()
    {
        warn!(
            target: "sb_adapters::register",
            "direct outbound bridge ignores bind/routing socket options during L20.3.1 wave#1"
        );
    }
    let tag = ir
        .name
        .clone()
        .or_else(|| param.name.clone())
        .unwrap_or_else(|| "direct".to_string());
    canonicalize_outbound_result(
        Some(Arc::new(crate::outbound::direct::DirectOutbound::with_tag(
            tag,
        ))),
        param,
        ir,
    )
}

fn build_block_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::block::BlockOutbound;

    let tag = ir
        .name
        .clone()
        .or_else(|| param.name.clone())
        .unwrap_or_else(|| "block".to_string());
    let block = BlockOutbound::with_tag(tag);
    let block_arc = Arc::new(block);
    Some(block_arc)
}

#[allow(unused_variables)]
fn build_tor_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
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

                Some(adapter_arc)
            }
            Err(e) => {
                warn!(target: "sb_adapters::tor", "Failed to create TorOutbound: {}", e);
                None
            }
        }
    }

    #[cfg(not(feature = "adapter-tor"))]
    {
        canonicalize_outbound_result(
            invalid_config_outbound("tor", unsupported_outbound_feature_reason("adapter-tor")),
            param,
            ir,
        )
    }
}

fn build_anytls_outbound(
    _param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    #[cfg(feature = "adapter-anytls")]
    {
        use crate::outbound::anytls::AnyTlsConnector;
        match AnyTlsConnector::try_from(ir) {
            Ok(connector) => Some(Arc::new(connector)),
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
) -> CanonicalOutboundBuilderResult {
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
    Some(Arc::new(connector))
}

#[cfg(not(feature = "adapter-wireguard-outbound"))]
#[allow(dead_code)]
fn build_wireguard_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    // Loud failure: register an InvalidConfigConnector so any dial surfaces the
    // missing cargo feature and a rebuild hint, instead of silently returning
    // None (which the bridge turns into a misleading "outbound not found").
    canonicalize_outbound_result(
        invalid_config_outbound(
            "wireguard",
            unsupported_outbound_feature_reason("adapter-wireguard-outbound"),
        ),
        param,
        ir,
    )
}

#[cfg(feature = "adapter-tailscale")]
fn build_tailscale_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::tailscale::{TailscaleConfig, TailscaleConnector};
    let direct: Arc<dyn sb_types::Outbound> =
        Arc::new(crate::outbound::direct::DirectOutbound::with_tag(
            param.name.clone().unwrap_or_else(|| "direct".to_string()),
        ));

    // NOTE: Tailscale-specific fields are defined in EndpointIR, not OutboundIR.
    // For now, use defaults with outbound name as tag.
    // Future: add tailscale fields to OutboundIR or use EndpointIR for configuration.
    let cfg = TailscaleConfig {
        tag: ir.name.clone(),
        ..Default::default()
    };

    let connector = TailscaleConnector::new(direct, cfg);
    Some(Arc::new(connector))
}

#[cfg(not(feature = "adapter-tailscale"))]
fn build_tailscale_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    invalid_config_outbound(
        "tailscale",
        unsupported_outbound_feature_reason("adapter-tailscale"),
    )
}

#[cfg(feature = "adapter-hysteria")]
fn build_hysteria_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
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
        tag: ir.name.clone().or_else(|| param.name.clone()),
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

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-hysteria"))]
fn build_hysteria_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    stub_outbound("hysteria");
    None
}

#[cfg(feature = "adapter-shadowtls")]
fn build_shadowtls_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::shadowtls::{ShadowTlsAdapterConfig, ShadowTlsConnector};

    let outbound_name = ir
        .name
        .as_deref()
        .or(param.name.as_deref())
        .unwrap_or("shadowtls");

    // Extract required fields
    let server = match ir.server.as_ref().or(param.server.as_ref()) {
        Some(server) => server,
        None => {
            let reason = invalid_outbound_config_reason(
                "shadowtls",
                outbound_name,
                "missing required field 'server'",
            );
            return canonicalize_outbound_result(
                invalid_config_outbound("shadowtls", reason),
                param,
                ir,
            );
        }
    };
    let port = ir.port.or(param.port).unwrap_or(443);
    let password = match ir
        .password
        .as_ref()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
    {
        Some(password) => password.to_string(),
        None => {
            let reason = invalid_outbound_config_reason(
                "shadowtls",
                outbound_name,
                "missing required field 'password'",
            );
            return canonicalize_outbound_result(
                invalid_config_outbound("shadowtls", reason),
                param,
                ir,
            );
        }
    };
    let version = ir.version.unwrap_or(1);
    if !(1..=3).contains(&version) {
        let reason = invalid_outbound_config_reason(
            "shadowtls",
            outbound_name,
            format!("unsupported version {version}; expected 1, 2, or 3"),
        );
        return canonicalize_outbound_result(
            invalid_config_outbound("shadowtls", reason),
            param,
            ir,
        );
    }

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
        tag: ir.name.clone().or_else(|| param.name.clone()),
        version,
        password,
        sni,
        alpn,
        skip_cert_verify,
        utls_fingerprint: ir.utls_fingerprint.clone(),
    };

    // Create connector
    let connector = ShadowTlsConnector::new(cfg);
    let connector_arc = Arc::new(connector);

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-shadowtls"))]
fn build_shadowtls_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    stub_outbound("shadowtls");
    None
}

#[cfg(feature = "adapter-tuic")]
fn build_tuic_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::tuic::{TuicAdapterConfig, TuicConnector, TuicUdpRelayMode};

    // Extract required fields
    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let outbound_name = ir.name.as_deref().unwrap_or("tuic");
    let uuid = match parse_required_outbound_uuid("tuic", outbound_name, ir.uuid.as_ref()) {
        Ok(Some(uuid)) => uuid,
        Ok(None) => return None,
        Err(reason) => {
            warn!("{reason}");
            return canonicalize_outbound_result(
                invalid_config_outbound("tuic", reason),
                param,
                ir,
            );
        }
    };
    // Sing-box TUIC v5 configs call this credential `password`; retain the
    // legacy `token` spelling as an explicit override for older Rust configs.
    let token = ir.token.as_ref().or(ir.password.as_ref())?.clone();

    // Map UDP relay mode
    let udp_relay_mode = match ir.udp_relay_mode.as_deref() {
        Some(m) if m.eq_ignore_ascii_case("quic") => TuicUdpRelayMode::Quic,
        _ => TuicUdpRelayMode::Native,
    };

    // Build adapter config
    let cfg = TuicAdapterConfig {
        tag: ir.name.clone().or_else(|| param.name.clone()),
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

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-tuic"))]
fn build_tuic_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    stub_outbound("tuic");
    None
}

#[cfg(feature = "adapter-hysteria2")]
fn hysteria2_adapter_config(
    param: &OutboundParam,
    ir: &OutboundIR,
) -> Option<crate::outbound::hysteria2::Hysteria2AdapterConfig> {
    use crate::outbound::hysteria2::{Hysteria2AdapterConfig, Hysteria2BrutalConfig};

    let server = ir.server.as_ref().or(param.server.as_ref())?;
    let port = ir.port.or(param.port)?;
    let password = ir.password.as_ref()?.clone();

    Some(Hysteria2AdapterConfig {
        tag: ir.name.clone().or_else(|| param.name.clone()),
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
        brutal: match (ir.brutal_up_mbps, ir.brutal_down_mbps) {
            (Some(up_mbps), Some(down_mbps)) => Some(Hysteria2BrutalConfig { up_mbps, down_mbps }),
            _ => None,
        },
        tls_ca_paths: ir.tls_ca_paths.clone(),
        tls_ca_pem: ir.tls_ca_pem.clone(),
        zero_rtt_handshake: ir.zero_rtt_handshake.unwrap_or(false),
    })
}

#[cfg(feature = "adapter-hysteria2")]
fn build_hysteria2_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    use crate::outbound::hysteria2::Hysteria2Connector;

    let connector = Hysteria2Connector::new(hysteria2_adapter_config(param, ir)?);
    let connector_arc = Arc::new(connector);

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-hysteria2"))]
fn build_hysteria2_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    stub_outbound("hysteria2");
    None
}

#[cfg(feature = "adapter-ssh")]
fn build_ssh_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
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
        tag: ir.name.clone().or_else(|| param.name.clone()),
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

    Some(connector_arc)
}

#[cfg(not(feature = "adapter-ssh"))]
fn build_ssh_outbound(
    _param: &OutboundParam,
    _ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    stub_outbound("ssh");
    None
}

#[allow(dead_code)]
fn stub_outbound(kind: &str) {
    warn!(target: "crate::register", outbound=%kind, "adapter outbound is not compiled into this build");
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the feature-gated tests below (dns / wireguard-outbound / shadowtls /
    // vless) construct OutboundIR literals; gate the import to match so the default
    // (no-adapter) test build doesn't see it as unused.
    #[cfg(any(
        feature = "adapter-dns",
        feature = "adapter-wireguard-outbound",
        feature = "adapter-shadowtls",
        feature = "adapter-vless",
        feature = "adapter-vmess",
    ))]
    use sb_config::ir::{OutboundIR, OutboundType};

    #[test]
    fn inbound_auth_users_preserves_legacy_basic_auth_fallback() {
        let credential = sb_config::ir::Credentials {
            username: Some("legacy".into()),
            password: Some("secret".into()),
            ..Default::default()
        };
        let param = InboundParam {
            basic_auth: Some(credential.clone()),
            ..Default::default()
        };
        assert_eq!(inbound_auth_users(&param), Some(vec![credential]));
    }

    #[test]
    #[cfg(feature = "adapter-vmess")]
    fn vmess_builder_rejects_unknown_security_without_aes_fallback() {
        let ir = OutboundIR {
            ty: OutboundType::Vmess,
            name: Some("vmess-bad-security".to_string()),
            server: Some("127.0.0.1".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            security: Some("mystery-cipher".to_string()),
            ..Default::default()
        };
        let param = OutboundParam {
            kind: "vmess".to_string(),
            name: ir.name.clone(),
            ..Default::default()
        };
        let context = sb_core::context::Context::new();
        let bridge = Arc::new(sb_core::adapter::Bridge::new(context));
        let ctx = sb_core::registry::AdapterOutboundContext {
            context: sb_core::context::ContextRegistry::from(&bridge.context),
            bridge,
        };
        let connector = build_vmess_outbound(&param, &ir, &ctx).expect("invalid connector");
        let error = futures::executor::block_on(connector.dial(&sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("example.com", 443),
        )))
        .err()
        .expect("unknown security must reject dial");
        assert!(error.to_string().contains("unsupported security"));
        assert!(error.to_string().contains("mystery-cipher"));
    }

    #[test]
    #[cfg(all(feature = "adapter-vmess", feature = "transport_tls"))]
    fn vmess_builder_executes_tls_lowering_before_dial() {
        use sb_config::ir::OutboundTlsOptionsIR;

        let ir = OutboundIR {
            ty: OutboundType::Vmess,
            name: Some("vmess-bad-root".to_string()),
            server: Some("127.0.0.1".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            tls: Some(OutboundTlsOptionsIR {
                enabled: true,
                certificate: Some(vec!["not a certificate".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let param = OutboundParam {
            kind: "vmess".to_string(),
            name: ir.name.clone(),
            ..Default::default()
        };
        let context = sb_core::context::Context::new();
        let bridge = Arc::new(sb_core::adapter::Bridge::new(context));
        let ctx = sb_core::registry::AdapterOutboundContext {
            context: sb_core::context::ContextRegistry::from(&bridge.context),
            bridge,
        };
        let connector = build_vmess_outbound(&param, &ir, &ctx).expect("invalid connector");
        let error = futures::executor::block_on(connector.dial(&sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("example.com", 443),
        )))
        .err()
        .expect("malformed root must reject before network dial");
        assert!(error.to_string().contains("TLS root CA"));
        assert!(error.to_string().contains("no certificates"));
    }

    #[test]
    #[cfg(feature = "adapter-dns")]
    fn build_dns_outbound_accepts_doh() {
        let ir = OutboundIR {
            ty: OutboundType::Dns,
            server: Some("1.1.1.1".into()),
            port: Some(443),
            dns_transport: Some("doh".into()),
            ..Default::default()
        };
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
    #[cfg(feature = "adapter-wireguard-outbound")]
    fn build_wireguard_outbound_feature_registers_real_builder() {
        let ir = OutboundIR {
            ty: OutboundType::Wireguard,
            name: Some("wg-out".to_string()),
            server: Some("198.51.100.1".to_string()),
            port: Some(51820),
            wireguard_private_key: Some("YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string()),
            wireguard_peer_public_key: Some(
                "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
            ),
            ..Default::default()
        };
        let param = OutboundParam {
            kind: "wireguard".into(),
            name: Some("wg-out".into()),
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

        let built = build_wireguard_outbound(&param, &ir, &ctx);
        assert!(
            built.is_some(),
            "adapter-wireguard-outbound feature must expose the real WireGuard outbound builder"
        );
        let connector = built.unwrap();
        assert!(
            connector.network().contains(&sb_types::NetworkKind::Udp),
            "adapter-wireguard-outbound must expose canonical UDP-over-tunnel support"
        );
    }

    #[test]
    #[cfg(feature = "adapter-hysteria2")]
    fn test_hysteria2_inbound_fields() {
        use sb_config::ir::{Hysteria2UserIR, InboundIR, InboundType};

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

    #[cfg(feature = "adapter-hysteria2")]
    #[test]
    fn hysteria2_outbound_mapping_preserves_transport_fields() {
        let param = OutboundParam {
            name: Some("hy2-edge".to_string()),
            ..Default::default()
        };
        let ir = OutboundIR {
            ty: sb_config::ir::OutboundType::Hysteria2,
            server: Some("hy2.example.com".to_string()),
            port: Some(8443),
            password: Some("secret".to_string()),
            tls_alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            tls_ca_paths: vec!["/tmp/ca.pem".to_string()],
            tls_ca_pem: vec!["PEM".to_string()],
            brutal_up_mbps: Some(50),
            brutal_down_mbps: Some(100),
            zero_rtt_handshake: Some(true),
            ..Default::default()
        };

        let config = hysteria2_adapter_config(&param, &ir).expect("valid hysteria2 config");
        assert_eq!(config.tag.as_deref(), Some("hy2-edge"));
        assert_eq!(config.server, "hy2.example.com");
        assert_eq!(config.port, 8443);
        assert_eq!(config.tls_ca_paths, ["/tmp/ca.pem"]);
        assert_eq!(config.tls_ca_pem, ["PEM"]);
        assert!(config.zero_rtt_handshake);
        let brutal = config.brutal.expect("brutal config");
        assert_eq!(brutal.up_mbps, 50);
        assert_eq!(brutal.down_mbps, 100);
    }

    #[test]
    #[cfg(feature = "adapter-shadowtls")]
    fn test_shadowtls_outbound_registration() {
        // Create a test OutboundIR for ShadowTLS
        let ir = OutboundIR {
            ty: OutboundType::Shadowtls,
            server: Some("example.com".to_string()),
            port: Some(443),
            password: Some("interop-password".to_string()),
            version: Some(1),
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
        let connector = result.unwrap();
        assert!(
            !connector.network().contains(&sb_types::NetworkKind::Udp),
            "ShadowTLS should not advertise canonical UDP support"
        );
    }

    #[tokio::test]
    #[cfg(feature = "adapter-shadowtls")]
    async fn test_shadowtls_outbound_registration_canonical_dial_exposes_wrapped_raw_stream() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();

        fn generate_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            let key = cert.key_pair.serialize_der();
            let cert = cert.cert.der().to_vec();
            (
                vec![CertificateDer::from(cert)],
                PrivateKeyDer::try_from(key).unwrap(),
            )
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let (certs, key) = generate_cert();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let tls_stream = acceptor.accept(stream).await.unwrap();
            let (mut raw_stream, _) = tls_stream.into_inner();
            let mut buf = [0u8; 4];
            raw_stream.read_exact(&mut buf).await.unwrap();
            raw_stream.write_all(&buf).await.unwrap();
        });

        let ir = OutboundIR {
            ty: OutboundType::Shadowtls,
            server: Some("127.0.0.1".to_string()),
            port: Some(server_addr.port()),
            password: Some("interop-password".to_string()),
            version: Some(1),
            tls_sni: Some("localhost".to_string()),
            tls_alpn: Some(vec!["http/1.1".to_string()]),
            skip_cert_verify: Some(true),
            ..Default::default()
        };

        let param = OutboundParam {
            kind: "shadowtls".into(),
            name: Some("shadowtls_test".into()),
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
        let connector = build_shadowtls_outbound(&param, &ir, &ctx)
            .expect("shadowtls bridge should be constructed");

        let mut stream = connector
            .dial(&sb_types::Session::new(
                0,
                sb_types::InboundTag::new("test"),
                sb_types::TargetAddr::domain("198.51.100.10", 443),
            ))
            .await
            .expect("detour bridge should expose wrapped raw stream for requested endpoint");
        futures::io::AsyncWriteExt::write_all(&mut stream, b"ping")
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        futures::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"ping");

        server_task.await.unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "adapter-vless")]
    async fn test_vless_outbound_bridge_canonical_dial_defers_vision_response_until_first_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;
        use uuid::Uuid;

        fn vision_frame(uuid: [u8; 16], content: &[u8]) -> Vec<u8> {
            let mut frame = Vec::with_capacity(16 + 5 + content.len());
            frame.extend_from_slice(&uuid);
            frame.push(0);
            frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.extend_from_slice(content);
            frame
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let uuid = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let (release_tx, release_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 256];
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut request))
                    .await
                    .unwrap()
                    .unwrap();
            assert!(
                read > 0,
                "server should observe a VLESS request before response"
            );
            assert_eq!(
                request[0], 0x00,
                "VLESS request should start with version 0"
            );

            release_rx.await.unwrap();

            stream.write_all(&[0x00, 0x00]).await.unwrap();
            stream
                .write_all(&vision_frame(*uuid.as_bytes(), b"pong"))
                .await
                .unwrap();
        });

        let ir = OutboundIR {
            ty: OutboundType::Vless,
            server: Some("127.0.0.1".to_string()),
            port: Some(server_addr.port()),
            uuid: Some(uuid.to_string()),
            flow: Some("xtls-rprx-vision".to_string()),
            ..Default::default()
        };
        let param = OutboundParam {
            kind: "vless".into(),
            name: Some("vless_test".into()),
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
        let connector =
            build_vless_outbound(&param, &ir, &ctx).expect("vless bridge should be constructed");

        let mut stream = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            connector.dial(&sb_types::Session::new(
                0,
                sb_types::InboundTag::new("test"),
                sb_types::TargetAddr::domain("example.com", 443),
            )),
        )
        .await
        .expect("canonical dial should return before the server sends a VLESS response")
        .expect("bridge should expose a layered stream");

        release_tx.send(()).unwrap();

        let mut payload = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            futures::io::AsyncReadExt::read_exact(&mut stream, &mut payload),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&payload, b"pong");

        server_task.await.unwrap();
    }

    #[test]
    #[cfg(feature = "adapter-shadowtls")]
    fn test_shadowtls_outbound_registration_requires_password() {
        let ir = OutboundIR {
            ty: OutboundType::Shadowtls,
            server: Some("example.com".to_string()),
            port: Some(443),
            version: Some(1),
            tls_sni: Some("example.com".to_string()),
            ..Default::default()
        };

        let param = OutboundParam {
            kind: "shadowtls".into(),
            name: Some("shadowtls_test".into()),
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
        let connector = build_shadowtls_outbound(&param, &ir, &ctx)
            .expect("shadowtls invalid config connector should still be constructed");

        let err = futures::executor::block_on(connector.dial(&sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("example.com", 443),
        )))
        .err()
        .expect("invalid shadowtls config should be rejected");
        assert!(err
            .to_string()
            .contains("missing required field 'password'"));
    }

    // ---- CAL-18: long-tail outbound loud-unsupported behavior ----

    #[test]
    fn longtail_unsupported_feature_reason_names_feature_and_rebuild() {
        // The reason string handed to a disabled long-tail outbound must name the
        // missing cargo feature and give a concrete next step (no generic message).
        for feature in ["adapter-tor", "adapter-tailscale", "legacy_shadowsocksr"] {
            let reason = unsupported_outbound_feature_reason(feature);
            let msg = reason.as_ref();
            assert!(
                msg.contains(feature),
                "reason must name the cargo feature: {msg}"
            );
            assert!(
                msg.contains("not compiled"),
                "reason must state it is not compiled in: {msg}"
            );
            assert!(
                msg.contains("--features"),
                "reason must give a rebuild hint: {msg}"
            );
        }
    }

    #[test]
    fn longtail_disabled_outbound_connect_fails_loudly() {
        // A feature-disabled long-tail outbound registers an InvalidConfigConnector
        // (instead of silently returning None), so a dial fails loudly carrying the
        // outbound type, the missing feature, and a rebuild hint.
        let connector =
            invalid_config_outbound("tor", unsupported_outbound_feature_reason("adapter-tor"))
                .expect("invalid_config_outbound always returns Some");
        let err = futures::executor::block_on(connector.dial(&sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("example.com", 443),
        )))
        .err()
        .expect("disabled long-tail outbound must reject dials");
        let msg = err.to_string();
        assert!(
            msg.contains("tor"),
            "error must name the outbound type: {msg}"
        );
        assert!(
            msg.contains("adapter-tor"),
            "error must name the cargo feature: {msg}"
        );
        assert!(
            msg.contains("--features"),
            "error must give a rebuild hint: {msg}"
        );
    }

    #[test]
    fn wireguard_disabled_outbound_connect_fails_loudly() {
        // P4-1: a feature-disabled WireGuard outbound registers an
        // InvalidConfigConnector (instead of silently returning None), so a dial
        // fails loudly carrying the outbound type, the missing cargo feature, and
        // a rebuild hint.
        let connector = invalid_config_outbound(
            "wireguard",
            unsupported_outbound_feature_reason("adapter-wireguard-outbound"),
        )
        .expect("invalid_config_outbound always returns Some");
        let err = futures::executor::block_on(connector.dial(&sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("example.com", 443),
        )))
        .err()
        .expect("disabled WireGuard outbound must reject dials");
        let msg = err.to_string();
        assert!(
            msg.contains("wireguard"),
            "error must name the outbound type: {msg}"
        );
        assert!(
            msg.contains("adapter-wireguard-outbound"),
            "error must name the cargo feature: {msg}"
        );
        assert!(
            msg.contains("--features"),
            "error must give a rebuild hint: {msg}"
        );
    }

    #[test]
    #[cfg(feature = "adapter-dns")]
    fn longtail_dns_outbound_is_real_not_stub() {
        // CAL-18 calibration: dns is wired into the adapters/parity aggregate, so the
        // real builder (not the #[cfg(not)] stub) must be compiled and return a
        // connector. Guards against regressing dns back into the long-tail stub set.
        let ir = OutboundIR {
            ty: OutboundType::Dns,
            server: Some("1.1.1.1".into()),
            port: Some(53),
            ..Default::default()
        };
        let param = OutboundParam {
            kind: "dns".into(),
            name: Some("dns-out".into()),
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
        assert!(
            build_dns_outbound(&param, &ir, &ctx).is_some(),
            "dns outbound must build a real connector under adapter-dns"
        );
    }
}

#[cfg(test)]
mod migration_tests {
    use super::{
        invalid_outbound_config_reason, parse_required_outbound_ip_addr,
        parse_required_outbound_socket_addr, parse_required_outbound_uuid,
    };
    use std::net::SocketAddr;

    #[test]
    fn invalid_outbound_uuid_is_rejected_explicitly() {
        let err =
            parse_required_outbound_uuid("vmess", "edge-vmess", Some(&"bad-uuid".to_string()))
                .expect_err("invalid uuid should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vmess outbound uuid 'bad-uuid' is invalid"));
        assert!(msg.contains("silent uuid parse fallback is disabled"));
    }

    #[test]
    fn invalid_vless_outbound_uuid_reports_protocol() {
        let err =
            parse_required_outbound_uuid("vless", "edge-vless", Some(&"bad-uuid".to_string()))
                .expect_err("invalid uuid should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vless outbound uuid 'bad-uuid' is invalid"));
        assert!(msg.contains("silent uuid parse fallback is disabled"));
    }

    #[test]
    fn invalid_tuic_outbound_uuid_reports_protocol() {
        let err = parse_required_outbound_uuid("tuic", "edge-tuic", Some(&"bad-uuid".to_string()))
            .expect_err("invalid uuid should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("tuic outbound uuid 'bad-uuid' is invalid"));
        assert!(msg.contains("silent uuid parse fallback is disabled"));
    }

    #[test]
    fn invalid_dns_outbound_server_reports_protocol() {
        let err =
            parse_required_outbound_ip_addr("dns", "server", "edge-dns", Some(&"bad-ip".into()))
                .expect_err("invalid ip should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("dns outbound server 'bad-ip' is invalid"));
        assert!(msg.contains("silent ip parse fallback is disabled"));
    }

    #[test]
    fn invalid_vmess_outbound_server_reports_protocol() {
        let endpoint =
            parse_required_outbound_socket_addr("vmess", "edge-vmess", "example.com", 443)
                .expect("domain-form endpoint should be accepted");
        assert_eq!(endpoint, ("example.com".to_string(), 443));
    }

    #[test]
    fn invalid_vless_outbound_server_reports_protocol() {
        let endpoint =
            parse_required_outbound_socket_addr("vless", "edge-vless", "example.com", 443)
                .expect("domain-form endpoint should be accepted");
        assert_eq!(endpoint, ("example.com".to_string(), 443));
    }

    #[test]
    fn invalid_vless_outbound_empty_server_is_rejected() {
        let err = parse_required_outbound_socket_addr("vless", "edge-vless", "   ", 443)
            .expect_err("empty server should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vless outbound server is empty"));
        assert!(msg.contains("silent endpoint fallback is disabled"));
    }

    #[test]
    fn invalid_vmess_outbound_zero_port_is_rejected() {
        let err = parse_required_outbound_socket_addr("vmess", "edge-vmess", "example.com", 0)
            .expect_err("zero port should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vmess outbound port '0' is invalid"));
        assert!(msg.contains("silent endpoint fallback is disabled"));
    }

    #[test]
    fn parse_listen_addr_explicitly_normalizes_ip_host() {
        let addr = super::parse_listen_addr("127.0.0.1", 8080)
            .expect("bare listen host should normalize with explicit path");
        assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_listen_addr_explicitly_normalizes_ipv6_host() {
        let addr = super::parse_listen_addr("::1", 8080)
            .expect("bare IPv6 listen host should normalize with explicit path");
        assert_eq!(addr, "[::1]:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_listen_addr_rejects_invalid_host() {
        assert!(super::parse_listen_addr("bad host", 8080).is_none());
    }

    #[test]
    fn invalid_shadowsocks_outbound_config_reports_protocol() {
        let msg = invalid_outbound_config_reason("shadowsocks", "edge-ss", "unsupported cipher")
            .to_string();
        assert!(msg.contains("shadowsocks outbound config is invalid"));
        assert!(msg.contains("silent builder failure is disabled"));
    }

    #[test]
    fn invalid_shadowsocksr_outbound_config_reports_protocol() {
        let msg =
            invalid_outbound_config_reason("shadowsocksr", "edge-ssr", "unsupported protocol")
                .to_string();
        assert!(msg.contains("shadowsocksr outbound config is invalid"));
        assert!(msg.contains("silent builder failure is disabled"));
    }
}

#[allow(dead_code)]
fn parse_listen_addr(listen: &str, port: u16) -> Option<SocketAddr> {
    match listen.parse() {
        Ok(addr) => Some(addr),
        Err(raw_err) => {
            let (normalized, parsed) = match listen.parse::<IpAddr>() {
                Ok(ip) => {
                    let addr = SocketAddr::new(ip, port);
                    (addr.to_string(), Ok(addr))
                }
                Err(_) => {
                    let text = format!("{listen}:{port}");
                    let parsed = text.parse::<SocketAddr>().map_err(|err| err.to_string());
                    (text, parsed)
                }
            };
            match parsed {
                Ok(addr) => {
                    warn!(
                        "listen addr '{listen}' is not a full socket address; explicit normalization to '{normalized}' is applied; silent listen parse fallback is disabled: {raw_err}"
                    );
                    Some(addr)
                }
                Err(normalized_err) => {
                    warn!(
                        "listen addr '{listen}' is invalid for port {port}; silent listen parse fallback is disabled; raw parse error: {raw_err}; normalized '{normalized}' parse error: {normalized_err}"
                    );
                    None
                }
            }
        }
    }
}

// ========== ShadowTLS Inbound ==========

// ========== TUN Inbound ==========

// ========== Redirect Inbound (Linux only) ==========

#[cfg(all(target_os = "linux", feature = "redirect", feature = "router"))]
#[allow(dead_code)]
fn build_redirect_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
    use crate::inbound::redirect::RedirectConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = RedirectConfig {
        listen,
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        conn_tracker: ctx.context.conn_tracker.clone(),
    };
    Some(Arc::new(
        crate::inbound::redirect::RedirectInboundDriver::new(cfg),
    ))
}

// ========== TProxy Inbound (Linux only) ==========

#[cfg(all(target_os = "linux", feature = "tproxy", feature = "router"))]
#[allow(dead_code)]
fn build_tproxy_inbound(
    param: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn InboundTaskDriver>> {
    use crate::inbound::tproxy::TproxyConfig;

    let listen = parse_listen_addr(&param.listen, param.port)?;
    let cfg = TproxyConfig {
        listen,
        tag: param.tag.clone(),
        stats: ctx.context.v2ray_server.as_ref().and_then(|s| s.stats()),
        conn_tracker: ctx.context.conn_tracker.clone(),
    };
    Some(Arc::new(crate::inbound::tproxy::TproxyInboundDriver::new(
        cfg,
    )))
}

// ========== TUIC Inbound ==========

// Selector and URLTest builders
fn build_selector_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    crate::outbound::selector::build_selector_outbound(param, ir, ctx)
}

fn build_urltest_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    crate::outbound::urltest::build_urltest_outbound(param, ir, ctx)
}

fn build_selector_outbound_canonical(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    build_selector_outbound(param, ir, ctx)
}

fn build_urltest_outbound_canonical(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    build_urltest_outbound(param, ir, ctx)
}

fn build_tailscale_outbound_canonical(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> CanonicalOutboundBuilderResult {
    build_tailscale_outbound(param, ir, ctx)
}
