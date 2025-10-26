use anyhow::{anyhow, Context, Result};
use sb_config::Config;
use sb_core::adapter::InboundService;
use tracing::{error, info, warn};

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::{
    net::TcpStream,
    sync::mpsc,
    time::{timeout, Duration},
};

// TEMPORARY: Simplified placeholder router functionality
// This is a minimal stub to allow compilation for subs security tests
use sb_core::adapter::OutboundConnector as AdapterConnector;
#[cfg(feature = "router")]
use sb_core::outbound::selector_group::{ProxyMember as GroupMember, SelectorGroup};
use sb_core::outbound::{endpoint::ProxyEndpoint, health as ob_health, registry as ob_registry};
use sb_core::outbound::{OutboundRegistry, OutboundRegistryHandle};
#[cfg(feature = "router")]
use sb_core::router::router_build_index_from_str;
#[cfg(feature = "router")]
use sb_core::router::RouterHandle;
#[cfg(feature = "router")]
use std::collections::HashMap;

use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
use sb_adapters::inbound::socks::udp::serve_socks5_udp_service;
use sb_adapters::inbound::socks::{serve_socks, SocksInboundConfig};
#[cfg(feature = "tun")]
use sb_adapters::inbound::tun::{TunInbound, TunInboundConfig};

const DEFAULT_URLTEST_URL: &str = "http://www.gstatic.com/generate_204";
const DEFAULT_URLTEST_INTERVAL_MS: u64 = 60_000;
const DEFAULT_URLTEST_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_URLTEST_TOLERANCE_MS: u64 = 50;

fn parse_alpn_tokens(src: &str) -> Vec<String> {
    src.split(',')
        .flat_map(|part| part.split_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn map_header_entries(entries: &[sb_config::ir::HeaderEntry]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|h| (h.name.clone(), h.value.clone()))
        .collect()
}

#[allow(dead_code)]
async fn probe(addr: SocketAddr) -> bool {
    timeout(Duration::from_secs(1), TcpStream::connect(addr))
        .await
        .is_ok()
}

pub struct Runtime {
    #[cfg(feature = "router")]
    pub router: Arc<sb_core::router::engine::RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
}

/// Initialize proxy registry from environment variables.
fn init_proxy_registry_from_env() {
    if let Ok(s) = std::env::var("SB_ROUTER_DEFAULT_PROXY") {
        if let Some(ep) = ProxyEndpoint::parse(&s) {
            let pools = load_pools_from_env().unwrap_or_default();
            let r = ob_registry::Registry {
                default: Some(ProxyEndpoint {
                    weight: 1,
                    max_fail: 3,
                    open_ms: 5000,
                    half_open_ms: 1000,
                    ..ep
                }),
                pools,
            };
            ob_registry::install_global(r);
        }
    }
}

/// Create router handle based on feature flags.
#[cfg(feature = "router")]
fn create_router_handle() -> Arc<sb_core::router::engine::RouterHandle> {
    // Prefer DNS-integrated handle if enabled via env
    use sb_core::router::dns_integration::setup_dns_routing;
    Arc::new(setup_dns_routing())
}

/// Convert string like "127.0.0.1:8080" to SocketAddr with friendly error.
fn parse_listen_addr(s: &str) -> Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .or_else(|_| {
            let t = s.trim();
            t.parse::<SocketAddr>()
        })
        .with_context(|| format!("invalid listen addr in config: '{s}'"))
}

/// Build OutboundRegistry from ConfigIR (minimal: direct/block/http/socks)
pub fn build_outbound_registry_from_ir(ir: &sb_config::ir::ConfigIR) -> OutboundRegistry {
    use sb_core::outbound::{HttpProxyConfig, OutboundImpl, Socks5Config};

    let mut map = std::collections::HashMap::new();

    for ob in &ir.outbounds {
        let name = match &ob.name {
            Some(n) if !n.is_empty() => n.clone(),
            _ => continue,
        };
        match ob.ty {
            sb_config::ir::OutboundType::Direct => {
                map.insert(name, OutboundImpl::Direct);
            }
            sb_config::ir::OutboundType::Block => {
                map.insert(name, OutboundImpl::Block);
            }
            sb_config::ir::OutboundType::Socks => {
                if let (Some(host), Some(port)) = (&ob.server, ob.port) {
                    if let Ok(addr) = resolve_host_port(host, port) {
                        let cfg = Socks5Config {
                            proxy_addr: addr,
                            username: ob.credentials.as_ref().and_then(|c| c.username.clone()),
                            password: ob.credentials.as_ref().and_then(|c| c.password.clone()),
                        };
                        map.insert(name, OutboundImpl::Socks5(cfg));
                    }
                }
            }
            sb_config::ir::OutboundType::Http => {
                if let (Some(host), Some(port)) = (&ob.server, ob.port) {
                    if let Ok(addr) = resolve_host_port(host, port) {
                        let cfg = HttpProxyConfig {
                            proxy_addr: addr,
                            username: ob.credentials.as_ref().and_then(|c| c.username.clone()),
                            password: ob.credentials.as_ref().and_then(|c| c.password.clone()),
                        };
                        map.insert(name, OutboundImpl::HttpProxy(cfg));
                    }
                }
            }
            sb_config::ir::OutboundType::Hysteria2 => {
                #[cfg(feature = "router")]
                {
                    if let (Some(server), Some(port), Some(password)) =
                        (&ob.server, ob.port, ob.password.as_ref())
                    {
                        use sb_core::outbound::hysteria2::BrutalConfig;

                        let alpn_list = ob
                            .tls_alpn
                            .as_ref()
                            .or(ob.alpn.as_ref())
                            .map(|raw| parse_alpn_tokens(raw));
                        let brutal_cfg = match (ob.brutal_up_mbps, ob.brutal_down_mbps) {
                            (Some(up), Some(down)) => Some(BrutalConfig {
                                up_mbps: up,
                                down_mbps: down,
                            }),
                            (Some(_), None) | (None, Some(_)) => {
                                tracing::warn!(
                                    outbound=%name,
                                    "ignored partial brutal config; both up_mbps/down_mbps required"
                                );
                                None
                            }
                            _ => None,
                        };
                        let cfg = sb_core::outbound::hysteria2::Hysteria2Config {
                            server: server.clone(),
                            port,
                            password: password.clone(),
                            congestion_control: ob.congestion_control.clone(),
                            up_mbps: ob.up_mbps,
                            down_mbps: ob.down_mbps,
                            obfs: ob.obfs.clone(),
                            skip_cert_verify: ob.skip_cert_verify.unwrap_or(false),
                            sni: ob.tls_sni.clone(),
                            alpn: alpn_list,
                            salamander: ob.salamander.clone(),
                            brutal: brutal_cfg,
                        };
                        map.insert(name, OutboundImpl::Hysteria2(cfg));
                    }
                }
            }
            sb_config::ir::OutboundType::Tuic => {
                #[cfg(feature = "router")]
                {
                    let uuid_str = ob.uuid.as_ref();
                    let token = ob.token.as_ref();
                    match (&ob.server, ob.port, uuid_str, token) {
                        (Some(server), Some(port), Some(uuid_str), Some(token)) => {
                            match uuid::Uuid::parse_str(uuid_str) {
                                Ok(uuid) => {
                                    use sb_core::outbound::tuic::{TuicConfig, UdpRelayMode};
                                    let relay_mode = match ob.udp_relay_mode.as_deref() {
                                        Some(mode) if mode.eq_ignore_ascii_case("quic") => {
                                            UdpRelayMode::Quic
                                        }
                                        _ => UdpRelayMode::Native,
                                    };
                                    let cfg = TuicConfig {
                                        server: server.clone(),
                                        port,
                                        uuid,
                                        token: token.clone(),
                                        password: ob.password.clone(),
                                        congestion_control: ob.congestion_control.clone(),
                                        alpn: ob.alpn.clone().or(ob.tls_alpn.clone()),
                                        skip_cert_verify: ob.skip_cert_verify.unwrap_or(false),
                                        udp_relay_mode: relay_mode,
                                        udp_over_stream: ob.udp_over_stream.unwrap_or(false),
                                    };
                                    map.insert(name, OutboundImpl::Tuic(cfg));
                                }
                                Err(e) => {
                                    warn!(
                                        outbound=%name,
                                        error=%e,
                                        "invalid UUID for TUIC outbound"
                                    );
                                }
                            }
                        }
                        _ => {
                            warn!(
                                outbound=%name,
                                "tuic outbound requires server, port, uuid, and token"
                            );
                        }
                    }
                }
            }
            sb_config::ir::OutboundType::Shadowsocks => {
                #[cfg(feature = "router")]
                {
                    use sb_core::outbound::shadowsocks::{ShadowsocksCipher, ShadowsocksConfig};
                    let server = match &ob.server {
                        Some(s) => s.clone(),
                        None => {
                            tracing::warn!(outbound=%name, "shadowsocks requires server");
                            continue;
                        }
                    };
                    let port = match ob.port {
                        Some(p) => p,
                        None => {
                            tracing::warn!(outbound=%name, "shadowsocks requires port");
                            continue;
                        }
                    };
                    let password = match &ob.password {
                        Some(p) if !p.is_empty() => p.clone(),
                        _ => {
                            tracing::warn!(outbound=%name, "shadowsocks requires password");
                            continue;
                        }
                    };
                    let method = ob
                        .method
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    let cipher = match method.as_str() {
                        "aes-256-gcm" => Some(ShadowsocksCipher::Aes256Gcm),
                        "chacha20-poly1305" => Some(ShadowsocksCipher::Chacha20Poly1305),
                        "" => {
                            tracing::warn!(outbound=%name, "shadowsocks requires method");
                            None
                        }
                        other => {
                            tracing::warn!(outbound=%name, method=%other, "unsupported shadowsocks method");
                            None
                        }
                    };
                    if let Some(cipher) = cipher {
                        let cfg = ShadowsocksConfig::new(server, port, password, cipher);
                        map.insert(name, OutboundImpl::Shadowsocks(cfg));
                    }
                }
            }
            sb_config::ir::OutboundType::Vless => {
                #[cfg(feature = "router")]
                {
                    if let (Some(server), Some(port), Some(uuid_str)) =
                        (&ob.server, ob.port, ob.uuid.as_ref())
                    {
                        if let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) {
                            let tls_alpn = ob
                                .tls_alpn
                                .as_ref()
                                .or(ob.alpn.as_ref())
                                .map(|raw| parse_alpn_tokens(raw));
                            let cfg = sb_core::outbound::vless::VlessConfig {
                                server: server.clone(),
                                port,
                                uuid,
                                flow: ob.flow.clone(),
                                encryption: Some("none".to_string()),
                                transport: ob.transport.clone(),
                                ws_path: ob.ws_path.clone(),
                                ws_host: ob.ws_host.clone(),
                                h2_path: ob.h2_path.clone(),
                                h2_host: ob.h2_host.clone(),
                                tls_sni: ob.tls_sni.clone(),
                                tls_alpn,
                                grpc_service: ob.grpc_service.clone(),
                                grpc_method: ob.grpc_method.clone(),
                                grpc_authority: ob.grpc_authority.clone(),
                                grpc_metadata: map_header_entries(&ob.grpc_metadata),
                                http_upgrade_path: ob.http_upgrade_path.clone(),
                                http_upgrade_headers: map_header_entries(&ob.http_upgrade_headers),
                            };
                            map.insert(name, OutboundImpl::Vless(cfg));
                        }
                    }
                }
            }
            sb_config::ir::OutboundType::Vmess => {
                #[cfg(feature = "router")]
                {
                    if let (Some(server), Some(port), Some(id_str)) =
                        (&ob.server, ob.port, ob.uuid.as_ref())
                    {
                        if let Ok(id) = uuid::Uuid::parse_str(id_str) {
                            let tls_alpn = ob
                                .tls_alpn
                                .as_ref()
                                .or(ob.alpn.as_ref())
                                .map(|raw| parse_alpn_tokens(raw));
                            let cfg = sb_core::outbound::vmess::VmessConfig {
                                server: server.clone(),
                                port,
                                id,
                                security: "aes-128-gcm".to_string(),
                                alter_id: 0,
                                transport: ob.transport.clone(),
                                ws_path: ob.ws_path.clone(),
                                ws_host: ob.ws_host.clone(),
                                h2_path: ob.h2_path.clone(),
                                h2_host: ob.h2_host.clone(),
                                tls_sni: ob.tls_sni.clone(),
                                tls_alpn,
                                grpc_service: ob.grpc_service.clone(),
                                grpc_method: ob.grpc_method.clone(),
                                grpc_authority: ob.grpc_authority.clone(),
                                grpc_metadata: map_header_entries(&ob.grpc_metadata),
                                http_upgrade_path: ob.http_upgrade_path.clone(),
                                http_upgrade_headers: map_header_entries(&ob.http_upgrade_headers),
                            };
                            map.insert(name, OutboundImpl::Vmess(cfg));
                        }
                    }
                }
            }
            sb_config::ir::OutboundType::Trojan => {
                #[cfg(feature = "router")]
                {
                    if let (Some(server), Some(port), Some(password)) =
                        (&ob.server, ob.port, ob.password.as_ref())
                    {
                        let sni = ob.tls_sni.clone().unwrap_or_else(|| server.clone());
                        let mut cfg = sb_core::outbound::trojan::TrojanConfig::new(
                            server.clone(),
                            port,
                            password.clone(),
                            sni,
                        );
                        if let Some(raw) = ob.tls_alpn.as_ref().or(ob.alpn.as_ref()) {
                            let tokens = parse_alpn_tokens(raw);
                            if !tokens.is_empty() {
                                cfg = cfg.with_alpn(tokens);
                            }
                        }
                        if ob.skip_cert_verify.unwrap_or(false) {
                            cfg = cfg.with_skip_cert_verify(true);
                        }
                        map.insert(name, OutboundImpl::Trojan(cfg));
                    }
                }
            }
            // Other protocols will be wired in Phase 2
            _ => {}
        }
    }

    // Build selector connectors in a second pass (requires members to exist first)
    #[cfg(feature = "router")]
    {
        // Snapshot of existing connectors for member lookup
        let mut existing: HashMap<String, OutboundImpl> = map.clone();

        for ob in &ir.outbounds {
            let name = match &ob.name {
                Some(n) if !n.is_empty() => n.clone(),
                _ => continue,
            };
            match ob.ty {
                sb_config::ir::OutboundType::Selector => {
                    let members = match &ob.members {
                        Some(v) if !v.is_empty() => v.clone(),
                        _ => {
                            tracing::warn!(selector=%name, "selector has no members; skipping");
                            continue;
                        }
                    };
                    let mut group_members: Vec<GroupMember> = Vec::new();
                    for member in members {
                        match existing.get(&member) {
                            Some(impl_ref) => {
                                if let Some(conn) = to_adapter_connector(impl_ref) {
                                    group_members.push(GroupMember::new(member.clone(), conn));
                                } else {
                                    tracing::warn!(
                                        member=%member,
                                        selector=%name,
                                        "member outbound cannot be used as connector; skipping"
                                    );
                                }
                            }
                            None => {
                                tracing::warn!(
                                    member=%member,
                                    selector=%name,
                                    "member outbound not found"
                                );
                            }
                        }
                    }
                    if group_members.is_empty() {
                        tracing::warn!(
                            selector=%name,
                            "no usable members; skipping selector"
                        );
                        continue;
                    }
                    let selector = SelectorGroup::new_manual(
                        name.clone(),
                        group_members,
                        ob.default_member.clone(),
                    );
                    let selector = Arc::new(selector);
                    map.insert(name.clone(), OutboundImpl::Connector(selector.clone()));
                    existing.insert(name, OutboundImpl::Connector(selector));
                }
                sb_config::ir::OutboundType::UrlTest => {
                    let members = match &ob.members {
                        Some(v) if !v.is_empty() => v.clone(),
                        _ => {
                            tracing::warn!(selector=%name, "urltest has no members; skipping");
                            continue;
                        }
                    };
                    let mut group_members: Vec<GroupMember> = Vec::new();
                    for member in members {
                        match existing.get(&member) {
                            Some(impl_ref) => {
                                if let Some(conn) = to_adapter_connector(impl_ref) {
                                    group_members.push(GroupMember::new(member.clone(), conn));
                                } else {
                                    tracing::warn!(
                                        member=%member,
                                        selector=%name,
                                        "member outbound cannot be used as connector; skipping"
                                    );
                                }
                            }
                            None => {
                                tracing::warn!(
                                    member=%member,
                                    selector=%name,
                                    "member outbound not found"
                                );
                            }
                        }
                    }
                    if group_members.is_empty() {
                        tracing::warn!(
                            selector=%name,
                            "no usable members; skipping urltest selector"
                        );
                        continue;
                    }
                    let interval_ms = ob.test_interval_ms.unwrap_or(DEFAULT_URLTEST_INTERVAL_MS);
                    let timeout_ms = ob.test_timeout_ms.unwrap_or(DEFAULT_URLTEST_TIMEOUT_MS);
                    let tolerance_ms = ob.test_tolerance_ms.unwrap_or(DEFAULT_URLTEST_TOLERANCE_MS);
                    let selector = SelectorGroup::new_urltest(
                        name.clone(),
                        group_members,
                        ob.test_url
                            .clone()
                            .unwrap_or_else(|| DEFAULT_URLTEST_URL.to_string()),
                        Duration::from_millis(interval_ms),
                        Duration::from_millis(timeout_ms),
                        tolerance_ms,
                    );
                    let selector = Arc::new(selector);
                    // Start health checker only if a Tokio runtime is available
                    if tokio::runtime::Handle::try_current().is_ok() {
                        selector.clone().start_health_check();
                    }
                    map.insert(name.clone(), OutboundImpl::Connector(selector.clone()));
                    existing.insert(name, OutboundImpl::Connector(selector));
                }
                _ => {}
            }
        }
    }

    // Ensure default aliases exist for router decisions
    map.entry("direct".to_string())
        .or_insert(OutboundImpl::Direct);
    map.entry("block".to_string())
        .or_insert(OutboundImpl::Block);

    OutboundRegistry::new(map)
}

#[cfg(feature = "router")]
fn to_adapter_connector(
    imp: &sb_core::outbound::OutboundImpl,
) -> Option<Arc<dyn AdapterConnector>> {
    use sb_core::outbound::{
        direct_connector::DirectConnector, http_upstream::HttpUp, socks_upstream::SocksUp,
    };
    match imp {
        sb_core::outbound::OutboundImpl::Direct => Some(Arc::new(DirectConnector::new())),
        sb_core::outbound::OutboundImpl::Socks5(cfg) => Some(Arc::new(SocksUp::new(
            cfg.proxy_addr.ip().to_string(),
            cfg.proxy_addr.port(),
            cfg.username.clone(),
            cfg.password.clone(),
        ))),
        sb_core::outbound::OutboundImpl::HttpProxy(cfg) => Some(Arc::new(HttpUp::new(
            cfg.proxy_addr.ip().to_string(),
            cfg.proxy_addr.port(),
            cfg.username.clone(),
            cfg.password.clone(),
        ))),
        sb_core::outbound::OutboundImpl::Vless(cfg) => {
            use sb_core::outbound::vless::VlessOutbound;
            VlessOutbound::new(cfg.clone())
                .ok()
                .map(|o| Arc::new(o) as Arc<dyn AdapterConnector>)
        }
        sb_core::outbound::OutboundImpl::Vmess(cfg) => {
            use sb_core::outbound::vmess::VmessOutbound;
            VmessOutbound::new(cfg.clone())
                .ok()
                .map(|o| Arc::new(o) as Arc<dyn AdapterConnector>)
        }
        sb_core::outbound::OutboundImpl::Tuic(cfg) => {
            use sb_core::outbound::tuic::TuicOutbound;
            TuicOutbound::new(cfg.clone())
                .ok()
                .map(|o| Arc::new(o) as Arc<dyn AdapterConnector>)
        }
        sb_core::outbound::OutboundImpl::Trojan(_cfg) => None,
        sb_core::outbound::OutboundImpl::Hysteria2(cfg) => {
            use sb_core::outbound::hysteria2::Hysteria2Outbound;
            Hysteria2Outbound::new(cfg.clone())
                .ok()
                .map(|o| Arc::new(o) as Arc<dyn AdapterConnector>)
        }
        // Not supported
        _ => None,
    }
}

/// Convert ConfigIR to router rules text (mirrors config_loader::config_ir_to_router_rules)
#[cfg(feature = "router")]
fn ir_to_router_rules_text(config: &sb_config::ir::ConfigIR) -> String {
    let mut rules = Vec::new();

    for rule in &config.route.rules {
        let outbound = rule.outbound.as_deref().unwrap_or("direct");

        for domain in &rule.domain {
            rules.push(format!("exact:{domain}={outbound}"));
        }
        for geosite in &rule.geosite {
            rules.push(format!("geosite:{geosite}={outbound}"));
        }
        for geoip in &rule.geoip {
            rules.push(format!("geoip:{geoip}={outbound}"));
        }
        for ipcidr in &rule.ipcidr {
            let rule_type = if ipcidr.contains(':') {
                "cidr6"
            } else {
                "cidr4"
            };
            rules.push(format!("{rule_type}:{ipcidr}={outbound}"));
        }
        for port in &rule.port {
            if port.contains('-') {
                rules.push(format!("portrange:{port}={outbound}"));
            } else {
                rules.push(format!("port:{port}={outbound}"));
            }
        }
        for process in &rule.process {
            rules.push(format!("process:{process}={outbound}"));
        }
        for network in &rule.network {
            rules.push(format!("transport:{network}={outbound}"));
        }
        for protocol in &rule.protocol {
            rules.push(format!("protocol:{protocol}={outbound}"));
        }
        // alpn/user-agent/source/dest can be added later when routed
    }

    if let Some(default) = &config.route.default {
        rules.push(format!("default={default}"));
    } else {
        rules.push("default=direct".to_string());
    }

    rules.join("\n")
}

/// Build a RouterIndex from Config using IR rules
#[cfg(feature = "router")]
pub fn build_router_index_from_config(cfg: &Config) -> Result<Arc<sb_core::router::RouterIndex>> {
    let cfg_ir = sb_config::present::to_ir(cfg).map_err(|e| anyhow!("to_ir failed: {e}"))?;
    let text = ir_to_router_rules_text(&cfg_ir);
    let max_rules = std::env::var("SB_ROUTER_RULES_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000usize);
    let idx = router_build_index_from_str(&text, max_rules)
        .map_err(|e| anyhow!("router index build failed: {e}"))?;
    Ok(idx)
}

fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let qp = format!("{}:{}", host, port);
    let mut it = qp
        .to_socket_addrs()
        .with_context(|| format!("resolve failed: {}", qp))?;
    it.next()
        .ok_or_else(|| anyhow!("no address resolved for {}", qp))
}

/// Start the proxy runtime from configuration.
///
/// # Errors
/// Returns an error if:
/// - Configuration validation fails
/// - Proxy registry initialization fails
/// - Inbound/outbound setup fails
/// - Network binding fails
pub async fn start_from_config(cfg: Config) -> Result<Runtime> {
    // Install proxy health registry (from default proxy env + proxy pools)
    init_proxy_registry_from_env();

    // Start health checking (behind env)
    ob_health::spawn_if_enabled().await;

    // 1) 构建 Registry/Router 并包装成 Handle（严格失败）
    cfg.validate()?; // Configuration validation (IR compiled inside)

    // Convert to IR once
    let cfg_ir = sb_config::present::to_ir(&cfg).map_err(|e| anyhow!("to_ir failed: {e}"))?;

    // Optionally configure DNS via config (env bridge for sb-core)
    apply_dns_from_config(&cfg);

    // Build outbounds registry from IR (minimal phase 1 set)
    let reg = build_outbound_registry_from_ir(&cfg_ir);
    let oh = Arc::new(OutboundRegistryHandle::new(reg));

    // Create router and install index from IR
    #[cfg(feature = "router")]
    let rh = {
        let handle = create_router_handle();
        match build_router_index_from_config(&cfg) {
            Ok(idx) => {
                if let Err(e) = handle.replace_index(idx).await {
                    error!(error=%e, "apply router index failed");
                }
            }
            Err(e) => {
                error!(error=%e, "build router index failed");
            }
        }
        handle
    };

    let (inbounds, outbounds, rules) = cfg.stats();
    info!("sb bootstrap: inbounds={inbounds}, outbounds={outbounds}, rules={rules}");

    // 2) 起入站（HTTP / SOCKS / TUN）：每个入站一个 stop 通道；当前不做热更新/回收
    start_inbounds_from_ir(
        &cfg_ir.inbounds,
        #[cfg(feature = "router")]
        rh.clone(),
        oh.clone(),
    )
    .await;

    Ok(Runtime {
        #[cfg(feature = "router")]
        router: rh,
        outbounds: oh,
    })
}

#[allow(dead_code)]
fn parse_addr(s: &str) -> Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .or_else(|_| {
            // 容忍用户写入 "127.0.0.1:port" 之外的空格等问题
            let t = s.trim();
            t.parse::<SocketAddr>()
        })
        .map_err(|e| anyhow::anyhow!("invalid listen addr in config '{s}': {e}"))
}

fn socks_udp_should_start() -> bool {
    // 显式开关优先；其次只要配置了监听地址也启动
    let enabled = std::env::var("SB_SOCKS_UDP_ENABLE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    enabled
        || std::env::var("SB_SOCKS_UDP_LISTEN")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
}

fn parse_udp_bind_from_env() -> Option<SocketAddr> {
    if let Ok(list) = std::env::var("SB_SOCKS_UDP_LISTEN") {
        let first = list
            .split(|c: char| c == ',' || c.is_whitespace())
            .find(|s| !s.is_empty());
        if let Some(tok) = first {
            if let Ok(sa) = tok.parse::<SocketAddr>() {
                return Some(sa);
            }
        }
    }
    None
}

/// Start HTTP/SOCKS inbounds based on legacy inbounds list
#[allow(clippy::unused_async)]
async fn start_inbounds_from_ir(
    inbounds: &[sb_config::ir::InboundIR],
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) {
    use sb_config::ir::InboundType;

    for ib in inbounds {
        match ib.ty {
            InboundType::Http => {
                let listen_str = if ib.listen.contains(':') {
                    ib.listen.clone()
                } else {
                    format!("{}:{}", ib.listen, ib.port)
                };
                if let Ok(addr) = parse_listen_addr(&listen_str) {
                    let (_tx, rx) = mpsc::channel::<()>(1);
                    let cfg = HttpProxyConfig {
                        listen: addr,
                        #[cfg(feature = "router")]
                        router: router.clone(),
                        #[cfg(not(feature = "router"))]
                        router: Arc::new(sb_core::router::RouterHandle::from_env()),
                        outbounds: outbounds.clone(),
                        tls: None,
                    };
                    tokio::spawn(async move {
                        if let Err(e) = serve_http(cfg, rx, None).await {
                            warn!(addr=%listen_str, error=%e, "http inbound failed");
                        }
                    });
                } else {
                    warn!(%listen_str, "http inbound: invalid listen address");
                }
            }
            InboundType::Socks => {
                let listen_str = if ib.listen.contains(':') {
                    ib.listen.clone()
                } else {
                    format!("{}:{}", ib.listen, ib.port)
                };
                if let Ok(addr) = parse_listen_addr(&listen_str) {
                    let (_tx, rx) = mpsc::channel::<()>(1);
                    let cfg = SocksInboundConfig {
                        listen: addr,
                        udp_bind: parse_udp_bind_from_env(),
                        #[cfg(feature = "router")]
                        router: router.clone(),
                        #[cfg(not(feature = "router"))]
                        router: Arc::new(sb_core::router::RouterHandle::from_env()),
                        outbounds: outbounds.clone(),
                        udp_nat_ttl: Duration::from_secs(60),
                    };
                    tokio::spawn(async move {
                        if let Err(e) = serve_socks(cfg, rx, None).await {
                            warn!(addr=%listen_str, error=%e, "socks inbound failed");
                        }
                    });
                    // start UDP association service if config or env enables
                    if ib.udp || socks_udp_should_start() {
                        tokio::spawn(async move {
                            if let Err(e) = serve_socks5_udp_service().await {
                                warn!(error=%e, "socks udp service failed");
                            }
                        });
                    }
                } else {
                    warn!(%listen_str, "socks inbound: invalid listen address");
                }
            }
            InboundType::Tun => {
                // Phase 1: spawn TUN inbound skeleton with defaults
                #[cfg(feature = "tun")]
                {
                    let cfg = TunInboundConfig::default();
                    let inbound = TunInbound::new(cfg, {
                        #[cfg(feature = "router")]
                        {
                            router.clone()
                        }
                        #[cfg(not(feature = "router"))]
                        {
                            Arc::new(sb_core::router::RouterHandle::from_env())
                        }
                    });
                    tokio::spawn(async move {
                        if let Err(e) = inbound.serve().await {
                            warn!(error=%e, "tun inbound failed");
                        }
                    });
                    info!("tun inbound spawned (phase1 skeleton)");
                }
                #[cfg(not(feature = "tun"))]
                {
                    warn!("config includes tun inbound, but feature 'tun' is disabled; skipping");
                }
            }
            InboundType::Direct => {
                // Direct forwarder: listen locally and forward to override_host:override_port
                let dst_host = match &ib.override_host {
                    Some(h) => h.clone(),
                    None => {
                        warn!("direct inbound missing override_host/override_address; skipping");
                        continue;
                    }
                };
                let dst_port = match ib.override_port {
                    Some(p) => p,
                    None => {
                        warn!("direct inbound missing override_port; skipping");
                        continue;
                    }
                };
                let listen_str = if ib.listen.contains(':') {
                    ib.listen.clone()
                } else {
                    format!("{}:{}", ib.listen, ib.port)
                };
                match parse_listen_addr(&listen_str) {
                    Ok(addr) => {
                        let f_dst = format!("{}:{}", dst_host, dst_port);
                        let forward = sb_core::inbound::direct::DirectForward::new(
                            addr, dst_host, dst_port, ib.udp,
                        );
                        tokio::task::spawn_blocking(move || {
                            let _ = forward.serve();
                        });
                        info!(addr=%listen_str, dst=%f_dst, "direct inbound spawned");
                    }
                    Err(e) => {
                        warn!(addr=%listen_str, error=%e, "direct inbound: invalid listen address");
                    }
                }
            }
        }
    }
}

fn load_pools_from_env(
) -> anyhow::Result<std::collections::HashMap<String, sb_core::outbound::registry::ProxyPool>> {
    use std::fs;
    if let Ok(txt) = std::env::var("SB_PROXY_POOL_JSON") {
        return parse_pool_json(&txt);
    }
    if let Ok(path) = std::env::var("SB_PROXY_POOL_FILE") {
        let txt = fs::read_to_string(path)?;
        return parse_pool_json(&txt);
    }
    Ok(std::collections::HashMap::new())
}

fn parse_pool_json(
    txt: &str,
) -> anyhow::Result<std::collections::HashMap<String, sb_core::outbound::registry::ProxyPool>> {
    use sb_core::outbound::{
        endpoint::ProxyKind,
        registry::{PoolPolicy, ProxyPool, StickyCfg},
    };

    #[derive(serde::Deserialize)]
    struct Ep {
        kind: String,
        addr: String,
        weight: Option<u32>,
        max_fail: Option<u32>,
        open_ms: Option<u64>,
        half_open_ms: Option<u64>,
    }

    #[derive(serde::Deserialize)]
    struct Pool {
        name: String,
        policy: Option<String>,
        sticky_ttl_ms: Option<u64>,
        sticky_cap: Option<usize>,
        endpoints: Vec<Ep>,
    }

    let v: Vec<Pool> = serde_json::from_str(txt)?;
    let mut map = std::collections::HashMap::new();

    for p in v {
        let eps = p
            .endpoints
            .into_iter()
            .filter_map(|e| {
                let kind = match e.kind.to_ascii_lowercase().as_str() {
                    "http" => ProxyKind::Http,
                    "socks5" => ProxyKind::Socks5,
                    _ => return None,
                };
                let addr = e.addr.parse().ok()?;
                Some(ProxyEndpoint {
                    kind,
                    addr,
                    auth: None,
                    weight: e.weight.unwrap_or(1),
                    max_fail: e.max_fail.unwrap_or(3),
                    open_ms: e.open_ms.unwrap_or(5000),
                    half_open_ms: e.half_open_ms.unwrap_or(1000),
                })
            })
            .collect();

        let pool = ProxyPool {
            name: p.name.clone(),
            endpoints: eps,
            policy: match p.policy.as_deref() {
                Some("latency_bias") => PoolPolicy::WeightedRRWithLatencyBias,
                _ => PoolPolicy::WeightedRR,
            },
            sticky: StickyCfg {
                ttl_ms: p.sticky_ttl_ms.unwrap_or(10_000),
                cap: p.sticky_cap.unwrap_or(4096),
            },
        };
        map.insert(p.name, pool);
    }
    Ok(map)
}

/// Apply DNS configuration from `config.raw()` via env for sb-core DNS resolver
fn apply_dns_from_config(cfg: &Config) {
    use serde_json::Value;
    let raw = cfg.raw();
    let mut pool_tokens: Vec<String> = Vec::new();

    if let Some(dns) = raw.get("dns").and_then(Value::as_object) {
        if let Some(servers) = dns.get("servers").and_then(|v| v.as_array()) {
            for sv in servers {
                if let Some(tok) = server_to_token(sv) {
                    push_dedup(&mut pool_tokens, tok);
                }
            }
        }

        // Optional strategy: race | sequential
        if let Some(strategy) = dns.get("strategy").and_then(Value::as_str) {
            std::env::set_var("SB_DNS_POOL_STRATEGY", strategy);
        }
        // Optional race window (ms)
        if let Some(win_ms) = dns.get("race_window_ms").and_then(Value::as_u64) {
            std::env::set_var("SB_DNS_RACE_WINDOW_MS", win_ms.to_string());
        }
        // Optional default timeout (ms)
        if let Some(timeout_ms) = dns.get("timeout_ms").and_then(Value::as_u64) {
            std::env::set_var("SB_DNS_TIMEOUT_MS", timeout_ms.to_string());
        }
        // Optional IPv6 enable
        if let Some(ipv6) = dns.get("ipv6").and_then(Value::as_bool) {
            if ipv6 {
                std::env::set_var("SB_DNS_IPV6", "1");
            }
        }
        // Optional HE order: A_FIRST | AAAA_FIRST
        if let Some(he) = dns.get("he_order").and_then(Value::as_str) {
            std::env::set_var("SB_DNS_HE_ORDER", he);
        }
    }

    if pool_tokens.is_empty() {
        // Default to system resolver when no dns.servers provided
        pool_tokens.push("system".to_string());
    }

    // Enable DNS and router DNS integration
    std::env::set_var("SB_DNS_ENABLE", "1");
    std::env::set_var("SB_ROUTER_DNS", "1");
    std::env::set_var("SB_DNS_POOL", pool_tokens.join(","));
}

// Helper: dedup push ignoring ASCII case
fn push_dedup(v: &mut Vec<String>, s: String) {
    if !v.iter().any(|x| x.eq_ignore_ascii_case(&s)) {
        v.push(s);
    }
}

// Convert a single server value to SB_DNS_POOL token
fn server_to_token(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => normalize_addr(s),
        serde_json::Value::Object(m) => m
            .get("address")
            .and_then(serde_json::Value::as_str)
            .and_then(normalize_addr),
        _ => None,
    }
}

// Normalize to supported tokens: system | udp:host:port | tcp:host:port | doh:https://... | dot:host:port | doq:host:port[@sni]
fn normalize_addr(addr: &str) -> Option<String> {
    let a = addr.trim();
    if a.is_empty() {
        return None;
    }
    // Pass through when already tokenized
    for pref in ["system", "udp:", "tcp:", "doh:", "dot:", "doq:"] {
        if a.eq_ignore_ascii_case("system") || a.starts_with(pref) {
            return Some(a.to_string());
        }
    }
    // URL schemes
    if a.starts_with("https://") {
        return Some(format!("doh:{a}"));
    }
    if a.starts_with("udp://") {
        return Some(format!("udp:{}", a.trim_start_matches("udp://")));
    }
    if a.starts_with("tcp://") {
        return Some(format!("tcp:{}", a.trim_start_matches("tcp://")));
    }
    if a.starts_with("dot://") {
        return Some(format!("dot:{}", a.trim_start_matches("dot://")));
    }
    if a.starts_with("doq://") {
        return Some(format!("doq:{}", a.trim_start_matches("doq://")));
    }
    // host:port -> default to UDP
    if a.contains(':') {
        return Some(format!("udp:{a}"));
    }
    // Fallback
    Some("system".to_string())
}

#[cfg(all(test, feature = "router"))]
mod tests {
    use super::*;

    #[test]
    fn tuic_outbound_registry_includes_runtime_config() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Tuic,
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            name: Some("tuic-out".to_string()),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            token: Some("secret-token".to_string()),
            password: Some("optional-pass".to_string()),
            congestion_control: Some("bbr".to_string()),
            alpn: Some("h3".to_string()),
            skip_cert_verify: Some(true),
            udp_relay_mode: Some("quic".to_string()),
            udp_over_stream: Some(true),
            ..Default::default()
        });

        let registry = build_outbound_registry_from_ir(&ir);
        let entry = registry
            .get("tuic-out")
            .expect("tuic outbound should be registered");

        match entry {
            sb_core::outbound::OutboundImpl::Tuic(cfg) => {
                assert_eq!(cfg.server, "tuic.example.com");
                assert_eq!(cfg.port, 443);
                assert_eq!(cfg.token, "secret-token");
                assert_eq!(cfg.congestion_control.as_deref(), Some("bbr"));
                assert_eq!(cfg.alpn.as_deref(), Some("h3"));
                assert!(cfg.skip_cert_verify);
                assert!(matches!(
                    cfg.udp_relay_mode,
                    sb_core::outbound::tuic::UdpRelayMode::Quic
                ));
                assert!(cfg.udp_over_stream);
            }
            other => panic!("unexpected outbound variant: {:?}", other),
        }
    }

    #[test]
    fn selector_outbound_becomes_connector() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Direct,
            name: Some("direct-a".to_string()),
            ..Default::default()
        });
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Direct,
            name: Some("direct-b".to_string()),
            ..Default::default()
        });
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Selector,
            name: Some("manual".to_string()),
            members: Some(vec!["direct-a".to_string(), "direct-b".to_string()]),
            default_member: Some("direct-a".to_string()),
            ..Default::default()
        });

        let registry = build_outbound_registry_from_ir(&ir);
        let entry = registry.get("manual").expect("manual selector registered");
        matches!(entry, sb_core::outbound::OutboundImpl::Connector(_))
            .then_some(())
            .expect("manual selector should be connector variant");
    }

    #[test]
    fn urltest_outbound_becomes_connector() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Direct,
            name: Some("direct-a".to_string()),
            ..Default::default()
        });
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::UrlTest,
            name: Some("auto".to_string()),
            members: Some(vec!["direct-a".to_string()]),
            test_url: Some("https://example.com/test".to_string()),
            test_interval_ms: Some(10_000),
            test_timeout_ms: Some(3_000),
            test_tolerance_ms: Some(40),
            ..Default::default()
        });

        let registry = build_outbound_registry_from_ir(&ir);
        let entry = registry.get("auto").expect("urltest selector registered");
        matches!(entry, sb_core::outbound::OutboundImpl::Connector(_))
            .then_some(())
            .expect("urltest selector should be connector variant");
    }

    #[test]
    fn shadowsocks_outbound_is_registered() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Shadowsocks,
            name: Some("ss-out".to_string()),
            server: Some("127.0.0.1".to_string()),
            port: Some(8388),
            password: Some("secret".to_string()),
            method: Some("aes-256-gcm".to_string()),
            ..Default::default()
        });

        let registry = build_outbound_registry_from_ir(&ir);
        let entry = registry.get("ss-out").expect("shadowsocks registered");
        match entry {
            sb_core::outbound::OutboundImpl::Shadowsocks(cfg) => {
                assert_eq!(cfg.server, "127.0.0.1");
                assert_eq!(cfg.port, 8388);
            }
            other => panic!("unexpected outbound variant: {:?}", other),
        }
    }

    #[test]
    fn hysteria2_outbound_registry_preserves_bandwidth() -> anyhow::Result<()> {
        use sb_core::outbound::OutboundImpl;
        use serde_json::json;
        use tempfile::NamedTempFile;

        let doc = json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "hysteria2",
                    "name": "hy2",
                    "server": "hy2.example.com",
                    "port": 443,
                    "password": "secret",
                    "congestion_control": "brutal",
                    "up_mbps": 150,
                    "down_mbps": "200Mbps",
                    "obfs": "obfs-key",
                    "salamander": "fingerprint",
                    "brutal": {
                        "up_mbps": 300,
                        "down_mbps": 400
                    }
                },
                { "type": "direct", "name": "direct" }
            ],
            "route": {
                "rules": [],
                "default": "direct"
            }
        });

        let tmp = NamedTempFile::new()?;
        std::fs::write(tmp.path(), serde_json::to_vec_pretty(&doc)?)?;

        let cfg = sb_config::Config::load(tmp.path())?;
        let ir = sb_config::present::to_ir(&cfg)?;
        let registry = build_outbound_registry_from_ir(&ir);

        let outbound = registry
            .get("hy2")
            .expect("hysteria2 outbound should be registered");

        match outbound {
            OutboundImpl::Hysteria2(cfg) => {
                assert_eq!(cfg.up_mbps, Some(150));
                assert_eq!(cfg.down_mbps, Some(200));
                assert_eq!(cfg.obfs.as_deref(), Some("obfs-key"));
                assert_eq!(cfg.salamander.as_deref(), Some("fingerprint"));
                assert_eq!(cfg.congestion_control.as_deref(), Some("brutal"));
                let brutal = cfg.brutal.as_ref().expect("brutal config present");
                assert_eq!(brutal.up_mbps, 300);
                assert_eq!(brutal.down_mbps, 400);
            }
            other => panic!("unexpected outbound variant: {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn trojan_outbound_respects_tls_options() -> anyhow::Result<()> {
        use sb_core::outbound::OutboundImpl;
        use serde_json::json;
        use tempfile::NamedTempFile;

        let doc = json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "trojan",
                    "name": "trojan-out",
                    "server": "trojan.example.com",
                    "port": 443,
                    "password": "s3cret",
                    "tls": {
                        "sni": "auth.example.com",
                        "alpn": "h2, http/1.1",
                        "skip_cert_verify": true
                    }
                },
                { "type": "direct", "name": "direct" }
            ],
            "route": {
                "rules": [],
                "default": "direct"
            }
        });

        let tmp = NamedTempFile::new()?;
        std::fs::write(tmp.path(), serde_json::to_vec_pretty(&doc)?)?;

        let cfg = sb_config::Config::load(tmp.path())?;
        let ir = sb_config::present::to_ir(&cfg)?;
        let registry = build_outbound_registry_from_ir(&ir);

        let outbound = registry
            .get("trojan-out")
            .expect("trojan outbound should be registered");

        match outbound {
            OutboundImpl::Trojan(cfg) => {
                assert_eq!(cfg.sni, "auth.example.com");
                assert!(cfg.skip_cert_verify);
                let alpn = cfg.alpn.as_ref().expect("alpn configured");
                assert_eq!(alpn, &vec!["h2".to_string(), "http/1.1".to_string()]);
            }
            other => panic!("unexpected outbound variant: {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn vless_transport_ws_preserved() -> anyhow::Result<()> {
        use sb_core::outbound::OutboundImpl;
        use serde_json::json;
        use tempfile::NamedTempFile;

        let doc = json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "vless",
                    "name": "vless-ws",
                    "server": "vless.example.com",
                    "port": 443,
                    "uuid": "12345678-1234-1234-1234-123456789abc",
                    "transport": {
                        "type": "ws",
                        "path": "/vless",
                        "headers": {
                            "Host": "vless.example.com"
                        }
                    }
                },
                { "type": "direct", "name": "direct" }
            ],
            "route": {
                "rules": [],
                "default": "direct"
            }
        });

        let tmp = NamedTempFile::new()?;
        std::fs::write(tmp.path(), serde_json::to_vec_pretty(&doc)?)?;

        let cfg = sb_config::Config::load(tmp.path())?;
        let ir = sb_config::present::to_ir(&cfg)?;
        let registry = build_outbound_registry_from_ir(&ir);

        let outbound = registry
            .get("vless-ws")
            .expect("vless outbound should be registered");

        match outbound {
            OutboundImpl::Vless(cfg) => {
                let transport = cfg.transport.as_ref().expect("transport tokens present");
                assert_eq!(transport.len(), 1);
                assert_eq!(transport[0], "ws");
                assert_eq!(cfg.ws_path.as_deref(), Some("/vless"));
                assert_eq!(cfg.ws_host.as_deref(), Some("vless.example.com"));
            }
            other => panic!("unexpected outbound variant: {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn vless_transport_grpc_preserved() -> anyhow::Result<()> {
        use sb_core::outbound::OutboundImpl;
        use serde_json::json;
        use tempfile::NamedTempFile;

        let doc = json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "vless",
                    "name": "vless-grpc",
                    "server": "grpc.example.com",
                    "port": 443,
                    "uuid": "12345678-1234-1234-1234-123456789abc",
                    "transport": {
                        "type": "grpc",
                        "service_name": "TunnelService",
                        "method_name": "Tunnel",
                        "authority": "grpc.example.com",
                        "metadata": {
                            "auth": "token",
                            "foo": "bar"
                        }
                    }
                },
                { "type": "direct", "name": "direct" }
            ],
            "route": {
                "rules": [],
                "default": "direct"
            }
        });

        let tmp = NamedTempFile::new()?;
        std::fs::write(tmp.path(), serde_json::to_vec_pretty(&doc)?)?;

        let cfg = sb_config::Config::load(tmp.path())?;
        let ir = sb_config::present::to_ir(&cfg)?;
        let registry = build_outbound_registry_from_ir(&ir);

        let outbound = registry
            .get("vless-grpc")
            .expect("vless outbound should be registered");

        match outbound {
            OutboundImpl::Vless(cfg) => {
                assert_eq!(cfg.transport.as_ref().expect("transport").len(), 1);
                assert_eq!(cfg.transport.as_ref().unwrap()[0], "grpc");
                assert_eq!(cfg.grpc_service.as_deref(), Some("TunnelService"));
                assert_eq!(cfg.grpc_method.as_deref(), Some("Tunnel"));
                assert_eq!(cfg.grpc_authority.as_deref(), Some("grpc.example.com"));
                assert!(cfg
                    .grpc_metadata
                    .contains(&("auth".to_string(), "token".to_string())));
                assert!(cfg
                    .grpc_metadata
                    .contains(&("foo".to_string(), "bar".to_string())));
            }
            other => panic!("unexpected outbound variant: {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn vless_transport_httpupgrade_preserved() -> anyhow::Result<()> {
        use sb_core::outbound::OutboundImpl;
        use serde_json::json;
        use tempfile::NamedTempFile;

        let doc = json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "vless",
                    "name": "vless-hup",
                    "server": "upgrade.example.com",
                    "port": 80,
                    "uuid": "12345678-1234-1234-1234-123456789abc",
                    "transport": {
                        "type": "httpupgrade",
                        "path": "/upgrade",
                        "headers": {
                            "User-Agent": "singbox",
                            "Authorization": "Bearer token"
                        }
                    }
                },
                { "type": "direct", "name": "direct" }
            ],
            "route": {
                "rules": [],
                "default": "direct"
            }
        });

        let tmp = NamedTempFile::new()?;
        std::fs::write(tmp.path(), serde_json::to_vec_pretty(&doc)?)?;

        let cfg = sb_config::Config::load(tmp.path())?;
        let ir = sb_config::present::to_ir(&cfg)?;
        let registry = build_outbound_registry_from_ir(&ir);

        let outbound = registry
            .get("vless-hup")
            .expect("vless outbound should be registered");

        match outbound {
            OutboundImpl::Vless(cfg) => {
                assert_eq!(cfg.transport.as_ref().expect("transport")[0], "httpupgrade");
                assert_eq!(cfg.http_upgrade_path.as_deref(), Some("/upgrade"));
                assert!(cfg
                    .http_upgrade_headers
                    .contains(&("User-Agent".to_string(), "singbox".to_string())));
                assert!(cfg
                    .http_upgrade_headers
                    .contains(&("Authorization".to_string(), "Bearer token".to_string())));
            }
            other => panic!("unexpected outbound variant: {:?}", other),
        }

        Ok(())
    }
}
