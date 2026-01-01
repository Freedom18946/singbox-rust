//! Adapter Bridge: Prioritizes sb-adapter registry; falls back to scaffold implementations.
//!
//! This module provides the core bridging logic to assemble inbound and outbound adapters
//! from configuration IR. It supports two strategies controlled by the `ADAPTER_FORCE` env var:
//! - `adapter`: Use sb-adapters registry (reserved for future implementation)
//! - `scaffold`: Use built-in simple implementations (direct/socks/http/ssh/selector/etc.)

use crate::adapter::registry;
use crate::adapter::{
    AnyTlsUserParam, Bridge, InboundParam, InboundService, OutboundConnector, OutboundParam,
    UdpOutboundFactory,
};
use crate::context::Context;
use crate::endpoint::{endpoint_registry, EndpointContext};
#[allow(unused_imports)]
use crate::outbound::selector::Selector;
#[allow(unused_imports)]
use crate::outbound::selector_group::{ProxyMember, SelectorGroup};
use crate::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
#[cfg(feature = "router")]
use crate::router::RouterHandle;
use crate::service::{service_registry, ServiceContext};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use sb_config::ir::{ConfigIR, InboundIR, OutboundIR, OutboundType};
use std::sync::Arc;
#[allow(unused_imports)]
use std::time::Instant;

fn outbound_registry_handle_from_bridge(br: &Bridge) -> Arc<OutboundRegistryHandle> {
    let mut reg = OutboundRegistry::default();
    for (name, _kind, conn) in &br.outbounds {
        reg.insert(name.clone(), OutboundImpl::Connector(conn.clone()));
    }
    Arc::new(OutboundRegistryHandle::new(reg))
}

#[cfg(feature = "router")]
fn router_handle_from_ir(cfg: &ConfigIR) -> Arc<RouterHandle> {
    // Use direct IR builder to support complex/logical rules (P1 parity)
    match crate::router::builder::build_index_from_ir(cfg).map_err(|e| crate::router::BuildError::Rule(e)) {
        Ok(idx) => {
            let mut handle = RouterHandle::from_index(idx.clone());

            // Populate RuleSetDb
            if !cfg.route.rule_set.is_empty() {
                let db = crate::router::rule_set::RuleSetDb::new();
                for rs in &cfg.route.rule_set {
                    if let Some(path) = &rs.path {
                        let _ = db.add_rule_set(rs.tag.clone(), path, &rs.format);
                    }
                }
                handle = handle.with_rule_set_db(Arc::new(db));
            }

            // Attach GeoIP/Geosite databases when paths are provided in RouteIR
            // Chain the operations properly since both methods consume self
            let mut handle = handle;
            if let Some(path) = &cfg.route.geoip_path {
                handle = handle.with_geoip_file(path).unwrap_or_else(|e| {
                    tracing::warn!(
                        target: "sb_core::adapter",
                        error = %e,
                        path = %path,
                        "failed to load GeoIP database from route.geoip_path"
                    );
                    RouterHandle::from_index(idx.clone())
                });
            }

            if let Some(path) = &cfg.route.geosite_path {
                handle = handle.with_geosite_file(path).unwrap_or_else(|e| {
                    tracing::warn!(
                        target: "sb_core::adapter",
                        error = %e,
                        path = %path,
                        "failed to load Geosite database from route.geosite_path"
                    );
                    RouterHandle::from_index(idx.clone())
                });
            }

            Arc::new(handle)
        }
        Err(e) => {
            tracing::warn!(
                target: "sb_core::adapter",
                error = %e,
                "router index build from ConfigIR failed; falling back to env handle"
            );
            Arc::new(RouterHandle::from_env())
        }
    }
}

#[cfg(feature = "router")]
#[allow(dead_code)]
fn ir_to_router_rules_text(cfg: &ConfigIR) -> String {
    fn rule_outbound(rule: &sb_config::ir::RuleIR, cfg: &ConfigIR) -> String {
        rule.outbound
            .clone()
            .or_else(|| cfg.route.default.clone())
            .or_else(|| cfg.route.final_outbound.clone())
            .unwrap_or_else(|| "direct".to_string())
    }

    let mut rules = Vec::new();
    for rule in &cfg.route.rules {
        let outbound = rule_outbound(rule, cfg);
        for domain in &rule.domain {
            rules.push(format!("domain:{domain}={outbound}"));
        }
        for suffix in &rule.domain_suffix {
            rules.push(format!("domain_suffix:{suffix}={outbound}"));
        }
        for keyword in &rule.domain_keyword {
            rules.push(format!("domain_keyword:{keyword}={outbound}"));
        }
        for regex in &rule.domain_regex {
            rules.push(format!("domain_regex:{regex}={outbound}"));
        }
        for geosite in &rule.geosite {
            rules.push(format!("geosite:{geosite}={outbound}"));
        }
        for geoip in &rule.geoip {
            rules.push(format!("geoip:{geoip}={outbound}"));
        }
        for ipcidr in &rule.ipcidr {
            let kind = if ipcidr.contains(':') {
                "cidr6"
            } else {
                "cidr4"
            };
            rules.push(format!("{kind}:{ipcidr}={outbound}"));
        }
        for port in &rule.port {
            if port.contains('-') {
                rules.push(format!("portrange:{port}={outbound}"));
            } else {
                rules.push(format!("port:{port}={outbound}"));
            }
        }
        for process in &rule.process_name {
            rules.push(format!("process:{process}={outbound}"));
        }
        for process_path in &rule.process_path {
            rules.push(format!("process_path:{process_path}={outbound}"));
        }
        for wifi_ssid in &rule.wifi_ssid {
            rules.push(format!("wifi_ssid:{wifi_ssid}={outbound}"));
        }
        for wifi_bssid in &rule.wifi_bssid {
            rules.push(format!("wifi_bssid:{wifi_bssid}={outbound}"));
        }
        for rule_set in &rule.rule_set {
            rules.push(format!("rule_set:{rule_set}={outbound}"));
        }
        for rule_set_ip in &rule.rule_set_ipcidr {
            rules.push(format!("rule_set_ip:{rule_set_ip}={outbound}"));
        }
        for uid in &rule.user_id {
            rules.push(format!("uid:{uid}={outbound}"));
        }
        for user in &rule.user {
            rules.push(format!("user:{user}={outbound}"));
        }
        for gid in &rule.group_id {
            rules.push(format!("gid:{gid}={outbound}"));
        }
        for group in &rule.group {
            rules.push(format!("group:{group}={outbound}"));
        }
        for source in &rule.source {
            rules.push(format!("source:{source}={outbound}"));
        }
        for dest in &rule.dest {
            rules.push(format!("dest:{dest}={outbound}"));
        }
        for user_agent in &rule.user_agent {
            rules.push(format!("user_agent:{user_agent}={outbound}"));
        }
        for network in &rule.network {
            rules.push(format!("transport:{network}={outbound}"));
        }
        for protocol in &rule.protocol {
            rules.push(format!("protocol:{protocol}={outbound}"));
        }
    }

    // Use 'default' or 'final_outbound' as the final fallback rule
    let final_rule = cfg
        .route
        .default
        .as_ref()
        .or(cfg.route.final_outbound.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("direct");
    rules.push(format!("default={final_rule}"));

    rules.join("\n")
}

/// Converts inbound IR to adapter parameter.
fn to_inbound_param(ib: &InboundIR) -> InboundParam {
    let users_anytls = ib.users_anytls.as_ref().map(|users| {
        users
            .iter()
            .map(|user| AnyTlsUserParam {
                name: user.name.clone(),
                password: user.password.clone(),
            })
            .collect()
    });

    // Serialize Hysteria2 users to JSON if present
    let users_hysteria2 = ib
        .users_hysteria2
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize TUIC users to JSON if present
    let users_tuic = ib
        .users_tuic
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Hysteria v1 users to JSON if present
    let users_hysteria = ib
        .users_hysteria
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Trojan users to JSON if present
    let users_trojan = ib
        .users_trojan
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize VLESS users to JSON if present
    let users_vless = ib
        .users_vless
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize VMess users to JSON if present
    let users_vmess = ib
        .users_vmess
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Shadowsocks users to JSON if present
    let users_shadowsocks = ib
        .users_shadowsocks
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Hysteria2 masquerade to JSON if present
    let masquerade = ib
        .masquerade
        .as_ref()
        .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".to_string()));

    // Serialize Tun options to JSON if present
    let tun_options = ib
        .tun
        .as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_else(|_| "{}".to_string()));

    InboundParam {
        kind: ib.ty.ty_str().to_string(),
        listen: ib.listen.clone(),
        port: ib.port,
        basic_auth: ib.basic_auth.clone(),
        sniff: ib.sniff,
        udp: ib.udp,
        override_host: ib.override_host.clone(),
        override_port: ib.override_port,
        network: ib.network.clone(),
        users_anytls,
        password: ib.password.clone(),
        uuid: ib.uuid.clone(),
        method: ib.method.clone(),
        security: ib.security.clone(),
        flow: ib.flow.clone(),
        anytls_padding: ib.anytls_padding.clone(),
        tls_cert_path: ib.tls_cert_path.clone(),
        tls_key_path: ib.tls_key_path.clone(),
        tls_cert_pem: ib.tls_cert_pem.clone(),
        tls_key_pem: ib.tls_key_pem.clone(),
        tls_server_name: ib.tls_server_name.clone(),
        tls_alpn: ib.tls_alpn.clone(),
        users_hysteria2,
        congestion_control: ib.congestion_control.clone(),
        salamander: ib.salamander.clone(),
        obfs: ib.obfs.clone(),
        masquerade,
        brutal_up_mbps: ib.brutal_up_mbps,
        brutal_down_mbps: ib.brutal_down_mbps,
        tun_options,
        users_tuic,
        users_hysteria,
        hysteria_protocol: ib.hysteria_protocol.clone(),
        hysteria_obfs: ib.hysteria_obfs.clone(),
        hysteria_up_mbps: ib.hysteria_up_mbps,
        hysteria_down_mbps: ib.hysteria_down_mbps,
        hysteria_recv_window_conn: ib.hysteria_recv_window_conn,
        hysteria_recv_window: ib.hysteria_recv_window,
        multiplex: ib.multiplex.clone(),
        users_trojan,
        users_vless,
        users_vmess,
        users_shadowsocks,
        udp_timeout: ib
            .udp_timeout
            .as_ref()
            .and_then(|s| humantime::parse_duration(s).ok()),
        domain_strategy: ib.domain_strategy.clone(),
        set_system_proxy: ib.set_system_proxy,
        allow_private_network: ib.allow_private_network,
        ssh_host_key_path: ib.ssh_host_key_path.clone(),
    }
}

/// Extracts credentials (username, password) from outbound parameter.
///
/// Returns `(Option<String>, Option<String>)` for username and password.
#[cfg(feature = "scaffold")]
#[allow(dead_code)]
fn extract_credentials(p: &OutboundParam) -> (Option<String>, Option<String>) {
    p.credentials
        .as_ref()
        .map(|c| (c.username.clone(), c.password.clone()))
        .unwrap_or((None, None))
}

/// Converts outbound IR to (name, parameter) tuple.
///
/// The name defaults to the outbound type string if not explicitly provided.
fn to_outbound_param(ob: &OutboundIR) -> (String, OutboundParam) {
    let name = ob.name.clone().unwrap_or_else(|| ob.ty_str().to_string());
    let kind = ob.ty.ty_str().to_string();
    (
        name,
        OutboundParam {
            kind,
            name: ob.name.clone(),
            server: ob.server.clone(),
            port: ob.port,
            credentials: ob.credentials.clone(),
            uuid: ob.uuid.clone(),
            token: ob.token.clone(),
            password: ob.password.clone(),
            congestion_control: ob.congestion_control.clone(),
            alpn: ob
                .alpn
                .clone()
                .or_else(|| ob.tls_alpn.as_ref().map(|v| v.join(","))),
            skip_cert_verify: ob.skip_cert_verify,
            udp_relay_mode: ob.udp_relay_mode.clone(),
            udp_over_stream: ob.udp_over_stream,
            ssh_private_key: ob
                .ssh_private_key
                .clone()
                .or(ob.ssh_private_key_path.clone()),
            ssh_private_key_passphrase: ob.ssh_private_key_passphrase.clone(),
            ssh_host_key_verification: ob.ssh_host_key_verification,
            ssh_known_hosts_path: ob.ssh_known_hosts_path.clone(),
            bind_interface: ob.bind_interface.clone(),
            inet4_bind_address: ob.inet4_bind_address.as_ref().and_then(|s| s.parse().ok()),
            inet6_bind_address: ob.inet6_bind_address.as_ref().and_then(|s| s.parse().ok()),
            routing_mark: ob.routing_mark,
            reuse_addr: ob.reuse_addr,
            connect_timeout: ob
                .connect_timeout
                .as_ref()
                .and_then(|s| humantime::parse_duration(s).ok()),
            tcp_fast_open: ob.tcp_fast_open,
            tcp_multi_path: ob.tcp_multi_path,
            udp_fragment: ob.udp_fragment,
            domain_strategy: ob.domain_strategy.clone(),
            multiplex: ob.multiplex.clone(),
        },
    )
}

/// Attempts to create an inbound service using the adapter registry (when feature enabled).
///
/// Supplies adapter builders with runtime context (engine/bridge) so they can wire routing.
fn try_adapter_inbound(
    p: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    if let Some(builder) = registry::get_inbound(&p.kind) {
        return builder(p, ctx);
    }
    None
}

/// Attempts to create an outbound connector using the adapter registry (when feature enabled).
/// Supplies adapter builders with runtime context (bridge) so they can resolve dependencies.
fn try_adapter_outbound(p: &OutboundParam, ob: &OutboundIR, br: &Bridge) -> Option<BuiltOutbound> {
    if let Some(builder) = registry::get_outbound(&p.kind) {
        let ctx = registry::AdapterOutboundContext {
            bridge: Arc::new(br.clone()),
            context: crate::context::ContextRegistry::from(&br.context),
        };
        if let Some((tcp, udp)) = builder(p, ob, &ctx) {
            return Some(BuiltOutbound { tcp, udp });
        }
    }
    None
}

struct BuiltOutbound {
    tcp: Arc<dyn OutboundConnector>,
    udp: Option<Arc<dyn UdpOutboundFactory>>,
}

// no-op wrapper for non-adapter builds (registry is available regardless)

/// Helper: assembles basic outbounds (excluding selectors).
fn assemble_outbounds(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
        // Skip selector/urltest in first pass - they need all other outbounds registered first
        if ob.ty == OutboundType::Selector || ob.ty == OutboundType::UrlTest {
            continue;
        }

        let (name, p) = to_outbound_param(ob);
        let kind = p.kind.clone();

        if let Some(o) = try_adapter_outbound(&p, ob, br) {
            // Optionally wrap with circuit breaker
            let tcp = maybe_wrap_with_cb(name.as_str(), o.tcp);
            br.add_outbound(name.clone(), kind, tcp);
            if let Some(udp_f) = o.udp {
                br.add_outbound_udp_factory(name, udp_f);
            }
        } else {
            tracing::error!(
                target: "sb_core::adapter",
                outbound = %name,
                kind = %kind,
                "no outbound builder available for requested kind"
            );
        }
    }
}

// ============================================================================
// Optional Circuit Breaker wrapper for outbound connectors
// ============================================================================

static CB_STATES: Lazy<DashMap<String, i32>> = Lazy::new(DashMap::new);

/// Update circuit breaker state for an outbound (0=closed,1=half-open,2=open)
pub fn cb_state_set(name: &str, code: i32) {
    CB_STATES.insert(name.to_string(), code);
}

/// Snapshot current circuit breaker states
pub fn cb_state_snapshot() -> Vec<(String, i32)> {
    CB_STATES
        .iter()
        .map(|kv| (kv.key().clone(), *kv.value()))
        .collect()
}

#[cfg(feature = "v2ray_transport")]
#[derive(Clone)]
struct CbConnector {
    name: String,
    inner: Arc<dyn OutboundConnector>,
    cb: std::sync::Arc<sb_transport::circuit_breaker::CircuitBreaker>,
}

#[cfg(feature = "v2ray_transport")]
impl std::fmt::Debug for CbConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CbConnector")
            .field("name", &self.name)
            .finish()
    }
}

#[cfg(feature = "v2ray_transport")]
#[async_trait::async_trait]
impl OutboundConnector for CbConnector {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        use std::io::Error;

        match self.cb.allow_request().await {
            sb_transport::circuit_breaker::CircuitBreakerDecision::Reject => {
                return Err(Error::other("circuit open"));
            }
            sb_transport::circuit_breaker::CircuitBreakerDecision::Allow => {}
        }

        let t0 = Instant::now();
        let res = self.inner.connect(host, port).await;

        // Heuristic: treat Timeout kind and "timeout" substring as timeout
        let mut is_timeout = false;
        let success = match &res {
            Ok(_) => true,
            Err(e) => {
                is_timeout = e.kind() == std::io::ErrorKind::TimedOut
                    || e.to_string().to_ascii_lowercase().contains("timeout")
                    || t0.elapsed().as_secs() >= 10; // coarse guard
                false
            }
        };
        self.cb.record_result(success, is_timeout).await;
        // Update CB state gauge
        let st = self.cb.state().await;
        let code = match st {
            sb_transport::circuit_breaker::CircuitState::Closed => 0,
            sb_transport::circuit_breaker::CircuitState::HalfOpen => 1,
            sb_transport::circuit_breaker::CircuitState::Open => 2,
        };
        crate::metrics::set_outbound_circuit_state(self.name.as_str(), code);
        cb_state_set(self.name.as_str(), code);
        res
    }
}

#[cfg(feature = "v2ray_transport")]
fn maybe_wrap_with_cb(name: &str, inner: Arc<dyn OutboundConnector>) -> Arc<dyn OutboundConnector> {
    // Default disabled; enable with SB_CB_ENABLE=1
    let enabled = std::env::var("SB_CB_ENABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return inner;
    }
    let cb = sb_transport::circuit_breaker::CircuitBreaker::from_env(name.to_string());
    Arc::new(CbConnector {
        name: name.to_string(),
        inner,
        cb: std::sync::Arc::new(cb),
    })
}

#[cfg(not(feature = "v2ray_transport"))]
fn maybe_wrap_with_cb(
    _name: &str,
    inner: Arc<dyn OutboundConnector>,
) -> Arc<dyn OutboundConnector> {
    // Circuit breaker requires v2ray_transport feature
    inner
}

/// Helper: assembles selector outbounds with resolved members.
///
/// Second-pass processing to bind selector members after basic outbounds are registered.
fn assemble_selectors(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
        if ob.ty == OutboundType::Selector || ob.ty == OutboundType::UrlTest {
            let (name, p) = to_outbound_param(ob);
            let kind = p.kind.clone();

            if let Some(o) = try_adapter_outbound(&p, ob, br) {
                let tcp = maybe_wrap_with_cb(name.as_str(), o.tcp);
                br.add_outbound(name.clone(), kind, tcp);
                if let Some(udp_f) = o.udp {
                    br.add_outbound_udp_factory(name, udp_f);
                }
            } else {
                tracing::error!(
                    target: "sb_core::adapter",
                    outbound = %name,
                    kind = %kind,
                    "no selector/urltest builder available for requested kind"
                );
            }
        }
    }
}

#[cfg(feature = "router")]
pub fn build_bridge<'a>(
    cfg: &'a ConfigIR,
    engine: crate::routing::engine::Engine<'a>,
    context: Context,
) -> Bridge {
    crate::endpoint::register_builtins();
    crate::services::register_builtins();
    let mut br = Bridge::new(context);
    let ctx_registry = crate::context::ContextRegistry::from(&br.context);

    // Initialize RouterHandle and attach to Bridge
    let handle = router_handle_from_ir(cfg);
    br.router = Some(handle);
    br.experimental = cfg.experimental.clone();

    // Step 1 & 2: Outbounds and selectors
    assemble_outbounds(cfg, &mut br);
    assemble_selectors(cfg, &mut br);
    let outbound_handle = outbound_registry_handle_from_bridge(&br);
    #[cfg(feature = "router")]
    let router_handle = router_handle_from_ir(cfg);

    // Step 3: Inbounds
    // Create shared connection manager for all inbounds (Go parity: route.ConnectionManager)
    let connection_manager = Arc::new(crate::router::RouteConnectionManager::new());

    // Build DNS components for inbound context
    let (_, dns_router) = crate::dns::config_builder::build_dns_components(cfg).ok().unzip();
    let dns_router = dns_router.flatten(); // Option<Option<Arc>> -> Option<Arc>

    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let adapter_ctx = registry::AdapterInboundContext {
            engine: engine.clone(),
            bridge: Arc::new(br.clone()),
            outbounds: outbound_handle.clone(),
            router: router_handle.clone(),
            dns_router: dns_router.clone(),
            connection_manager: Some(connection_manager.clone()),
            context: ctx_registry.clone(),
        };

        if let Some(i) = try_adapter_inbound(&p, &adapter_ctx) {
            br.add_inbound_with_kind(p.kind.as_str(), i);
        } else {
            tracing::error!(
                target: "sb_core::adapter",
                inbound = %p.kind,
                listen = %format!("{}:{}", p.listen, p.port),
                "no inbound builder available for requested kind"
            );
        }
    }

    // Step 4: Endpoints
    for endpoint_ir in &cfg.endpoints {
        let ctx = EndpointContext::default();
        if let Some(endpoint) = endpoint_registry().build(endpoint_ir, &ctx) {
            br.add_endpoint(endpoint);
        } else {
            tracing::warn!(
                target: "sb_core::adapter",
                endpoint = %endpoint_ir.tag.as_deref().unwrap_or("unknown"),
                "endpoint builder not found"
            );
        }
    }

    // Step 5: Services
    for service_ir in &cfg.services {
        let ctx = ServiceContext::default();
        if let Some(service) = service_registry().build(service_ir, &ctx) {
            br.add_service(service);
        } else {
            tracing::warn!(
                target: "sb_core::adapter",
                service = %service_ir.tag.as_deref().unwrap_or("unknown"),
                "service builder not found"
            );
        }
    }

    br
}

/// Assembles IR configuration into a Bridge (without router feature).
///
/// Placeholder version when router feature is disabled. Assembles outbounds and inbounds
/// without routing engine dependencies.
#[cfg(not(feature = "router"))]
pub fn build_bridge(cfg: &ConfigIR, _engine: (), context: Context) -> Bridge {
    crate::endpoint::register_builtins();
    crate::services::register_builtins();
    let mut br = Bridge::new(context);
    let ctx_registry = crate::context::ContextRegistry::from(&br.context);

    // Step 1 & 2: Outbounds and selectors
    assemble_outbounds(cfg, &mut br);
    assemble_selectors(cfg, &mut br);
    let outbound_handle = outbound_registry_handle_from_bridge(&br);

    // Step 3: Inbounds (without engine)
    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let adapter_ctx = registry::AdapterInboundContext {
            bridge: Arc::new(br.clone()),
            outbounds: outbound_handle.clone(),
            dns_router: None, // TODO: Wire DNS router when available
            context: ctx_registry.clone(),
            _phantom: std::marker::PhantomData,
        };

        if let Some(i) = try_adapter_inbound(&p, &adapter_ctx) {
            br.add_inbound_with_kind(p.kind.as_str(), i);
        } else {
            tracing::error!(
                target: "sb_core::adapter",
                inbound = %p.kind,
                listen = %format!("{}:{}", p.listen, p.port),
                "no inbound builder available for requested kind"
            );
        }
    }

    // Step 4: Endpoints
    for endpoint_ir in &cfg.endpoints {
        let ctx = EndpointContext::default();
        if let Some(endpoint) = endpoint_registry().build(endpoint_ir, &ctx) {
            br.add_endpoint(endpoint);
        } else {
            tracing::warn!(
                target: "sb_core::adapter",
                endpoint = %endpoint_ir.tag.as_deref().unwrap_or("unknown"),
                "endpoint builder not found"
            );
        }
    }

    // Step 5: Services
    for service_ir in &cfg.services {
        let ctx = ServiceContext::default();
        if let Some(service) = service_registry().build(service_ir, &ctx) {
            br.add_service(service);
        } else {
            tracing::warn!(
                target: "sb_core::adapter",
                service = %service_ir.tag.as_deref().unwrap_or("unknown"),
                "service builder not found"
            );
        }
    }

    br
}
