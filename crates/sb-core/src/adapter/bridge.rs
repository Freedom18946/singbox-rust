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
use crate::endpoint::{endpoint_registry, EndpointContext};
#[allow(unused_imports)]
use crate::outbound::selector::Selector;
#[allow(unused_imports)]
use crate::outbound::selector_group::{ProxyMember, SelectorGroup};
use crate::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
#[cfg(feature = "router")]
use crate::router::{router_build_index_from_str, RouterHandle};
use crate::service::{service_registry, ServiceContext};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use sb_config::ir::{ConfigIR, InboundIR, OutboundIR, OutboundType};
use std::sync::Arc;
#[allow(unused_imports)]
use std::time::Instant;

/// Environment variable to force adapter selection strategy
const ENV_ADAPTER_FORCE: &str = "ADAPTER_FORCE";

/// Default SOCKS5 port when not specified
#[cfg(feature = "scaffold")]
const DEFAULT_SOCKS_PORT: u16 = 1080;

/// Default HTTP proxy port when not specified
#[cfg(feature = "scaffold")]
const DEFAULT_HTTP_PORT: u16 = 8080;

/// Default SSH port when not specified
#[cfg(all(feature = "scaffold", feature = "out_ssh"))]
const DEFAULT_SSH_PORT: u16 = 22;

/// Cached adapter selection strategy from environment variable
static ADAPTER_STRATEGY: Lazy<Option<bool>> =
    Lazy::new(|| match std::env::var(ENV_ADAPTER_FORCE).ok().as_deref() {
        Some("adapter") => Some(true),
        Some("scaffold") => Some(false),
        _ => None,
    });

/// Register scaffold inbounds with the adapter facade so `ADAPTER_FORCE=adapter`
/// remains functional until sb-adapters wiring is complete.
static REGISTER_SCAFFOLD_INBOUNDS: Lazy<()> = Lazy::new(register_scaffold_inbounds);
static REGISTER_SCAFFOLD_OUTBOUNDS: Lazy<()> = Lazy::new(register_scaffold_outbounds);

/// Determines the desired adapter strategy from environment variables.
///
/// Returns:
/// - `Some(true)`: Force use of adapter registry
/// - `Some(false)`: Force use of scaffold implementations
/// - `None`: Auto-select (try adapter first, fall back to scaffold)
fn want_adapter() -> Option<bool> {
    *ADAPTER_STRATEGY
}

/// Register scaffold implementations as adapter builders (best-effort).
fn register_scaffold_inbounds() {
    const KINDS: &[&str] = &[
        "socks", "http", "mixed", "tun", "direct", "redirect", "tproxy",
    ];
    for kind in KINDS {
        let _ = registry::register_inbound(kind, scaffold_builder);
    }
}

fn register_scaffold_outbounds() {
    const KINDS: &[&str] = &[
        "direct",
        "http",
        "socks",
        "block",
        "selector",
        "shadowsocks",
        "urltest",
        "shadowtls",
        "hysteria2",
        "tuic",
        "vless",
        "vmess",
        "trojan",
        "ssh",
    ];
    for kind in KINDS {
        let _ = registry::register_outbound(*kind, scaffold_outbound_builder);
    }
}

#[cfg(feature = "router")]
fn scaffold_builder(
    p: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    try_scaffold_inbound(p, ctx.engine.clone(), &ctx.bridge)
}

#[cfg(not(feature = "router"))]
fn scaffold_builder(
    p: &InboundParam,
    ctx: &registry::AdapterInboundContext<'_>,
) -> Option<Arc<dyn InboundService>> {
    try_scaffold_inbound(p, &ctx.bridge)
}

fn scaffold_outbound_builder(
    p: &OutboundParam,
    ir: &OutboundIR,
    _ctx: &registry::AdapterOutboundContext,
) -> Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)> {
    try_scaffold_outbound(p, ir).map(|built| (built.tcp, built.udp))
}

fn outbound_registry_handle_from_bridge(br: &Bridge) -> Arc<OutboundRegistryHandle> {
    let mut reg = OutboundRegistry::default();
    for (name, _kind, conn) in &br.outbounds {
        reg.insert(name.clone(), OutboundImpl::Connector(conn.clone()));
    }
    Arc::new(OutboundRegistryHandle::new(reg))
}

#[cfg(feature = "router")]
fn router_handle_from_ir(cfg: &ConfigIR) -> Arc<RouterHandle> {
    let text = ir_to_router_rules_text(cfg);
    let max_rules = std::env::var("SB_ROUTER_RULES_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000usize);
    match router_build_index_from_str(&text, max_rules) {
        Ok(idx) => Arc::new(RouterHandle::from_index(idx)),
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
fn ir_to_router_rules_text(cfg: &ConfigIR) -> String {
    fn rule_outbound(rule: &sb_config::ir::RuleIR, cfg: &ConfigIR) -> String {
        rule.outbound
            .clone()
            .or_else(|| cfg.route.default.clone())
            .unwrap_or_else(|| "direct".to_string())
    }

    let mut rules = Vec::new();
    for rule in &cfg.route.rules {
        let outbound = rule_outbound(rule, cfg);
        for domain in &rule.domain {
            rules.push(format!("domain:{domain}={outbound}"));
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
        for process in &rule.process {
            rules.push(format!("process:{process}={outbound}"));
        }
        for network in &rule.network {
            rules.push(format!("transport:{network}={outbound}"));
        }
        for protocol in &rule.protocol {
            rules.push(format!("protocol:{protocol}={outbound}"));
        }
    }

    if let Some(default) = &cfg.route.default {
        rules.push(format!("default={default}"));
    } else {
        rules.push("default=direct".to_string());
    }
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
        brutal_up_mbps: ib.brutal_up_mbps,
        brutal_down_mbps: ib.brutal_down_mbps,
        users_tuic,
        users_hysteria,
        hysteria_protocol: ib.hysteria_protocol.clone(),
        hysteria_obfs: ib.hysteria_obfs.clone(),
        hysteria_up_mbps: ib.hysteria_up_mbps,
        hysteria_down_mbps: ib.hysteria_down_mbps,
        hysteria_recv_window_conn: ib.hysteria_recv_window_conn,
        hysteria_recv_window: ib.hysteria_recv_window,
    }
}

/// Extracts credentials (username, password) from outbound parameter.
///
/// Returns `(Option<String>, Option<String>)` for username and password.
#[cfg(feature = "scaffold")]
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
    Lazy::force(&REGISTER_SCAFFOLD_INBOUNDS);
    if let Some(builder) = registry::get_inbound(&p.kind) {
        return builder(p, ctx);
    }
    None
}

/// Attempts to create an outbound connector using the adapter registry (when feature enabled).
/// Supplies adapter builders with runtime context (bridge) so they can resolve dependencies.
fn try_adapter_outbound(p: &OutboundParam, ob: &OutboundIR, br: &Bridge) -> Option<BuiltOutbound> {
    Lazy::force(&REGISTER_SCAFFOLD_OUTBOUNDS);
    if let Some(builder) = registry::get_outbound(&p.kind) {
        let ctx = registry::AdapterOutboundContext {
            bridge: Arc::new(br.clone()),
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

/// Attempts to create an inbound service using scaffold implementations (when router feature enabled).
///
/// Supports: socks, http, tun inbound types.
#[cfg(all(feature = "scaffold", feature = "router"))]
fn try_scaffold_inbound(
    p: &InboundParam,
    engine: crate::routing::engine::Engine<'_>,
    br: &Bridge,
) -> Option<Arc<dyn InboundService>> {
    match p.kind.as_str() {
        "direct" => {
            // Build a simple direct forwarder (TCP and optional UDP) to a fixed destination
            #[cfg(feature = "scaffold")]
            {
                use crate::inbound::direct::DirectForward;
                use std::net::SocketAddr;

                let Some(dst_host) = p.override_host.clone() else {
                    let ib = crate::inbound::unsupported::UnsupportedInbound::new(
                        "direct",
                        "missing override_host/override_port for direct inbound",
                        Some(
                            "Provide inbound.override_host and inbound.override_port in config"
                                .to_string(),
                        ),
                    );
                    return Some(Arc::new(ib));
                };
                let Some(dst_port) = p.override_port else {
                    let ib = crate::inbound::unsupported::UnsupportedInbound::new(
                        "direct",
                        "missing override_host/override_port for direct inbound",
                        Some(
                            "Provide inbound.override_host and inbound.override_port in config"
                                .to_string(),
                        ),
                    );
                    return Some(Arc::new(ib));
                };

                let listen: SocketAddr = super::parse_socket_addr(&p.listen, p.port)
                    .map_err(|e| {
                        tracing::warn!("invalid inbound listen address: {}", e);
                        e
                    })
                    .ok()?;
                let srv = DirectForward::new(listen, dst_host, dst_port, p.udp);
                Some(Arc::new(srv))
            }
            #[cfg(not(feature = "scaffold"))]
            {
                None
            }
        }
        "socks" => {
            use crate::inbound::socks5::Socks5;
            let srv = Socks5::new(p.listen.clone(), p.port)
                .with_engine(engine.clone_as_static())
                .with_bridge(Arc::new(br.clone()))
                .with_sniff(p.sniff);
            Some(Arc::new(srv))
        }
        "http" => {
            use crate::inbound::http_connect::HttpConnect;
            let mut srv = HttpConnect::new(p.listen.clone(), p.port)
                .with_engine(engine.clone_as_static())
                .with_bridge(Arc::new(br.clone()))
                .with_sniff(p.sniff);
            if let Some(c) = &p.basic_auth {
                srv = srv.with_basic_auth(c.username.clone(), c.password.clone());
            }
            Some(Arc::new(srv))
        }
        "mixed" => {
            use crate::inbound::mixed::MixedInbound;
            let mut srv = MixedInbound::new(p.listen.clone(), p.port)
                .with_engine(engine.clone_as_static())
                .with_bridge(Arc::new(br.clone()))
                .with_sniff(p.sniff);
            if let Some(c) = &p.basic_auth {
                srv = srv.with_basic_auth(c.username.clone(), c.password.clone());
            }
            Some(Arc::new(srv))
        }
        "tun" => {
            // Basic TUN inbound (scaffold); enhanced implementation lives in sb-adapters
            use crate::inbound::tun::TunInboundService;
            let srv = TunInboundService::new().with_sniff(p.sniff);
            Some(Arc::new(srv))
        }
        _ => None,
    }
}

/// Router present but scaffold disabled: keep signature compatible with router path
#[cfg(all(feature = "router", not(feature = "scaffold")))]
fn try_scaffold_inbound(
    _p: &InboundParam,
    _engine: crate::routing::engine::Engine<'_>,
    _br: &Bridge,
) -> Option<Arc<dyn InboundService>> {
    None
}

/// No router: provide a minimal stub without engine (used by the no-router `build_bridge`)
#[cfg(not(feature = "router"))]
fn try_scaffold_inbound(p: &InboundParam, _br: &Bridge) -> Option<Arc<dyn InboundService>> {
    match p.kind.as_str() {
        "mixed" => {
            #[cfg(feature = "scaffold")]
            {
                use crate::inbound::mixed::MixedInbound;
                let mut srv = MixedInbound::new(p.listen.clone(), p.port)
                    .with_engine(crate::inbound::mixed::Engine::new(
                        sb_config::ir::ConfigIR::default(),
                    ))
                    .with_bridge(Arc::new(_br.clone()))
                    .with_sniff(p.sniff);
                if let Some(c) = &p.basic_auth {
                    srv = srv.with_basic_auth(c.username.clone(), c.password.clone());
                }
                Some(Arc::new(srv))
            }
            #[cfg(not(feature = "scaffold"))]
            {
                None
            }
        }
        "direct" => {
            #[cfg(feature = "scaffold")]
            {
                use crate::inbound::direct::DirectForward;
                use std::net::SocketAddr;
                let (Some(dst_host), Some(dst_port)) = (p.override_host.clone(), p.override_port)
                else {
                    let ib = crate::inbound::unsupported::UnsupportedInbound::new(
                        "direct",
                        "missing override_host/override_port for direct inbound",
                        Some(
                            "Provide inbound.override_host and inbound.override_port in config"
                                .to_string(),
                        ),
                    );
                    return Some(Arc::new(ib));
                };
                let listen: SocketAddr = super::parse_socket_addr(&p.listen, p.port).ok()?;
                let srv = DirectForward::new(listen, dst_host, dst_port, p.udp);
                Some(Arc::new(srv))
            }
            #[cfg(not(feature = "scaffold"))]
            {
                None
            }
        }
        _ => None,
    }
}

/// Attempts to create an outbound connector using scaffold implementations.
///
/// Supports: direct, socks, http, ssh outbound types.
#[cfg(feature = "scaffold")]
fn try_scaffold_outbound(p: &OutboundParam, ob: &OutboundIR) -> Option<BuiltOutbound> {
    match p.kind.as_str() {
        "direct" => {
            use crate::outbound::direct_simple::Direct;
            Some(BuiltOutbound {
                tcp: Arc::new(Direct),
                udp: None,
            })
        }
        "block" => {
            use crate::outbound::block_connector::BlockConnector;
            Some(BuiltOutbound {
                tcp: Arc::new(BlockConnector::new()),
                udp: None,
            })
        }
        "socks" => {
            use crate::outbound::socks_upstream::SocksUp;
            let (u, pw) = extract_credentials(p);
            let tcp = Arc::new(SocksUp::new(
                p.server.clone().unwrap_or_default(),
                p.port.unwrap_or(DEFAULT_SOCKS_PORT),
                u,
                pw,
            ));
            Some(BuiltOutbound { tcp, udp: None })
        }
        "http" => {
            use crate::outbound::http_upstream::HttpUp;
            let (u, pw) = extract_credentials(p);
            let tcp = Arc::new(HttpUp::new(
                p.server.clone().unwrap_or_default(),
                p.port.unwrap_or(DEFAULT_HTTP_PORT),
                u,
                pw,
            ));
            Some(BuiltOutbound { tcp, udp: None })
        }
        "shadowsocks" => {
            #[cfg(feature = "out_ss")]
            {
                use crate::metrics::outbound::{
                    record_connect_attempt, record_connect_duration, record_connect_error,
                    record_connect_success, OutboundErrorClass,
                };
                use crate::outbound::address::{encode_ss_addr, Addr};
                use crate::outbound::ss::aead_tcp::{
                    decrypt_aead, encrypt_aead_chunk, SsAeadCipher as SsCipher,
                };
                use crate::outbound::ss::aead_udp::{SsAeadUdpConfig, SsAeadUdpSocket};
                use crate::outbound::ss::hkdf::{derive_subkey, generate_salt, HashAlgorithm};
                use crate::outbound::types::TargetAddr as SsTarget;
                use crate::outbound::OutboundKind;
                use async_trait::async_trait;

                let server = p.server.clone().unwrap_or_default();
                let port = p.port.unwrap_or(0);
                let password = p.password.clone().unwrap_or_default();
                let cipher = match ob.method.as_deref().unwrap_or("") {
                    "chacha20-poly1305" => SsCipher::ChaCha20Poly1305,
                    _ => SsCipher::Aes256Gcm,
                };
                if server.is_empty() || port == 0 || password.is_empty() {
                    None
                } else {
                    // Derive master key from password (EVP_BytesToKey-like SHA-256 truncation)
                    fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
                        use sha2::{Digest, Sha256};
                        let mut key = Vec::new();
                        let mut prev = Vec::new();
                        while key.len() < key_len {
                            let mut hasher = Sha256::new();
                            if !prev.is_empty() {
                                hasher.update(&prev);
                            }
                            hasher.update(password.as_bytes());
                            prev = hasher.finalize().to_vec();
                            key.extend_from_slice(&prev);
                        }
                        key.truncate(key_len);
                        key
                    }

                    #[derive(Clone)]
                    struct SsOc2 {
                        server: String,
                        port: u16,
                        cipher: SsCipher,
                        master_key: Vec<u8>,
                    }

                    impl std::fmt::Debug for SsOc2 {
                        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                            f.debug_struct("SsOc2")
                                .field("server", &self.server)
                                .field("port", &self.port)
                                .finish()
                        }
                    }

                    #[async_trait]
                    impl OutboundConnector for SsOc2 {
                        async fn connect(
                            &self,
                            host: &str,
                            port: u16,
                        ) -> std::io::Result<tokio::net::TcpStream> {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let t0 = std::time::Instant::now();
                            record_connect_attempt(OutboundKind::Shadowsocks);
                            // 1) Connect to SS server
                            let mut ss_tcp = match tokio::net::TcpStream::connect((
                                self.server.as_str(),
                                self.port,
                            ))
                            .await
                            {
                                Ok(s) => s,
                                Err(e) => {
                                    let class = match e.kind() {
                                        std::io::ErrorKind::TimedOut => OutboundErrorClass::Timeout,
                                        _ => OutboundErrorClass::Io,
                                    };
                                    record_connect_error(OutboundKind::Shadowsocks, class);
                                    return Err(e);
                                }
                            };

                            // 2) Generate salt and derive subkey
                            let salt = generate_salt(self.cipher.key_size());
                            let subkey =
                                derive_subkey(&self.master_key, &salt, HashAlgorithm::Sha1);

                            // 3) Send salt
                            ss_tcp.write_all(&salt).await?;

                            // 4) Prepare and send encrypted target address using nonce 0,1
                            let addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                                match ip {
                                    std::net::IpAddr::V4(v4) => Addr::V4(v4),
                                    std::net::IpAddr::V6(v6) => Addr::V6(v6),
                                }
                            } else {
                                Addr::Domain(host.to_string())
                            };
                            let mut addr_buf = Vec::new();
                            encode_ss_addr(&addr, port, &mut addr_buf);
                            let first =
                                match encrypt_aead_chunk(&addr_buf, &subkey, 0, &self.cipher) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        record_connect_error(
                                            OutboundKind::Shadowsocks,
                                            OutboundErrorClass::Handshake,
                                        );
                                        return Err(std::io::Error::other(e));
                                    }
                                };
                            if let Err(e) = ss_tcp.write_all(&first).await {
                                record_connect_error(
                                    OutboundKind::Shadowsocks,
                                    OutboundErrorClass::Handshake,
                                );
                                return Err(e);
                            }

                            // 5) Create a local TCP pair to hand back to caller
                            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                            let addr = listener.local_addr()?;
                            let server_task =
                                tokio::spawn(
                                    async move { listener.accept().await.map(|(s, _)| s) },
                                );
                            let client = match tokio::net::TcpStream::connect(addr).await {
                                Ok(c) => c,
                                Err(e) => {
                                    // Local loopback failure is considered IO error
                                    record_connect_error(
                                        OutboundKind::Shadowsocks,
                                        OutboundErrorClass::Io,
                                    );
                                    return Err(e);
                                }
                            };
                            let local_server =
                                server_task.await.map_err(std::io::Error::other)??;
                            let (mut ls_r, mut ls_w) = local_server.into_split();

                            // 到此视为连接建立完成
                            let elapsed = t0.elapsed();
                            record_connect_success(OutboundKind::Shadowsocks);
                            if let Ok(ms) = u64::try_from(elapsed.as_millis()) {
                                record_connect_duration(ms as f64);
                            }

                            // 6) Pump plaintext<->ciphertext in background with proper AEAD framing
                            let (mut ss_tcp_r, mut ss_tcp_w) = ss_tcp.into_split();
                            let _cipher_name = self.cipher.name().to_string();

                            // Writer: ls_r -> ss_tcp_w (encrypt)
                            let cipher_w = self.cipher.clone();
                            let subkey_w = subkey;
                            tokio::spawn(async move {
                                let mut write_nonce: u64 = 2; // after addr (0,1)
                                let mut buf = vec![0u8; 32 * 1024];
                                loop {
                                    match ls_r.read(&mut buf).await {
                                        Ok(0) => {
                                            let _ = ss_tcp_w.shutdown().await;
                                            break;
                                        }
                                        Ok(n) => {
                                            #[cfg(feature = "metrics")]
                                            let start = std::time::Instant::now();
                                            let enc_res = encrypt_aead_chunk(
                                                &buf[..n],
                                                &subkey_w,
                                                write_nonce,
                                                &cipher_w,
                                            );
                                            #[cfg(feature = "metrics")]
                                            if enc_res.is_ok() {
                                                let ms = start.elapsed().as_millis() as f64;
                                                crate::metrics::outbound::record_ss_aead_op_duration(ms, &_cipher_name, "tcp_encrypt");
                                            }
                                            if let Ok(enc) = enc_res {
                                                #[cfg(feature = "metrics")]
                                                    crate::metrics::outbound::record_ss_encrypt_bytes_with_cipher(n as u64, &_cipher_name);
                                                if ss_tcp_w.write_all(&enc).await.is_err() {
                                                    #[cfg(feature = "metrics")]
                                                    crate::metrics::outbound::record_ss_stream_error_with_cipher("write", &_cipher_name);
                                                    break;
                                                }
                                                write_nonce = write_nonce.wrapping_add(2);
                                            } else {
                                                #[cfg(feature = "metrics")]
                                                crate::metrics::outbound::record_ss_stream_error_with_cipher("encrypt", &_cipher_name);
                                                break;
                                            }
                                        }
                                        Err(_) => {
                                            #[cfg(feature = "metrics")]
                                            crate::metrics::outbound::record_ss_stream_error_with_cipher("local_read", &_cipher_name);
                                            break;
                                        }
                                    }
                                }
                            });

                            // Reader: ss_tcp_r -> ls_w (decrypt)
                            let cipher_r = self.cipher.clone();
                            let subkey_r = subkey; // same subkey
                            tokio::spawn(async move {
                                let mut read_nonce: u64 = 0;
                                let tag = cipher_r.tag_size();
                                let mut len_buf = vec![0u8; 2 + tag];
                                loop {
                                    // read encrypted length
                                    if let Err(_) = ss_tcp_r.read_exact(&mut len_buf).await {
                                        #[cfg(feature = "metrics")]
                                        crate::metrics::outbound::record_ss_stream_error_with_cipher("read_len", &cipher_name_r);
                                        break;
                                    }
                                    #[cfg(feature = "metrics")]
                                    let start_len = std::time::Instant::now();
                                    let len_res =
                                        decrypt_aead(&len_buf, &subkey_r, read_nonce, &cipher_r)
                                            .and_then(|v| {
                                                if v.len() >= 2 {
                                                    Ok::<_, std::io::Error>(u16::from_be_bytes([
                                                        v[0], v[1],
                                                    ])
                                                        as usize)
                                                } else {
                                                    Err(std::io::Error::other("bad len"))
                                                }
                                            });
                                    #[cfg(feature = "metrics")]
                                    if len_res.is_ok() {
                                        let ms = start_len.elapsed().as_millis() as f64;
                                        crate::metrics::outbound::record_ss_aead_op_duration(
                                            ms,
                                            &cipher_name_r,
                                            "tcp_len_decrypt",
                                        );
                                    }
                                    let plain_len = match len_res {
                                        Ok(l) => l,
                                        Err(_) => {
                                            #[cfg(feature = "metrics")]
                                            crate::metrics::outbound::record_ss_stream_error_with_cipher("len_decrypt", &cipher_name_r);
                                            break;
                                        }
                                    };
                                    // read encrypted payload
                                    let mut payload = vec![0u8; plain_len + tag];
                                    if let Err(_) = ss_tcp_r.read_exact(&mut payload).await {
                                        #[cfg(feature = "metrics")]
                                        crate::metrics::outbound::record_ss_stream_error_with_cipher("read_payload", &cipher_name_r);
                                        break;
                                    }
                                    #[cfg(feature = "metrics")]
                                    let start_payload = std::time::Instant::now();
                                    let dec_res = decrypt_aead(
                                        &payload,
                                        &subkey_r,
                                        read_nonce.wrapping_add(1),
                                        &cipher_r,
                                    );
                                    #[cfg(feature = "metrics")]
                                    if dec_res.is_ok() {
                                        let ms = start_payload.elapsed().as_millis() as f64;
                                        crate::metrics::outbound::record_ss_aead_op_duration(
                                            ms,
                                            &cipher_name_r,
                                            "tcp_payload_decrypt",
                                        );
                                    }
                                    let plain = match dec_res {
                                        Ok(v) => v,
                                        Err(_) => {
                                            #[cfg(feature = "metrics")]
                                            crate::metrics::outbound::record_ss_stream_error_with_cipher("decrypt", &cipher_name_r);
                                            break;
                                        }
                                    };
                                    #[cfg(feature = "metrics")]
                                    crate::metrics::outbound::record_ss_decrypt_bytes_with_cipher(
                                        plain.len() as u64,
                                        &cipher_name_r,
                                    );
                                    if ls_w.write_all(&plain).await.is_err() {
                                        #[cfg(feature = "metrics")]
                                        crate::metrics::outbound::record_ss_stream_error_with_cipher("local_write", &cipher_name_r);
                                        break;
                                    }
                                    read_nonce = read_nonce.wrapping_add(2);
                                }
                                let _ = ls_w.shutdown().await;
                            });

                            Ok(client)
                        }
                    }

                    let tcp: Arc<dyn OutboundConnector> = Arc::new(SsOc2 {
                        server: server.clone(),
                        port,
                        cipher: cipher.clone(),
                        master_key: evp_bytes_to_key(&password, cipher.key_size()),
                    });

                    // UDP factory for Shadowsocks AEAD UDP
                    #[derive(Clone, Debug)]
                    struct SsUdpFactory {
                        server: String,
                        port: u16,
                        cipher: SsCipher,
                        key: Vec<u8>,
                    }

                    #[async_trait]
                    impl UdpOutboundFactory for SsUdpFactory {
                        fn open_session(
                            &self,
                        ) -> std::pin::Pin<
                            Box<
                                dyn std::future::Future<
                                        Output = std::io::Result<
                                            Arc<dyn crate::adapter::UdpOutboundSession>,
                                        >,
                                    > + Send,
                            >,
                        > {
                            let this = self.clone();
                            Box::pin(async move {
                                #[cfg(feature = "metrics")]
                                metrics::counter!("udp_session_open_total", "proto"=>"shadowsocks", "stage"=>"attempt").increment(1);
                                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
                                    .await
                                    .map_err(std::io::Error::other)?;
                                sock.connect((this.server.as_str(), this.port))
                                    .await
                                    .map_err(std::io::Error::other)?;
                                let cfg = SsAeadUdpConfig {
                                    server: this.server.clone(),
                                    port: this.port,
                                    cipher: this.cipher.clone(),
                                    master_key: this.key.clone(),
                                };
                                let aead = match SsAeadUdpSocket::new(sock, cfg) {
                                    Ok(s) => {
                                        #[cfg(feature = "metrics")]
                                        metrics::counter!("udp_session_open_total", "proto"=>"shadowsocks", "result"=>"ok").increment(1);
                                        s
                                    }
                                    Err(e) => {
                                        #[cfg(feature = "metrics")]
                                        metrics::counter!("udp_session_open_total", "proto"=>"shadowsocks", "result"=>"error").increment(1);
                                        return Err(std::io::Error::other(e));
                                    }
                                };
                                #[derive(Clone)]
                                struct SsUdpSess {
                                    inner: Arc<SsAeadUdpSocket>,
                                }
                                impl std::fmt::Debug for SsUdpSess {
                                    fn fmt(
                                        &self,
                                        f: &mut std::fmt::Formatter<'_>,
                                    ) -> std::fmt::Result {
                                        f.debug_struct("SsUdpSess")
                                            .field("inner", &"<ss-aead-udp>")
                                            .finish()
                                    }
                                }
                                #[async_trait]
                                impl crate::adapter::UdpOutboundSession for SsUdpSess {
                                    async fn send_to(
                                        &self,
                                        data: &[u8],
                                        host: &str,
                                        port: u16,
                                    ) -> std::io::Result<()> {
                                        let dst = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                                            SsTarget::Ip(std::net::SocketAddr::from((ip, port)))
                                        } else {
                                            SsTarget::Domain(host.to_string(), port)
                                        };
                                        let _ = self
                                            .inner
                                            .send_to_target(data, &dst)
                                            .await
                                            .map_err(std::io::Error::other)?;
                                        Ok(())
                                    }

                                    async fn recv_from(
                                        &self,
                                    ) -> std::io::Result<(Vec<u8>, std::net::SocketAddr)>
                                    {
                                        let mut buf = vec![0u8; 64 * 1024];
                                        let (n, dst) = self
                                            .inner
                                            .recv_from_server(&mut buf)
                                            .await
                                            .map_err(std::io::Error::other)?;
                                        buf.truncate(n);
                                        let addr = match dst {
                                            SsTarget::Ip(sa) => sa,
                                            SsTarget::Domain(name, port) => {
                                                tokio::net::lookup_host((name.as_str(), port))
                                                    .await
                                                    .ok()
                                                    .and_then(|mut it| it.next())
                                                    .unwrap_or_else(|| {
                                                        std::net::SocketAddr::from((
                                                            [0, 0, 0, 0],
                                                            port,
                                                        ))
                                                    })
                                            }
                                        };
                                        Ok((buf, addr))
                                    }
                                }
                                Ok(Arc::new(SsUdpSess {
                                    inner: Arc::new(aead),
                                })
                                    as Arc<dyn crate::adapter::UdpOutboundSession>)
                            })
                        }
                    }

                    let udp: Option<Arc<dyn UdpOutboundFactory>> = Some(Arc::new(SsUdpFactory {
                        server: server.clone(),
                        port,
                        cipher: match ob.method.as_deref().unwrap_or("") {
                            "chacha20-poly1305" => SsCipher::ChaCha20Poly1305,
                            _ => SsCipher::Aes256Gcm,
                        },
                        key: password.as_bytes().to_vec(),
                    }));

                    Some(BuiltOutbound { tcp, udp })
                }
            }
            #[cfg(not(feature = "out_ss"))]
            {
                None
            }
        }
        "vless" => {
            #[cfg(all(feature = "out_vless", feature = "v2ray_transport"))]
            {
                use crate::outbound::types::HostPort as Hp;
                use crate::outbound::vless::VlessOutbound;
                use async_trait::async_trait;
                use sb_transport::Dialer as _;
                // use sb_transport::TransportBuilder; // removed: unused in this build path

                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let uuid = match &p.uuid {
                    Some(u) => uuid::Uuid::parse_str(u).ok()?,
                    None => return None,
                };

                #[derive(Clone, Debug)]
                struct VlessIoOc {
                    server: String,
                    port: u16,
                    uuid: uuid::Uuid,
                    ob_ir: OutboundIR,
                }

                #[async_trait]
                impl OutboundConnector for VlessIoOc {
                    async fn connect(
                        &self,
                        host: &str,
                        port: u16,
                    ) -> std::io::Result<tokio::net::TcpStream> {
                        use tokio::io::copy_bidirectional;

                        // Compose layered transport from IR via unified builder
                        let builder = crate::runtime::transport::map::builder_from_ir(&self.ob_ir);

                        // Dial server via layered transport
                        let mut stream = match builder
                            .build()
                            .connect(self.server.as_str(), self.port)
                            .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    target: "sb_core::adapter",
                                    error = %e,
                                    ob = %self.server,
                                    "vless transport connect failed; attempting fallback"
                                );
                                // Fallback: try TLS-only if SNI/ALPN present, otherwise plain TCP
                                let tls_sni = self.ob_ir.tls_sni.clone();
                                let tls_alpn_csv =
                                    self.ob_ir.tls_alpn.as_ref().map(|v| v.join(","));
                                let base = sb_transport::TransportBuilder::tcp();
                                let fb_tls = crate::runtime::transport::map::tls_override_from_ob(
                                    &self.ob_ir,
                                );
                                let fb_builder = crate::runtime::transport::map::apply_layers(
                                    base,
                                    Some(&[]),
                                    tls_sni.as_deref(),
                                    tls_alpn_csv.as_deref(),
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                    &[],
                                    None,
                                    None,
                                    None,
                                    &[],
                                    fb_tls,
                                );
                                fb_builder
                                    .build()
                                    .connect(self.server.as_str(), self.port)
                                    .await
                                    .map_err(std::io::Error::other)?
                            }
                        };

                        // Perform VLESS handshake over the layered stream
                        let target = Hp::new(host.to_string(), port);
                        let outbound = VlessOutbound::new(crate::outbound::vless::VlessConfig {
                            server: self.server.clone(),
                            port: self.port,
                            uuid: self.uuid,
                            encryption: Some("none".into()),
                            ..Default::default()
                        })
                        .map_err(std::io::Error::other)?;

                        match outbound.do_handshake_on(&target, &mut *stream).await {
                            Ok(()) => {
                                #[cfg(feature = "metrics")]
                                metrics::counter!("outbound_handshake_total", "proto"=>"vless", "result"=>"ok").increment(1);
                            }
                            Err(e) => {
                                #[cfg(feature = "metrics")]
                                metrics::counter!("outbound_handshake_total", "proto"=>"vless", "result"=>"error").increment(1);
                                return Err(std::io::Error::other(e));
                            }
                        }

                        // Bridge layered stream to a local TcpStream that implements the expected type
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                        let addr = listener.local_addr()?;
                        let server_task =
                            tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
                        let client = tokio::net::TcpStream::connect(addr).await?;
                        let mut server = server_task.await.map_err(std::io::Error::other)??;

                        tokio::spawn(async move {
                            let _ = copy_bidirectional(&mut server, &mut *stream).await;
                        });

                        Ok(client)
                    }
                }

                let tcp: Arc<dyn OutboundConnector> = Arc::new(VlessIoOc {
                    server,
                    port,
                    uuid,
                    ob_ir: ob.clone(),
                });
                Some(BuiltOutbound { tcp, udp: None })
            }
            #[cfg(all(feature = "out_vless", not(feature = "v2ray_transport")))]
            {
                use crate::outbound::vless::{VlessConfig, VlessOutbound};
                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let uuid = match &p.uuid {
                    Some(u) => uuid::Uuid::parse_str(u).ok()?,
                    None => return None,
                };

                let cfg = VlessConfig {
                    server,
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
                    tls_alpn: ob.tls_alpn.clone(),
                    grpc_service: ob.grpc_service.clone(),
                    grpc_method: ob.grpc_method.clone(),
                    grpc_authority: ob.grpc_authority.clone(),
                    grpc_metadata: ob
                        .grpc_metadata
                        .iter()
                        .map(|h| (h.key.clone(), h.value.clone()))
                        .collect(),
                    http_upgrade_path: ob.http_upgrade_path.clone(),
                    http_upgrade_headers: ob
                        .http_upgrade_headers
                        .iter()
                        .map(|h| (h.key.clone(), h.value.clone()))
                        .collect(),
                };

                match VlessOutbound::new(cfg) {
                    Ok(obd) => Some(Arc::new(obd) as Arc<dyn OutboundConnector>),
                    Err(e) => {
                        tracing::warn!(target: "sb_core::adapter", error=%e, "vless outbound init failed");
                        None
                    }
                }
            }
            #[cfg(not(feature = "out_vless"))]
            {
                None
            }
        }
        "vmess" => {
            #[cfg(all(feature = "out_vmess", feature = "v2ray_transport"))]
            {
                use crate::outbound::vmess::VmessOutbound;
                use async_trait::async_trait;
                // VMess handshake utilities expect HostPort from crypto_types
                use crate::outbound::crypto_types::HostPort as Hp;
                use sb_transport::Dialer as _;
                // use sb_transport::TransportBuilder; // removed: unused in this build path

                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let uuid = match &p.uuid {
                    Some(u) => uuid::Uuid::parse_str(u).ok()?,
                    None => return None,
                };
                let security = ob.method.clone().unwrap_or_else(|| "aes-128-gcm".into());

                #[derive(Clone, Debug)]
                struct VmessIoOc {
                    server: String,
                    port: u16,
                    uuid: uuid::Uuid,
                    security: String,
                    ob_ir: OutboundIR,
                }

                #[async_trait]
                impl OutboundConnector for VmessIoOc {
                    async fn connect(
                        &self,
                        host: &str,
                        port: u16,
                    ) -> std::io::Result<tokio::net::TcpStream> {
                        use tokio::io::copy_bidirectional;

                        // Compose layered transport via unified builder
                        let builder = crate::runtime::transport::map::builder_from_ir(&self.ob_ir);

                        let mut stream = match builder
                            .build()
                            .connect(self.server.as_str(), self.port)
                            .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    target: "sb_core::adapter",
                                    error = %e,
                                    ob = %self.server,
                                    "vmess transport connect failed; attempting fallback"
                                );
                                let tls_sni = self.ob_ir.tls_sni.clone();
                                let tls_alpn_csv =
                                    self.ob_ir.tls_alpn.as_ref().map(|v| v.join(","));
                                let base = sb_transport::TransportBuilder::tcp();
                                let fb_tls = crate::runtime::transport::map::tls_override_from_ob(
                                    &self.ob_ir,
                                );
                                let fb_builder = crate::runtime::transport::map::apply_layers(
                                    base,
                                    Some(&[]),
                                    tls_sni.as_deref(),
                                    tls_alpn_csv.as_deref(),
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                    &[],
                                    None,
                                    None,
                                    None,
                                    &[],
                                    fb_tls,
                                );
                                fb_builder
                                    .build()
                                    .connect(self.server.as_str(), self.port)
                                    .await
                                    .map_err(std::io::Error::other)?
                            }
                        };

                        // Perform VMess handshake over layered stream
                        let target = Hp::new(host.to_string(), port);
                        let outbound = VmessOutbound::new(crate::outbound::vmess::VmessConfig {
                            server: self.server.clone(),
                            port: self.port,
                            id: self.uuid,
                            security: self.security.clone(),
                            alter_id: 0,
                            ..Default::default()
                        })
                        .map_err(std::io::Error::other)?;

                        match outbound.do_handshake_on(&target, &mut *stream).await {
                            Ok(_k) => {
                                #[cfg(feature = "metrics")]
                                metrics::counter!("outbound_handshake_total", "proto"=>"vmess", "result"=>"ok").increment(1);
                            }
                            Err(e) => {
                                #[cfg(feature = "metrics")]
                                metrics::counter!("outbound_handshake_total", "proto"=>"vmess", "result"=>"error").increment(1);
                                return Err(std::io::Error::other(e));
                            }
                        }

                        // Bridge to local TcpStream
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                        let addr = listener.local_addr()?;
                        let server_task =
                            tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
                        let client = tokio::net::TcpStream::connect(addr).await?;
                        let mut server = server_task.await.map_err(std::io::Error::other)??;
                        tokio::spawn(async move {
                            let _ = copy_bidirectional(&mut server, &mut *stream).await;
                        });
                        Ok(client)
                    }
                }

                let tcp: Arc<dyn OutboundConnector> = Arc::new(VmessIoOc {
                    server,
                    port,
                    uuid,
                    security,
                    ob_ir: ob.clone(),
                });
                Some(BuiltOutbound { tcp, udp: None })
            }
            #[cfg(all(feature = "out_vmess", not(feature = "v2ray_transport")))]
            {
                use crate::outbound::vmess::{VmessConfig, VmessOutbound};
                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let uuid = match &p.uuid {
                    Some(u) => uuid::Uuid::parse_str(u).ok()?,
                    None => return None,
                };

                let cfg = VmessConfig {
                    server,
                    port,
                    id: uuid,
                    security: ob.method.clone().unwrap_or_else(|| "aes-128-gcm".into()),
                    alter_id: 0,
                    transport: ob.transport.clone(),
                    ws_path: ob.ws_path.clone(),
                    ws_host: ob.ws_host.clone(),
                    h2_path: ob.h2_path.clone(),
                    h2_host: ob.h2_host.clone(),
                    tls_sni: ob.tls_sni.clone(),
                    tls_alpn: ob.tls_alpn.clone(),
                    grpc_service: ob.grpc_service.clone(),
                    grpc_method: ob.grpc_method.clone(),
                    grpc_authority: ob.grpc_authority.clone(),
                    grpc_metadata: ob
                        .grpc_metadata
                        .iter()
                        .map(|h| (h.key.clone(), h.value.clone()))
                        .collect(),
                    http_upgrade_path: ob.http_upgrade_path.clone(),
                    http_upgrade_headers: ob
                        .http_upgrade_headers
                        .iter()
                        .map(|h| (h.key.clone(), h.value.clone()))
                        .collect(),
                };

                match VmessOutbound::new(cfg) {
                    Ok(obd) => Some(Arc::new(obd) as Arc<dyn OutboundConnector>),
                    Err(e) => {
                        tracing::warn!(target: "sb_core::adapter", error=%e, "vmess outbound init failed");
                        None
                    }
                }
            }
            #[cfg(not(feature = "out_vmess"))]
            {
                None
            }
        }
        "trojan" => {
            #[cfg(all(feature = "out_trojan", feature = "v2ray_transport"))]
            {
                use async_trait::async_trait;
                use sb_transport::Dialer as _;
                // use sb_transport::TransportBuilder; // removed: unused in this build path
                use crate::outbound::crypto_types::HostPort as Hp;
                use crate::outbound::trojan::TrojanOutbound;

                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let password = match &p.password {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let sni = ob.tls_sni.clone().unwrap_or_else(|| server.clone());
                let alpn = p.alpn.clone();

                #[derive(Clone, Debug)]
                struct TrojanIoOc {
                    server: String,
                    port: u16,
                    password: String,
                    sni: String,
                    alpn: Option<String>,
                    ob_ir: OutboundIR,
                }

                #[async_trait]
                impl OutboundConnector for TrojanIoOc {
                    async fn connect(
                        &self,
                        host: &str,
                        port: u16,
                    ) -> std::io::Result<tokio::net::TcpStream> {
                        use tokio::io::copy_bidirectional;

                        // Compose layered transport via unified builder
                        let builder = crate::runtime::transport::map::builder_from_ir(&self.ob_ir);

                        let mut stream = match builder
                            .build()
                            .connect(self.server.as_str(), self.port)
                            .await
                        {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    target: "sb_core::adapter",
                                    error = %e,
                                    ob = %self.server,
                                    "trojan transport connect failed; attempting fallback"
                                );
                                let base = sb_transport::TransportBuilder::tcp();
                                // For Trojan, fallback at least to TLS-only with SNI/ALPN
                                let fb_tls = crate::runtime::transport::map::tls_override_from_ob(
                                    &self.ob_ir,
                                );
                                let fb_builder = crate::runtime::transport::map::apply_layers(
                                    base,
                                    Some(&["tls".to_string()]),
                                    Some(self.sni.as_str()),
                                    self.alpn.as_deref(),
                                    None,
                                    None,
                                    None,
                                    None,
                                    None,
                                    &[],
                                    None,
                                    None,
                                    None,
                                    &[],
                                    fb_tls,
                                );
                                fb_builder
                                    .build()
                                    .connect(self.server.as_str(), self.port)
                                    .await
                                    .map_err(std::io::Error::other)?
                            }
                        };

                        // Perform Trojan handshake
                        let target = Hp::new(host.to_string(), port);
                        match TrojanOutbound::handshake_on(&self.password, &target, &mut *stream)
                            .await
                        {
                            Ok(()) => {
                                #[cfg(feature = "metrics")]
                                metrics::counter!("outbound_handshake_total", "proto"=>"trojan", "result"=>"ok").increment(1);
                            }
                            Err(e) => {
                                #[cfg(feature = "metrics")]
                                metrics::counter!("outbound_handshake_total", "proto"=>"trojan", "result"=>"error").increment(1);
                                return Err(std::io::Error::other(e));
                            }
                        }

                        // Bridge to local TcpStream
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                        let addr = listener.local_addr()?;
                        let server_task =
                            tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
                        let client = tokio::net::TcpStream::connect(addr).await?;
                        let mut server = server_task.await.map_err(std::io::Error::other)??;
                        tokio::spawn(async move {
                            let _ = copy_bidirectional(&mut server, &mut *stream).await;
                        });
                        Ok(client)
                    }
                }

                Some(BuiltOutbound {
                    tcp: Arc::new(TrojanIoOc {
                        server,
                        port,
                        password,
                        sni,
                        alpn,
                        ob_ir: ob.clone(),
                    }) as Arc<dyn OutboundConnector>,
                    udp: None,
                })
            }
            #[cfg(all(feature = "out_trojan", not(feature = "v2ray_transport")))]
            {
                use crate::outbound::trojan::{TrojanConfig, TrojanOutbound};
                use async_trait::async_trait;
                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let password = match &p.password {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let sni = match (&ob.tls_sni).as_ref() {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => server.clone(),
                };
                let mut cfg = TrojanConfig::new(server, port, password, sni);
                if let Some(alpn) = &p.alpn {
                    let list = alpn
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>();
                    if !list.is_empty() {
                        cfg = cfg.with_alpn(list);
                    }
                }
                if let Some(skip) = p.skip_cert_verify {
                    cfg = cfg.with_skip_cert_verify(skip);
                }
                match TrojanOutbound::new(cfg) {
                    Ok(inner) => {
                        #[derive(Clone)]
                        struct TrojanOc {
                            inner: Arc<TrojanOutbound>,
                        }

                        impl std::fmt::Debug for TrojanOc {
                            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                                f.debug_struct("TrojanOc")
                                    .field("inner", &"<trojan>")
                                    .finish()
                            }
                        }

                        #[async_trait]
                        impl OutboundConnector for TrojanOc {
                            async fn connect(
                                &self,
                                host: &str,
                                port: u16,
                            ) -> std::io::Result<tokio::net::TcpStream>
                            {
                                use tokio::io::copy_bidirectional;
                                let target = crate::outbound::crypto_types::HostPort::new(
                                    host.to_string(),
                                    port,
                                );
                                let mut tls_stream =
                                    crate::outbound::crypto_types::OutboundTcp::connect(
                                        &*self.inner,
                                        &target,
                                    )
                                    .await?;

                                // Create local TCP pair and proxy
                                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                                let addr = listener.local_addr()?;
                                let server_task =
                                    tokio::spawn(
                                        async move { listener.accept().await.map(|(s, _)| s) },
                                    );
                                let client = tokio::net::TcpStream::connect(addr).await?;
                                let mut server =
                                    server_task.await.map_err(std::io::Error::other)??;

                                tokio::spawn(async move {
                                    let _ = copy_bidirectional(&mut server, &mut tls_stream).await;
                                });

                                Ok(client)
                            }
                        }

                        let tcp: Arc<dyn OutboundConnector> = Arc::new(TrojanOc {
                            inner: Arc::new(inner),
                        });
                        Some(BuiltOutbound { tcp, udp: None })
                    }
                    Err(e) => {
                        tracing::warn!(target: "sb_core::adapter", error=%e, "trojan outbound init failed");
                        None
                    }
                }
            }
            #[cfg(not(feature = "out_trojan"))]
            {
                None
            }
        }
        "tuic" => {
            #[cfg(feature = "out_tuic")]
            {
                use crate::outbound::tuic::{TuicConfig, TuicOutbound, UdpRelayMode};

                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let uuid = match &p.uuid {
                    Some(u) => uuid::Uuid::parse_str(u).ok()?,
                    None => return None,
                };
                let token = match &p.token {
                    Some(t) if !t.is_empty() => t.clone(),
                    _ => return None,
                };

                let relay_mode = match p.udp_relay_mode.as_deref() {
                    Some(m) if m.eq_ignore_ascii_case("quic") => UdpRelayMode::Quic,
                    _ => UdpRelayMode::Native,
                };
                let cfg = TuicConfig {
                    server,
                    port,
                    uuid,
                    token,
                    password: p.password.clone(),
                    congestion_control: p.congestion_control.clone(),
                    alpn: ob.tls_alpn.clone(),
                    skip_cert_verify: p.skip_cert_verify.unwrap_or(false),
                    sni: ob.tls_sni.clone(),
                    tls_ca_paths: ob.tls_ca_paths.clone(),
                    tls_ca_pem: ob.tls_ca_pem.clone(),
                    udp_relay_mode: relay_mode,
                    udp_over_stream: p.udp_over_stream.unwrap_or(false),
                    zero_rtt_handshake: ob.zero_rtt_handshake.unwrap_or(false),
                };
                match TuicOutbound::new(cfg) {
                    Ok(obd) => {
                        let inner = Arc::new(obd);
                        let tcp: Arc<dyn OutboundConnector> = inner.clone();
                        let udp: Option<Arc<dyn UdpOutboundFactory>> = Some(inner.clone());
                        Some(BuiltOutbound { tcp, udp })
                    }
                    Err(e) => {
                        tracing::warn!(target: "sb_core::adapter", error=%e, "tuic outbound init failed");
                        None
                    }
                }
            }
            #[cfg(not(feature = "out_tuic"))]
            {
                None
            }
        }
        "hysteria2" => {
            #[cfg(feature = "out_hysteria2")]
            {
                use crate::outbound::hysteria2::{
                    BrutalConfig, Hysteria2Config, Hysteria2Outbound,
                };
                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let password = match &p.password {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };

                let brutal = match (ob.brutal_up_mbps, ob.brutal_down_mbps) {
                    (Some(up), Some(down)) => Some(BrutalConfig {
                        up_mbps: up,
                        down_mbps: down,
                    }),
                    _ => None,
                };

                let cfg = Hysteria2Config {
                    server,
                    port,
                    password,
                    congestion_control: p.congestion_control.clone(),
                    up_mbps: ob.up_mbps,
                    down_mbps: ob.down_mbps,
                    obfs: ob.obfs.clone(),
                    skip_cert_verify: p.skip_cert_verify.unwrap_or(false),
                    sni: ob.tls_sni.clone(),
                    alpn: ob.tls_alpn.clone(),
                    salamander: ob.salamander.clone(),
                    brutal,
                    tls_ca_paths: ob.tls_ca_paths.clone(),
                    tls_ca_pem: ob.tls_ca_pem.clone(),
                    zero_rtt_handshake: ob.zero_rtt_handshake.unwrap_or(false),
                };
                match Hysteria2Outbound::new(cfg) {
                    Ok(obd) => {
                        let inner = Arc::new(obd);
                        let tcp: Arc<dyn OutboundConnector> = inner.clone();
                        let udp: Option<Arc<dyn UdpOutboundFactory>> = Some(inner.clone());
                        Some(BuiltOutbound { tcp, udp })
                    }
                    Err(e) => {
                        tracing::warn!(target: "sb_core::adapter", error=%e, "hysteria2 outbound init failed");
                        None
                    }
                }
            }
            #[cfg(not(feature = "out_hysteria2"))]
            {
                None
            }
        }
        "shadowtls" => {
            #[cfg(feature = "out_shadowtls")]
            {
                use crate::outbound::shadowtls::{ShadowTlsConfig, ShadowTlsOutbound};
                use async_trait::async_trait;
                let server = match &p.server {
                    Some(s) if !s.is_empty() => s.clone(),
                    _ => return None,
                };
                let port = match p.port {
                    Some(p) if p != 0 => p,
                    _ => return None,
                };
                let sni = ob.tls_sni.clone().unwrap_or_else(|| server.clone());
                let cfg = ShadowTlsConfig {
                    server,
                    port,
                    sni,
                    alpn: ob.tls_alpn.clone().or_else(|| {
                        p.alpn.as_ref().map(|raw| {
                            raw.split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect::<Vec<String>>()
                        })
                    }),
                    skip_cert_verify: p.skip_cert_verify.unwrap_or(false),
                };
                if cfg.skip_cert_verify {
                    tracing::warn!(target: "sb_core::adapter", "ShadowTLS configured with skip_cert_verify=true; TLS verification disabled");
                }
                match ShadowTlsOutbound::new(cfg) {
                    Ok(inner) => {
                        #[derive(Clone)]
                        struct StlOc {
                            inner: Arc<ShadowTlsOutbound>,
                        }

                        impl std::fmt::Debug for StlOc {
                            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                                f.debug_struct("StlOc")
                                    .field("inner", &"<shadowtls>")
                                    .finish()
                            }
                        }

                        #[async_trait]
                        impl OutboundConnector for StlOc {
                            async fn connect(
                                &self,
                                host: &str,
                                port: u16,
                            ) -> std::io::Result<tokio::net::TcpStream>
                            {
                                use tokio::io::copy_bidirectional;
                                let target =
                                    crate::outbound::types::HostPort::new(host.to_string(), port);
                                let mut tls_stream = crate::outbound::types::OutboundTcp::connect(
                                    &*self.inner,
                                    &target,
                                )
                                .await?;

                                // Local TCP pair and proxy
                                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                                let addr = listener.local_addr()?;
                                let server_task =
                                    tokio::spawn(
                                        async move { listener.accept().await.map(|(s, _)| s) },
                                    );
                                let client = tokio::net::TcpStream::connect(addr).await?;
                                let mut server =
                                    server_task.await.map_err(std::io::Error::other)??;

                                tokio::spawn(async move {
                                    let _ = copy_bidirectional(&mut server, &mut tls_stream).await;
                                });

                                Ok(client)
                            }
                        }

                        let tcp: Arc<dyn OutboundConnector> = Arc::new(StlOc {
                            inner: Arc::new(inner),
                        });
                        Some(BuiltOutbound { tcp, udp: None })
                    }
                    Err(e) => {
                        tracing::warn!(target: "sb_core::adapter", error=%e, "shadowtls outbound init failed");
                        None
                    }
                }
            }
            #[cfg(not(feature = "out_shadowtls"))]
            {
                None
            }
        }
        "ssh" => try_create_ssh_outbound(p).map(|tcp| BuiltOutbound { tcp, udp: None }),
        _ => None,
    }
}

#[cfg(not(feature = "scaffold"))]
fn try_scaffold_outbound(_p: &OutboundParam, _ob: &OutboundIR) -> Option<BuiltOutbound> {
    None
}

/// Helper to create SSH outbound connector (when ssh feature is enabled).
#[cfg(all(feature = "scaffold", feature = "out_ssh"))]
fn try_create_ssh_outbound(p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    use crate::adapter::OutboundConnector as Oc;
    use crate::outbound::crypto_types::{HostPort, OutboundTcp};
    use crate::outbound::ssh_stub::{SshConfig, SshOutbound};
    use async_trait::async_trait;

    #[derive(Clone)]
    struct SshOc {
        inner: Arc<SshOutbound>,
    }

    impl std::fmt::Debug for SshOc {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SshOc")
                .field("inner", &"<ssh-outbound>")
                .finish()
        }
    }

    #[async_trait]
    impl Oc for SshOc {
        async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
            let hp = HostPort::new(host.to_string(), port);
            self.inner.connect(&hp).await
        }
    }

    let (u, pw) = extract_credentials(p);
    let server = p.server.clone().unwrap_or_default();
    let port = p.port.unwrap_or(DEFAULT_SSH_PORT);
    let using_key = p.ssh_private_key.is_some();
    let has_auth = u.is_some() && (pw.is_some() || using_key);

    if server.is_empty() || !has_auth {
        return None;
    }

    let username = u?;

    let cfg = SshConfig {
        server,
        port,
        username,
        password: if using_key { None } else { pw },
        private_key: p.ssh_private_key.clone(),
        private_key_passphrase: p.ssh_private_key_passphrase.clone(),
        host_key_verification: p.ssh_host_key_verification.unwrap_or(true),
        compression: false,
        keepalive_interval: Some(30),
        connect_timeout: Some(10),
        connection_pool_size: Some(2),
        known_hosts_path: p.ssh_known_hosts_path.clone(),
    };

    match SshOutbound::new(cfg) {
        Ok(inner) => Some(Arc::new(SshOc {
            inner: Arc::new(inner),
        })),
        Err(e) => {
            tracing::warn!(
                target: "sb_core::adapter",
                error = %e,
                "ssh outbound init failed; fallback"
            );
            None
        }
    }
}

#[cfg(all(feature = "scaffold", not(feature = "out_ssh")))]
fn try_create_ssh_outbound(_p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    None
}

/// Helper: assembles basic outbounds (non-selector) into the bridge.
///
/// Iterates through config outbounds, attempts to create connectors via adapter or scaffold,
/// and registers them in the bridge. Skips Selector/URLTest which are assembled in second pass.
fn assemble_outbounds(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
        // Skip selector/urltest in first pass - they need all other outbounds registered first
        if ob.ty == OutboundType::Selector || ob.ty == OutboundType::UrlTest {
            continue;
        }

        let (name, p) = to_outbound_param(ob);
        let kind = p.kind.clone();
        let forced = want_adapter();

        let inst: Option<BuiltOutbound> = match forced {
            Some(true) => {
                let inst = try_adapter_outbound(&p, ob, br);
                if inst.is_none() {
                    tracing::warn!(
                        target: "sb_core::adapter",
                        outbound = %name,
                        kind = %p.kind,
                        "adapter path unavailable; falling back to scaffold"
                    );
                }
                inst.or_else(|| try_scaffold_outbound(&p, ob))
            }
            Some(false) => try_scaffold_outbound(&p, ob),
            None => try_adapter_outbound(&p, ob, br).or_else(|| try_scaffold_outbound(&p, ob)),
        };

        if let Some(o) = inst {
            // Optionally wrap with circuit breaker
            let tcp = maybe_wrap_with_cb(name.as_str(), o.tcp);
            br.add_outbound(name.clone(), kind, tcp);
            if let Some(udp_f) = o.udp {
                br.add_outbound_udp_factory(name, udp_f);
            }
        }
    }
}

// ============================================================================
// Optional Circuit Breaker wrapper for outbound connectors
// ============================================================================

static CB_STATES: Lazy<DashMap<String, i32>> = Lazy::new(|| DashMap::new());

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
        use std::io::{Error, ErrorKind};

        match self.cb.allow_request().await {
            sb_transport::circuit_breaker::CircuitBreakerDecision::Reject => {
                return Err(Error::new(ErrorKind::Other, "circuit open"));
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
/// Now uses adapter registry to allow sb-adapters to handle selector/urltest logic.
fn assemble_selectors(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
        if ob.ty == OutboundType::Selector || ob.ty == OutboundType::UrlTest {
            let (name, p) = to_outbound_param(ob);
            let kind = p.kind.clone();
            let forced = want_adapter();

            let inst: Option<BuiltOutbound> = match forced {
                Some(true) => {
                    let inst = try_adapter_outbound(&p, ob, br);
                    if inst.is_none() {
                        tracing::warn!(
                            target: "sb_core::adapter",
                            outbound = %name,
                            kind = %p.kind,
                            "adapter path unavailable for selector/urltest; falling back to scaffold"
                        );
                    }
                    inst.or_else(|| try_scaffold_selector(ob, br))
                }
                Some(false) => try_scaffold_selector(ob, br),
                None => try_adapter_outbound(&p, ob, br).or_else(|| try_scaffold_selector(ob, br)),
            };

            if let Some(o) = inst {
                let tcp = maybe_wrap_with_cb(name.as_str(), o.tcp);
                br.add_outbound(name.clone(), kind, tcp);
                if let Some(udp_f) = o.udp {
                    br.add_outbound_udp_factory(name, udp_f);
                }
            }
        }
    }
}

/// Fallback scaffold implementation for Selector/URLTest when adapter is unavailable.
/// This keeps the existing hardcoded logic as a fallback.
#[cfg(feature = "scaffold")]
fn try_scaffold_selector(ob: &OutboundIR, br: &Bridge) -> Option<BuiltOutbound> {
    if ob.ty == OutboundType::Selector {
        let name = ob.name.clone().unwrap_or_else(|| "selector".into());
        let members = ob.members.clone().unwrap_or_default();
        let mut resolved = Vec::new();

        for m in members {
            if let Some(conn) = br.find_outbound(&m) {
                resolved.push(crate::outbound::selector::Member {
                    name: m.clone(),
                    conn,
                });
            } else {
                tracing::warn!(
                    target: "sb_core::adapter",
                    selector = %name,
                    missing_member = %m,
                    "selector member not found, skipping"
                );
            }
        }

        if !resolved.is_empty() {
            let sel = Selector::new(name.clone(), resolved);
            return Some(BuiltOutbound {
                tcp: Arc::new(sel),
                udp: None,
            });
        }
    } else if ob.ty == OutboundType::UrlTest {
        let name = ob.name.clone().unwrap_or_else(|| "urltest".into());
        let members = ob.members.clone().unwrap_or_default();
        let mut proxies = Vec::new();

        for m in members {
            if let Some(conn) = br.find_outbound(&m) {
                let udp_factory = br.find_udp_factory(&m);
                proxies.push(ProxyMember::new(m.clone(), conn, udp_factory));
            } else {
                tracing::warn!(
                    target: "sb_core::adapter",
                    selector = %name,
                    missing_member = %m,
                    "urltest member not found, skipping"
                );
            }
        }

        if !proxies.is_empty() {
            let test_url = ob
                .test_url
                .clone()
                .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string());
            let interval = std::time::Duration::from_millis(ob.test_interval_ms.unwrap_or(10_000));
            let timeout = std::time::Duration::from_millis(ob.test_timeout_ms.unwrap_or(1_500));
            let tol = ob.test_tolerance_ms.unwrap_or(50);

            let group =
                SelectorGroup::new_urltest(name.clone(), proxies, test_url, interval, timeout, tol);
            let group = Arc::new(group);
            if tokio::runtime::Handle::try_current().is_ok() {
                group.clone().start_health_check();
            } else {
                tracing::debug!(
                    target: "sb_core::adapter",
                    selector = %name,
                    "urltest group built without runtime; health check not started"
                );
            }
            return Some(BuiltOutbound {
                tcp: group,
                udp: None,
            });
        }
    }
    None
}

#[cfg(not(feature = "scaffold"))]
fn try_scaffold_selector(_ob: &OutboundIR, _br: &Bridge) -> Option<BuiltOutbound> {
    None
}

/// Assembles IR configuration into a Bridge (with router feature enabled).
///
/// This function prioritizes adapter implementations but falls back to scaffold.
/// The strategy can be overridden via the `ADAPTER_FORCE` environment variable.
///
/// # Processing Order
/// 1. Assemble basic outbounds (direct, socks, http, etc.)
/// 2. Assemble selector outbounds (binds members from step 1)
/// 3. Assemble inbounds (uses routing engine)
#[cfg(feature = "router")]
pub fn build_bridge<'a>(cfg: &'a ConfigIR, engine: crate::routing::engine::Engine<'a>) -> Bridge {
    let mut br = Bridge::new();

    // Step 1 & 2: Outbounds and selectors
    assemble_outbounds(cfg, &mut br);
    assemble_selectors(cfg, &mut br);
    let outbound_handle = outbound_registry_handle_from_bridge(&br);
    #[cfg(feature = "router")]
    let router_handle = router_handle_from_ir(cfg);

    // Step 3: Inbounds
    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let forced = want_adapter();
        let adapter_ctx = registry::AdapterInboundContext {
            engine: engine.clone(),
            bridge: Arc::new(br.clone()),
            outbounds: outbound_handle.clone(),
            router: router_handle.clone(),
        };

        let inst: Option<Arc<dyn InboundService>> = match forced {
            Some(true) => {
                let inst = try_adapter_inbound(&p, &adapter_ctx);
                if inst.is_none() {
                    tracing::warn!(
                        target: "sb_core::adapter",
                        inbound = %p.kind,
                        listen = %format!("{}:{}", p.listen, p.port),
                        "adapter path unavailable; falling back to scaffold"
                    );
                }
                inst.or_else(|| try_scaffold_inbound(&p, engine.clone(), &br))
            }
            Some(false) => try_scaffold_inbound(&p, engine.clone(), &br),
            None => try_adapter_inbound(&p, &adapter_ctx)
                .or_else(|| try_scaffold_inbound(&p, engine.clone(), &br)),
        };

        if let Some(i) = inst {
            br.add_inbound_with_kind(p.kind.as_str(), i);
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
pub fn build_bridge(cfg: &ConfigIR, _engine: ()) -> Bridge {
    let mut br = Bridge::new();

    // Step 1 & 2: Outbounds and selectors
    assemble_outbounds(cfg, &mut br);
    assemble_selectors(cfg, &mut br);
    let outbound_handle = outbound_registry_handle_from_bridge(&br);

    // Step 3: Inbounds (without engine)
    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let forced = want_adapter();
        let adapter_ctx = registry::AdapterInboundContext {
            bridge: Arc::new(br.clone()),
            outbounds: outbound_handle.clone(),
            _phantom: std::marker::PhantomData,
        };

        let inst: Option<Arc<dyn InboundService>> = match forced {
            Some(true) => {
                let inst = try_adapter_inbound(&p, &adapter_ctx);
                if inst.is_none() {
                    tracing::warn!(
                        target: "sb_core::adapter",
                        inbound = %p.kind,
                        listen = %format!("{}:{}", p.listen, p.port),
                        "adapter path unavailable; falling back to scaffold"
                    );
                }
                inst.or_else(|| try_scaffold_inbound(&p, &br))
            }
            Some(false) => try_scaffold_inbound(&p, &br),
            None => try_adapter_inbound(&p, &adapter_ctx).or_else(|| try_scaffold_inbound(&p, &br)),
        };

        if let Some(i) = inst {
            br.add_inbound_with_kind(p.kind.as_str(), i);
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
