//! Adapter Bridge: Prioritizes sb-adapter registry; falls back to scaffold implementations.
//!
//! This module provides the core bridging logic to assemble inbound and outbound adapters
//! from configuration IR. It supports two strategies controlled by the `ADAPTER_FORCE` env var:
//! - `adapter`: Use sb-adapters registry (reserved for future implementation)
//! - `scaffold`: Use built-in simple implementations (direct/socks/http/ssh/selector/etc.)

use crate::adapter::{Bridge, InboundParam, InboundService, OutboundConnector, OutboundParam};
use crate::outbound::selector::Selector;
use once_cell::sync::Lazy;
use sb_config::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType};
use std::sync::Arc;

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
static ADAPTER_STRATEGY: Lazy<Option<bool>> = Lazy::new(|| {
    match std::env::var(ENV_ADAPTER_FORCE).ok().as_deref() {
        Some("adapter") => Some(true),
        Some("scaffold") => Some(false),
        _ => None,
    }
});

/// Determines the desired adapter strategy from environment variables.
///
/// Returns:
/// - `Some(true)`: Force use of adapter registry
/// - `Some(false)`: Force use of scaffold implementations
/// - `None`: Auto-select (try adapter first, fall back to scaffold)
fn want_adapter() -> Option<bool> {
    *ADAPTER_STRATEGY
}

/// Converts inbound IR to adapter parameter.
fn to_inbound_param(ib: &InboundIR) -> InboundParam {
    InboundParam {
        kind: match ib.ty {
            InboundType::Socks => "socks",
            InboundType::Http => "http",
            InboundType::Tun => "tun",
            InboundType::Direct => "direct",
        }
        .to_string(),
        listen: ib.listen.clone(),
        port: ib.port,
        basic_auth: ib.basic_auth.clone(),
        sniff: ib.sniff,
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
    let kind = match ob.ty {
        OutboundType::Direct => "direct",
        OutboundType::Http => "http",
        OutboundType::Socks => "socks",
        OutboundType::Block => "block",
        OutboundType::Selector => "selector",
        OutboundType::Shadowsocks => "shadowsocks",
        OutboundType::UrlTest => "urltest",
        OutboundType::Shadowtls => "shadowtls",
        OutboundType::Hysteria2 => "hysteria2",
        OutboundType::Tuic => "tuic",
        OutboundType::Vless => "vless",
        OutboundType::Vmess => "vmess",
        OutboundType::Trojan => "trojan",
        OutboundType::Ssh => "ssh",
    }
    .to_string();
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
            alpn: ob.alpn.clone().or_else(|| ob.tls_alpn.clone()),
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
/// Currently returns `None` as a placeholder until sb-adapters is fully implemented.
#[cfg(feature = "adapter")]
fn try_adapter_inbound(_p: &InboundParam) -> Option<Arc<dyn InboundService>> {
    None
}

#[cfg(not(feature = "adapter"))]
fn try_adapter_inbound(_p: &InboundParam) -> Option<Arc<dyn InboundService>> {
    None
}

/// Attempts to create an outbound connector using the adapter registry (when feature enabled).
///
/// Currently returns `None` as a placeholder until sb-adapters is fully implemented.
#[cfg(feature = "adapter")]
fn try_adapter_outbound(_p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    // Future implementation:
    // let server = p.server.clone().unwrap_or_default();
    // let port = p.port.unwrap_or(0);
    // sb_adapter::registry::outbound_create(p.kind.as_str(), p.name.as_deref(),
    //     if server.is_empty() { None } else { Some(server.as_str()) }, port)
    None
}

#[cfg(not(feature = "adapter"))]
fn try_adapter_outbound(_p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    None
}

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
        "socks" => {
            use crate::inbound::socks5::Socks5;
            let srv = Socks5::new(p.listen.clone(), p.port)
                .with_engine(engine.clone_as_static())
                .with_bridge(Arc::new(br.clone()));
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
fn try_scaffold_inbound(_p: &InboundParam, _br: &Bridge) -> Option<Arc<dyn InboundService>> {
    None
}

/// Attempts to create an outbound connector using scaffold implementations.
///
/// Supports: direct, socks, http, ssh outbound types.
#[cfg(feature = "scaffold")]
fn try_scaffold_outbound(p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
    match p.kind.as_str() {
        "direct" => {
            use crate::outbound::direct_simple::Direct;
            Some(Arc::new(Direct))
        }
        "socks" => {
            use crate::outbound::socks_upstream::SocksUp;
            let (u, pw) = extract_credentials(p);
            Some(Arc::new(SocksUp::new(
                p.server.clone().unwrap_or_default(),
                p.port.unwrap_or(DEFAULT_SOCKS_PORT),
                u,
                pw,
            )))
        }
        "http" => {
            use crate::outbound::http_upstream::HttpUp;
            let (u, pw) = extract_credentials(p);
            Some(Arc::new(HttpUp::new(
                p.server.clone().unwrap_or_default(),
                p.port.unwrap_or(DEFAULT_HTTP_PORT),
                u,
                pw,
            )))
        }
        "ssh" => try_create_ssh_outbound(p),
        _ => None,
    }
}

#[cfg(not(feature = "scaffold"))]
fn try_scaffold_outbound(_p: &OutboundParam) -> Option<Arc<dyn OutboundConnector>> {
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
/// and registers them in the bridge.
fn assemble_outbounds(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
        let (name, p) = to_outbound_param(ob);
        let kind = p.kind.clone();
        let forced = want_adapter();

        let inst: Option<Arc<dyn OutboundConnector>> = match forced {
            Some(true) => try_adapter_outbound(&p),
            Some(false) => try_scaffold_outbound(&p),
            None => try_adapter_outbound(&p).or_else(|| try_scaffold_outbound(&p)),
        };

        if let Some(o) = inst {
            br.add_outbound(name, kind, o);
        }
    }
}

/// Helper: assembles selector outbounds with resolved members.
///
/// Second-pass processing to bind selector members after basic outbounds are registered.
fn assemble_selectors(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
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
                    // Member missing: skip. Preflight warns; runtime falls back to direct or errors.
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
                br.add_outbound(name, "selector".into(), Arc::new(sel));
            }
        }
    }
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

    // Step 3: Inbounds
    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let forced = want_adapter();

        let inst: Option<Arc<dyn InboundService>> = match forced {
            Some(true) => try_adapter_inbound(&p),
            Some(false) => try_scaffold_inbound(&p, engine.clone(), &br),
            None => {
                try_adapter_inbound(&p).or_else(|| try_scaffold_inbound(&p, engine.clone(), &br))
            }
        };

        if let Some(i) = inst {
            br.add_inbound(i);
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

    // Step 3: Inbounds (without engine)
    for ib in &cfg.inbounds {
        let p = to_inbound_param(ib);
        let forced = want_adapter();

        let inst: Option<Arc<dyn InboundService>> = match forced {
            Some(true) => try_adapter_inbound(&p),
            Some(false) => try_scaffold_inbound(&p, &br),
            None => try_adapter_inbound(&p).or_else(|| try_scaffold_inbound(&p, &br)),
        };

        if let Some(i) = inst {
            br.add_inbound(i);
        }
    }

    br
}
