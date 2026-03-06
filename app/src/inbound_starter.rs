#[cfg(any(feature = "adapters", feature = "router"))]
use anyhow::{Context, Result};
#[cfg(any(feature = "router", feature = "adapters"))]
use sb_config::ir::{InboundIR, InboundType};
#[cfg(feature = "router")]
use sb_core::adapter::InboundService;
#[cfg(feature = "router")]
use sb_core::outbound::OutboundRegistryHandle;
#[cfg(feature = "adapters")]
use std::collections::HashMap;
#[cfg(any(feature = "adapters", feature = "router"))]
use std::net::SocketAddr;
#[cfg(any(feature = "router", feature = "adapters"))]
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
#[cfg(feature = "adapters")]
use tokio::time::Duration;
#[cfg(feature = "router")]
use tracing::info;
#[cfg(any(feature = "router", feature = "adapters"))]
use tracing::warn;

#[cfg(feature = "router")]
use sb_core::router::RouterHandle;

#[cfg(feature = "adapters")]
use sb_adapters::inbound::http::{HttpProxyConfig, serve_http};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::mixed::{MixedInboundConfig, serve_mixed};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::socks::udp::serve_socks5_udp_service;
#[cfg(feature = "adapters")]
use sb_adapters::inbound::socks::{SocksInboundConfig, serve_socks};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::trojan::{TrojanInboundConfig, TrojanUser, serve as serve_trojan};
#[cfg(all(feature = "tun", feature = "adapters"))]
use sb_adapters::inbound::tun::{TunInbound, TunInboundConfig};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::vless::{VlessInboundConfig, serve as serve_vless};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::vmess::{VmessInboundConfig, serve as serve_vmess};

pub enum InboundStop {
    Channel(mpsc::Sender<()>),
    #[cfg(feature = "router")]
    Direct(Arc<sb_core::inbound::direct::DirectForward>),
    Abort,
}

pub struct InboundHandle {
    #[allow(dead_code)]
    name: String,
    stop: InboundStop,
    join: JoinHandle<()>,
}

impl InboundHandle {
    pub async fn shutdown(self) {
        match self.stop {
            InboundStop::Channel(tx) => {
                let _ = tx.send(()).await;
                let _ = self.join.await;
            }
            #[cfg(feature = "router")]
            InboundStop::Direct(forward) => {
                forward.request_shutdown();
                let _ = self.join.await;
            }
            InboundStop::Abort => {
                self.join.abort();
                let _ = self.join.await;
            }
        }
    }
}

/// Convert string like "127.0.0.1:8080" to `SocketAddr` with friendly error.
#[cfg(any(feature = "adapters", feature = "router"))]
fn parse_listen_addr(s: &str) -> Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .or_else(|_| {
            let t = s.trim();
            t.parse::<SocketAddr>()
        })
        .with_context(|| format!("invalid listen addr in config: '{s}'"))
}

#[cfg(feature = "adapters")]
fn parse_optional_inbound_fallback_addr(
    protocol: &str,
    listen_str: &str,
    value: Option<&str>,
) -> Result<Option<SocketAddr>> {
    value
        .map(|fallback| {
            parse_listen_addr(fallback).with_context(|| {
                format!(
                    "{protocol} inbound fallback '{fallback}' is invalid for listen '{listen_str}'; silent fallback parsing is disabled; fix the config explicitly"
                )
            })
        })
        .transpose()
}

#[cfg(feature = "adapters")]
fn parse_inbound_fallback_for_alpn(
    protocol: &str,
    listen_str: &str,
    entries: Option<&HashMap<String, String>>,
) -> Result<HashMap<String, SocketAddr>> {
    let mut parsed = HashMap::new();
    if let Some(entries) = entries {
        for (alpn, addr) in entries {
            let socket_addr = parse_listen_addr(addr).with_context(|| {
                format!(
                    "{protocol} inbound fallback_for_alpn['{alpn}']='{addr}' is invalid for listen '{listen_str}'; silent fallback parsing is disabled; fix the config explicitly"
                )
            })?;
            parsed.insert(alpn.clone(), socket_addr);
        }
    }
    Ok(parsed)
}

#[cfg(feature = "adapters")]
fn parse_optional_inbound_duration(
    protocol: &str,
    listen_str: &str,
    field: &str,
    value: Option<&str>,
) -> Result<Option<std::time::Duration>> {
    value
        .map(|raw| {
            humantime::parse_duration(raw).with_context(|| {
                format!(
                    "{protocol} inbound {field} '{raw}' is invalid for listen '{listen_str}'; silent duration fallback is disabled; fix the config explicitly"
                )
            })
        })
        .transpose()
}

#[cfg(feature = "adapters")]
fn parse_optional_inbound_uuid(
    protocol: &str,
    listen_str: &str,
    value: Option<&str>,
) -> Result<Option<uuid::Uuid>> {
    value
        .map(|raw| {
            uuid::Uuid::parse_str(raw).with_context(|| {
                format!(
                    "{protocol} inbound uuid '{raw}' is invalid for listen '{listen_str}'; silent uuid parse fallback is disabled; fix the config explicitly"
                )
            })
        })
        .transpose()
}

#[cfg(feature = "adapters")]
fn socks_udp_should_start() -> bool {
    // 显式开关优先；其次只要配置了监听地址也启动
    let enabled = std::env::var("SB_SOCKS_UDP_ENABLE")
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
    enabled
        || std::env::var("SB_SOCKS_UDP_LISTEN")
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
}

#[cfg(feature = "adapters")]
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
#[cfg(feature = "router")]
#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
pub fn start_inbounds_from_ir(
    inbounds: &[InboundIR],
    #[cfg(feature = "router")] router: &Arc<RouterHandle>,
    outbounds: &Arc<OutboundRegistryHandle>,
) -> Vec<InboundHandle> {
    info!("start_inbounds_from_ir: count={}", inbounds.len());
    let mut handles = Vec::new();

    for ib in inbounds {
        info!("Starting inbound: type={:?} listen={}", ib.ty, ib.listen);
        match ib.ty {
            InboundType::Http => {
                #[cfg(feature = "adapters")]
                if let Some(handle) = start_http_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                    outbounds.clone(),
                ) {
                    handles.push(handle);
                }
                #[cfg(not(feature = "adapters"))]
                warn!("http inbound requires 'adapters' feature; skipping");
            }
            InboundType::Socks => {
                #[cfg(feature = "adapters")]
                handles.extend(start_socks_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                    outbounds.clone(),
                ));
                #[cfg(not(feature = "adapters"))]
                warn!("socks inbound requires 'adapters' feature; skipping");
            }
            InboundType::Mixed => {
                #[cfg(feature = "adapters")]
                if let Some(handle) = start_mixed_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                    outbounds.clone(),
                ) {
                    handles.push(handle);
                }
                #[cfg(not(feature = "adapters"))]
                warn!("mixed inbound requires 'adapters' feature; skipping");
            }
            InboundType::Tun => {
                #[cfg(all(feature = "tun", feature = "adapters"))]
                if let Some(handle) = start_tun_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                    outbounds.clone(),
                ) {
                    handles.push(handle);
                }
                #[cfg(any(not(feature = "tun"), not(feature = "adapters")))]
                warn!("config includes tun inbound, but feature 'tun' is disabled; skipping");
            }
            InboundType::Direct => {
                #[cfg(feature = "router")]
                if let Some(handle) = start_direct_inbound(ib) {
                    handles.push(handle);
                }
                #[cfg(not(feature = "router"))]
                warn!("direct inbound requires 'router' feature; skipping");
            }
            InboundType::Trojan => {
                #[cfg(feature = "adapters")]
                if let Some(handle) = start_trojan_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                ) {
                    handles.push(handle);
                }
                #[cfg(not(feature = "adapters"))]
                warn!("trojan inbound requires 'adapters' feature; skipping");
            }
            InboundType::Vless => {
                #[cfg(feature = "adapters")]
                if let Some(handle) = start_vless_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                ) {
                    handles.push(handle);
                }
                #[cfg(not(feature = "adapters"))]
                warn!("vless inbound requires 'adapters' feature; skipping");
            }
            InboundType::Vmess => {
                #[cfg(feature = "adapters")]
                if let Some(handle) = start_vmess_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                ) {
                    handles.push(handle);
                }
                #[cfg(not(feature = "adapters"))]
                warn!("vmess inbound requires 'adapters' feature; skipping");
            }
            InboundType::Redirect | InboundType::Tproxy => {
                warn!(
                    kind=?ib.ty,
                    "inbound type not supported in this build; consider using 'tun' or SOCKS/HTTP inbound"
                );
            }
            _ => {
                warn!(
                    kind=?ib.ty,
                    "inbound type requires adapters feature; enable 'app/adapters' or route through sb_core bridge"
                );
            }
        }
    }
    handles
}

#[cfg(feature = "adapters")]
fn start_http_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) -> Option<InboundHandle> {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    parse_listen_addr(&listen_str).map_or_else(
        |_| {
            warn!(%listen_str, "http inbound: invalid listen address");
            None
        },
        |addr| {
            let (tx, rx) = mpsc::channel::<()>(1);
            let cfg = HttpProxyConfig {
                listen: addr,
                #[cfg(feature = "router")]
                router,
                #[cfg(not(feature = "router"))]
                router: Arc::new(sb_core::router::RouterHandle::from_env()),
                outbounds,
                tag: None,
                stats: None,
                tls: None,
                users: ib.users.clone(),
                set_system_proxy: ib.set_system_proxy,
                allow_private_network: ib.allow_private_network,
            };
            let listen_str_log = listen_str.clone();
            let join = tokio::spawn(async move {
                if let Err(e) = serve_http(cfg, rx, None).await {
                    warn!(addr=%listen_str_log, error=%e, "http inbound failed");
                }
            });
            Some(InboundHandle {
                name: "http".to_string(),
                stop: InboundStop::Channel(tx),
                join,
            })
        },
    )
}

#[cfg(feature = "adapters")]
fn start_socks_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) -> Vec<InboundHandle> {
    let mut handles = Vec::new();
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        use sb_adapters::inbound::socks::DomainStrategy;

        let udp_timeout = match parse_optional_inbound_duration(
            "socks",
            &listen_str,
            "udp_timeout",
            ib.udp_timeout.as_deref(),
        ) {
            Ok(udp_timeout) => udp_timeout,
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "socks inbound: invalid duration config; refusing to start"
                );
                return handles;
            }
        };
        let domain_strategy =
            ib.domain_strategy
                .as_deref()
                .and_then(|s| match s.to_ascii_lowercase().as_str() {
                    "asis" | "as_is" => Some(DomainStrategy::AsIs),
                    "useip" | "use_ip" => Some(DomainStrategy::UseIp),
                    "useipv4" | "use_ipv4" => Some(DomainStrategy::UseIpv4),
                    "useipv6" | "use_ipv6" => Some(DomainStrategy::UseIpv6),
                    _ => None,
                });

        let (tx, rx) = mpsc::channel::<()>(1);
        let cfg = SocksInboundConfig {
            listen: addr,
            udp_bind: parse_udp_bind_from_env(),
            #[cfg(feature = "router")]
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            outbounds,
            tag: None,
            stats: None,
            udp_nat_ttl: Duration::from_secs(60),
            users: ib.users.clone(),
            udp_timeout,
            domain_strategy,
        };
        let listen_str_log = listen_str.clone();
        let join = tokio::spawn(async move {
            if let Err(e) = serve_socks(cfg, rx, None).await {
                warn!(addr=%listen_str_log, error=%e, "socks inbound failed");
            }
        });
        handles.push(InboundHandle {
            name: "socks".to_string(),
            stop: InboundStop::Channel(tx),
            join,
        });
        // start UDP association service if config or env enables
        if ib.udp || socks_udp_should_start() {
            let join = tokio::spawn(async move {
                if let Err(e) = serve_socks5_udp_service().await {
                    warn!(error=%e, "socks udp service failed");
                }
            });
            handles.push(InboundHandle {
                name: "socks-udp".to_string(),
                stop: InboundStop::Abort,
                join,
            });
        }
    } else {
        warn!(%listen_str, "socks inbound: invalid listen address");
    }
    handles
}

#[cfg(feature = "adapters")]
fn start_mixed_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) -> Option<InboundHandle> {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    parse_listen_addr(&listen_str).map_or_else(
        |_| {
            warn!(%listen_str, "mixed inbound: invalid listen address");
            None
        },
        |addr| {
            use sb_adapters::inbound::socks::DomainStrategy;

            let udp_timeout = match parse_optional_inbound_duration(
                "mixed",
                &listen_str,
                "udp_timeout",
                ib.udp_timeout.as_deref(),
            ) {
                Ok(udp_timeout) => udp_timeout,
                Err(e) => {
                    warn!(
                        addr=%listen_str,
                        error=%e,
                        "mixed inbound: invalid duration config; refusing to start"
                    );
                    return None;
                }
            };
            let domain_strategy =
                ib.domain_strategy
                    .as_deref()
                    .and_then(|s| match s.to_ascii_lowercase().as_str() {
                        "asis" | "as_is" => Some(DomainStrategy::AsIs),
                        "useip" | "use_ip" => Some(DomainStrategy::UseIp),
                        "useipv4" | "use_ipv4" => Some(DomainStrategy::UseIpv4),
                        "useipv6" | "use_ipv6" => Some(DomainStrategy::UseIpv6),
                        _ => None,
                    });

            let (tx, rx) = mpsc::channel::<()>(1);
            let cfg = MixedInboundConfig {
                listen: addr,
                #[cfg(feature = "router")]
                router,
                #[cfg(not(feature = "router"))]
                router: Arc::new(sb_core::router::RouterHandle::from_env()),
                outbounds,
                tag: None,
                stats: None,
                read_timeout: None,
                tls: None,
                users: ib.users.clone(),
                set_system_proxy: ib.set_system_proxy,
                allow_private_network: ib.allow_private_network,
                udp_timeout,
                domain_strategy,
            };
            let listen_str_log = listen_str.clone();
            let join = tokio::spawn(async move {
                if let Err(e) = serve_mixed(cfg, rx, None).await {
                    warn!(addr=%listen_str_log, error=%e, "mixed inbound failed");
                }
            });
            Some(InboundHandle {
                name: "mixed".to_string(),
                stop: InboundStop::Channel(tx),
                join,
            })
        },
    )
}

#[cfg(all(feature = "tun", feature = "adapters"))]
fn start_tun_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) -> Option<InboundHandle> {
    let cfg = TunInboundConfig::default();
    let inbound = TunInbound::new(
        cfg,
        {
            #[cfg(feature = "router")]
            {
                router
            }
            #[cfg(not(feature = "router"))]
            {
                Arc::new(sb_core::router::RouterHandle::from_env())
            }
        },
        outbounds,
        ib.tag.clone(),
        None,
    );
    let join = tokio::spawn(async move {
        if let Err(e) = inbound.serve().await {
            warn!(error=%e, "tun inbound failed");
        }
    });
    info!("tun inbound spawned (phase1 skeleton)");
    Some(InboundHandle {
        name: "tun".to_string(),
        stop: InboundStop::Abort,
        join,
    })
}

#[cfg(feature = "router")]
fn start_direct_inbound(ib: &InboundIR) -> Option<InboundHandle> {
    let dst_host = if let Some(h) = &ib.override_host {
        h.clone()
    } else {
        warn!("direct inbound missing override_host/override_address; skipping");
        return None;
    };
    let Some(dst_port) = ib.override_port else {
        warn!("direct inbound missing override_port; skipping");
        return None;
    };
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    match parse_listen_addr(&listen_str) {
        Ok(addr) => {
            let f_dst = format!("{dst_host}:{dst_port}");
            let forward = Arc::new(sb_core::inbound::direct::DirectForward::new(
                addr, dst_host, dst_port, ib.udp,
            ));
            let forward_spawn = Arc::clone(&forward);
            let join = tokio::task::spawn_blocking(move || {
                let _ = forward_spawn.serve();
            });
            info!(addr=%listen_str, dst=%f_dst, "direct inbound spawned");
            Some(InboundHandle {
                name: "direct".to_string(),
                stop: InboundStop::Direct(forward),
                join,
            })
        }
        Err(e) => {
            warn!(addr=%listen_str, error=%e, "direct inbound: invalid listen address");
            None
        }
    }
}

#[cfg(feature = "adapters")]
fn start_trojan_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
) -> Option<InboundHandle> {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        let (tx, rx) = mpsc::channel::<()>(1);

        // Map users
        let users = ib
            .users_trojan
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|u| TrojanUser::new(u.name.clone(), u.password.clone()))
                    .collect()
            })
            .unwrap_or_default();

        let fallback = match parse_optional_inbound_fallback_addr(
            "trojan",
            &listen_str,
            ib.fallback.as_deref(),
        ) {
            Ok(fallback) => fallback,
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "trojan inbound: invalid fallback config; refusing to start"
                );
                return None;
            }
        };
        let fallback_for_alpn = match parse_inbound_fallback_for_alpn(
            "trojan",
            &listen_str,
            ib.fallback_for_alpn.as_ref(),
        ) {
            Ok(fallback_for_alpn) => fallback_for_alpn,
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "trojan inbound: invalid fallback config; refusing to start"
                );
                return None;
            }
        };

        let cfg = TrojanInboundConfig {
            listen: addr,
            #[allow(deprecated)]
            password: None,
            users,
            cert_path: ib.tls_cert_path.clone().unwrap_or_default(),
            key_path: ib.tls_key_path.clone().unwrap_or_default(),
            #[cfg(feature = "router")]
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            tag: None,
            stats: None,
            #[cfg(feature = "tls_reality")]
            reality: None,
            multiplex: None,
            transport_layer: None,
            fallback,
            fallback_for_alpn,
        };
        let listen_str_log = listen_str.clone();
        let join = tokio::spawn(async move {
            if let Err(e) = serve_trojan(cfg, rx).await {
                warn!(addr=%listen_str, error=%e, "trojan inbound failed");
            }
        });
        info!(addr=%listen_str_log, "trojan inbound spawned");
        Some(InboundHandle {
            name: "trojan".to_string(),
            stop: InboundStop::Channel(tx),
            join,
        })
    } else {
        warn!(%listen_str, "trojan inbound: invalid listen address");
        None
    }
}

#[cfg(feature = "adapters")]
fn start_vless_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
) -> Option<InboundHandle> {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        let (tx, rx) = mpsc::channel::<()>(1);

        let uuid = match parse_optional_inbound_uuid("vless", &listen_str, ib.uuid.as_deref()) {
            Ok(Some(uuid)) => uuid,
            Ok(None) => {
                warn!(%listen_str, "vless inbound missing uuid; skipping");
                return None;
            }
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "vless inbound: invalid uuid config; refusing to start"
                );
                return None;
            }
        };

        let fallback = match parse_optional_inbound_fallback_addr(
            "vless",
            &listen_str,
            ib.fallback.as_deref(),
        ) {
            Ok(fallback) => fallback,
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "vless inbound: invalid fallback config; refusing to start"
                );
                return None;
            }
        };
        let fallback_for_alpn = match parse_inbound_fallback_for_alpn(
            "vless",
            &listen_str,
            ib.fallback_for_alpn.as_ref(),
        ) {
            Ok(fallback_for_alpn) => fallback_for_alpn,
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "vless inbound: invalid fallback config; refusing to start"
                );
                return None;
            }
        };

        let cfg = VlessInboundConfig {
            listen: addr,
            uuid,
            #[cfg(feature = "router")]
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            tag: None,
            stats: None,
            #[cfg(feature = "tls_reality")]
            reality: None,
            multiplex: None,
            transport_layer: None,
            fallback,
            fallback_for_alpn,
            flow: ib.flow.clone(),
        };
        let listen_str_log = listen_str.clone();
        let join = tokio::spawn(async move {
            if let Err(e) = serve_vless(cfg, rx).await {
                warn!(addr=%listen_str, error=%e, "vless inbound failed");
            }
        });
        info!(addr=%listen_str_log, "vless inbound spawned");
        Some(InboundHandle {
            name: "vless".to_string(),
            stop: InboundStop::Channel(tx),
            join,
        })
    } else {
        warn!(%listen_str, "vless inbound: invalid listen address");
        None
    }
}

#[cfg(feature = "adapters")]
fn start_vmess_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
) -> Option<InboundHandle> {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        let (tx, rx) = mpsc::channel::<()>(1);

        let uuid = match parse_optional_inbound_uuid("vmess", &listen_str, ib.uuid.as_deref()) {
            Ok(Some(uuid)) => uuid,
            Ok(None) => {
                warn!(%listen_str, "vmess inbound missing uuid; skipping");
                return None;
            }
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "vmess inbound: invalid uuid config; refusing to start"
                );
                return None;
            }
        };

        let fallback = match parse_optional_inbound_fallback_addr(
            "vmess",
            &listen_str,
            ib.fallback.as_deref(),
        ) {
            Ok(fallback) => fallback,
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "vmess inbound: invalid fallback config; refusing to start"
                );
                return None;
            }
        };
        let fallback_for_alpn = match parse_inbound_fallback_for_alpn(
            "vmess",
            &listen_str,
            ib.fallback_for_alpn.as_ref(),
        ) {
            Ok(fallback_for_alpn) => fallback_for_alpn,
            Err(e) => {
                warn!(
                    addr=%listen_str,
                    error=%e,
                    "vmess inbound: invalid fallback config; refusing to start"
                );
                return None;
            }
        };

        let cfg = VmessInboundConfig {
            listen: addr,
            uuid,
            security: "chacha20-poly1305".to_string(),
            #[cfg(feature = "router")]
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            tag: None,
            stats: None,
            multiplex: None,
            transport_layer: None,
            fallback,
            fallback_for_alpn,
        };
        let listen_str_log = listen_str.clone();
        let join = tokio::spawn(async move {
            if let Err(e) = serve_vmess(cfg, rx).await {
                warn!(addr=%listen_str, error=%e, "vmess inbound failed");
            }
        });
        info!(addr=%listen_str_log, "vmess inbound spawned");
        Some(InboundHandle {
            name: "vmess".to_string(),
            stop: InboundStop::Channel(tx),
            join,
        })
    } else {
        warn!(%listen_str, "vmess inbound: invalid listen address");
        None
    }
}

#[cfg(all(test, feature = "adapters"))]
mod tests {
    use super::{
        parse_inbound_fallback_for_alpn, parse_optional_inbound_duration,
        parse_optional_inbound_fallback_addr, parse_optional_inbound_uuid,
    };
    use std::collections::HashMap;

    #[test]
    fn invalid_optional_fallback_is_rejected_explicitly() {
        let err = parse_optional_inbound_fallback_addr("trojan", "127.0.0.1:443", Some("bad"))
            .expect_err("invalid fallback should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("trojan inbound fallback 'bad' is invalid"));
        assert!(msg.contains("silent fallback parsing is disabled"));
    }

    #[test]
    fn invalid_fallback_for_alpn_entry_is_rejected_explicitly() {
        let mut entries = HashMap::new();
        entries.insert("h2".to_string(), "bad".to_string());

        let err = parse_inbound_fallback_for_alpn("trojan", "127.0.0.1:443", Some(&entries))
            .expect_err("invalid fallback_for_alpn entry should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("fallback_for_alpn['h2']='bad'"));
        assert!(msg.contains("silent fallback parsing is disabled"));
    }

    #[test]
    fn invalid_optional_fallback_reports_requested_protocol() {
        let err = parse_optional_inbound_fallback_addr("vmess", "127.0.0.1:80", Some("bad"))
            .expect_err("invalid fallback should be rejected");
        assert!(
            err.to_string()
                .contains("vmess inbound fallback 'bad' is invalid")
        );
    }

    #[test]
    fn invalid_optional_fallback_reports_vless_protocol() {
        let err = parse_optional_inbound_fallback_addr("vless", "127.0.0.1:80", Some("bad"))
            .expect_err("invalid fallback should be rejected");
        assert!(
            err.to_string()
                .contains("vless inbound fallback 'bad' is invalid")
        );
    }

    #[test]
    fn invalid_duration_is_rejected_explicitly() {
        let err =
            parse_optional_inbound_duration("socks", "127.0.0.1:1080", "udp_timeout", Some("bad"))
                .expect_err("invalid duration should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("socks inbound udp_timeout 'bad' is invalid"));
        assert!(msg.contains("silent duration fallback is disabled"));
    }

    #[test]
    fn invalid_duration_reports_mixed_protocol() {
        let err =
            parse_optional_inbound_duration("mixed", "127.0.0.1:1080", "udp_timeout", Some("bad"))
                .expect_err("invalid duration should be rejected");
        assert!(
            err.to_string()
                .contains("mixed inbound udp_timeout 'bad' is invalid")
        );
    }

    #[test]
    fn invalid_uuid_reports_vless_protocol() {
        let err = parse_optional_inbound_uuid("vless", "127.0.0.1:443", Some("bad-uuid"))
            .expect_err("invalid uuid should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vless inbound uuid 'bad-uuid' is invalid"));
        assert!(msg.contains("silent uuid parse fallback is disabled"));
    }

    #[test]
    fn invalid_uuid_reports_vmess_protocol() {
        let err = parse_optional_inbound_uuid("vmess", "127.0.0.1:443", Some("bad-uuid"))
            .expect_err("invalid uuid should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vmess inbound uuid 'bad-uuid' is invalid"));
        assert!(msg.contains("silent uuid parse fallback is disabled"));
    }
}
