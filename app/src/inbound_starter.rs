use anyhow::{Context, Result};
use sb_config::ir::{InboundIR, InboundType};
#[cfg(feature = "router")]
use sb_core::adapter::InboundService;
use sb_core::outbound::OutboundRegistryHandle;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{info, warn};

#[cfg(feature = "router")]
use sb_core::router::RouterHandle;

#[cfg(feature = "adapters")]
use sb_adapters::inbound::http::{serve_http, HttpProxyConfig};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::mixed::{serve_mixed, MixedInboundConfig};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::socks::udp::serve_socks5_udp_service;
#[cfg(feature = "adapters")]
use sb_adapters::inbound::socks::{serve_socks, SocksInboundConfig};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::trojan::{serve as serve_trojan, TrojanInboundConfig, TrojanUser};
#[cfg(all(feature = "tun", feature = "adapters"))]
use sb_adapters::inbound::tun::{TunInbound, TunInboundConfig};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::vless::{serve as serve_vless, VlessInboundConfig};
#[cfg(feature = "adapters")]
use sb_adapters::inbound::vmess::{serve as serve_vmess, VmessInboundConfig};

/// Convert string like "127.0.0.1:8080" to `SocketAddr` with friendly error.
fn parse_listen_addr(s: &str) -> Result<SocketAddr> {
    s.parse::<SocketAddr>()
        .or_else(|_| {
            let t = s.trim();
            t.parse::<SocketAddr>()
        })
        .with_context(|| format!("invalid listen addr in config: '{s}'"))
}

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
#[allow(
    clippy::cognitive_complexity,
    clippy::too_many_lines
)]
pub async fn start_inbounds_from_ir(
    inbounds: &[InboundIR],
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) {
    info!("start_inbounds_from_ir: count={}", inbounds.len());

    for ib in inbounds {
        info!("Starting inbound: type={:?} listen={}", ib.ty, ib.listen);
        match ib.ty {
            InboundType::Http => {
                #[cfg(feature = "adapters")]
                start_http_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                    outbounds.clone(),
                );
                #[cfg(not(feature = "adapters"))]
                warn!("http inbound requires 'adapters' feature; skipping");
            }
            InboundType::Socks => {
                #[cfg(feature = "adapters")]
                start_socks_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                    outbounds.clone(),
                );
                #[cfg(not(feature = "adapters"))]
                warn!("socks inbound requires 'adapters' feature; skipping");
            }
            InboundType::Mixed => {
                #[cfg(feature = "adapters")]
                start_mixed_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                    outbounds.clone(),
                );
                #[cfg(not(feature = "adapters"))]
                warn!("mixed inbound requires 'adapters' feature; skipping");
            }
            InboundType::Tun => {
                #[cfg(all(feature = "tun", feature = "adapters"))]
                start_tun_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                );
                #[cfg(any(not(feature = "tun"), not(feature = "adapters")))]
                warn!("config includes tun inbound, but feature 'tun' is disabled; skipping");
            }
            InboundType::Direct => {
                #[cfg(feature = "router")]
                start_direct_inbound(ib);
                #[cfg(not(feature = "router"))]
                warn!("direct inbound requires 'router' feature; skipping");
            }
            InboundType::Trojan => {
                #[cfg(feature = "adapters")]
                start_trojan_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                );
                #[cfg(not(feature = "adapters"))]
                warn!("trojan inbound requires 'adapters' feature; skipping");
            }
            InboundType::Vless => {
                #[cfg(feature = "adapters")]
                start_vless_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                );
                #[cfg(not(feature = "adapters"))]
                warn!("vless inbound requires 'adapters' feature; skipping");
            }
            InboundType::Vmess => {
                #[cfg(feature = "adapters")]
                start_vmess_inbound(
                    ib,
                    #[cfg(feature = "router")]
                    router.clone(),
                );
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
}

#[cfg(feature = "adapters")]
#[cfg(feature = "adapters")]
fn start_http_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) {
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
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            outbounds,
            tls: None,
            users: ib.users.clone(),
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

#[cfg(feature = "adapters")]
#[cfg(feature = "adapters")]
fn start_socks_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) {
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
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            outbounds,
            udp_nat_ttl: Duration::from_secs(60),
            users: ib.users.clone(),
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

#[cfg(feature = "adapters")]
#[cfg(feature = "adapters")]
fn start_mixed_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
) {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        let (_tx, rx) = mpsc::channel::<()>(1);
        let cfg = MixedInboundConfig {
            listen: addr,
            #[cfg(feature = "router")]
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            outbounds,
            read_timeout: None,
            tls: None,
            users: ib.users.clone(),
            set_system_proxy: false,
        };
        tokio::spawn(async move {
            if let Err(e) = serve_mixed(cfg, rx, None).await {
                warn!(addr=%listen_str, error=%e, "mixed inbound failed");
            }
        });
    } else {
        warn!(%listen_str, "mixed inbound: invalid listen address");
    }
}

#[cfg(all(feature = "tun", feature = "adapters"))]
#[cfg(all(feature = "tun", feature = "adapters"))]
fn start_tun_inbound(_ib: &InboundIR, #[cfg(feature = "router")] router: Arc<RouterHandle>) {
    let cfg = TunInboundConfig::default();
    let inbound = TunInbound::new(cfg, {
        #[cfg(feature = "router")]
        {
            router
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

#[cfg(feature = "router")]
#[cfg(feature = "router")]
fn start_direct_inbound(ib: &InboundIR) {
    let dst_host = if let Some(h) = &ib.override_host {
        h.clone()
    } else {
        warn!("direct inbound missing override_host/override_address; skipping");
        return;
    };
    let Some(dst_port) = ib.override_port else {
        warn!("direct inbound missing override_port; skipping");
        return;
    };
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    match parse_listen_addr(&listen_str) {
        Ok(addr) => {
            let f_dst = format!("{dst_host}:{dst_port}");
            let forward =
                sb_core::inbound::direct::DirectForward::new(addr, dst_host, dst_port, ib.udp);
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

#[cfg(feature = "adapters")]
#[cfg(feature = "adapters")]
fn start_trojan_inbound(
    ib: &InboundIR,
    #[cfg(feature = "router")] router: Arc<RouterHandle>,
) {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        let (_tx, rx) = mpsc::channel::<()>(1);

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

        // Map fallback
        let fallback = ib.fallback.as_ref().and_then(|s| parse_listen_addr(s).ok());
        let fallback_for_alpn = ib
            .fallback_for_alpn
            .as_ref()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| parse_listen_addr(v).ok().map(|a| (k.clone(), a)))
                    .collect()
            })
            .unwrap_or_default();

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
            reality: None,
            multiplex: None,
            transport_layer: None,
            fallback,
            fallback_for_alpn,
        };
        let listen_str_log = listen_str.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_trojan(cfg, rx).await {
                warn!(addr=%listen_str, error=%e, "trojan inbound failed");
            }
        });
        info!(addr=%listen_str_log, "trojan inbound spawned");
    } else {
        warn!(%listen_str, "trojan inbound: invalid listen address");
    }
}

#[cfg(feature = "adapters")]
fn start_vless_inbound(ib: &InboundIR, #[cfg(feature = "router")] router: Arc<RouterHandle>) {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        let (_tx, rx) = mpsc::channel::<()>(1);

        let Some(uuid) = ib.uuid.as_ref().and_then(|u| uuid::Uuid::parse_str(u).ok()) else {
            warn!(%listen_str, "vless inbound missing or invalid uuid; skipping");
            return;
        };

        // Map fallback
        let fallback = ib.fallback.as_ref().and_then(|s| parse_listen_addr(s).ok());
        let fallback_for_alpn = ib
            .fallback_for_alpn
            .as_ref()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| parse_listen_addr(v).ok().map(|a| (k.clone(), a)))
                    .collect()
            })
            .unwrap_or_default();

        let cfg = VlessInboundConfig {
            listen: addr,
            uuid,
            #[cfg(feature = "router")]
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            reality: None,
            multiplex: None,
            transport_layer: None,
            fallback,
            fallback_for_alpn,
            flow: ib.flow.clone(),
        };
        let listen_str_log = listen_str.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_vless(cfg, rx).await {
                warn!(addr=%listen_str, error=%e, "vless inbound failed");
            }
        });
        info!(addr=%listen_str_log, "vless inbound spawned");
    } else {
        warn!(%listen_str, "vless inbound: invalid listen address");
    }
}

#[cfg(feature = "adapters")]
fn start_vmess_inbound(ib: &InboundIR, #[cfg(feature = "router")] router: Arc<RouterHandle>) {
    let listen_str = if ib.listen.contains(':') {
        ib.listen.clone()
    } else {
        format!("{}:{}", ib.listen, ib.port)
    };
    if let Ok(addr) = parse_listen_addr(&listen_str) {
        let (_tx, rx) = mpsc::channel::<()>(1);

        let Some(uuid) = ib.uuid.as_ref().and_then(|u| uuid::Uuid::parse_str(u).ok()) else {
            warn!(%listen_str, "vmess inbound missing or invalid uuid; skipping");
            return;
        };

        // Map fallback
        let fallback = ib.fallback.as_ref().and_then(|s| parse_listen_addr(s).ok());
        let fallback_for_alpn = ib
            .fallback_for_alpn
            .as_ref()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| parse_listen_addr(v).ok().map(|a| (k.clone(), a)))
                    .collect()
            })
            .unwrap_or_default();

        let cfg = VmessInboundConfig {
            listen: addr,
            uuid,
            security: "chacha20-poly1305".to_string(),
            #[cfg(feature = "router")]
            router,
            #[cfg(not(feature = "router"))]
            router: Arc::new(sb_core::router::RouterHandle::from_env()),
            multiplex: None,
            transport_layer: None,
            fallback,
            fallback_for_alpn,
        };
        let listen_str_log = listen_str.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_vmess(cfg, rx).await {
                warn!(addr=%listen_str, error=%e, "vmess inbound failed");
            }
        });
        info!(addr=%listen_str_log, "vmess inbound spawned");
    } else {
        warn!(%listen_str, "vmess inbound: invalid listen address");
    }
}
