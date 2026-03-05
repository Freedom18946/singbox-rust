//! Linux REDIRECT inbound (transparent proxy via iptables REDIRECT)
//!
//! - TCP only (IPv4). Retrieves original destination using SO_ORIGINAL_DST.
//! - Routes via sb-core router and connects using outbounds registry.
//!
//! Usage:
//!   - iptables -t nat -A PREROUTING -p tcp --dport <dst> -j REDIRECT --to-port <listen>
//!   - run this inbound with the same `listen` port.

use anyhow::{anyhow, Result};
use sb_core::net::metered;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{health as ob_health, registry, selector::PoolSelector};
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::services::v2ray_api::StatsManager;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct RedirectConfig {
    pub listen: SocketAddr,
    pub tag: Option<String>,
    pub stats: Option<Arc<StatsManager>>,
}

pub async fn serve(cfg: RedirectConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "redirect: bound");

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => {
                // tracing::debug!("redirect: accept-loop heartbeat");
            }
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "redirect: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("redirect", &e);
                        continue;
                    }
                };
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(&cfg_clone, cli, peer).await {
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("redirect", &e);
                        warn!(%peer, error=%e, "redirect: session error");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(cfg: &RedirectConfig, mut cli: TcpStream, peer: SocketAddr) -> Result<()> {
    // Obtain original destination (IPv4 only)
    let orig = get_original_dst(&cli)?;
    info!(%peer, ?orig, "redirect: original destination");

    let (host, port) = (orig.ip().to_string(), orig.port());
    let mut decision = RDecision::Direct;
    let mut rule: Option<String> = None;

    if let Some(eng) = rules_global::global() {
        let mut domain_opt = None;
        if let Some(name) = sb_core::dns::fakeip::to_domain(&orig.ip()) {
            domain_opt = Some(name);
        }
        let ctx = RouteCtx {
            domain: domain_opt,
            ip: if domain_opt.is_some() {
                None
            } else {
                Some(orig.ip())
            },
            transport_udp: false,
            port: Some(port),
            process_name: None,
            process_path: None,
        };
        let (d, r) = eng.decide_with_meta(&ctx);
        #[cfg(feature = "metrics")]
        {
            metrics::counter!(
                "router_decide_total",
                "decision" => match &d { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" }
            ).increment(1);
        }
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("redirect: rejected by rules"));
        }
        decision = d;
        rule = r;
    }

    let opts = ConnectOpts::default();
    let mut outbound_tag: Option<String> = None;
    let mut upstream = match decision {
        RDecision::Direct => {
            outbound_tag = Some("direct".to_string());
            direct_connect_hostport(&host, port, &opts).await?
        }
        RDecision::Proxy(Some(name)) => {
            // Resolve named pool from registry; fallback path is disabled.
            let sel = PoolSelector::new("redirect".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(pool) = reg.pools.get(&name) {
                    if let Some(ep) = sel.select(&name, peer, &format!("{}:{}", host, port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                outbound_tag = Some("http".to_string());
                                http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                outbound_tag = Some("socks5".to_string());
                                socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?
                            }
                        }
                    } else {
                        return Err(anyhow!(
                            "redirect: named proxy decision '{}' has no selectable endpoint; implicit fallback is disabled; use adapter bridge/supervisor path",
                            name
                        ));
                    }
                } else {
                    return Err(anyhow!(
                        "redirect: named proxy decision '{}' not found in registry; implicit fallback is disabled; use adapter bridge/supervisor path",
                        name
                    ));
                }
            } else {
                return Err(anyhow!(
                    "redirect: named proxy decision '{}' cannot be resolved because registry is unavailable; implicit fallback is disabled; use adapter bridge/supervisor path",
                    name
                ));
            }
        }
        RDecision::Proxy(None) => {
            return Err(anyhow!(
                "redirect: proxy decision without outbound tag is unsupported; implicit fallback is disabled; provide explicit outbound in routing"
            ));
        }
        RDecision::Reject | RDecision::RejectDrop => {
            return Err(anyhow!("redirect: rejected by rules"))
        }
        // Sniff/Resolve/Hijack not yet supported in inbound handlers
        _ => return Err(anyhow!("redirect: unsupported routing action")),
    };

    // Bidirectional copy
    let traffic = cfg.stats.as_ref().and_then(|stats| {
        stats.traffic_recorder(cfg.tag.as_deref(), outbound_tag.as_deref(), None)
    });
    let chains = sb_core::outbound::chain::compute_chain_for_decision(
        None,
        &decision,
        outbound_tag.as_deref(),
    );
    let wiring = sb_core::conntrack::register_inbound_tcp(
        peer,
        host.clone(),
        port,
        host.clone(),
        "redirect",
        cfg.tag.clone(),
        outbound_tag.clone(),
        chains,
        rule.clone(),
        None,
        None,
        traffic,
    );
    let _guard = wiring.guard;
    let copy_res = metered::copy_bidirectional_streaming_ctl(
        &mut cli,
        &mut upstream,
        "redirect",
        Duration::from_secs(1),
        None,
        None,
        Some(wiring.cancel),
        Some(wiring.traffic),
    )
    .await;
    if let Err(e) = copy_res {
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    }
    Ok(())
}

pub(crate) fn get_original_dst(s: &TcpStream) -> std::io::Result<SocketAddr> {
    // SAFETY: Linux-only; get SO_ORIGINAL_DST (IPv4)
    let fd = s.as_raw_fd();
    unsafe {
        // sockaddr_in
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if addr.sin_family != libc::AF_INET as u16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "redirect: non-IPv4 original dst",
            ));
        }
        let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
        let port = u16::from_be(addr.sin_port);
        Ok(SocketAddr::new(ip, port))
    }
}
