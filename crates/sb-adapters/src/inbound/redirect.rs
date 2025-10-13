//! Linux REDIRECT inbound (transparent proxy via iptables REDIRECT)
//!
//! - TCP only (IPv4). Retrieves original destination using SO_ORIGINAL_DST.
//! - Routes via sb-core router and connects using outbounds registry.
//!
//! Usage:
//!   - iptables -t nat -A PREROUTING -p tcp --dport <dst> -j REDIRECT --to-port <listen>
//!   - run this inbound with the same `listen` port.

use anyhow::{anyhow, Result};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{health as ob_health, registry, selector::PoolSelector};
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
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
                tracing::debug!("redirect: accept-loop heartbeat");
            }
            r = listener.accept() => {
                let (cli, peer) = match r { Ok(v) => v, Err(e) => { warn!(error=%e, "redirect: accept error"); continue; } };
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(cli, peer).await { warn!(%peer, error=%e, "redirect: session error"); }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(mut cli: TcpStream, peer: SocketAddr) -> Result<()> {
    // Obtain original destination (IPv4 only)
    let orig = get_original_dst(&cli)?;
    info!(%peer, ?orig, "redirect: original destination");

    let (host, port) = (orig.ip().to_string(), orig.port());
    let mut decision = RDecision::Direct;
    let proxy = default_proxy();

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
        let d = eng.decide(&ctx);
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
    }

    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(&host, port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            // Resolve named pool from registry; fallback to default proxy choice
            let peer_default: SocketAddr = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            let sel = PoolSelector::new("redirect".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(pool) = reg.pools.get(&name) {
                    if let Some(ep) = sel.select(&name, peer, &format!("{}:{}", host, port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
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
                        // Pool exhausted: fallback
                        match proxy {
                            ProxyChoice::Direct => {
                                direct_connect_hostport(&host, port, &opts).await?
                            }
                            ProxyChoice::Http(addr) => {
                                http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
                            }
                            ProxyChoice::Socks5(addr) => {
                                socks5_connect_through_socks5(addr, &host, port, &opts).await?
                            }
                        }
                    }
                } else {
                    // Pool not found: default proxy
                    match proxy {
                        ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                        ProxyChoice::Http(addr) => {
                            http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
                        }
                        ProxyChoice::Socks5(addr) => {
                            socks5_connect_through_socks5(addr, &host, port, &opts).await?
                        }
                    }
                }
            } else {
                // No registry: default proxy
                match proxy {
                    ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
                    ProxyChoice::Http(addr) => {
                        http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
                    }
                    ProxyChoice::Socks5(addr) => {
                        socks5_connect_through_socks5(addr, &host, port, &opts).await?
                    }
                }
            }
        }
        RDecision::Proxy(None) => match proxy {
            ProxyChoice::Direct => direct_connect_hostport(&host, port, &opts).await?,
            ProxyChoice::Http(addr) => {
                http_proxy_connect_through_proxy(addr, &host, port, &opts).await?
            }
            ProxyChoice::Socks5(addr) => {
                socks5_connect_through_socks5(addr, &host, port, &opts).await?
            }
        },
        RDecision::Reject => unreachable!(),
    };

    // Bidirectional copy
    let _ = tokio::io::copy_bidirectional(&mut cli, &mut upstream).await;
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
