//! Linux TProxy inbound (transparent proxy via iptables TPROXY)
//!
//! - TCP only (IPv4). Requires CAP_NET_ADMIN and appropriate iptables/ip rule setup.
//! - Listens with IP_TRANSPARENT to accept non-local traffic.
//! - Retrieves original destination similar to REDIRECT using SO_ORIGINAL_DST.

use anyhow::{anyhow, Result};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{health as ob_health, registry, selector::PoolSelector};
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::FromRawFd;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Build a transparent TcpListener bound to `listen` with IP_TRANSPARENT set.
fn build_transparent_listener(listen: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = match listen.ip() {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    // Enable IP_TRANSPARENT
    #[allow(clippy::useless_conversion)]
    unsafe {
        let val: libc::c_int = 1;
        let (level, optname) = match listen.ip() {
            IpAddr::V4(_) => (libc::SOL_IP, libc::IP_TRANSPARENT),
            IpAddr::V6(_) => (libc::SOL_IPV6, libc::IPV6_TRANSPARENT),
        };
        let ret = libc::setsockopt(
            sock.as_raw_fd(),
            level,
            optname,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    sock.set_reuse_address(true)?;
    sock.bind(&listen.into())?;
    sock.listen(1024)?;
    let std_listener: std::net::TcpListener = sock.into();
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

#[derive(Clone, Debug)]
pub struct TproxyConfig {
    pub listen: SocketAddr,
}

pub async fn serve(cfg: TproxyConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let listener = build_transparent_listener(cfg.listen)?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "tproxy: bound (IP_TRANSPARENT)");

    loop {
        select! {
            _ = stop_rx.recv() => break,
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "tproxy: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("tproxy", &e);
                        continue;
                    }
                };
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(cli, peer).await {
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("tproxy", &e);
                        warn!(%peer, error=%e, "tproxy: session error");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(mut cli: TcpStream, peer: SocketAddr) -> Result<()> {
    let orig = super::redirect::get_original_dst(&cli)?;
    info!(%peer, ?orig, "tproxy: original destination");

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
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("tproxy: rejected by rules"));
        }
        decision = d;
    }

    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(&host, port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("tproxy".into(), "default".into());
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
        RDecision::Reject | RDecision::RejectDrop => return Err(anyhow!("tproxy: rejected by rules")),
        _ => return Err(anyhow!("tproxy: unsupported routing action")),
    };

    let _ = tokio::io::copy_bidirectional(&mut cli, &mut upstream).await;
    Ok(())
}
