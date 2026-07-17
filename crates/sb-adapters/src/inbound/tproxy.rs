//! Linux TProxy inbound (transparent proxy via iptables TPROXY)
//!
//! - TCP only (IPv4). Requires CAP_NET_ADMIN and appropriate iptables/ip rule setup.
//! - Listens with IP_TRANSPARENT to accept non-local traffic.
//! - Retrieves original destination similar to REDIRECT using SO_ORIGINAL_DST.

use crate::inbound::connect::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use crate::outbound::pool_selector::PoolSelector;
use anyhow::{anyhow, Result};
use sb_core::net::metered;
use sb_core::outbound::registry;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::v2ray_stats::StatsManager;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::Duration;
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
    pub tag: Option<String>,
    pub stats: Option<Arc<StatsManager>>,
    pub conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
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
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(&cfg_clone, cli, peer).await {
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

async fn handle_conn(cfg: &TproxyConfig, mut cli: TcpStream, peer: SocketAddr) -> Result<()> {
    let orig = super::redirect::get_original_dst(&cli)?;
    info!(%peer, ?orig, "tproxy: original destination");

    let (host, port) = (orig.ip().to_string(), orig.port());
    let (decision, rule) = match rules_global::global() {
        Some(eng) => {
            let mut domain_opt = None;
            if let Some(name) = sb_core::dns::fakeip::to_domain(&orig.ip()) {
                domain_opt = Some(name);
            }
            let ctx = RouteCtx {
                domain: domain_opt.as_deref(),
                ip: if domain_opt.is_some() {
                    None
                } else {
                    Some(orig.ip())
                },
                transport_udp: false,
                port: Some(port),
                process_name: None,
                process_path: None,
                network: Some("tcp"),
                ..Default::default()
            };
            let (d, r) = eng.decide_with_meta(&ctx);
            if matches!(d, RDecision::Reject) {
                return Err(anyhow!("tproxy: rejected by rules"));
            }
            (d, r)
        }
        None => {
            tracing::warn!(
                "tproxy: router engine not initialized; implicit direct fallback is disabled"
            );
            return Err(anyhow!(
                "tproxy: router engine not initialized, implicit direct fallback is disabled"
            ));
        }
    };

    let opts = ConnectOpts;
    let (mut upstream, outbound_tag) = match &decision {
        RDecision::Direct => (
            direct_connect_hostport(&host, port, &opts).await?,
            Some("direct".to_string()),
        ),
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("tproxy".into(), "default".into());
            if let Some(reg) = registry::global() {
                if reg.pools.contains_key(name) {
                    if let Some(ep) = sel.select(name, peer, &format!("{}:{}", host, port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => (
                                http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?,
                                Some("http".to_string()),
                            ),
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => (
                                socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?,
                                Some("socks5".to_string()),
                            ),
                        }
                    } else {
                        return Err(anyhow!(
                            "tproxy: named proxy decision '{}' has no selectable endpoint; implicit fallback is disabled; use adapter bridge/supervisor path",
                            name
                        ));
                    }
                } else {
                    return Err(anyhow!(
                        "tproxy: named proxy decision '{}' not found in registry; implicit fallback is disabled; use adapter bridge/supervisor path",
                        name
                    ));
                }
            } else {
                return Err(anyhow!(
                    "tproxy: named proxy decision '{}' cannot be resolved because registry is unavailable; implicit fallback is disabled; use adapter bridge/supervisor path",
                    name
                ));
            }
        }
        RDecision::Proxy(None) => {
            return Err(anyhow!(
                "tproxy: proxy decision without outbound tag is unsupported; implicit fallback is disabled; provide explicit outbound in routing"
            ));
        }
        RDecision::Reject | RDecision::RejectDrop => {
            return Err(anyhow!("tproxy: rejected by rules"))
        }
        _ => return Err(anyhow!("tproxy: unsupported routing action")),
    };

    let traffic = cfg.stats.as_ref().and_then(|stats| {
        stats.traffic_recorder(cfg.tag.as_deref(), outbound_tag.as_deref(), None)
    });
    let chains = sb_core::outbound::chain::compute_chain_for_decision(
        None,
        &decision,
        outbound_tag.as_deref(),
    );
    let wiring = sb_core::conntrack::register_inbound_tcp_with_tracker(
        cfg.conn_tracker.clone(),
        peer,
        host.clone(),
        port,
        host.clone(),
        "tproxy",
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
        "tproxy",
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
/// Transitional blocking driver for TProxy inbound registration.
#[cfg(all(target_os = "linux", feature = "router"))]
#[derive(Debug)]
pub(crate) struct TproxyInboundDriver {
    cfg: TproxyConfig,
    stop_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl TproxyInboundDriver {
    pub(crate) fn new(cfg: TproxyConfig) -> Self {
        Self {
            cfg,
            stop_tx: std::sync::Mutex::new(None),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "router"))]
impl sb_core::adapter::InboundTaskDriver for TproxyInboundDriver {
    fn serve(&self) -> std::io::Result<()> {
        let runtime = tokio::runtime::Runtime::new().map_err(std::io::Error::other)?;
        let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
        *self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(stop_tx);
        let result = runtime.block_on(async {
            serve(self.cfg.clone(), stop_rx)
                .await
                .map_err(std::io::Error::other)
        });
        let _ = self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        result
    }

    fn request_shutdown(&self) {
        if let Some(stop_tx) = self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = stop_tx.try_send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires Linux CAP_NET_ADMIN for IP_TRANSPARENT"]
    async fn linux_tproxy_listener_binds_and_stops_with_net_admin() {
        let (stop_tx, stop_rx) = mpsc::channel(1);
        stop_tx.send(()).await.expect("queue tproxy shutdown");

        let cfg = TproxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tag: Some("linux-tproxy-smoke".to_string()),
            stats: None,
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::default()),
        };

        tokio::time::timeout(Duration::from_secs(2), serve(cfg, stop_rx))
            .await
            .expect("tproxy shutdown timed out")
            .expect("tproxy listener failed");
    }
}
