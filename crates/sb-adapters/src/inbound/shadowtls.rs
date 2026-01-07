//! ShadowTLS inbound (TLS server) implementation
//!
//! Complete ShadowTLS server supporting:
//! - TLS server using sb-tls infrastructure (Standard TLS, REALITY, ECH)
//! - Expects client to send: `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n`
//! - Parses target from HTTP CONNECT, routes via sb-core router/outbounds
//! - Bidirectional relay
//!
//! ShadowTLS masks proxy traffic as legitimate TLS connections.
//! Sprint 19 Phase 1.1: Complete integration with sb-tls infrastructure from Sprint 5

use anyhow::{anyhow, Result};
use sb_core::adapter::InboundService;
use sb_core::outbound::registry;
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::net::metered;
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use sb_core::services::v2ray_api::StatsManager;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct ShadowTlsInboundConfig {
    pub listen: SocketAddr,
    /// TLS configuration using sb-tls infrastructure (Standard, REALITY, ECH)
    pub tls: sb_transport::TlsConfig,
    pub router: Arc<router::RouterHandle>,
    pub tag: Option<String>,
    pub stats: Option<Arc<StatsManager>>,
}

pub async fn serve(cfg: ShadowTlsInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(
        addr=?cfg.listen,
        actual=?actual,
        "shadowtls: TLS server bound"
    );

    // Create TLS transport using sb-tls infrastructure
    // Note: TlsTransport is created inside each spawn to avoid clone issues

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => {
                // debug!("shadowtls: accept-loop heartbeat");
            }
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("shadowtls", &e);
                        warn!(error=%e, "shadowtls: accept error");
                        continue;
                    }
                };

                let cfg_clone = cfg.clone();

                tokio::spawn(async move {
                    // Create TLS transport inside the spawn to avoid clone issues
                    let tls_transport = sb_transport::TlsTransport::new(cfg_clone.tls.clone());
                    match tls_transport.wrap_server(cli).await {
                        Ok(tls_stream) => {
                            if let Err(e) = handle_conn(&cfg_clone, tls_stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("shadowtls", &e);
                                warn!(%peer, error=%e, "shadowtls: session error");
                            }
                        }
                        Err(e) => {
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("shadowtls", &e);
                            warn!(%peer, error=%e, "shadowtls: TLS handshake failed")
                        },
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn<S>(cfg: &ShadowTlsInboundConfig, mut tls: S, peer: SocketAddr) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Read HTTP CONNECT header
    // Format: CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];
    loop {
        let n = tls.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("shadowtls: client closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(anyhow!("shadowtls: header too large"));
        }
    }

    // Parse CONNECT line
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let connect_line = lines.next().unwrap_or("");

    // Parse: CONNECT host:port HTTP/1.1
    let mut parts = connect_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(anyhow!("shadowtls: unsupported method: {}", method));
    }

    let target = parts
        .next()
        .ok_or_else(|| anyhow!("shadowtls: missing target"))?;

    // Parse host:port
    let (host, port) = if let Some(colon_pos) = target.rfind(':') {
        let host = &target[..colon_pos];
        let port_str = &target[colon_pos + 1..];
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow!("shadowtls: invalid port"))?;
        (host.to_string(), port)
    } else {
        return Err(anyhow!("shadowtls: invalid target format"));
    };

    debug!(%peer, host=%host, port=%port, "shadowtls: parsed target");

    // Router decision with updated RouteCtx (Sprint 19 Phase 1.1)
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(host.as_str()),
            ip: None,
            transport_udp: false,
            port: Some(port),
            network: Some("tcp"),
            ..Default::default()
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("shadowtls: rejected by rules"));
        }
        decision = d;
    }

    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let (mut upstream, outbound_tag) = match decision {
        RDecision::Direct => {
            (direct_connect_hostport(&host, port, &opts).await?, Some("direct".to_string()))
        }
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("shadowtls".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(_pool) = reg.pools.get(&name) {
                    if let Some(ep) = sel.select(&name, peer, &format!("{}:{}", host, port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                let stream = http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?;
                                (stream, Some("http".to_string()))
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                let stream = socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &host,
                                    port,
                                    &opts,
                                )
                                .await?;
                                (stream, Some("socks5".to_string()))
                            }
                        }
                    } else {
                        let stream = fallback_connect(proxy, &host, port, &opts).await?;
                        let tag = match proxy {
                            ProxyChoice::Direct => "direct",
                            ProxyChoice::Http(_) => "http",
                            ProxyChoice::Socks5(_) => "socks5",
                        };
                        (stream, Some(tag.to_string()))
                    }
                } else {
                    let stream = fallback_connect(proxy, &host, port, &opts).await?;
                    let tag = match proxy {
                        ProxyChoice::Direct => "direct",
                        ProxyChoice::Http(_) => "http",
                        ProxyChoice::Socks5(_) => "socks5",
                    };
                    (stream, Some(tag.to_string()))
                }
            } else {
                let stream = fallback_connect(proxy, &host, port, &opts).await?;
                let tag = match proxy {
                    ProxyChoice::Direct => "direct",
                    ProxyChoice::Http(_) => "http",
                    ProxyChoice::Socks5(_) => "socks5",
                };
                (stream, Some(tag.to_string()))
            }
        }
        RDecision::Proxy(None) => {
            let stream = fallback_connect(proxy, &host, port, &opts).await?;
            let tag = match proxy {
                ProxyChoice::Direct => "direct",
                ProxyChoice::Http(_) => "http",
                ProxyChoice::Socks5(_) => "socks5",
            };
            (stream, Some(tag.to_string()))
        }
        RDecision::Reject | RDecision::RejectDrop => return Err(anyhow!("shadowtls: rejected by rules")),
        _ => return Err(anyhow!("shadowtls: unsupported routing action")),
    };

    // Bidirectional relay
    let traffic = cfg.stats.as_ref().and_then(|stats| {
        stats.traffic_recorder(cfg.tag.as_deref(), outbound_tag.as_deref(), None)
    });
    let _ = metered::copy_bidirectional_streaming_ctl(
        &mut tls,
        &mut upstream,
        "shadowtls",
        Duration::from_secs(1),
        None,
        None,
        None,
        traffic,
    )
    .await;
    Ok(())
}

async fn fallback_connect(
    proxy: &ProxyChoice,
    host: &str,
    port: u16,
    opts: &ConnectOpts,
) -> Result<tokio::net::TcpStream> {
    match proxy {
        ProxyChoice::Direct => Ok(direct_connect_hostport(host, port, opts).await?),
        ProxyChoice::Http(addr) => {
            Ok(http_proxy_connect_through_proxy(addr, host, port, opts).await?)
        }
        ProxyChoice::Socks5(addr) => {
            Ok(socks5_connect_through_socks5(addr, host, port, opts).await?)
        }
    }
}

#[derive(Debug)]
pub struct ShadowTlsInboundAdapter {
    cfg: ShadowTlsInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

impl ShadowTlsInboundAdapter {
    pub fn new(cfg: ShadowTlsInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

impl InboundService for ShadowTlsInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock().unwrap();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let res = rt.block_on(async { serve(cfg, rx).await.map_err(io::Error::other) });
        let _ = self.stop_tx.lock().unwrap().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }
}
