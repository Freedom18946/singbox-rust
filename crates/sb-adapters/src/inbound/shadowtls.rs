//! ShadowTLS inbound (TLS server) implementation
//!
//! Minimal ShadowTLS server supporting:
//! - TLS server with provided cert/key (PEM)
//! - Expects client to send: `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n`
//! - Parses target from HTTP CONNECT, routes via sb-core router/outbounds
//! - Bidirectional relay
//!
//! ShadowTLS masks proxy traffic as legitimate TLS connections.

use anyhow::{anyhow, Result};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::registry;
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct ShadowTlsInboundConfig {
    pub listen: SocketAddr,
    pub cert_path: String,
    pub key_path: String,
    pub router: Arc<router::RouterHandle>,
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    // Load cert chain
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .map_err(|_| anyhow!("invalid cert file"))?
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();

    // Load private key (PKCS#8 or RSA)
    let mut key_reader = BufReader::new(File::open(key_path)?);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map_err(|_| anyhow!("invalid key file (pkcs8)"))?
        .into_iter()
        .map(rustls::PrivateKey)
        .collect::<Vec<_>>();
    if keys.is_empty() {
        // try RSA
        let mut key_reader = BufReader::new(File::open(key_path)?);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .map_err(|_| anyhow!("invalid key file (rsa)"))?
            .into_iter()
            .map(rustls::PrivateKey)
            .collect::<Vec<_>>();
    }
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no private key found"))?;

    let cfg = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("tls config error: {}", e))?;
    Ok(cfg)
}

pub async fn serve(cfg: ShadowTlsInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let tls_cfg = load_tls_config(&cfg.cert_path, &cfg.key_path)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "shadowtls: TLS server bound");

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => { debug!("shadowtls: accept-loop heartbeat"); }
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "shadowtls: accept error");
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    match acceptor.accept(cli).await {
                        Ok(mut tls_stream) => {
                            if let Err(e) = handle_conn(&cfg_clone, &mut tls_stream, peer).await {
                                warn!(%peer, error=%e, "shadowtls: session error");
                                let _ = tls_stream.shutdown().await;
                            }
                        }
                        Err(e) => warn!(%peer, error=%e, "shadowtls: tls accept error"),
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(
    cfg: &ShadowTlsInboundConfig,
    tls: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    peer: SocketAddr,
) -> Result<()> {
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

    let target = parts.next().ok_or_else(|| anyhow!("shadowtls: missing target"))?;

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

    // Router decision
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(host.as_str()),
            ip: None,
            transport_udp: false,
            port: Some(port),
            process_name: None,
            process_path: None,
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("shadowtls: rejected by rules"));
        }
        decision = d;
    }

    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(&host, port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("shadowtls".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(_pool) = reg.pools.get(&name) {
                    if let Some(ep) =
                        sel.select(&name, peer, &format!("{}:{}", host, port), &())
                    {
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
                                socks5_connect_through_socks5(&ep.addr.to_string(), &host, port, &opts)
                                    .await?
                            }
                        }
                    } else {
                        fallback_connect(&proxy, &host, port, &opts).await?
                    }
                } else {
                    fallback_connect(&proxy, &host, port, &opts).await?
                }
            } else {
                fallback_connect(&proxy, &host, port, &opts).await?
            }
        }
        RDecision::Proxy(None) => fallback_connect(&proxy, &host, port, &opts).await?,
        RDecision::Reject => unreachable!(),
    };

    // Relay
    let _ = tokio::io::copy_bidirectional(tls, &mut upstream).await;
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
        ProxyChoice::Socks5(addr) => Ok(socks5_connect_through_socks5(addr, host, port, opts).await?),
    }
}
