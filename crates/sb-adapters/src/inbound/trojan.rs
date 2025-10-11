//! Trojan inbound (TLS server) implementation
//!
//! Minimal compatible server:
//! - TLS server with provided cert/key (PEM)
//! - Expects client to send: `password\r\nCONNECT host port\r\n\r\n`
//! - Verifies password, parses target, routes via sb-core router/outbounds
//! - Bidirectional relay

use anyhow::{anyhow, Result};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5, ConnectOpts,
};
use sb_core::outbound::{registry, selector::PoolSelector};
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

#[cfg(feature = "tls_reality")]
#[allow(unused_imports)]
use sb_tls::RealityAcceptor;

#[derive(Clone, Debug)]
pub struct TrojanInboundConfig {
    pub listen: SocketAddr,
    pub password: String,
    pub cert_path: String,
    pub key_path: String,
    pub router: Arc<router::RouterHandle>,
    /// Optional REALITY TLS configuration for inbound
    #[cfg(feature = "tls_reality")]
    pub reality: Option<sb_tls::RealityServerConfig>,
    /// Optional Multiplex configuration
    pub multiplex: Option<sb_transport::multiplex::MultiplexServerConfig>,
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    // Load cert chain
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("invalid cert file"))?;

    // Load private key (PKCS#8 or RSA)
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    
    let key = {
        // Try PKCS#8 first
        if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .next()
            .transpose()
            .map_err(|_| anyhow!("invalid key file (pkcs8)"))?
        {
            rustls_pki_types::PrivateKeyDer::Pkcs8(key)
        } else {
            // Try RSA
            let key_file = File::open(key_path)?;
            let mut key_reader = BufReader::new(key_file);
            let key = rustls_pemfile::rsa_private_keys(&mut key_reader)
                .next()
                .ok_or_else(|| anyhow!("no private key found"))?
                .map_err(|_| anyhow!("invalid key file (rsa)"))?;
            rustls_pki_types::PrivateKeyDer::Pkcs1(key)
        }
    };

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("tls config error: {}", e))?;
    Ok(cfg)
}

pub async fn serve(cfg: TrojanInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    
    // Note: Multiplex support for Trojan inbound is configured but not yet fully implemented
    // Trojan typically uses TLS directly, and multiplex integration would require
    // wrapping TLS streams with multiplex, which needs architectural changes
    if cfg.multiplex.is_some() {
        warn!("Multiplex configuration present but not yet fully implemented for Trojan inbound");
    }
    
    // Create REALITY acceptor if configured, otherwise use standard TLS
    #[cfg(feature = "tls_reality")]
    let reality_acceptor = if let Some(ref reality_cfg) = cfg.reality {
        info!(addr=?cfg.listen, actual=?actual, multiplex=?cfg.multiplex.is_some(), "trojan: REALITY TLS server bound");
        Some(Arc::new(sb_tls::RealityAcceptor::new(reality_cfg.clone())
            .map_err(|e| anyhow!("Failed to create REALITY acceptor: {}", e))?))
    } else {
        info!(addr=?cfg.listen, actual=?actual, multiplex=?cfg.multiplex.is_some(), "trojan: TLS server bound");
        None
    };
    
    #[cfg(not(feature = "tls_reality"))]
    info!(addr=?cfg.listen, actual=?actual, multiplex=?cfg.multiplex.is_some(), "trojan: TLS server bound");
    
    // Load standard TLS config if not using REALITY
    let tls_acceptor = {
        #[cfg(feature = "tls_reality")]
        {
            if cfg.reality.is_none() {
                let tls_cfg = load_tls_config(&cfg.cert_path, &cfg.key_path)?;
                Some(TlsAcceptor::from(Arc::new(tls_cfg)))
            } else {
                None
            }
        }
        #[cfg(not(feature = "tls_reality"))]
        {
            let tls_cfg = load_tls_config(&cfg.cert_path, &cfg.key_path)?;
            Some(TlsAcceptor::from(Arc::new(tls_cfg)))
        }
    };

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => { tracing::debug!("trojan: accept-loop heartbeat"); }
            r = listener.accept() => {
                let (cli, peer) = match r { Ok(v) => v, Err(e) => { warn!(error=%e, "trojan: accept error"); continue; } };
                
                #[cfg(feature = "tls_reality")]
                let reality_acceptor_clone = reality_acceptor.clone();
                let tls_acceptor_clone = tls_acceptor.clone();
                let cfg_clone = cfg.clone();
                
                tokio::spawn(async move {
                    #[cfg(feature = "tls_reality")]
                    {
                        if let Some(acceptor) = reality_acceptor_clone {
                            // Handle REALITY connection
                            match acceptor.accept(cli).await {
                                Ok(reality_conn) => {
                                    match reality_conn.handle().await {
                                        Ok(Some(mut tls_stream)) => {
                                            // Proxy connection - handle Trojan protocol over TLS
                                            if let Err(e) = handle_conn(&cfg_clone, &mut tls_stream, peer).await {
                                                warn!(%peer, error=%e, "trojan: REALITY session error");
                                            }
                                        }
                                        Ok(None) => {
                                            // Fallback connection - already handled by REALITY
                                            debug!(%peer, "trojan: REALITY fallback completed");
                                        }
                                        Err(e) => {
                                            warn!(%peer, error=%e, "trojan: REALITY connection handling error");
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(%peer, error=%e, "trojan: REALITY accept error");
                                }
                            }
                        } else if let Some(acceptor) = tls_acceptor_clone {
                            // Standard TLS
                            match acceptor.accept(cli).await {
                                Ok(mut tls_stream) => {
                                    if let Err(e) = handle_conn(&cfg_clone, &mut tls_stream, peer).await {
                                        warn!(%peer, error=%e, "trojan: session error");
                                        let _ = tls_stream.shutdown().await;
                                    }
                                }
                                Err(e) => warn!(%peer, error=%e, "trojan: tls accept error"),
                            }
                        }
                    }
                    
                    #[cfg(not(feature = "tls_reality"))]
                    {
                        if let Some(acceptor) = tls_acceptor_clone {
                            match acceptor.accept(cli).await {
                                Ok(mut tls_stream) => {
                                    if let Err(e) = handle_conn(&cfg_clone, &mut tls_stream, peer).await {
                                        warn!(%peer, error=%e, "trojan: session error");
                                        let _ = tls_stream.shutdown().await;
                                    }
                                }
                                Err(e) => warn!(%peer, error=%e, "trojan: tls accept error"),
                            }
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(
    cfg: &TrojanInboundConfig,
    tls: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    peer: SocketAddr,
) -> Result<()> {
    // Read until CRLFCRLF
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];
    loop {
        let n = tls.read(&mut tmp).await?;
        if n == 0 { return Err(anyhow!("trojan: client closed")); }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
        if buf.len() > 8192 { return Err(anyhow!("trojan: header too large")); }
    }

    // Parse lines
    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let pass = lines.next().unwrap_or("");
    if pass != cfg.password {
        return Err(anyhow!("trojan: bad password"));
    }
    let req = lines.next().unwrap_or("");
    let mut it = req.split_whitespace();
    let method = it.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(anyhow!("trojan: unsupported method"));
    }
    let host = it.next().ok_or_else(|| anyhow!("trojan: missing host"))?;
    let port: u16 = it.next().ok_or_else(|| anyhow!("trojan: missing port"))?.parse().map_err(|_| anyhow!("trojan: bad port"))?;

    // Router decision
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx { domain: Some(host), ip: None, transport_udp: false, port: Some(port), process_name: None, process_path: None };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) { return Err(anyhow!("trojan: rejected by rules")); }
        decision = d;
    }

    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(host, port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("trojan".into(), "default".into());
            if let Some(reg) = registry::global() {
                if reg.pools.contains_key(&name) {
                    if let Some(ep) = sel.select(&name, peer, &format!("{}:{}", host, port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                http_proxy_connect_through_proxy(&ep.addr.to_string(), host, port, &opts).await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(&ep.addr.to_string(), host, port, &opts).await?
                            }
                        }
                    } else {
                        match proxy {
                            ProxyChoice::Direct => direct_connect_hostport(host, port, &opts).await?,
                            ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, host, port, &opts).await?,
                            ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, host, port, &opts).await?,
                        }
                    }
                } else {
                    match proxy {
                        ProxyChoice::Direct => direct_connect_hostport(host, port, &opts).await?,
                        ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, host, port, &opts).await?,
                        ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, host, port, &opts).await?,
                    }
                }
            } else {
                match proxy {
                    ProxyChoice::Direct => direct_connect_hostport(host, port, &opts).await?,
                    ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, host, port, &opts).await?,
                    ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, host, port, &opts).await?,
                }
            }
        }
        RDecision::Proxy(None) => {
            match proxy {
                ProxyChoice::Direct => direct_connect_hostport(host, port, &opts).await?,
                ProxyChoice::Http(addr) => http_proxy_connect_through_proxy(addr, host, port, &opts).await?,
                ProxyChoice::Socks5(addr) => socks5_connect_through_socks5(addr, host, port, &opts).await?,
            }
        }
        RDecision::Reject => unreachable!(),
    };

    // Relay
    let _ = tokio::io::copy_bidirectional(tls, &mut upstream).await;
    Ok(())
}
