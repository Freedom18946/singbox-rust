//! Trojan inbound (TLS server) implementation
//!
//! Minimal compatible server:
//! - TLS server with provided cert/key (PEM)
//! - Expects client to send: `password\r\nCONNECT host port\r\n\r\n`
//! - Verifies password, parses target, routes via sb-core router/outbounds
//! - Bidirectional relay

use anyhow::{anyhow, Result};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
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
use tokio::io::AsyncReadExt;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

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
    /// V2Ray transport layer configuration (WebSocket, gRPC, HTTPUpgrade)
    /// If None, defaults to TCP
    pub transport_layer: Option<crate::transport_config::TransportConfig>,
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
    // Create listener based on transport configuration (defaults to TCP if not specified)
    let transport = cfg.transport_layer.clone().unwrap_or_default();
    let listener = transport.create_inbound_listener(cfg.listen).await?;
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
        info!(
            addr=?cfg.listen,
            actual=?actual,
            transport=?transport.transport_type(),
            multiplex=?cfg.multiplex.is_some(),
            "trojan: REALITY TLS server bound"
        );
        Some(Arc::new(
            sb_tls::RealityAcceptor::new(reality_cfg.clone())
                .map_err(|e| anyhow!("Failed to create REALITY acceptor: {}", e))?,
        ))
    } else {
        info!(
            addr=?cfg.listen,
            actual=?actual,
            transport=?transport.transport_type(),
            multiplex=?cfg.multiplex.is_some(),
            "trojan: TLS server bound"
        );
        None
    };

    #[cfg(not(feature = "tls_reality"))]
    info!(
        addr=?cfg.listen,
        actual=?actual,
        transport=?transport.transport_type(),
        multiplex=?cfg.multiplex.is_some(),
        "trojan: TLS server bound"
    );

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
                let mut stream = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "trojan: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("trojan", &e);
                        continue;
                    }
                };

                // For non-TCP transports, we don't have peer address
                let peer = SocketAddr::from(([0, 0, 0, 0], 0));

                #[cfg(feature = "tls_reality")]
                let reality_acceptor_clone = reality_acceptor.clone();
                let tls_acceptor_clone = tls_acceptor.clone();
                let cfg_clone = cfg.clone();

                tokio::spawn(async move {
                    // Note: For V2Ray transports (WebSocket/gRPC/HTTPUpgrade), TLS might already
                    // be handled at the transport layer, or we need to wrap the stream with TLS here

                    #[cfg(feature = "tls_reality")]
                    {
                        if reality_acceptor_clone.is_some() {
                            // Handle REALITY connection
                            // Note: This needs refactoring to support generic streams
                            warn!("REALITY TLS over V2Ray transports not yet supported, using stream directly");
                            // TODO: Implement generic TLS wrapping for any AsyncRead+AsyncWrite stream
                            if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("trojan", &e);
                                warn!(%peer, error=%e, "trojan: REALITY session error (direct stream)");
                            }
                        } else if tls_acceptor_clone.is_some() {
                            // Standard TLS over transport stream
                            warn!("Standard TLS over V2Ray transports not yet fully supported, using stream directly");
                            // TODO: Implement TLS acceptor for generic streams
                            if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("trojan", &e);
                                warn!(%peer, error=%e, "trojan: session error (direct stream)");
                            }
                        } else {
                            // No TLS configured, use stream directly
                            if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                warn!(%peer, error=%e, "trojan: session error (no TLS)");
                            }
                        }
                    }

                    #[cfg(not(feature = "tls_reality"))]
                    {
                        if tls_acceptor_clone.is_some() {
                            // Standard TLS over transport stream
                            warn!("Standard TLS over V2Ray transports not yet fully supported, using stream directly");
                            // TODO: Implement TLS acceptor for generic streams
                            if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("trojan", &e);
                                warn!(%peer, error=%e, "trojan: session error (direct stream)");
                            }
                        } else {
                            // No TLS configured, use stream directly
                            if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("trojan", &e);
                                warn!(%peer, error=%e, "trojan: session error (no TLS)");
                            }
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

// Helper function to handle connections from generic streams (for V2Ray transport support)
async fn handle_conn_stream(
    cfg: &TrojanInboundConfig,
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    peer: SocketAddr,
) -> Result<()> {
    handle_conn_impl(cfg, stream, peer).await
}

async fn handle_conn_impl(
    cfg: &TrojanInboundConfig,
    tls: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    peer: SocketAddr,
) -> Result<()> {
    // Read until CRLFCRLF
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];
    loop {
        let n = tls.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("trojan: client closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(anyhow!("trojan: header too large"));
        }
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
    let port: u16 = it
        .next()
        .ok_or_else(|| anyhow!("trojan: missing port"))?
        .parse()
        .map_err(|_| anyhow!("trojan: bad port"))?;

    // Router decision
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(host),
            ip: None,
            transport_udp: false,
            port: Some(port),
            process_name: None,
            process_path: None,
            inbound_tag: None,
            outbound_tag: None,
            auth_user: None,
            query_type: None,
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("trojan: rejected by rules"));
        }
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
                                http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    host,
                                    port,
                                    &opts,
                                )
                                .await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    host,
                                    port,
                                    &opts,
                                )
                                .await?
                            }
                        }
                    } else {
                        match proxy {
                            ProxyChoice::Direct => {
                                direct_connect_hostport(host, port, &opts).await?
                            }
                            ProxyChoice::Http(addr) => {
                                http_proxy_connect_through_proxy(addr, host, port, &opts).await?
                            }
                            ProxyChoice::Socks5(addr) => {
                                socks5_connect_through_socks5(addr, host, port, &opts).await?
                            }
                        }
                    }
                } else {
                    match proxy {
                        ProxyChoice::Direct => direct_connect_hostport(host, port, &opts).await?,
                        ProxyChoice::Http(addr) => {
                            http_proxy_connect_through_proxy(addr, host, port, &opts).await?
                        }
                        ProxyChoice::Socks5(addr) => {
                            socks5_connect_through_socks5(addr, host, port, &opts).await?
                        }
                    }
                }
            } else {
                match proxy {
                    ProxyChoice::Direct => direct_connect_hostport(host, port, &opts).await?,
                    ProxyChoice::Http(addr) => {
                        http_proxy_connect_through_proxy(addr, host, port, &opts).await?
                    }
                    ProxyChoice::Socks5(addr) => {
                        socks5_connect_through_socks5(addr, host, port, &opts).await?
                    }
                }
            }
        }
        RDecision::Proxy(None) => match proxy {
            ProxyChoice::Direct => direct_connect_hostport(host, port, &opts).await?,
            ProxyChoice::Http(addr) => {
                http_proxy_connect_through_proxy(addr, host, port, &opts).await?
            }
            ProxyChoice::Socks5(addr) => {
                socks5_connect_through_socks5(addr, host, port, &opts).await?
            }
        },
        RDecision::Reject => return Err(anyhow!("trojan: rejected by rules")),
    };

    // Relay
    let _ = tokio::io::copy_bidirectional(tls, &mut upstream).await;
    Ok(())
}
