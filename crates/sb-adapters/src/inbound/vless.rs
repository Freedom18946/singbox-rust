//! VLESS inbound (TCP) server implementation
//!
//! Minimal VLESS server supporting:
//! - UUID-based authentication
//! - TCP connections (encryption="none")
//! - Target address parsing and routing
//! - Bidirectional relay
//!
//! Protocol flow:
//! 1. Client sends request: version (1) + UUID (16) + additional (1) + command (1) + address
//! 2. Server validates UUID
//! 3. Server sends response: version (1) + additional length (1) + [additional data]
//! 4. Bidirectional relay

use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[cfg(feature = "tls_reality")]
#[allow(unused_imports)]
use sb_tls::RealityAcceptor;

use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::registry;

#[derive(Clone, Debug)]
pub struct VlessInboundConfig {
    pub listen: SocketAddr,
    pub uuid: Uuid,
    pub router: Arc<router::RouterHandle>,
    /// Optional REALITY TLS configuration for inbound
    #[cfg(feature = "tls_reality")]
    pub reality: Option<sb_tls::RealityServerConfig>,
    /// Optional Multiplex configuration
    pub multiplex: Option<sb_transport::multiplex::MultiplexServerConfig>,
}

// VLESS protocol constants
const VLESS_VERSION: u8 = 0x01;
const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

pub async fn serve(cfg: VlessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, multiplex=?cfg.multiplex.is_some(), "vless: inbound bound");
    
    // Note: Multiplex support for VLESS inbound is configured but not yet fully implemented
    // VLESS can work with or without TLS, and multiplex integration would require
    // wrapping streams appropriately based on the configuration
    if cfg.multiplex.is_some() {
        warn!("Multiplex configuration present but not yet fully implemented for VLESS inbound");
    }

    // Create REALITY acceptor if configured
    #[cfg(feature = "tls_reality")]
    let reality_acceptor = if let Some(ref reality_cfg) = cfg.reality {
        Some(Arc::new(sb_tls::RealityAcceptor::new(reality_cfg.clone())
            .map_err(|e| anyhow!("Failed to create REALITY acceptor: {}", e))?))
    } else {
        None
    };

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => { debug!("vless: accept-loop heartbeat"); }
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "vless: accept error");
                        continue;
                    }
                };
                let cfg_clone = cfg.clone();
                
                #[cfg(feature = "tls_reality")]
                let reality_acceptor_clone = reality_acceptor.clone();
                
                tokio::spawn(async move {
                    #[cfg(feature = "tls_reality")]
                    {
                        if let Some(acceptor) = reality_acceptor_clone {
                            // Handle REALITY connection
                            match acceptor.accept(cli).await {
                                Ok(reality_conn) => {
                                    match reality_conn.handle().await {
                                        Ok(Some(mut tls_stream)) => {
                                            // Proxy connection - handle VLESS protocol over TLS
                                            if let Err(e) = handle_conn(&cfg_clone, &mut tls_stream, peer).await {
                                                warn!(%peer, error=%e, "vless: REALITY session error");
                                            }
                                        }
                                        Ok(None) => {
                                            // Fallback connection - already handled by REALITY
                                            debug!(%peer, "vless: REALITY fallback completed");
                                        }
                                        Err(e) => {
                                            warn!(%peer, error=%e, "vless: REALITY connection handling error");
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(%peer, error=%e, "vless: REALITY accept error");
                                }
                            }
                        } else {
                            // No REALITY - handle plain connection
                            let mut cli = cli;
                            if let Err(e) = handle_conn(&cfg_clone, &mut cli, peer).await {
                                warn!(%peer, error=%e, "vless: session error");
                                let _ = cli.shutdown().await;
                            }
                        }
                    }
                    
                    #[cfg(not(feature = "tls_reality"))]
                    {
                        let mut cli = cli;
                        if let Err(e) = handle_conn(&cfg_clone, &mut cli, peer).await {
                            warn!(%peer, error=%e, "vless: session error");
                            let _ = cli.shutdown().await;
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_conn(
    cfg: &VlessInboundConfig,
    cli: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    peer: SocketAddr,
) -> Result<()> {
    // Step 1: Read version (1 byte)
    let version = cli.read_u8().await?;
    if version != VLESS_VERSION {
        return Err(anyhow!("vless: invalid version: {}", version));
    }

    // Step 2: Read UUID (16 bytes)
    let mut uuid_bytes = [0u8; 16];
    cli.read_exact(&mut uuid_bytes).await?;
    let client_uuid = Uuid::from_bytes(uuid_bytes);

    // Validate UUID
    if client_uuid != cfg.uuid {
        return Err(anyhow!("vless: authentication failed"));
    }

    debug!(%peer, "vless: authentication successful");

    // Step 3: Read additional length (1 byte) and skip additional data
    let additional_len = cli.read_u8().await?;
    if additional_len > 0 {
        let mut additional = vec![0u8; additional_len as usize];
        cli.read_exact(&mut additional).await?;
    }

    // Step 4: Read command (1 byte)
    let command = cli.read_u8().await?;
    if command != CMD_TCP {
        return Err(anyhow!("vless: unsupported command: {}", command));
    }

    // Step 5: Parse target address
    let (target_host, target_port) = parse_vless_address(cli).await?;

    debug!(%peer, host=%target_host, port=%target_port, "vless: parsed target");

    // Step 6: Send response header
    // Version (1 byte) + Additional length (0 byte for minimal)
    cli.write_u8(VLESS_VERSION).await?;
    cli.write_u8(0x00).await?; // No additional data

    // Step 7: Router decision
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(target_host.as_str()),
            ip: None,
            transport_udp: false,
            port: Some(target_port),
            process_name: None,
            process_path: None,
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("vless: rejected by rules"));
        }
        decision = d;
    }

    // Step 8: Connect to upstream
    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(&target_host, target_port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("vless".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(_pool) = reg.pools.get(&name) {
                    if let Some(ep) = sel.select(&name, peer, &format!("{}:{}", target_host, target_port), &()) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                http_proxy_connect_through_proxy(&ep.addr.to_string(), &target_host, target_port, &opts).await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(&ep.addr.to_string(), &target_host, target_port, &opts).await?
                            }
                        }
                    } else {
                        fallback_connect(&proxy, &target_host, target_port, &opts).await?
                    }
                } else {
                    fallback_connect(&proxy, &target_host, target_port, &opts).await?
                }
            } else {
                fallback_connect(&proxy, &target_host, target_port, &opts).await?
            }
        }
        RDecision::Proxy(None) => {
            fallback_connect(&proxy, &target_host, target_port, &opts).await?
        }
        RDecision::Reject => unreachable!(),
    };

    // Step 9: Bidirectional relay (plain)
    let _ = tokio::io::copy_bidirectional(cli, &mut upstream).await;

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
        ProxyChoice::Http(addr) => Ok(http_proxy_connect_through_proxy(addr, host, port, opts).await?),
        ProxyChoice::Socks5(addr) => Ok(socks5_connect_through_socks5(addr, host, port, opts).await?),
    }
}

async fn parse_vless_address(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<(String, u16)> {
    let atyp = r.read_u8().await?;

    match atyp {
        ATYP_IPV4 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut ip_bytes = [0u8; 4];
            r.read_exact(&mut ip_bytes).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(ip_bytes));
            let port = r.read_u16().await?;
            Ok((ip.to_string(), port))
        }
        ATYP_DOMAIN => {
            // Domain: 1 byte length + domain + 2 bytes port
            let domain_len = r.read_u8().await?;
            let mut domain_bytes = vec![0u8; domain_len as usize];
            r.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8(domain_bytes)
                .map_err(|e| anyhow!("invalid domain: {}", e))?;
            let port = r.read_u16().await?;
            Ok((domain, port))
        }
        ATYP_IPV6 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut ip_bytes = [0u8; 16];
            r.read_exact(&mut ip_bytes).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(ip_bytes));
            let port = r.read_u16().await?;
            Ok((ip.to_string(), port))
        }
        _ => Err(anyhow!("vless: unknown address type: {}", atyp)),
    }
}
