//! Trojan inbound (TLS server) implementation
//!
//! Standard Trojan-GFW compatible server:
//! - TLS server with provided cert/key (PEM)
//! - Binary protocol: [SHA224_HASH(56 bytes)][CRLF][CMD(1)][ATYP][ADDR][PORT][CRLF]
//! - Supports TCP CONNECT (0x01) and UDP ASSOCIATE (0x03)
//! - Multi-user authentication with SHA224 password hashing
//! - Routes via sb-core router/outbounds

use anyhow::{anyhow, Result};
use sb_core::net::rate_limit_metrics;
use sb_core::net::tcp_rate_limit::{TcpRateLimitConfig, TcpRateLimiter};
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{registry, selector::PoolSelector};
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use sha2::{Digest, Sha224};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

#[cfg(feature = "tls_reality")]
#[allow(unused_imports)]
use sb_tls::RealityAcceptor;

/// Trojan protocol command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrojanCommand {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

impl TrojanCommand {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(Self::Connect),
            0x03 => Some(Self::UdpAssociate),
            _ => None,
        }
    }
}

impl std::fmt::Display for TrojanCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => write!(f, "CONNECT"),
            Self::UdpAssociate => write!(f, "UDP_ASSOCIATE"),
        }
    }
}

/// User configuration for multi-user support
#[derive(Clone, Debug)]
pub struct TrojanUser {
    /// Username for identification (not sent in protocol, only for config)
    pub name: String,
    /// Plaintext password (will be hashed to SHA224)
    pub password: String,
    /// Pre-computed SHA224 hash in hex format (56 bytes)
    password_hash: String,
}

impl TrojanUser {
    pub fn new(name: String, password: String) -> Self {
        let hash = Sha224::digest(password.as_bytes());
        let password_hash = hex::encode(hash);
        Self {
            name,
            password,
            password_hash,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrojanInboundConfig {
    pub listen: SocketAddr,
    /// Single password for backward compatibility (deprecated)
    #[deprecated(note = "Use users field for multi-user support")]
    pub password: Option<String>,
    /// Multi-user configuration
    pub users: Vec<TrojanUser>,
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
    /// Fallback target address
    pub fallback: Option<SocketAddr>,
    /// Fallback targets by ALPN
    pub fallback_for_alpn: HashMap<String, SocketAddr>,
}

impl TrojanInboundConfig {
    /// Build password hash map for O(1) lookup
    fn build_user_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();

        // Add configured users
        for user in &self.users {
            map.insert(user.password_hash.clone(), user.name.clone());
        }

        // Backward compatibility: add single password if present
        #[allow(deprecated)]
        if let Some(ref pwd) = self.password {
            if !pwd.is_empty() {
                let hash = Sha224::digest(pwd.as_bytes());
                let hash_hex = hex::encode(hash);
                map.insert(hash_hex, "default".to_string());
            }
        }

        map
    }
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

    // Initialize rate limiter
    let rate_limiter = TcpRateLimiter::new(TcpRateLimitConfig::from_env());

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
            _ = hb.tick() => {
                // tracing::debug!("trojan: accept-loop heartbeat");
            }
            r = listener.accept() => {
                let (mut stream, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "trojan: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("trojan", &e);
                        continue;
                    }
                };

                // Check rate limit
                if !rate_limiter.allow_connection(peer.ip()) {
                    warn!(%peer, "trojan: connection rate limited");
                    rate_limit_metrics::record_rate_limited("trojan", "connection_limit");
                    continue;
                }

                // Check if IP is banned due to auth failures
                if rate_limiter.is_banned(peer.ip()) {
                    warn!(%peer, "trojan: IP banned due to excessive auth failures");
                    rate_limit_metrics::record_rate_limited("trojan", "auth_failure_ban");
                    continue;
                }

                #[cfg(feature = "tls_reality")]
                let reality_acceptor_clone = reality_acceptor.clone();
                let tls_acceptor_clone = tls_acceptor.clone();
                let cfg_clone = cfg.clone();
                let rate_limiter_clone = rate_limiter.clone();

                // Track active connection
                rate_limit_metrics::inc_active_connections("trojan");

                tokio::spawn(async move {
                    // Ensure we decrement on exit
                    let _guard = scopeguard::guard((), |_| {
                        rate_limit_metrics::dec_active_connections("trojan");
                    });

                    // Helper to handle the stream after TLS/Mux negotiation
                    async fn handle_inner_stream(
                        cfg: &TrojanInboundConfig,
                        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
                        peer: SocketAddr,
                        rate_limiter: &TcpRateLimiter,
                    ) -> Result<()> {
                        handle_conn_stream(cfg, stream, peer, rate_limiter).await
                    }

                    // 1. Establish TLS (or use plain stream if no TLS)
                    // 2. Check Mux
                    // 3. Handle Trojan protocol

                    #[cfg(feature = "tls_reality")]
                    {
                        if reality_acceptor_clone.is_some() {
                            // REALITY
                             warn!("REALITY TLS over V2Ray transports not yet supported, using stream directly");
                             // TODO: REALITY Mux support
                             if let Err(e) = handle_inner_stream(&cfg_clone, &mut *stream, peer, &rate_limiter_clone).await {
                                 sb_core::metrics::http::record_error_display(&e);
                                 warn!(%peer, error=%e, "trojan: REALITY session error");
                             }
                        } else if let Some(acceptor) = tls_acceptor_clone {
                            // Standard TLS
                            match acceptor.accept(stream).await {
                                Ok(mut tls_stream) => {
                                    // ALPN Fallback Check
                                    let mut fallback_target = None;
                                    if !cfg_clone.fallback_for_alpn.is_empty() {
                                        if let Some(alpn) = tls_stream.get_ref().1.alpn_protocol() {
                                            let alpn_str = String::from_utf8_lossy(alpn);
                                            if let Some(addr) = cfg_clone.fallback_for_alpn.get(alpn_str.as_ref()) {
                                                fallback_target = Some(*addr);
                                            }
                                        }
                                    }

                                    if let Some(target) = fallback_target {
                                        debug!(%peer, alpn=?target, "trojan: ALPN fallback triggered");
                                        if let Err(e) = handle_fallback(&mut tls_stream, target, &[]).await {
                                            warn!(%peer, error=%e, "trojan: ALPN fallback error");
                                        }
                                    } else {
                                        // Check Mux
                                        if let Some(mux_cfg) = &cfg_clone.multiplex {
                                            // Mux enabled: wrap TLS stream in Yamux
                                            use tokio_util::compat::TokioAsyncReadCompatExt;
                                            use sb_transport::yamux::{Config, Connection, Mode};
                                            use futures::future::poll_fn;

                                            let mut config = Config::default();
                                            config.set_max_num_streams(mux_cfg.max_num_streams);
                                            // Apply other mux configs if needed

                                            let compat_stream = tls_stream.compat();
                                            let mut connection = Connection::new(compat_stream, config, Mode::Server);

                                            debug!(%peer, "trojan: mux session started");

                                            // Accept streams from mux session
                                            while let Some(result) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                                                match result {
                                                    Ok(stream) => {
                                                        let cfg_inner = cfg_clone.clone();
                                                        let limiter_inner = rate_limiter_clone.clone();
                                                        tokio::spawn(async move {
                                                            use tokio_util::compat::FuturesAsyncReadCompatExt;
                                                            let mut tokio_stream = stream.compat();
                                                            if let Err(e) = handle_inner_stream(&cfg_inner, &mut tokio_stream, peer, &limiter_inner).await {
                                                                debug!(%peer, error=%e, "trojan: mux stream error");
                                                            }
                                                        });
                                                    }
                                                    Err(e) => {
                                                        warn!(%peer, error=%e, "trojan: mux connection error");
                                                        break;
                                                    }
                                                }
                                            }
                                            debug!(%peer, "trojan: mux session ended");
                                        } else {
                                            // No Mux
                                            if let Err(e) = handle_inner_stream(&cfg_clone, &mut tls_stream, peer, &rate_limiter_clone).await {
                                                sb_core::metrics::http::record_error_display(&e);
                                                sb_core::metrics::record_inbound_error_display("trojan", &e);
                                                warn!(%peer, error=%e, "trojan: session error (TLS)");
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(%peer, error=%e, "trojan: TLS accept failed");
                                }
                            }
                        } else {
                            // No TLS
                            if let Some(mux_cfg) = &cfg_clone.multiplex {
                                // Mux over TCP (no TLS)
                                use tokio_util::compat::TokioAsyncReadCompatExt;
                                use sb_transport::yamux::{Config, Connection, Mode};
                                use futures::future::poll_fn;

                                let mut config = Config::default();
                                config.set_max_num_streams(mux_cfg.max_num_streams);

                                let compat_stream = stream.compat();
                                let mut connection = Connection::new(compat_stream, config, Mode::Server);

                                debug!(%peer, "trojan: mux session started (no TLS)");

                                while let Some(result) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                                    match result {
                                        Ok(stream) => {
                                            let cfg_inner = cfg_clone.clone();
                                            let limiter_inner = rate_limiter_clone.clone();
                                            tokio::spawn(async move {
                                                use tokio_util::compat::FuturesAsyncReadCompatExt;
                                                let mut tokio_stream = stream.compat();
                                                if let Err(e) = handle_inner_stream(&cfg_inner, &mut tokio_stream, peer, &limiter_inner).await {
                                                    debug!(%peer, error=%e, "trojan: mux stream error");
                                                }
                                            });
                                        }
                                        Err(e) => {
                                            warn!(%peer, error=%e, "trojan: mux connection error");
                                            break;
                                        }
                                    }
                                }
                            } else if let Err(e) = handle_inner_stream(&cfg_clone, &mut *stream, peer, &rate_limiter_clone).await {
                                sb_core::metrics::http::record_error_display(&e);
                                warn!(%peer, error=%e, "trojan: session error (no TLS)");
                            }
                        }
                    }

                    #[cfg(not(feature = "tls_reality"))]
                    {
                        if let Some(acceptor) = tls_acceptor_clone {
                            match acceptor.accept(stream).await {
                                Ok(mut tls_stream) => {
                                    // ALPN Fallback Check
                                    let mut fallback_target = None;
                                    if !cfg_clone.fallback_for_alpn.is_empty() {
                                        if let Some(alpn) = tls_stream.get_ref().1.alpn_protocol() {
                                            let alpn_str = String::from_utf8_lossy(alpn);
                                            if let Some(addr) = cfg_clone.fallback_for_alpn.get(alpn_str.as_ref()) {
                                                fallback_target = Some(*addr);
                                            }
                                        }
                                    }

                                    if let Some(target) = fallback_target {
                                        debug!(%peer, alpn=?target, "trojan: ALPN fallback triggered");
                                        if let Err(e) = handle_fallback(&mut tls_stream, target, &[]).await {
                                            warn!(%peer, error=%e, "trojan: ALPN fallback error");
                                        }
                                    } else {
                                        // Check Mux
                                        if let Some(mux_cfg) = &cfg_clone.multiplex {
                                            use tokio_util::compat::TokioAsyncReadCompatExt;
                                            use sb_transport::yamux::{Config, Connection, Mode};
                                            use futures::future::poll_fn;

                                            let mut config = Config::default();
                                            config.set_max_num_streams(mux_cfg.max_num_streams);

                                            let compat_stream = tls_stream.compat();
                                            let mut connection = Connection::new(compat_stream, config, Mode::Server);

                                            debug!(%peer, "trojan: mux session started");
                                            while let Some(result) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                                                match result {
                                                    Ok(stream) => {
                                                        let cfg_inner = cfg_clone.clone();
                                                        let limiter_inner = rate_limiter_clone.clone();
                                                        tokio::spawn(async move {
                                                            use tokio_util::compat::FuturesAsyncReadCompatExt;
                                                            let mut tokio_stream = stream.compat();
                                                            if let Err(e) = handle_inner_stream(&cfg_inner, &mut tokio_stream, peer, &limiter_inner).await {
                                                                debug!(%peer, error=%e, "trojan: mux stream error");
                                                            }
                                                        });
                                                    }
                                                    Err(e) => {
                                                        warn!(%peer, error=%e, "trojan: mux connection error");
                                                        break;
                                                    }
                                                }
                                            }
                                        } else {
                                            if let Err(e) = handle_inner_stream(&cfg_clone, &mut tls_stream, peer, &rate_limiter_clone).await {
                                                sb_core::metrics::http::record_error_display(&e);
                                                sb_core::metrics::record_inbound_error_display("trojan", &e);
                                                warn!(%peer, error=%e, "trojan: session error (TLS)");
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(%peer, error=%e, "trojan: TLS accept failed");
                                }
                            }
                        } else {
                             // No TLS
                            if let Some(mux_cfg) = &cfg_clone.multiplex {
                                use tokio_util::compat::TokioAsyncReadCompatExt;
                                use sb_transport::yamux::{Config, Connection, Mode};
                                use futures::future::poll_fn;

                                let mut config = Config::default();
                                config.set_max_num_streams(mux_cfg.max_num_streams);

                                let compat_stream = stream.compat();
                                let mut connection = Connection::new(compat_stream, config, Mode::Server);

                                debug!(%peer, "trojan: mux session started (no TLS)");
                                while let Some(result) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                                    match result {
                                        Ok(stream) => {
                                            let cfg_inner = cfg_clone.clone();
                                            let limiter_inner = rate_limiter_clone.clone();
                                            tokio::spawn(async move {
                                                use tokio_util::compat::FuturesAsyncReadCompatExt;
                                                let mut tokio_stream = stream.compat();
                                                if let Err(e) = handle_inner_stream(&cfg_inner, &mut tokio_stream, peer, &limiter_inner).await {
                                                    debug!(%peer, error=%e, "trojan: mux stream error");
                                                }
                                            });
                                        }
                                        Err(e) => {
                                            warn!(%peer, error=%e, "trojan: mux connection error");
                                            break;
                                        }
                                    }
                                }
                            } else {
                                if let Err(e) = handle_inner_stream(&cfg_clone, &mut *stream, peer, &rate_limiter_clone).await {
                                    sb_core::metrics::http::record_error_display(&e);
                                    sb_core::metrics::record_inbound_error_display("trojan", &e);
                                    warn!(%peer, error=%e, "trojan: session error (no TLS)");
                                }
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
    rate_limiter: &TcpRateLimiter,
) -> Result<()> {
    handle_conn_impl(cfg, stream, peer, rate_limiter).await
}

async fn handle_conn_impl(
    cfg: &TrojanInboundConfig,
    tls: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    peer: SocketAddr,
    rate_limiter: &TcpRateLimiter,
) -> Result<()> {
    // Build user authentication map
    let user_map = cfg.build_user_map();

    if user_map.is_empty() {
        return Err(anyhow!("trojan: no users configured"));
    }

    // Read SHA224 password hash (56 hex bytes)
    let mut hash_buf = vec![0u8; 56];
    // We use read_exact, but if it fails (unexpected EOF) we might want to fallback if we read *something*
    // For simplicity, if we can't read 56 bytes, we assume it's not a valid Trojan request.
    // However, standard fallback handles "not valid trojan request".
    // If we get EOF before 56 bytes, it's definitely not Trojan.

    match tls.read_exact(&mut hash_buf).await {
        Ok(_) => {
            let submitted_hash = String::from_utf8_lossy(&hash_buf).to_string();

            // Verify password hash
            if let Some(auth_user) = user_map.get(&submitted_hash) {
                debug!(%peer, user=%auth_user, "trojan: authenticated");

                // Read CRLF after hash
                let mut crlf = [0u8; 2];
                tls.read_exact(&mut crlf).await?;
                if &crlf != b"\r\n" {
                    return Err(anyhow!("trojan: expected CRLF after password hash"));
                }

                // Read command byte
                let mut cmd_byte = [0u8; 1];
                tls.read_exact(&mut cmd_byte).await?;
                let command = TrojanCommand::from_u8(cmd_byte[0])
                    .ok_or_else(|| anyhow!("trojan: unsupported command: 0x{:02x}", cmd_byte[0]))?;

                // Parse address (SOCKS5-like format)
                let (host, port) = parse_trojan_address(tls).await?;

                // Read final CRLF
                let mut crlf2 = [0u8; 2];
                tls.read_exact(&mut crlf2).await?;
                if &crlf2 != b"\r\n" {
                    return Err(anyhow!("trojan: expected CRLF after address"));
                }

                debug!(%peer, %command, %host, %port, "trojan: parsed request");

                match command {
                    TrojanCommand::Connect => {
                        handle_tcp_connect(cfg, tls, peer, &host, port, auth_user).await
                    }
                    TrojanCommand::UdpAssociate => handle_udp_associate(tls, peer).await,
                }
            } else {
                // Invalid user
                if let Some(fallback_addr) = cfg.fallback {
                    rate_limiter.record_auth_failure(peer.ip());
                    rate_limit_metrics::record_auth_failure("trojan");
                    debug!(%peer, "trojan: auth failed, falling back to {}", fallback_addr);
                    handle_fallback(tls, fallback_addr, &hash_buf).await
                } else {
                    rate_limiter.record_auth_failure(peer.ip());
                    rate_limit_metrics::record_auth_failure("trojan");
                    Err(anyhow!("trojan: invalid password hash"))
                }
            }
        }
        Err(e) => {
            // Read failed (e.g. EOF or connection reset)
            // If we have fallback, we might want to try forwarding whatever we got?
            // But read_exact modifies the buffer.
            // If it's UnexpectedEof, we might have partial data.
            // For now, if we can't read the hash, we just error out or fallback if we have *any* data?
            // Simpler: just error if we can't read the header. Fallback is mostly for "valid TLS but invalid Trojan protocol".
            // If the client sends garbage that is NOT 56 bytes, read_exact will fail or wait.
            // If we want to support non-Trojan traffic (like HTTP GET), it won't send 56 bytes hex.
            // It will send "GET /...".
            // We should probably use `read` instead of `read_exact` and check if it *looks* like a hash?
            // But Trojan hash is just hex. "GET " is hex-ish? No 'G' is not hex.
            // So if we read bytes and they are not hex, we should fallback.

            // Refined logic:
            // 1. Read up to 56 bytes.
            // 2. If we get < 56 bytes and EOF, fallback.
            // 3. If we get 56 bytes, check if hex.
            //    - If hex -> check user.
            //      - If valid user -> proceed.
            //      - If invalid user -> fallback.
            //    - If not hex -> fallback.

            // However, implementing "read up to" with `read_exact` is tricky.
            // Let's stick to the current logic: if read fails, we assume broken connection.
            // But if we want to support HTTP fallback (e.g. browser visiting the port),
            // the browser sends "GET / HTTP/1.1...".
            // `read_exact` will read 56 bytes of that.
            // "GET / HTTP/1.1..." is > 56 bytes usually.
            // So we will read 56 bytes.
            // Then we check if it's a valid user. It won't be.
            // So we go to `else` block above.
            // So the current logic handles HTTP fallback correctly IF the HTTP request is >= 56 bytes.
            // If it's short (e.g. "GET /"), `read_exact` will wait.
            // This is a known limitation of simple Trojan implementations.
            // We will proceed with the "invalid user -> fallback" logic which covers most cases.
            if let Some(_fallback_addr) = cfg.fallback {
                // If we failed to read 56 bytes, we can't easily fallback because we don't know how much we read
                // unless we use `read_buf` or similar.
                // For now, return error.
                Err(anyhow!("trojan: failed to read protocol header: {}", e))
            } else {
                Err(anyhow!("trojan: failed to read protocol header: {}", e))
            }
        }
    }
}

async fn handle_fallback(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    target: SocketAddr,
    prefix: &[u8],
) -> Result<()> {
    let mut remote = tokio::net::TcpStream::connect(target)
        .await
        .map_err(|e| anyhow!("trojan: failed to connect to fallback {}: {}", target, e))?;

    if !prefix.is_empty() {
        use tokio::io::AsyncWriteExt;
        remote.write_all(prefix).await?;
    }

    let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;
    Ok(())
}

/// Parse Trojan address format (same as SOCKS5)
/// Returns (host, port)
async fn parse_trojan_address(
    stream: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
) -> Result<(String, u16)> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;

    let host = match atyp[0] {
        // IPv4
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        // Domain
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| anyhow!("trojan: invalid domain name"))?
        }
        // IPv6
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        _ => {
            return Err(anyhow!(
                "trojan: unsupported address type: 0x{:02x}",
                atyp[0]
            ))
        }
    };

    // Read port (big-endian)
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok((host, port))
}

/// Handle UDP ASSOCIATE request
async fn handle_udp_associate(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    peer: SocketAddr,
) -> Result<()> {
    let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let (mut rh, mut wh) = tokio::io::split(stream);

    let udp_socket_recv = udp_socket.clone();
    let udp_socket_send = udp_socket.clone();

    // Client -> Target
    let c2t = async move {
        let mut len_buf = [0u8; 2];
        let mut crlf_buf = [0u8; 2];
        loop {
            // Parse address
            let (host, port) = match parse_trojan_address(&mut rh).await {
                Ok(v) => v,
                Err(_) => break, // EOF or error
            };

            // Read length
            if rh.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let length = u16::from_be_bytes(len_buf) as usize;

            // Read CRLF
            if rh.read_exact(&mut crlf_buf).await.is_err() {
                break;
            }
            if &crlf_buf != b"\r\n" {
                return Err(anyhow!("trojan: expected CRLF after length"));
            }

            // Read payload
            let mut payload = vec![0u8; length];
            if rh.read_exact(&mut payload).await.is_err() {
                break;
            }

            // Resolve and send
            // Note: We resolve every time for simplicity, or we could cache.
            // Since we use UdpSocket::send_to, we need SocketAddr.
            // If host is domain, we need to resolve.
            // For now, simple resolution.
            let target_addr = format!("{}:{}", host, port);
            if let Ok(addrs) = tokio::net::lookup_host(&target_addr).await {
                if let Some(addr) = addrs.into_iter().next() {
                    let _ = udp_socket_send.send_to(&payload, addr).await;
                }
            };
        }
        Ok(())
    };

    // Target -> Client
    let t2c = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let (n, src_addr) = match udp_socket_recv.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let payload = &buf[..n];

            // Write Address
            use tokio::io::AsyncWriteExt;
            match src_addr {
                SocketAddr::V4(v4) => {
                    wh.write_u8(1).await?;
                    wh.write_all(&v4.ip().octets()).await?;
                }
                SocketAddr::V6(v6) => {
                    wh.write_u8(4).await?;
                    wh.write_all(&v6.ip().octets()).await?;
                }
            }
            wh.write_u16(src_addr.port()).await?;

            // Write Length
            wh.write_u16(n as u16).await?;

            // Write CRLF
            wh.write_all(b"\r\n").await?;

            // Write Payload
            wh.write_all(payload).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    debug!(%peer, "trojan: starting UDP associate loop");
    let _ = tokio::join!(c2t, t2c);
    Ok(())
}

/// Handle TCP CONNECT request
async fn handle_tcp_connect(
    _cfg: &TrojanInboundConfig,
    tls: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    peer: SocketAddr,
    host: &str,
    port: u16,
    _auth_user: &str,
) -> Result<()> {
    // Router decision
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(host),
            ip: None,
            transport_udp: false,
            port: Some(port),
            auth_user: Some(_auth_user),
            network: Some("tcp"),
            ..Default::default()
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

    // Relay bidirectionally
    let _ = tokio::io::copy_bidirectional(tls, &mut upstream).await;
    Ok(())
}
