//! VLESS inbound (TCP) server implementation
//! VLESS 入站 (TCP) 服务端实现
//!
//! Minimal VLESS server supporting:
//! 最小化 VLESS 服务端，支持：
//! - UUID-based authentication
//! - 基于 UUID 的认证
//! - TCP connections (encryption="none")
//! - TCP 连接 (加密="none")
//! - Target address parsing and routing
//! - 目标地址解析和路由
//! - Bidirectional relay
//! - 双向转发
//!
//! Protocol flow:
//! 协议流程：
//! 1. Client sends request: version (1) + UUID (16) + additional (1) + command (1) + address
//! 1. 客户端发送请求：版本 (1) + UUID (16) + 附加信息 (1) + 命令 (1) + 地址
//! 2. Server validates UUID
//! 2. 服务端验证 UUID
//! 3. Server sends response: version (1) + additional length (1) + [additional data]
//! 3. 服务端发送响应：版本 (1) + 附加信息长度 (1) + [附加数据]
//! 4. Bidirectional relay
//! 4. 双向转发

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[cfg(feature = "tls_reality")]
use sb_tls::reality::server::RealityConnection;
#[cfg(feature = "tls_reality")]
#[allow(unused_imports)]
use sb_tls::RealityAcceptor;
use crate::transport_config::InboundStream;

type StreamBox = Box<dyn InboundStream>;

use sb_core::outbound::registry;
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};

#[derive(Clone, Debug)]
pub struct VlessInboundConfig {
    pub listen: SocketAddr,
    pub uuid: Uuid,
    pub router: Arc<router::RouterHandle>,
    /// Optional REALITY TLS configuration for inbound
    /// 可选的 REALITY TLS 入站配置
    #[cfg(feature = "tls_reality")]
    pub reality: Option<sb_tls::RealityServerConfig>,
    /// Optional Multiplex configuration
    /// 可选的多路复用配置
    pub multiplex: Option<sb_transport::multiplex::MultiplexServerConfig>,
    /// V2Ray transport layer configuration (WebSocket, gRPC, HTTPUpgrade)
    /// If None, defaults to TCP
    /// V2Ray 传输层配置 (WebSocket, gRPC, HTTPUpgrade)
    /// 如果为 None，默认为 TCP
    pub transport_layer: Option<crate::transport_config::TransportConfig>,
    /// Fallback target address
    pub fallback: Option<SocketAddr>,
    /// Fallback targets by ALPN
    pub fallback_for_alpn: HashMap<String, SocketAddr>,
    /// Flow control (e.g. "xtls-rprx-vision")
    pub flow: Option<String>,
}

// VLESS protocol constants
// VLESS 协议常量
const VLESS_VERSION: u8 = 0x01;
const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

pub async fn serve(cfg: VlessInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    // Create listener based on transport configuration (defaults to TCP if not specified)
    // 根据传输配置创建监听器 (如果未指定则默认为 TCP)
    let transport = cfg.transport_layer.clone().unwrap_or_default();
    let listener = transport.create_inbound_listener(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);

    info!(
        addr=?cfg.listen,
        actual=?actual,
        transport=?transport.transport_type(),
        multiplex=?cfg.multiplex.is_some(),
        "vless: inbound bound"
    );

    // Initialize reality_acceptor if configured (outside loop for efficiency)
    #[cfg(feature = "tls_reality")]
    let reality_acceptor = if let Some(ref reality_cfg) = cfg.reality {
        match RealityAcceptor::new(reality_cfg.clone()) {
            Ok(acc) => Some(Arc::new(acc)),
            Err(e) => {
                return Err(anyhow!("vless: failed to create REALITY acceptor: {}", e));
            }
        }
    } else {
        None
    };

    // Warn about missing Vision support if configured
    if let Some(flow) = &cfg.flow {
        if flow.eq_ignore_ascii_case("xtls-rprx-vision") {
            #[cfg(feature = "tls_reality")]
            {
                if cfg.reality.is_none() {
                    warn!(
                        "VLESS: Flow control '{}' requires REALITY/TLS but it is not configured. Connection serves as standard TCP.",
                        flow
                    );
                }
            }
            #[cfg(not(feature = "tls_reality"))]
            {
                warn!(
                    "VLESS: Flow control '{}' requires REALITY feature which is disabled. Connection serves as standard TCP.",
                    flow
                );
            }
        }
    }

    // Load standard TLS config if not using REALITY
    // 加载标准 TLS 配置 (如果不使用 REALITY)
    let tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>> = {
        #[cfg(feature = "tls_reality")]
        {
            if cfg.reality.is_none() {
                // We assume there is a standard TLS way?
                // VLESS config doesn't have cert_path/key_path fields visible in the snippet I saw?
                // Wait, VlessInboundConfig definition L55... L77 does NOT have cert_path/key_path!
                // Trojan has them. Vless usually relies on `TransportConfig` for Ws/Grpc TLS?
                // Or maybe Vless TCP TLS is handled differently?
                // Check L1 to 543 again. VlessInboundConfig has `reality`, `multiplex`, `transport_layer`.
                // It does NOT have `cert_path` / `key_path`!
                // So VLESS Inbound only supports TLS via REALITY or via TransportLayer (WS/GRPC + TLS)?
                // OR external transport?
                // But `trojan.rs` has `cert_path`.
                // Let's re-read VLESS logic I am replacing.
                // L220: `if let Some(acceptor) = reality_acceptor_clone { ... } else { Plain TCP }`.
                // It does NOT seem to support standard TLS (Rustls) directly for TCP?
                // Unless `transport_layer` creates a TLS listener?
                // If `transport_layer` creates a TLS listener, then `listener.accept()` yields TlsStreams?
                // If so, my abstraction `prepare_tls_layer` handling `tls: Option<&TlsAcceptor>` logic:
                // If I pass `None` for generic TLS (since I can't build one), it just returns simple stream.
                // So if listener is already TLS, `stream` is `TlsStream` (wrapped in generic).
                // My abstraction works: it adds REALITY if configured, else pass through.
                None
            } else {
                None
            }
        }
        #[cfg(not(feature = "tls_reality"))]
        {
            None
        }
    };

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
             _ = stop_rx.recv() => break,
             _ = hb.tick() => {
                 // debug!("vless: accept-loop heartbeat");
             }
             r = listener.accept() => {
                 let (stream, peer) = match r {
                     Ok(v) => v,
                     Err(e) => {
                         warn!(error=%e, "vless: accept error");
                         sb_core::metrics::http::record_error_display(&e);
                         sb_core::metrics::record_inbound_error_display("vless", &e);
                         continue;
                     }
                 };

                 #[cfg(feature = "tls_reality")]
                 let reality_acceptor_clone = reality_acceptor.clone();
                 let tls_acceptor_clone = tls_acceptor.clone();
                 let cfg_clone = cfg.clone();

                 tokio::spawn(async move {
                     // Prepare TLS Layer (REALITY or None)
                     let stream_res = {
                         #[cfg(feature = "tls_reality")]
                         { prepare_tls_layer(stream, reality_acceptor_clone.as_deref(), tls_acceptor_clone.as_deref(), &cfg_clone.fallback_for_alpn, peer).await }
                         #[cfg(not(feature = "tls_reality"))]
                         { prepare_tls_layer(stream, tls_acceptor_clone.as_deref(), &cfg_clone.fallback_for_alpn, peer).await }
                     };

                     match stream_res {
                         Ok(Some(stream)) => {
                             // Check Mux
                             if let Some(mux_cfg) = &cfg_clone.multiplex {
                                 use tokio_util::compat::TokioAsyncReadCompatExt;
                                 use sb_transport::yamux::{Config, Connection, Mode};
                                 use futures::future::poll_fn;

                                 let mut config = Config::default();
                                 config.set_max_num_streams(mux_cfg.max_num_streams);
                                 
                                 let compat_stream = stream.compat();
                                 let mut connection = Connection::new(compat_stream, config, Mode::Server);

                                 debug!(%peer, "vless: mux session started");
                                 
                                 while let Some(result) = poll_fn(|cx| connection.poll_next_inbound(cx)).await {
                                     match result {
                                         Ok(stream) => {
                                             let cfg_inner = cfg_clone.clone();
                                             tokio::spawn(async move {
                                                 use tokio_util::compat::FuturesAsyncReadCompatExt;
                                                 let mut tokio_stream = stream.compat();
                                                 if let Err(e) = handle_conn_stream(&cfg_inner, &mut tokio_stream, peer).await {
                                                     debug!(%peer, error=%e, "vless: mux stream error");
                                                 }
                                             });
                                         }
                                         Err(e) => {
                                             warn!(%peer, error=%e, "vless: mux connection error");
                                             break;
                                         }
                                     }
                                 }
                                 debug!(%peer, "vless: mux session ended");
                             } else {
                                 // No Mux
                                 let mut stream = stream;
                                 if let Err(e) = handle_conn_stream(&cfg_clone, &mut stream, peer).await {
                                     sb_core::metrics::http::record_error_display(&e);
                                     sb_core::metrics::record_inbound_error_display("vless", &e);
                                     warn!(%peer, error=%e, "vless: session error");
                                 }
                             }
                         }
                         Ok(None) => {}, // Handled
                         Err(e) => {
                             warn!(%peer, error=%e, "vless: TLS/REALITY error");
                         }
                     }
                 });
             }
        }
    }
    Ok(())
}

async fn prepare_tls_layer(
    stream: StreamBox,
    #[cfg(feature = "tls_reality")]
    reality: Option<&RealityAcceptor>,
    tls: Option<&tokio_rustls::TlsAcceptor>,
    fallback_for_alpn: &HashMap<String, SocketAddr>,
    peer: SocketAddr,
) -> Result<Option<StreamBox>> {
    #[cfg(feature = "tls_reality")]
    if let Some(acceptor) = reality {
        match acceptor.accept(stream).await {
            Ok(conn) => match conn {
                RealityConnection::Proxy(s) => return Ok(Some(Box::new(s))),
                RealityConnection::Fallback { client, target } => {
                     debug!(%peer, "vless: REALITY fallback triggered");
                     // For VLESS, fallback logic is typically bidirectional relay
                     // In old code: RealityConnection::Fallback { client, target }.handle()
                     // We need to reconstruct or call method if possible.
                     // The `conn` *is* the enum.
                     // We can't reuse `conn` after matching it unless ref.
                     // Reconstruct:
                     let conn = RealityConnection::Fallback { client, target };
                     if let Err(e) = conn.handle().await {
                         warn!(%peer, error=%e, "vless: REALITY fallback error");
                     }
                     return Ok(None);
                }
            },
            Err(e) => return Err(anyhow!("REALITY handshake failed: {}", e)),
        }
    }
    
    if let Some(acceptor) = tls {
        let mut tls_stream = acceptor.accept(stream).await.map_err(|e| anyhow!("TLS handshake failed: {}", e))?;
        
        // ALPN Fallback Check
        let mut fallback_target = None;
        if !fallback_for_alpn.is_empty() {
             if let Some(alpn) = tls_stream.get_ref().1.alpn_protocol() {
                let alpn_str = String::from_utf8_lossy(alpn);
                if let Some(addr) = fallback_for_alpn.get(alpn_str.as_ref()) {
                    fallback_target = Some(*addr);
                }
            }
        }

        if let Some(target) = fallback_target {
            debug!(%peer, alpn=?target, "vless: ALPN fallback triggered");
            if let Err(e) = handle_fallback(&mut tls_stream, target, &[]).await {
                 warn!(%peer, error=%e, "vless: ALPN fallback error");
            }
            return Ok(None);
        }

        return Ok(Some(Box::new(tls_stream)));
    } else {
        // No TLS
        return Ok(Some(Box::new(stream)));
    }
}

async fn handle_fallback(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    target: SocketAddr,
    prefix: &[u8],
) -> Result<()> {
    let mut remote = tokio::net::TcpStream::connect(target)
        .await
        .map_err(|e| anyhow!("vless: failed to connect to fallback {}: {}", target, e))?;

    if !prefix.is_empty() {
        remote.write_all(prefix).await?;
    }

    let _ = tokio::io::copy_bidirectional(stream, &mut remote).await;
    Ok(())
}

// Helper function to handle connections from generic streams (for V2Ray transport support)
// 处理来自通用流 (用于 V2Ray 传输支持) 连接的辅助函数
async fn handle_conn_stream(
    cfg: &VlessInboundConfig,
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    peer: SocketAddr,
) -> Result<()> {
    handle_conn_impl(cfg, stream, peer).await
}

async fn handle_conn_impl(
    cfg: &VlessInboundConfig,
    cli: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized),
    peer: SocketAddr,
) -> Result<()> {
    // Step 1: Read version (1 byte)
    // 步骤 1: 读取版本 (1 字节)
    let version = match cli.read_u8().await {
        Ok(v) => v,
        Err(e) => {
            // Read failed, if we have fallback, try it?
            // But we have no data. Just error.
            return Err(anyhow!("vless: failed to read version: {}", e));
        }
    };

    if version != VLESS_VERSION {
        if let Some(fallback_addr) = cfg.fallback {
            debug!(%peer, version=%version, "vless: invalid version, falling back to {}", fallback_addr);
            // We read 1 byte. We need to send it to fallback.
            return handle_fallback(cli, fallback_addr, &[version]).await;
        }
        return Err(anyhow!("vless: invalid version: {}", version));
    }

    // Step 2: Read UUID (16 bytes)
    // 步骤 2: 读取 UUID (16 字节)
    let mut uuid_bytes = [0u8; 16];
    cli.read_exact(&mut uuid_bytes).await?;
    let client_uuid = Uuid::from_bytes(uuid_bytes);

    // Validate UUID
    // 验证 UUID
    if client_uuid != cfg.uuid {
        if let Some(fallback_addr) = cfg.fallback {
            debug!(%peer, "vless: auth failed, falling back to {}", fallback_addr);
            // We read 1+16 = 17 bytes.
            let mut prefix = Vec::with_capacity(17);
            prefix.push(version);
            prefix.extend_from_slice(&uuid_bytes);
            return handle_fallback(cli, fallback_addr, &prefix).await;
        }
        return Err(anyhow!("vless: authentication failed"));
    }

    debug!(%peer, "vless: authentication successful");

    // Step 3: Read additional length (1 byte) and skip additional data
    // 步骤 3: 读取附加长度 (1 字节) 并跳过附加数据
    let additional_len = cli.read_u8().await?;
    if additional_len > 0 {
        let mut additional = vec![0u8; additional_len as usize];
        cli.read_exact(&mut additional).await?;
    }

    // Step 4: Read command (1 byte)
    // 步骤 4: 读取命令 (1 字节)
    let command = cli.read_u8().await?;
    if command != CMD_TCP {
        return Err(anyhow!("vless: unsupported command: {}", command));
    }

    // Step 5: Parse target address
    // 步骤 5: 解析目标地址
    let (target_host, target_port) = parse_vless_address(cli).await?;

    debug!(%peer, host=%target_host, port=%target_port, "vless: parsed target");

    // Step 6: Send response header
    // Version (1 byte) + Additional length (0 byte for minimal)
    // 步骤 6: 发送响应头
    // 版本 (1 字节) + 附加长度 (0 字节表示最小化)
    cli.write_u8(VLESS_VERSION).await?;
    cli.write_u8(0x00).await?; // No additional data

    // Step 7: Router decision
    // 步骤 7: 路由决策
    let mut decision = RDecision::Direct;
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(target_host.as_str()),
            ip: None,
            transport_udp: false,
            port: Some(target_port),
            network: Some("tcp"),
            ..Default::default()
        };
        let d = eng.decide(&ctx);
        if matches!(d, RDecision::Reject) {
            return Err(anyhow!("vless: rejected by rules"));
        }
        decision = d;
    }

    // Step 8: Connect to upstream
    // 步骤 8: 连接上游
    let proxy = default_proxy();
    let opts = ConnectOpts::default();
    let mut upstream = match decision {
        RDecision::Direct => direct_connect_hostport(&target_host, target_port, &opts).await?,
        RDecision::Proxy(Some(name)) => {
            let sel = PoolSelector::new("vless".into(), "default".into());
            if let Some(reg) = registry::global() {
                if let Some(_pool) = reg.pools.get(&name) {
                    if let Some(ep) = sel.select(
                        &name,
                        peer,
                        &format!("{}:{}", target_host, target_port),
                        &(),
                    ) {
                        match ep.kind {
                            sb_core::outbound::endpoint::ProxyKind::Http => {
                                http_proxy_connect_through_proxy(
                                    &ep.addr.to_string(),
                                    &target_host,
                                    target_port,
                                    &opts,
                                )
                                .await?
                            }
                            sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                socks5_connect_through_socks5(
                                    &ep.addr.to_string(),
                                    &target_host,
                                    target_port,
                                    &opts,
                                )
                                .await?
                            }
                        }
                    } else {
                        fallback_connect(proxy, &target_host, target_port, &opts).await?
                    }
                } else {
                    fallback_connect(proxy, &target_host, target_port, &opts).await?
                }
            } else {
                fallback_connect(proxy, &target_host, target_port, &opts).await?
            }
        }
        RDecision::Proxy(None) => fallback_connect(proxy, &target_host, target_port, &opts).await?,
        RDecision::Reject => return Err(anyhow!("vless: rejected by rules")),
    };

    // Step 9: Bidirectional relay (plain)
    // 步骤 9: 双向转发 (普通)
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
        ProxyChoice::Http(addr) => {
            Ok(http_proxy_connect_through_proxy(addr, host, port, opts).await?)
        }
        ProxyChoice::Socks5(addr) => {
            Ok(socks5_connect_through_socks5(addr, host, port, opts).await?)
        }
    }
}

async fn parse_vless_address(
    r: &mut (impl tokio::io::AsyncRead + Unpin + ?Sized),
) -> Result<(String, u16)> {
    let atyp = r.read_u8().await?;

    match atyp {
        ATYP_IPV4 => {
            // IPv4: 4 bytes + 2 bytes port
            // IPv4: 4 字节 + 2 字节端口
            let mut ip_bytes = [0u8; 4];
            r.read_exact(&mut ip_bytes).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(ip_bytes));
            let port = r.read_u16().await?;
            Ok((ip.to_string(), port))
        }
        ATYP_DOMAIN => {
            // Domain: 1 byte length + domain + 2 bytes port
            // 域名: 1 字节长度 + 域名 + 2 字节端口
            let domain_len = r.read_u8().await?;
            let mut domain_bytes = vec![0u8; domain_len as usize];
            r.read_exact(&mut domain_bytes).await?;
            let domain =
                String::from_utf8(domain_bytes).map_err(|e| anyhow!("invalid domain: {}", e))?;
            let port = r.read_u16().await?;
            Ok((domain, port))
        }
        ATYP_IPV6 => {
            // IPv6: 16 bytes + 2 bytes port
            // IPv6: 16 字节 + 2 字节端口
            let mut ip_bytes = [0u8; 16];
            r.read_exact(&mut ip_bytes).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(ip_bytes));
            let port = r.read_u16().await?;
            Ok((ip.to_string(), port))
        }
        _ => Err(anyhow!("vless: unknown address type: {}", atyp)),
    }
}

use parking_lot::Mutex;
use sb_core::adapter::InboundService;

#[derive(Debug)]
pub struct VlessInboundAdapter {
    config: VlessInboundConfig,
    stop_tx: Mutex<Option<mpsc::Sender<()>>>,
}

impl VlessInboundAdapter {
    pub fn new(config: VlessInboundConfig) -> Self {
        Self {
            config,
            stop_tx: Mutex::new(None),
        }
    }
}

impl InboundService for VlessInboundAdapter {
    fn serve(&self) -> std::io::Result<()> {
        let (tx, rx) = mpsc::channel(1);
        *self.stop_tx.lock() = Some(tx);

        let rt = tokio::runtime::Handle::current();
        rt.block_on(async { serve(self.config.clone(), rx).await })
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn request_shutdown(&self) {
        if let Some(tx) = self.stop_tx.lock().take() {
            let _ = tx.try_send(());
        }
    }
}
