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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};
use uuid::Uuid;

#[cfg(feature = "tls_reality")]
#[allow(unused_imports)]
use sb_tls::RealityAcceptor;

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

    // Note: Multiplex support for VLESS inbound is configured but not yet fully implemented
    // VLESS can work with or without TLS, and multiplex integration would require
    // wrapping streams appropriately based on the configuration
    // 注意：VLESS 入站的多路复用支持已配置，但尚未完全实现
    // VLESS 可以在有或无 TLS 的情况下工作，多路复用集成需要根据配置适当地包装流
    if cfg.multiplex.is_some() {
        warn!("Multiplex configuration present but not yet fully implemented for VLESS inbound");
    }

    // Create REALITY acceptor if configured
    // 如果配置了 REALITY 接收器，则创建它
    #[cfg(feature = "tls_reality")]
    let reality_acceptor = if let Some(ref reality_cfg) = cfg.reality {
        Some(Arc::new(
            sb_tls::RealityAcceptor::new(reality_cfg.clone())
                .map_err(|e| anyhow!("Failed to create REALITY acceptor: {}", e))?,
        ))
    } else {
        None
    };

    let mut hb = interval(Duration::from_secs(5));
    loop {
        select! {
            _ = stop_rx.recv() => break,
            _ = hb.tick() => { debug!("vless: accept-loop heartbeat"); }
            r = listener.accept() => {
                let (mut stream, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "vless: accept error");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("vless", &e);
                        continue;
                    }
                };

                // For non-TCP transports, we don't have peer address (it will be 0.0.0.0:0)
                // let peer = SocketAddr::from(([0, 0, 0, 0], 0)); // Removed, use peer from accept
                // 对于非 TCP 传输，我们没有对等地址 (它将是 0.0.0.0:0)
                // let peer = SocketAddr::from(([0, 0, 0, 0], 0)); // 已移除，使用 accept 中的 peer
                let cfg_clone = cfg.clone();

                #[cfg(feature = "tls_reality")]
                let reality_acceptor_clone = reality_acceptor.clone();

                tokio::spawn(async move {
                    #[cfg(feature = "tls_reality")]
                    {
                        if reality_acceptor_clone.is_some() {
                            // Handle REALITY connection
                            // Note: This needs refactoring to support generic streams
                            // 处理 REALITY 连接
                            // 注意：这需要重构以支持通用流
                            warn!("REALITY TLS over V2Ray transports not yet supported, using stream directly");
                            // TODO: Implement generic TLS wrapping for any AsyncRead+AsyncWrite stream
                            // TODO: 为任何 AsyncRead+AsyncWrite 流实现通用 TLS 包装
                            if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("vless", &e);
                                warn!(%peer, error=%e, "vless: REALITY session error (direct stream)");
                            }
                        } else {
                            // No REALITY - handle plain connection
                            // 无 REALITY - 处理普通连接
                            if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("vless", &e);
                                warn!(%peer, error=%e, "vless: session error");
                            }
                        }
                    }

                    #[cfg(not(feature = "tls_reality"))]
                    {
                        if let Err(e) = handle_conn_stream(&cfg_clone, &mut *stream, peer).await {
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("vless", &e);
                            warn!(%peer, error=%e, "vless: session error");
                        }
                    }
                });
            }
        }
    }
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
    let version = cli.read_u8().await?;
    if version != VLESS_VERSION {
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
            process_name: None,
            process_path: None,
            inbound_tag: None,
            outbound_tag: None,
            auth_user: None,
            query_type: None,
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
