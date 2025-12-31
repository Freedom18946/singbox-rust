// crates/sb-adapters/src/inbound/socks/mod.rs
//! SOCKS5 Inbound (TCP CONNECT + Optional UDP ASSOCIATE Announcement)
//! SOCKS5 入站（TCP CONNECT + 可选 UDP ASSOCIATE 宣告）
//! - Same routing/outbound abstraction as HTTP inbound: RouterHandle + OutboundRegistryHandle + Endpoint
//! - 与 HTTP 入站相同的路由/出站抽象：RouterHandle + OutboundRegistryHandle + Endpoint
//! - P1.5: Unified IO metering via sb_core::net::metered
//! - P1.5：IO 计量统一走 sb_core::net::metered

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    select,
    sync::{mpsc, oneshot},
};

use tracing::{debug, info, warn};

use once_cell::sync::OnceCell;
use sb_core::adapter::InboundService;
use sb_core::outbound::health as ob_health;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{health::MultiHealthView, registry, selector::PoolSelector};
use sb_core::outbound::{Endpoint, OutboundRegistryHandle};
use sb_core::outbound::{Endpoint as OutEndpoint, RouteTarget as OutRouteTarget};
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx as RulesRouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};
use sb_core::router::{RouteCtx, RouterHandle, Transport};
use sb_transport::IoStream;

static SELECTOR: OnceCell<PoolSelector> = OnceCell::new();
// 本文件只用到了 inbound_parse，其他两个会在具体错误路径里再接入
use sb_config::ir::Credentials;
use sb_core::telemetry::inbound_parse;

#[cfg(feature = "metrics")]
use metrics;

pub mod tcp;
pub mod udp;

/// SOCKS5 inbound configuration
/// SOCKS5 入站配置
#[derive(Clone, Debug)]
pub struct SocksInboundConfig {
    /// Listen address
    /// 监听地址
    pub listen: SocketAddr,
    /// 给 UDP ASSOCIATE 用于宣告的地址；仅在 Some 时回复非 0 地址。
    pub udp_bind: Option<SocketAddr>,
    /// Router handle
    /// 路由器句柄
    pub router: Arc<RouterHandle>,
    /// Outbound registry handle
    /// 出站注册表句柄
    pub outbounds: Arc<OutboundRegistryHandle>,
    /// Reserved for future: used when we natively start the udp module here
    /// 保留给未来：当我们在这里内置启动 udp 模块时使用
    #[allow(dead_code)]
    pub udp_nat_ttl: Duration,
    /// User credentials for authentication
    pub users: Option<Vec<Credentials>>,
    /// UDP Timeout
    pub udp_timeout: Option<Duration>,
    /// Domain resolution strategy
    pub domain_strategy: Option<DomainStrategy>,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum DomainStrategy {
    AsIs,
    UseIp,
    UseIpv4,
    UseIpv6,
}


/// Serve SOCKS5 proxy with ready signal notification
/// 运行 SOCKS5 代理服务，并提供就绪信号通知
pub async fn serve_socks(
    cfg: SocksInboundConfig,
    stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    serve_socks_internal(cfg, stop_rx, ready_tx, None).await
}

async fn serve_socks_internal(
    cfg: SocksInboundConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<()>>,
    udp_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "SOCKS5 bound");
    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }

    // 可通过环境变量在测试时禁止 stop 打断（与 HTTP 入站一致）
    // Can disable stop interruption during testing via environment variable (consistent with HTTP inbound)
    let disable_stop = std::env::var("SB_SOCKS_DISABLE_STOP").as_deref() == Ok("1");

    loop {
        select! {
            _ = stop_rx.recv(), if !disable_stop => break,
            r = listener.accept() => {
                let (mut cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "accept failed");
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("socks", &e);
                        continue;
                    }
                };
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_conn(&mut cli, peer, &cfg_clone, udp_addr).await {
                        // 客户端在方法协商后立刻断开（脚本探活的典型场景），降级为 debug
                        // Client closed immediately after method negotiation (typical scenario for script probing), downgrade to debug
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            tracing::debug!(
                                peer=%peer,
                                "socks: client closed after method (expected in probe)"
                            );
                            return;
                        }
                        // 其他错误继续告警
                        // Continue to warn for other errors
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("socks", &e);
                        warn!(peer=%peer, error=%e, "socks session error");
                    }
                });
            }
        }
    }
    Ok(())
}

// Compatible with old alias
// 兼容旧别名
/// Compatibility alias - run SOCKS5 proxy
/// 兼容性别名 - 运行 SOCKS5 代理
pub async fn run(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {
    // Enable UDP Associate if configured or enabled via env
    let udp_enabled = std::env::var("SB_SOCKS_UDP_ENABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let udp_addr = if udp_enabled {
        // Bind UDP socket
        let bind_addr = cfg.udp_bind.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
        let local_addr = sock.local_addr()?;
        let sock = std::sync::Arc::new(sock);

        // Spawn UDP handler
        let timeout = cfg.udp_timeout;
        tokio::spawn(async move {
            if let Err(e) = udp::serve_udp_datagrams(sock, timeout).await {
                tracing::warn!("socks/udp serve error: {:?}", e);
            }
        });

        info!(addr=?local_addr, "SOCKS5 UDP Associate enabled");
        Some(local_addr)
    } else {
        None
    };

    serve_socks_internal(cfg, stop_rx, None, udp_addr).await
}

/// Compatibility alias - serve SOCKS5 proxy
/// 兼容性别名 - 运行 SOCKS5 代理
pub async fn serve(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {
    serve_socks(cfg, stop_rx, None).await
}

pub async fn serve_conn<S>(
    cli: &mut S,
    peer: SocketAddr,
    cfg: &SocksInboundConfig,
    udp_addr: Option<SocketAddr>,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    #[cfg(feature = "metrics")]
    metrics::counter!("inbound_connections_total",
        "protocol" => "socks", "network" => "tcp")
    .increment(1);

    // --- greeting ---
    let ver = read_u8(cli).await?;
    match ver {
        0x04 => {
            // SOCKS4
            handle_socks4(cli, peer, cfg).await
        }
        0x05 => {
            // SOCKS5
            handle_socks5(cli, peer, cfg, udp_addr).await
        }
        _ => {
            inbound_parse("socks", "error", "bad_version");
            Err(io::Error::new(io::ErrorKind::InvalidData, "bad ver"))
        }
    }
}

async fn handle_socks4<S>(cli: &mut S, peer: SocketAddr, cfg: &SocksInboundConfig) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let cmd = read_u8(cli).await?;
    if cmd != 0x01 {
        // Only CONNECT is supported
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socks4: bad cmd",
        ));
    }
    let port = read_u16(cli).await?;
    let mut ip_bytes = [0u8; 4];
    cli.read_exact(&mut ip_bytes).await?;

    // Read UserID (null-terminated)
    let mut user_id = Vec::new();
    loop {
        let b = read_u8(cli).await?;
        if b == 0 {
            break;
        }
        user_id.push(b);
    }

    let ip = Ipv4Addr::from(ip_bytes);
    let (endpoint, _host_str) =
        if ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0 {
            // SOCKS4a: Read domain
            let mut domain = Vec::new();
            loop {
                let b = read_u8(cli).await?;
                if b == 0 {
                    break;
                }
                domain.push(b);
            }
            let host = String::from_utf8_lossy(&domain).to_string();
            (Endpoint::Domain(host.clone(), port), host)
        } else {
            (
                Endpoint::Ip(SocketAddr::new(IpAddr::V4(ip), port)),
                ip.to_string(),
            )
        };

    // Go parity: SOCKS4 does not support authentication.
    // If users are configured (authentication required), reject SOCKS4 connections.
    if let Some(users) = &cfg.users {
        if !users.is_empty() {
            // Reply 91 (Request rejected or failed) - No auth mechanism available
            let mut resp = [0u8; 8];
            resp[0] = 0x00;
            resp[1] = 0x5B; // 91 = Request rejected
            cli.write_all(&resp).await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socks4: authentication required but not supported",
            ));
        }
    }

    inbound_parse("socks", "ok", "socks4_request");

    // Reply 90 (Request granted)
    // Format: VN(0) | CD(90) | DSTPORT | DSTIP
    let mut resp = [0u8; 8];
    resp[0] = 0x00;
    resp[1] = 0x5A; // 90
                    // Port/IP ignored by client usually, but we send 0
    cli.write_all(&resp).await?;

    process_request(cli, peer, cfg, endpoint).await
}

async fn handle_socks5<S>(
    cli: &mut S,
    peer: SocketAddr,
    cfg: &SocksInboundConfig,
    udp_addr: Option<SocketAddr>,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let n_methods = read_u8(cli).await? as usize;
    let mut methods = vec![0u8; n_methods];
    cli.read_exact(&mut methods).await?;

    let mut method = 0xFF; // No acceptable methods

    if let Some(users) = &cfg.users {
        if !users.is_empty() {
            if methods.contains(&0x02) {
                method = 0x02; // Username/Password
            }
        } else if methods.contains(&0x00) {
            method = 0x00; // No Auth
        }
    } else if methods.contains(&0x00) {
        method = 0x00; // No Auth
    }

    cli.write_all(&[0x05, method]).await?;

    if method == 0xFF {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable auth method",
        ));
    }

    if method == 0x02 {
        // Handle Auth
        let ver = read_u8(cli).await?;
        if ver != 0x01 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad auth ver"));
        }
        let ulen = read_u8(cli).await? as usize;
        let mut uname_bytes = vec![0u8; ulen];
        cli.read_exact(&mut uname_bytes).await?;
        let plen = read_u8(cli).await? as usize;
        let mut pass_bytes = vec![0u8; plen];
        cli.read_exact(&mut pass_bytes).await?;

        let uname = String::from_utf8_lossy(&uname_bytes);
        let pass = String::from_utf8_lossy(&pass_bytes);

        let mut authenticated = false;
        if let Some(users) = &cfg.users {
            for user in users {
                let u = user
                    .username
                    .as_deref()
                    .or(user.username_env.as_deref())
                    .unwrap_or("");
                let p = user
                    .password
                    .as_deref()
                    .or(user.password_env.as_deref())
                    .unwrap_or("");
                if u == uname && p == pass {
                    authenticated = true;
                    break;
                }
            }
        }

        if authenticated {
            cli.write_all(&[0x01, 0x00]).await?; // Success
        } else {
            cli.write_all(&[0x01, 0x01]).await?; // Failure
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "auth failed",
            ));
        }
    }

    // --- request header ---
    let mut head = [0u8; 4];
    cli.read_exact(&mut head).await?;
    // VER, CMD, RSV, ATYP
    if head[0] != 0x05 {
        inbound_parse("socks", "error", "bad_version");
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad req ver"));
    }
    let cmd = head[1];
    let atyp = head[3];

    // 解析目标
    // Parse target
    let (endpoint, _host_for_route, _port) = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            cli.read_exact(&mut b).await?;
            let port = read_u16(cli).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(b));
            (
                Endpoint::Ip(SocketAddr::new(ip, port)),
                ip.to_string(),
                port,
            )
        }
        0x04 => {
            let mut b = [0u8; 16];
            cli.read_exact(&mut b).await?;
            let port = read_u16(cli).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(b));
            (
                Endpoint::Ip(SocketAddr::new(ip, port)),
                ip.to_string(),
                port,
            )
        }
        0x03 => {
            let len = read_u8(cli).await? as usize;
            let mut d = vec![0u8; len];
            cli.read_exact(&mut d).await?;
            let host = String::from_utf8_lossy(&d).to_string();
            let port = read_u16(cli).await?;
            (Endpoint::Domain(host.clone(), port), host, port)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad atyp")),
    };

    match cmd {
        0x01 => {
            // CONNECT
            // 握手阶段（greeting/auth/req）完成
            // Handshake phase (greeting/auth/req) completed
            inbound_parse("socks", "ok", "greeting+request");
            process_request(cli, peer, cfg, endpoint).await
        }
        0x03 => {
            // UDP ASSOCIATE
            // If we have a bound UDP address (from serve_socks_internal), use it.
            // Otherwise fall back to cfg.udp_bind or 0.0.0.0
            let bind_addr = udp_addr.or(cfg.udp_bind);
            reply(cli, 0x00, bind_addr).await?;
            #[cfg(feature = "metrics")]
            metrics::counter!("inbound_connections_total",
                "protocol" => "socks", "network" => "udp")
            .increment(1);
            Ok(())
        }
        0x02 => {
            // BIND（不支持）
            // BIND (not supported)
            inbound_parse("socks", "error", "bad_method");
            reply(cli, 0x07, None).await?; // Command not supported
            Ok(())
        }
        _ => {
            inbound_parse("socks", "error", "bad_method");
            reply(cli, 0x07, None).await?;
            Ok(())
        }
    }
}

async fn process_request<S>(
    cli: &mut S,
    peer: SocketAddr,
    cfg: &SocksInboundConfig,
    endpoint: Endpoint,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    use sb_core::dns::Resolver;

    // Apply domain strategy
    let mut endpoint = endpoint;
    if let Some(strategy) = cfg.domain_strategy {
        if let Endpoint::Domain(ref host, port) = endpoint {
            if matches!(strategy, DomainStrategy::UseIp | DomainStrategy::UseIpv4 | DomainStrategy::UseIpv6) {
                if let Some(resolver) = sb_core::dns::global::get() {
                    match resolver.resolve(host).await {
                        Ok(ans) => {
                            let ip = match strategy {
                                DomainStrategy::UseIpv4 => ans.ips.iter().find(|i| i.is_ipv4()),
                                DomainStrategy::UseIpv6 => ans.ips.iter().find(|i| i.is_ipv6()),
                                DomainStrategy::UseIp => ans.ips.first(),
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                tracing::debug!(host=%host, ip=%ip, "socks domain strategy rewrote target");
                                endpoint = Endpoint::Ip(SocketAddr::new(*ip, port));
                            }
                        }
                        Err(e) => {
                            // On resolution failure, continue with domain (or fail? Go usually continues or fails depending on sniff)
                            // Here we just log and continue
                            tracing::debug!(host=%host, error=%e, "socks domain strategy resolution failed");
                        }
                    }
                }
            }
        }
    }

    let mut decision = RDecision::Direct;
    let proxy = default_proxy();

    // 运行态规则引擎（先判决）
    // Runtime rule engine (decide first)
    if let Some(eng) = rules_global::global() {
        let (dom, ip, port) = match &endpoint {
            Endpoint::Domain(h, p) => (Some(h.as_str()), None, Some(*p)),
            Endpoint::Ip(sa) => (None, Some(sa.ip()), Some(sa.port())),
        };
        let ctx = RulesRouteCtx {
            domain: dom,
            ip,
            transport_udp: false,
            port,
            network: Some("tcp"),
            ..Default::default()
        };
        let d = eng.decide(&ctx);
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("router_decide_total", "decision"=> match &d { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" }).increment(1);
        }
        if matches!(d, RDecision::Reject) {
            // SOCKS5: REP=0x02 (connection not allowed by ruleset)
            reply(cli, 0x02, None).await?;
            return Ok(());
        }
        decision = d;
    }

    #[cfg(feature="metrics")]
    metrics::counter!("router_route_total",
        "inbound"=>"socks5",
        "decision"=>match &decision { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" },
        "proxy_kind"=>proxy.label()
    ).increment(1);

    // Health check fallback logic
    let fallback_enabled = std::env::var("SB_PROXY_HEALTH_FALLBACK_DIRECT")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if fallback_enabled && matches!(decision, RDecision::Proxy(_)) {
        if let Some(st) = ob_health::global_status() {
            if !st.is_up() {
                tracing::warn!("router: proxy unhealthy; fallback to direct (socks5 inbound)");
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "router_route_fallback_total",
                    "from" => "proxy",
                    "to" => "direct",
                    "inbound" => "socks5"
                )
                .increment(1);
                // Override routing result to Direct
                decision = RDecision::Direct;
            }
        }
    }

    let opts = ConnectOpts::default();

    // Fast path: if router decided a named outbound, try OutboundRegistry first
    if let RDecision::Proxy(Some(name)) = &decision {
        let out_ep = match &endpoint {
            Endpoint::Domain(h, p) => OutEndpoint::Domain(h.clone(), *p),
            Endpoint::Ip(sa) => OutEndpoint::Ip(*sa),
        };
        if let Ok(mut s) = cfg
            .outbounds
            .connect_io(&OutRouteTarget::Named(name.clone()), out_ep)
            .await
        {
            // Success: reply and start piping
            reply(cli, 0x00, None).await?;

            fn dur_from_env(key: &str) -> Option<std::time::Duration> {
                std::env::var(key)
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .and_then(|ms| {
                        if ms > 0 {
                            Some(std::time::Duration::from_millis(ms))
                        } else {
                            None
                        }
                    })
            }
            let rt = dur_from_env("SB_TCP_READ_TIMEOUT_MS");
            let wt = dur_from_env("SB_TCP_WRITE_TIMEOUT_MS");
            let (_up, _down) = sb_core::net::metered::copy_bidirectional_streaming_ctl(
                cli,
                &mut s,
                "socks",
                std::time::Duration::from_secs(1),
                rt,
                wt,
                None,
            )
            .await?;
            return Ok(());
        }
    }

    // 与上游建立连接（根据决策与默认代理）
    // Establish connection with upstream (based on decision and default proxy)
    let mut srv: IoStream = match decision {
        RDecision::Direct => match &endpoint {
            Endpoint::Domain(host, port) => {
                let s = direct_connect_hostport(host, *port, &opts).await?;
                Box::new(s)
            }
            Endpoint::Ip(sa) => {
                let s = direct_connect_hostport(&sa.ip().to_string(), sa.port(), &opts).await?;
                Box::new(s)
            }
        },
        RDecision::Proxy(pool_name) => {
            if let Some(name) = pool_name {
                // Named proxy pool selection
                let sel = SELECTOR.get_or_init(|| {
                    let ttl = std::env::var("SB_PROXY_STICKY_TTL_MS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(10_000);
                    let cap = std::env::var("SB_PROXY_STICKY_CAP")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(4096);
                    PoolSelector::new_with_capacity(cap, std::time::Duration::from_millis(ttl))
                });
                let _health = MultiHealthView;
                let target_str = match &endpoint {
                    Endpoint::Domain(host, port) => format!("{}:{}", host, port),
                    Endpoint::Ip(sa) => sa.to_string(),
                };

                if let Some(reg) = registry::global() {
                    if let Some(_pool) = reg.pools.get(&name) {
                        if let Some(ep) = sel.select(&name, peer, &target_str, &()) {
                            match ep.kind {
                                sb_core::outbound::endpoint::ProxyKind::Http => match &endpoint {
                                    Endpoint::Domain(host, port) => Box::new(
                                        http_proxy_connect_through_proxy(
                                            &ep.addr.to_string(),
                                            host,
                                            *port,
                                            &opts,
                                        )
                                        .await?,
                                    ),
                                    Endpoint::Ip(sa) => Box::new(
                                        http_proxy_connect_through_proxy(
                                            &ep.addr.to_string(),
                                            &sa.ip().to_string(),
                                            sa.port(),
                                            &opts,
                                        )
                                        .await?,
                                    ),
                                },
                                sb_core::outbound::endpoint::ProxyKind::Socks5 => match &endpoint {
                                    Endpoint::Domain(host, port) => Box::new(
                                        socks5_connect_through_socks5(
                                            &ep.addr.to_string(),
                                            host,
                                            *port,
                                            &opts,
                                        )
                                        .await?,
                                    ),
                                    Endpoint::Ip(sa) => Box::new(
                                        socks5_connect_through_socks5(
                                            &ep.addr.to_string(),
                                            &sa.ip().to_string(),
                                            sa.port(),
                                            &opts,
                                        )
                                        .await?,
                                    ),
                                },
                            }
                        } else {
                            // Pool empty or all endpoints down - fallback to direct or default proxy
                            match fallback_enabled {
                                true => {
                                    #[cfg(feature = "metrics")]
                                    metrics::counter!("router_route_fallback_total", "from" => "proxy", "to" => "direct", "reason" => "pool_empty").increment(1);
                                    match &endpoint {
                                        Endpoint::Domain(host, port) => Box::new(
                                            direct_connect_hostport(host, *port, &opts).await?,
                                        ),
                                        Endpoint::Ip(sa) => Box::new(
                                            direct_connect_hostport(
                                                &sa.ip().to_string(),
                                                sa.port(),
                                                &opts,
                                            )
                                            .await?,
                                        ),
                                    }
                                }
                                false => {
                                    reply(cli, 0x01, None).await?; // General failure
                                    return Ok(());
                                }
                            }
                        }
                    } else {
                        // Pool not found - fallback to default proxy
                        match proxy {
                            ProxyChoice::Direct => match &endpoint {
                                Endpoint::Domain(host, port) => {
                                    Box::new(direct_connect_hostport(host, *port, &opts).await?)
                                }
                                Endpoint::Ip(sa) => Box::new(
                                    direct_connect_hostport(&sa.ip().to_string(), sa.port(), &opts)
                                        .await?,
                                ),
                            },
                            ProxyChoice::Http(addr) => match &endpoint {
                                Endpoint::Domain(host, port) => Box::new(
                                    http_proxy_connect_through_proxy(addr, host, *port, &opts)
                                        .await?,
                                ),
                                Endpoint::Ip(sa) => Box::new(
                                    http_proxy_connect_through_proxy(
                                        addr,
                                        &sa.ip().to_string(),
                                        sa.port(),
                                        &opts,
                                    )
                                    .await?,
                                ),
                            },
                            ProxyChoice::Socks5(addr) => match &endpoint {
                                Endpoint::Domain(host, port) => Box::new(
                                    socks5_connect_through_socks5(addr, host, *port, &opts).await?,
                                ),
                                Endpoint::Ip(sa) => Box::new(
                                    socks5_connect_through_socks5(
                                        addr,
                                        &sa.ip().to_string(),
                                        sa.port(),
                                        &opts,
                                    )
                                    .await?,
                                ),
                            },
                        }
                    }
                } else {
                    // No registry - fallback to default proxy
                    match proxy {
                        ProxyChoice::Direct => match &endpoint {
                            Endpoint::Domain(host, port) => {
                                let s = direct_connect_hostport(host, *port, &opts).await?;
                                Box::new(s)
                            }
                            Endpoint::Ip(sa) => {
                                let s =
                                    direct_connect_hostport(&sa.ip().to_string(), sa.port(), &opts)
                                        .await?;
                                Box::new(s)
                            }
                        },
                        ProxyChoice::Http(addr) => match &endpoint {
                            Endpoint::Domain(host, port) => {
                                let s = http_proxy_connect_through_proxy(addr, host, *port, &opts)
                                    .await?;
                                Box::new(s)
                            }
                            Endpoint::Ip(sa) => {
                                let s = http_proxy_connect_through_proxy(
                                    addr,
                                    &sa.ip().to_string(),
                                    sa.port(),
                                    &opts,
                                )
                                .await?;
                                Box::new(s)
                            }
                        },
                        ProxyChoice::Socks5(addr) => match &endpoint {
                            Endpoint::Domain(host, port) => {
                                let s =
                                    socks5_connect_through_socks5(addr, host, *port, &opts).await?;
                                Box::new(s)
                            }
                            Endpoint::Ip(sa) => {
                                let s = socks5_connect_through_socks5(
                                    addr,
                                    &sa.ip().to_string(),
                                    sa.port(),
                                    &opts,
                                )
                                .await?;
                                Box::new(s)
                            }
                        },
                    }
                }
            } else {
                // Default proxy (no named pool)
                match proxy {
                    ProxyChoice::Direct => match &endpoint {
                        Endpoint::Domain(host, port) => {
                            let s = direct_connect_hostport(host, *port, &opts).await?;
                            Box::new(s)
                        }
                        Endpoint::Ip(sa) => {
                            let s = direct_connect_hostport(&sa.ip().to_string(), sa.port(), &opts)
                                .await?;
                            Box::new(s)
                        }
                    },
                    ProxyChoice::Http(addr) => match &endpoint {
                        Endpoint::Domain(host, port) => {
                            let s =
                                http_proxy_connect_through_proxy(addr, host, *port, &opts).await?;
                            Box::new(s)
                        }
                        Endpoint::Ip(sa) => {
                            let s = http_proxy_connect_through_proxy(
                                addr,
                                &sa.ip().to_string(),
                                sa.port(),
                                &opts,
                            )
                            .await?;
                            Box::new(s)
                        }
                    },
                    ProxyChoice::Socks5(addr) => match &endpoint {
                        Endpoint::Domain(host, port) => {
                            let s = socks5_connect_through_socks5(addr, host, *port, &opts).await?;
                            Box::new(s)
                        }
                        Endpoint::Ip(sa) => {
                            let s = socks5_connect_through_socks5(
                                addr,
                                &sa.ip().to_string(),
                                sa.port(),
                                &opts,
                            )
                            .await?;
                            Box::new(s)
                        }
                    },
                }
            }
        }
        RDecision::Reject | RDecision::RejectDrop => {
            // Should have been filtered earlier; return explicit error to avoid panic.
            return Err(io::Error::other("socks: rejected by rules"));
        }
        RDecision::Hijack { .. } | RDecision::Sniff | RDecision::Resolve => {
            // Not handled by SOCKS inbound directly; fall back to direct
            match &endpoint {
                Endpoint::Domain(host, port) => {
                    let s = direct_connect_hostport(host, *port, &opts).await?;
                    Box::new(s)
                }
                Endpoint::Ip(sa) => {
                    let s = direct_connect_hostport(&sa.ip().to_string(), sa.port(), &opts).await?;
                    Box::new(s)
                }
            }
        }
    };

    // 成功：回复 0x00，BND=0.0.0.0:0
    // Success: reply 0x00, BND=0.0.0.0:0
    reply(cli, 0x00, None).await?;
    debug!(peer=%peer, "socks connect established");

    // 双向转发 + 计量 + 读/写超时（可选，来自环境）
    // Bidirectional forwarding + metering + read/write timeout (optional, from env)
    fn dur_from_env(key: &str) -> Option<std::time::Duration> {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .and_then(|ms| {
                if ms > 0 {
                    Some(std::time::Duration::from_millis(ms))
                } else {
                    None
                }
            })
    }

    let rt = dur_from_env("SB_TCP_READ_TIMEOUT_MS");
    let wt = dur_from_env("SB_TCP_WRITE_TIMEOUT_MS");
    let (_up, _down) = sb_core::net::metered::copy_bidirectional_streaming_ctl(
        cli,
        &mut srv,
        "socks",
        std::time::Duration::from_secs(1),
        rt,
        wt,
        None,
    )
    .await?;
    Ok(())
}

// 握手开始处（收到 VERS/NMETHODS 等）
// 如果版本不是 0x05，在返回之前补：
// inbound_parse("socks","error","bad_version");
// 如果认证方法不支持，返回前补：
// inbound_parse("socks","error","bad_method");
// 如果命令不是 CONNECT（或 UDP ASSOCIATE 在此处仅宣告不实现），在返回前补：
// inbound_parse("socks","error","bad_cmd");

// 在各个错误返回点（如版本不匹配、方法不支持、ATYP 不支持等），附带：
// inbound_parse("socks","error","bad_version"|"bad_method"|"bad_cmd"|"bad_atyp");
// 若上游连接/握手失败，在 Err 分支前：
// inbound_forward("socks","error",Some(err_kind(&e)));
// timeout： inbound_forward("socks","timeout",Some("timeout"));
// At each error return point (e.g., version mismatch, unsupported method, unsupported ATYP, etc.), attach:
// inbound_parse("socks","error","bad_version"|"bad_method"|"bad_cmd"|"bad_atyp");
// If upstream connection/handshake fails, before the Err branch:
// inbound_forward("socks","error",Some(err_kind(&e)));
// timeout: inbound_forward("socks","timeout",Some("timeout"));

async fn reply<S>(cli: &mut S, rep: u8, bnd: Option<SocketAddr>) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin + Send,
{
    // 统一回复格式：VER=5, REP=rep, RSV=0, ATYP + ADDR + PORT
    // Unified reply format: VER=5, REP=rep, RSV=0, ATYP + ADDR + PORT
    let mut buf = Vec::with_capacity(4 + 18 + 2);
    buf.push(0x05);
    buf.push(rep);
    buf.push(0x00);
    match bnd {
        Some(sa) => match sa.ip() {
            IpAddr::V4(v4) => {
                buf.push(0x01);
                buf.extend_from_slice(&v4.octets());
                buf.push((sa.port() >> 8) as u8);
                buf.push((sa.port() & 0xff) as u8);
            }
            IpAddr::V6(v6) => {
                buf.push(0x04);
                buf.extend_from_slice(&v6.octets());
                buf.push((sa.port() >> 8) as u8);
                buf.push((sa.port() & 0xff) as u8);
            }
        },
        None => {
            // 0.0.0.0:0
            buf.push(0x01);
            buf.extend_from_slice(&[0, 0, 0, 0]);
            buf.extend_from_slice(&[0, 0]);
        }
    }
    cli.write_all(&buf).await
}

async fn read_u8<S>(s: &mut S) -> io::Result<u8>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    Ok(b[0])
}
async fn read_u16<S>(s: &mut S) -> io::Result<u16>
where
    S: tokio::io::AsyncRead + Unpin + Send,
{
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await?;
    Ok(u16::from_be_bytes(b))
}

// 构造 RouteCtx 的小助手（避免借用/解引用细节）
// Helper for constructing RouteCtx (avoid borrowing/dereferencing details)
#[allow(dead_code)] // Reserved for context building
fn route_ctx_from_endpoint(ep: &Endpoint) -> RouteCtx<'_> {
    match ep {
        Endpoint::Domain(h, p) => RouteCtx {
            host: Some(h.as_str()),
            ip: None,
            port: Some(*p),
            transport: Transport::Tcp,
            network: "tcp",
            ..Default::default()
        },
        Endpoint::Ip(sa) => RouteCtx {
            host: None,
            ip: Some(sa.ip()),
            port: Some(sa.port()),
            transport: Transport::Tcp,
            network: "tcp",
            ..Default::default()
        },
    }
}

// 供 UDP 子模块复用（入站内部工具）
// Reused by UDP submodule (inbound internal utility)
fn _target_to_string_lossy(ep: &Endpoint) -> String {
    match ep {
        Endpoint::Ip(sa) => sa.to_string(),
        Endpoint::Domain(h, p) => format!("{}:{}", h, p),
    }
}

pub struct SocksInbound {
    // Placeholder fields for the structure
}

impl SocksInbound {
    pub async fn run(&self) -> anyhow::Result<()> {
        // ... 既有 TCP 接受/处理逻辑 ...
        // ... Existing TCP accept/handle logic ...

        // NOTE(linus): UDP Associate 接入（默认关闭）。仅当显式设置 SB_SOCKS_UDP_ENABLE=1 时启用。
        // 行为守恒：不开关 → 不绑定端口，不起后台任务。
        // NOTE(linus): UDP Associate integration (disabled by default). Enabled only when SB_SOCKS_UDP_ENABLE=1 is explicitly set.
        // Behavior conservation: No switch -> No port binding, no background task.
        if std::env::var("SB_SOCKS_UDP_ENABLE").is_ok() {
            // 绑定：支持 SB_SOCKS_UDP_BIND="0.0.0.0:0,[::]:0" 多地址
            // Bind: Support SB_SOCKS_UDP_BIND="0.0.0.0:0,[::]:0" multiple addresses
            let sockets = udp::bind_udp_from_env_or_any()
                .await
                .map_err(|e| anyhow::anyhow!("bind_udp_from_env_or_any failed: {e}"))?;
            // 起 NAT 驱逐占位（内部会 spawn，并持续运行；目前不依赖 self 的成员，零侵入）
            // Start NAT eviction placeholder (internally spawns and runs continuously; currently does not depend on self members, zero intrusion)
            let nat = std::sync::Arc::new(sb_core::net::datagram::UdpNatMap::new(
                std::time::Duration::from_secs(60),
            ));
            udp::spawn_nat_evictor(&udp::UdpRuntime {
                map: nat,
                ttl: std::time::Duration::from_secs(60),
                scan: std::time::Duration::from_secs(30),
            });
            // 后台处理 UDP 报文（解析+上游转发+回写）
            // Background processing of UDP packets (parse + upstream forward + write back)
            for s in sockets {
                tokio::spawn({
                    let sock = s.clone();
                    async move {
                        // 这里的 sock 已经是 Arc<UdpSocket>，与新签名匹配
                        // sock here is already Arc<UdpSocket>, matching the new signature
                        if let Err(e) = udp::serve_udp_datagrams(sock, None).await {
                            tracing::warn!("socks/udp serve ended: {e}");
                        }
                    }
                });
                tracing::info!(
                    "socks: UDP inbound enabled (SB_SOCKS_UDP_ENABLE=1) bind={:?}",
                    s.local_addr()
                );
            }
        }

        // NOTE(linus): TCP（仅 UDP_ASSOCIATE）接入（默认关闭）。
        // NOTE(linus): TCP (UDP_ASSOCIATE only) integration (disabled by default).
        if std::env::var("SB_SOCKS_TCP_ENABLE").is_ok() {
            // 如果用户只开了 TCP 开关而没开 UDP，我们也要保证有一个 UDP 绑定用于 BND.ADDR/PORT
            // If user only enabled TCP switch but not UDP, we must ensure there is a UDP binding for BND.ADDR/PORT
            if udp::get_udp_bind_addr().is_none() {
                let sockets = udp::bind_udp_from_env_or_any()
                    .await
                    .map_err(|e| anyhow::anyhow!("bind_udp_from_env_or_any failed: {e}"))?;
                for s in sockets {
                    tokio::spawn({
                        let sock = s.clone();
                        async move {
                            if let Err(e) = udp::serve_udp_datagrams(sock, None).await {
                                tracing::warn!("socks/udp (autostart for TCP) ended: {e}");
                            }
                        }
                    });
                    tracing::info!(
                        "socks: auto-enable UDP for TCP UDP_ASSOCIATE, bind={:?}",
                        s.local_addr()
                    );
                }
            }
            let addr =
                std::env::var("SB_SOCKS_TCP_ADDR").unwrap_or_else(|_| "127.0.0.1:1080".to_string());
            let addr_for_log = addr.clone();
            tokio::spawn(async move {
                let addr = addr; // move 进闭包，避免后续 borrow moved value
                                 // move into closure to avoid subsequent borrow moved value
                if let Err(e) = crate::inbound::socks::tcp::run_tcp(&addr).await {
                    tracing::warn!("socks/tcp run failed: {e}");
                }
            });
            tracing::info!("socks: TCP (UDP_ASSOCIATE) enabled at {}", addr_for_log);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct SocksInboundAdapter {
    cfg: SocksInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

impl SocksInboundAdapter {
    pub fn new(cfg: SocksInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
        }
    }
}

impl InboundService for SocksInboundAdapter {
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
        let res = rt.block_on(async { serve_socks(cfg, rx, None).await.map_err(io::Error::other) });
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
