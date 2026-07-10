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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
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
use sb_core::adapter::{InboundReadySender, InboundTaskDriver};
use sb_core::net::rate_limit_metrics;
use sb_core::net::tcp_rate_limit::{TcpRateLimitConfig, TcpRateLimiter};
use sb_core::outbound::health as ob_health;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{health::MultiHealthView, registry, selector::PoolSelector};
use sb_core::outbound::{Endpoint, OutboundRegistryHandle};
use sb_core::outbound::{Endpoint as OutEndpoint, RouteTarget as OutRouteTarget};
use sb_core::router::rules::Decision as RDecision;
use sb_core::router::{RouteCtx, RouterHandle, Transport};
use sb_core::services::v2ray_api::StatsManager;
use sb_transport::IoStream;

static SELECTOR: OnceCell<PoolSelector> = OnceCell::new();
// 本文件只用到了 inbound_parse，其他两个会在具体错误路径里再接入
use sb_config::ir::Credentials;
use sb_core::telemetry::inbound_parse;

#[cfg(feature = "metrics")]
use metrics;

pub mod tcp;
pub mod udp;
mod upstream;

/// SOCKS5 inbound configuration
/// SOCKS5 入站配置
#[derive(Clone, Debug)]
pub struct SocksInboundConfig {
    /// Inbound tag for stats
    pub tag: Option<String>,
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
    /// UDP NAT entry TTL used by the SOCKS UDP associate runtime.
    /// SOCKS UDP ASSOCIATE 运行时使用的 UDP NAT 条目 TTL。
    pub udp_nat_ttl: Duration,
    /// User credentials for authentication
    pub users: Option<Vec<Credentials>>,
    /// UDP Timeout
    pub udp_timeout: Option<Duration>,
    /// Domain resolution strategy
    pub domain_strategy: Option<DomainStrategy>,
    /// Optional V2Ray stats manager
    pub stats: Option<Arc<StatsManager>>,
    /// Explicit conntrack dependency for SOCKS TCP/UDP sessions.
    pub conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
    /// Inbound sniff configuration (Go parity: sniff_enabled).
    pub sniff: bool,
    /// Override destination with sniffed hostname (Go parity: sniff_override_destination).
    pub sniff_override_destination: bool,
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
    ready_tx: Option<oneshot::Sender<io::Result<()>>>,
) -> io::Result<()> {
    serve_socks_internal(
        cfg,
        stop_rx,
        ready_tx,
        None,
        Arc::new(AtomicU64::new(0)),
        TcpRateLimiter::new(TcpRateLimitConfig::from_env()),
    )
    .await
}

async fn serve_socks_internal(
    cfg: SocksInboundConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<io::Result<()>>>,
    udp_addr: Option<SocketAddr>,
    active_connections: Arc<AtomicU64>,
    rate_limiter: TcpRateLimiter,
) -> io::Result<()> {
    let listener = match TcpListener::bind(cfg.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            if let Some(tx) = ready_tx {
                let _ = tx.send(Err(io::Error::new(error.kind(), error.to_string())));
            }
            return Err(error);
        }
    };
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "SOCKS5 bound");
    if let Some(tx) = ready_tx {
        let _ = tx.send(Ok(()));
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
                if !rate_limiter.allow_connection(peer.ip()) {
                    warn!(%peer, "socks: connection rate limited");
                    rate_limit_metrics::record_rate_limited("socks", "connection_limit");
                    continue;
                }
                let cfg_clone = cfg.clone();
                let active = active_connections.clone();
                let current = active.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                sb_core::metrics::inbound::set_active_connections("socks", current);
                tokio::spawn(async move {
                    let _active_guard = scopeguard::guard(active, |active| {
                        let remaining = active
                            .fetch_sub(1, Ordering::Relaxed)
                            .saturating_sub(1);
                        sb_core::metrics::inbound::set_active_connections("socks", remaining);
                    });
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
pub async fn run_with_ready(
    cfg: SocksInboundConfig,
    stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<io::Result<()>>>,
) -> io::Result<()> {
    run_with_ready_and_active(cfg, stop_rx, ready_tx, Arc::new(AtomicU64::new(0))).await
}

async fn run_with_ready_and_active(
    cfg: SocksInboundConfig,
    stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<io::Result<()>>>,
    active_connections: Arc<AtomicU64>,
) -> io::Result<()> {
    // Enable UDP Associate by default (Go parity); opt-out with SB_SOCKS_UDP_ENABLE=0
    let udp_enabled = std::env::var("SB_SOCKS_UDP_ENABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let udp_addr = if udp_enabled {
        // Bind UDP socket
        let bind_addr = cfg
            .udp_bind
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
        let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
        let local_addr = sock.local_addr()?;
        let sock = std::sync::Arc::new(sock);

        // Spawn UDP handler
        let timeout = cfg.udp_timeout;
        let inbound_tag = cfg.tag.clone();
        let stats = cfg.stats.clone();
        let conn_tracker = cfg.conn_tracker.clone();
        let udp_runtime =
            udp::UdpDatagramRuntime::new(Some(cfg.router.clone()), Some(cfg.outbounds.clone()))
                .with_nat_ttl(cfg.udp_nat_ttl);
        tokio::spawn(async move {
            if let Err(e) = udp::serve_udp_datagrams_with_runtime(
                sock,
                timeout,
                inbound_tag,
                stats,
                conn_tracker,
                udp_runtime,
            )
            .await
            {
                tracing::warn!("socks/udp serve error: {:?}", e);
            }
        });

        info!(addr=?local_addr, "SOCKS5 UDP Associate enabled");
        Some(local_addr)
    } else {
        None
    };

    serve_socks_internal(
        cfg,
        stop_rx,
        ready_tx,
        udp_addr,
        active_connections,
        TcpRateLimiter::new(TcpRateLimitConfig::from_env()),
    )
    .await
}

pub async fn run(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {
    run_with_ready(cfg, stop_rx, None).await
}

/// Compatibility alias - serve SOCKS5 proxy
/// 兼容性别名 - 运行 SOCKS5 代理
pub async fn serve(cfg: SocksInboundConfig, stop_rx: mpsc::Receiver<()>) -> io::Result<()> {
    serve_socks(cfg, stop_rx, None).await
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::TcpListener as StdTcpListener;
    #[cfg(feature = "metrics")]
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{sleep, timeout};

    fn test_cfg(listen: SocketAddr) -> SocksInboundConfig {
        SocksInboundConfig {
            tag: Some("socks-ready-test".to_string()),
            listen,
            udp_bind: None,
            router: Arc::new(RouterHandle::from_env()),
            outbounds: Arc::new(OutboundRegistryHandle::default()),
            udp_nat_ttl: Duration::from_secs(60),
            users: None,
            udp_timeout: None,
            domain_strategy: None,
            stats: None,
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
            sniff: false,
            sniff_override_destination: false,
        }
    }

    fn test_limiter(max_connections: usize) -> TcpRateLimiter {
        TcpRateLimiter::new(TcpRateLimitConfig {
            max_connections,
            window: Duration::from_secs(60),
            ..TcpRateLimitConfig::default()
        })
    }

    async fn wait_for_active(active: &AtomicU64, expected: u64) {
        timeout(Duration::from_secs(2), async {
            loop {
                if active.load(Ordering::Relaxed) == expected {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("active connection count did not converge");
    }

    #[tokio::test]
    async fn readiness_reports_success_after_bind() {
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();

        let task = tokio::spawn(serve_socks(
            test_cfg("127.0.0.1:0".parse().unwrap()),
            stop_rx,
            Some(ready_tx),
        ));

        timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("socks ready timed out")
            .expect("socks ready sender dropped")
            .expect("socks bind failed");
        let _ = stop_tx.send(()).await;
        task.await
            .expect("socks task panicked")
            .expect("socks stopped");
    }

    #[tokio::test]
    async fn readiness_reports_bind_failure_on_occupied_port() {
        let holder = StdTcpListener::bind("127.0.0.1:0").expect("hold socks port");
        let addr = holder.local_addr().expect("held socks address");
        let (_stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();

        let err = serve_socks(test_cfg(addr), stop_rx, Some(ready_tx))
            .await
            .expect_err("occupied socks port must fail");
        let ready_err = timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("socks ready failure timed out")
            .expect("socks ready sender dropped")
            .expect_err("socks ready must report bind failure");

        assert_eq!(ready_err.kind(), ErrorKind::AddrInUse);
        assert_eq!(err.kind(), ErrorKind::AddrInUse);
        drop(holder);
    }

    #[tokio::test]
    async fn limiter_rejects_second_peer_and_active_count_recovers() {
        let holder = StdTcpListener::bind("127.0.0.1:0").expect("reserve socks port");
        let addr = holder.local_addr().expect("reserved socks address");
        drop(holder);

        let active = Arc::new(AtomicU64::new(0));
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(serve_socks_internal(
            test_cfg(addr),
            stop_rx,
            Some(ready_tx),
            None,
            active.clone(),
            test_limiter(1),
        ));
        timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("socks ready timed out")
            .expect("socks ready sender dropped")
            .expect("socks bind failed");

        let first = TcpStream::connect(addr).await.expect("first socks connect");
        wait_for_active(&active, 1).await;

        let rejected_before = sb_core::net::rate_limit_metrics::RATE_LIMITED_TOTAL
            .with_label_values(&["socks", "connection_limit"])
            .get();
        let second = TcpStream::connect(addr)
            .await
            .expect("second socks connect");
        timeout(Duration::from_secs(2), async {
            loop {
                let rejected = sb_core::net::rate_limit_metrics::RATE_LIMITED_TOTAL
                    .with_label_values(&["socks", "connection_limit"])
                    .get();
                if rejected > rejected_before {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second SOCKS connection was not rate limited");
        assert_eq!(active.load(Ordering::Relaxed), 1);

        drop(second);
        drop(first);
        wait_for_active(&active, 0).await;
        let _ = stop_tx.send(()).await;
        task.await
            .expect("socks task panicked")
            .expect("socks stopped");
    }

    #[test]
    fn adapter_reports_active_connections() {
        let adapter = SocksInboundAdapter::new(test_cfg("127.0.0.1:0".parse().unwrap()));
        assert_eq!(adapter.active_connections(), Some(0));
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    async fn udp_associate_emits_compat_metric() {
        fn metric_value(name: &str) -> f64 {
            sb_metrics::export_prometheus()
                .lines()
                .find_map(|line| {
                    line.strip_prefix(name)
                        .and_then(|value| value.trim().parse::<f64>().ok())
                })
                .unwrap_or(0.0)
        }

        let before = metric_value("inbound_socks_udp_associate_total");
        let (mut server, mut client) = duplex(1024);
        let cfg = test_cfg("127.0.0.1:0".parse().unwrap());
        let task = tokio::spawn(async move {
            serve_conn(
                &mut server,
                "127.0.0.1:12345".parse().unwrap(),
                &cfg,
                Some("127.0.0.1:54321".parse().unwrap()),
            )
            .await
        });

        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00]);
        client
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);
        task.await.unwrap().unwrap();

        assert_eq!(
            metric_value("inbound_socks_udp_associate_total"),
            before + 1.0
        );
    }
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
            let endpoint = host.parse::<IpAddr>().map_or_else(
                |_| Endpoint::Domain(host.clone(), port),
                |ip| Endpoint::Ip(SocketAddr::new(ip, port)),
            );
            (endpoint, host)
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

    process_request(cli, peer, cfg, endpoint, None).await
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
    let mut auth_user: Option<String> = None;

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
                    auth_user = Some(u.to_string());
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
            let endpoint = host.parse::<IpAddr>().map_or_else(
                |_| Endpoint::Domain(host.clone(), port),
                |ip| Endpoint::Ip(SocketAddr::new(ip, port)),
            );
            (endpoint, host, port)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad atyp")),
    };

    match cmd {
        0x01 => {
            // CONNECT
            // 握手阶段（greeting/auth/req）完成
            // Handshake phase (greeting/auth/req) completed
            inbound_parse("socks", "ok", "greeting+request");
            process_request(cli, peer, cfg, endpoint, auth_user).await
        }
        0x03 => {
            // UDP ASSOCIATE
            #[cfg(feature = "metrics")]
            sb_metrics::inc_socks_udp_assoc();
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
    auth_user: Option<String>,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // use sb_core::dns::Resolver; // Unused

    // Apply domain strategy
    let mut endpoint = endpoint;
    if let Some(strategy) = cfg.domain_strategy {
        if let Endpoint::Domain(ref host, port) = endpoint {
            if matches!(
                strategy,
                DomainStrategy::UseIp | DomainStrategy::UseIpv4 | DomainStrategy::UseIpv6
            ) {
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

    // Routing via cfg.router (from config IR) with minimal matched rule metadata.
    let (host_opt, ip_opt, port_opt) = match &endpoint {
        Endpoint::Domain(h, p) => (Some(h.as_str()), None, Some(*p)),
        Endpoint::Ip(sa) => (None, Some(sa.ip()), Some(sa.port())),
    };
    let route_ctx = RouteCtx {
        host: host_opt,
        ip: ip_opt,
        port: port_opt,
        transport: Transport::Tcp,
        network: "tcp",
        inbound_tag: cfg.tag.as_deref(),
        inbound_sniff: cfg.sniff,
        inbound_sniff_override: cfg.sniff_override_destination,
        ..Default::default()
    };
    let meta = cfg.router.decide_with_meta(&route_ctx);
    let mut rule: Option<String> = meta.rule;
    let mut decision: RDecision = meta.decision;

    // Handle Decision::Sniff: send reply early, read initial bytes, sniff, re-decide
    let mut sniff_prefix: Vec<u8> = Vec::new();
    let mut sniff_reply_sent = false;
    let mut override_host: Option<String> = None;
    if let RDecision::Sniff {
        override_destination,
    } = decision
    {
        let dest_port = port_opt.unwrap_or(0);
        if sb_core::router::sniff::skip_sniff(dest_port) {
            decision = RDecision::Direct;
        } else {
            // Send SOCKS5 success reply early so client starts sending data
            reply(cli, 0x00, None).await?;
            sniff_reply_sent = true;

            // Read initial bytes with 300ms timeout
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_millis(300), cli.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => 0,
            };
            buf.truncate(n);

            if n > 0 {
                let outcome = sb_core::router::sniff::sniff_stream(&buf);
                tracing::debug!(
                    protocol = ?outcome.protocol,
                    host = ?outcome.host,
                    "socks5: sniffed stream"
                );
                // Build new RouteCtx with sniffed protocol/host and re-decide
                let sniffed_host_owned: String;
                let host_for_ctx = if let Some(ref h) = outcome.host {
                    sniffed_host_owned = h.clone();
                    Some(sniffed_host_owned.as_str())
                } else {
                    host_opt
                };
                let route_ctx2 = RouteCtx {
                    host: host_for_ctx,
                    ip: ip_opt,
                    port: port_opt,
                    transport: Transport::Tcp,
                    network: "tcp",
                    protocol: outcome.protocol,
                    inbound_tag: cfg.tag.as_deref(),
                    ..Default::default()
                };
                let meta2 = cfg.router.decide_with_meta(&route_ctx2);
                decision = meta2.decision;
                rule = meta2.rule;
                sniff_prefix = buf;

                // OverrideDestination: replace outbound target with sniffed domain
                if override_destination {
                    if let Some(ref h) = outcome.host {
                        if !h.is_empty() {
                            tracing::debug!(sniffed_host = %h, "socks5: override destination with sniffed host");
                            override_host = Some(h.clone());
                        }
                    }
                }
            }

            // Safety net: if still Sniff after re-decide, fall back to Direct
            if matches!(decision, RDecision::Sniff { .. }) {
                decision = RDecision::Direct;
            }
        }
    }

    // Apply sniff override: use sniffed domain as outbound target
    if let Some(ref oh) = override_host {
        if let Some(p) = port_opt {
            endpoint = Endpoint::Domain(oh.clone(), p);
        }
    }

    #[cfg(feature = "metrics")]
    {
        metrics::counter!(
            "router_decide_total",
            "decision" => match &decision {
                RDecision::Direct => "direct",
                RDecision::Proxy(_) => "proxy",
                RDecision::Reject | RDecision::RejectDrop => "reject",
                _ => "other",
            }
        )
        .increment(1);
    }
    if matches!(decision, RDecision::Reject) {
        // SOCKS5: REP=0x02 (connection not allowed by ruleset)
        reply(cli, 0x02, None).await?;
        return Ok(());
    }

    #[cfg(feature="metrics")]
    metrics::counter!("router_route_total",
        "inbound"=>"socks5",
        "decision"=>match &decision { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject | RDecision::RejectDrop=>"reject", _=>"other" },
        "proxy_kind"=>match &decision { RDecision::Direct=>"direct", RDecision::Proxy(Some(_))=>"named", RDecision::Proxy(None)=>"unnamed", RDecision::Reject | RDecision::RejectDrop=>"reject", _=>"other" }
    ).increment(1);

    if matches!(decision, RDecision::Proxy(_)) {
        if let Some(st) = ob_health::global_status() {
            if !st.is_up() {
                tracing::warn!(
                    "router: proxy unhealthy; direct fallback is disabled (socks5 inbound)"
                );
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "router_route_fallback_total",
                    "from" => "proxy",
                    "to" => "blocked",
                    "inbound" => "socks5"
                )
                .increment(1);
            }
        }
    }

    let opts = ConnectOpts::default();
    let outbound_tag: Option<String>;

    // Fast path: if router decided a named outbound, try OutboundRegistry first
    // Skip fast-path when sniff already sent reply (fast-path sends its own reply)
    if sniff_prefix.is_empty() {
        if let RDecision::Proxy(Some(name)) = &decision {
            let out_ep = match &endpoint {
                Endpoint::Domain(h, p) => OutEndpoint::Domain(h.clone(), *p),
                Endpoint::Ip(sa) => OutEndpoint::Ip(*sa),
            };
            match cfg
                .outbounds
                .connect_tcp_stream(&OutRouteTarget::Named(name.clone()), out_ep)
                .await
            {
                Ok(mut s) => {
                    // Success: reply and start piping
                    reply(cli, 0x00, None).await?;
                    outbound_tag = Some(name.clone());

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
                    let traffic = cfg.stats.as_ref().and_then(|stats| {
                        stats.traffic_recorder(
                            cfg.tag.as_deref(),
                            outbound_tag.as_deref(),
                            auth_user.as_deref(),
                        )
                    });
                    let (dst_host, dst_port) = match &endpoint {
                        Endpoint::Domain(h, p) => (h.clone(), *p),
                        Endpoint::Ip(sa) => (sa.ip().to_string(), sa.port()),
                    };
                    let chains = sb_core::outbound::chain::compute_chain_for_decision(
                        Some(cfg.outbounds.as_ref()),
                        &decision,
                        outbound_tag.as_deref(),
                    );
                    let wiring = sb_core::conntrack::register_inbound_tcp_with_tracker(
                        cfg.conn_tracker.clone(),
                        peer,
                        dst_host.clone(),
                        dst_port,
                        dst_host,
                        "socks",
                        cfg.tag.clone(),
                        outbound_tag.clone(),
                        chains,
                        rule.clone(),
                        None,
                        None,
                        traffic,
                    );
                    let _guard = wiring.guard;

                    let copy_res = sb_core::net::metered::copy_bidirectional_streaming_ctl(
                        cli,
                        &mut s,
                        "socks",
                        std::time::Duration::from_secs(1),
                        rt,
                        wt,
                        Some(wiring.cancel),
                        Some(wiring.traffic),
                    )
                    .await;
                    match copy_res {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        outbound = %name,
                        error = %e,
                        "socks5 inbound: named outbound canonical dial failed; falling back to registry path"
                    );
                }
            }
        }
    } // end skip fast-path when sniffed

    // 与上游建立连接（根据决策与默认代理）
    // Establish connection with upstream (based on decision and default proxy)
    let mut srv: IoStream = match &decision {
        RDecision::Direct => {
            outbound_tag = Some("direct".to_string());
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
        RDecision::Proxy(pool_name) => {
            if let Some(name) = pool_name {
                outbound_tag = Some(name.clone());
                // Named proxy pool selection
                let sel = SELECTOR.get_or_init(|| {
                    let ttl = socks_sticky_env_u64("SB_PROXY_STICKY_TTL_MS", 10_000);
                    let cap = socks_sticky_env_usize("SB_PROXY_STICKY_CAP", 4096);
                    PoolSelector::new_with_capacity(cap, std::time::Duration::from_millis(ttl))
                });
                let _health = MultiHealthView;
                let target_str = match &endpoint {
                    Endpoint::Domain(host, port) => format!("{}:{}", host, port),
                    Endpoint::Ip(sa) => sa.to_string(),
                };

                if let Some(reg) = registry::global() {
                    if let Some(_pool) = reg.pools.get(name) {
                        if let Some(ep) = sel.select(name, peer, &target_str, &()) {
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
                            tracing::warn!(
                                "socks5 inbound: named proxy decision '{}' has no selectable endpoint; implicit fallback is disabled; use adapter bridge/supervisor path",
                                name
                            );
                            reply(cli, 0x01, None).await?; // General failure
                            return Ok(());
                        }
                    } else {
                        tracing::warn!(
                            "socks5 inbound: named proxy decision '{}' not found in registry; implicit fallback is disabled; use adapter bridge/supervisor path",
                            name
                        );
                        reply(cli, 0x01, None).await?; // General failure
                        return Ok(());
                    }
                } else {
                    tracing::warn!(
                        "socks5 inbound: named proxy decision '{}' cannot be resolved because registry is unavailable; implicit fallback is disabled; use adapter bridge/supervisor path",
                        name
                    );
                    reply(cli, 0x01, None).await?; // General failure
                    return Ok(());
                }
            } else {
                tracing::warn!(
                    "socks5 inbound: proxy decision without outbound tag is unsupported; implicit fallback is disabled; provide explicit outbound in routing"
                );
                reply(cli, 0x01, None).await?; // General failure
                return Ok(());
            }
        }
        RDecision::Reject | RDecision::RejectDrop => {
            // Should have been filtered earlier; return explicit error to avoid panic.
            return Err(io::Error::other("socks: rejected by rules"));
        }
        RDecision::Hijack { .. }
        | RDecision::Sniff { .. }
        | RDecision::Resolve
        | RDecision::HijackDns => {
            tracing::warn!("socks5 inbound: unsupported routing decision in adapter path; direct fallback is disabled; use explicit direct/proxy decision");
            outbound_tag = Some("direct".to_string());
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
    if !sniff_reply_sent {
        reply(cli, 0x00, None).await?;
    }
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
    let traffic = cfg.stats.as_ref().and_then(|stats| {
        stats.traffic_recorder(
            cfg.tag.as_deref(),
            outbound_tag.as_deref(),
            auth_user.as_deref(),
        )
    });
    let (dst_host, dst_port) = match &endpoint {
        Endpoint::Domain(h, p) => (h.clone(), *p),
        Endpoint::Ip(sa) => (sa.ip().to_string(), sa.port()),
    };
    let chains = sb_core::outbound::chain::compute_chain_for_decision(
        Some(cfg.outbounds.as_ref()),
        &decision,
        outbound_tag.as_deref(),
    );
    let wiring = sb_core::conntrack::register_inbound_tcp_with_tracker(
        cfg.conn_tracker.clone(),
        peer,
        dst_host.clone(),
        dst_port,
        dst_host,
        "socks",
        cfg.tag.clone(),
        outbound_tag.clone(),
        chains,
        rule.clone(),
        None,
        None,
        traffic,
    );
    let _guard = wiring.guard;

    let copy_res = if sniff_prefix.is_empty() {
        sb_core::net::metered::copy_bidirectional_streaming_ctl(
            cli,
            &mut srv,
            "socks",
            std::time::Duration::from_secs(1),
            rt,
            wt,
            Some(wiring.cancel),
            Some(wiring.traffic),
        )
        .await
    } else {
        let mut sniffed = crate::inbound::sniff_util::SniffedStream::new(cli, sniff_prefix);
        sb_core::net::metered::copy_bidirectional_streaming_ctl(
            &mut sniffed,
            &mut srv,
            "socks",
            std::time::Duration::from_secs(1),
            rt,
            wt,
            Some(wiring.cancel),
            Some(wiring.traffic),
        )
        .await
    };
    match copy_res {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(()),
        Err(e) => Err(e),
    }
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

#[derive(Debug)]
pub struct SocksInboundAdapter {
    cfg: SocksInboundConfig,
    stop_tx: Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
    active_connections: Arc<AtomicU64>,
}

impl SocksInboundAdapter {
    pub fn new(cfg: SocksInboundConfig) -> Self {
        Self {
            cfg,
            stop_tx: Mutex::new(None),
            active_connections: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl InboundTaskDriver for SocksInboundAdapter {
    fn serve(&self) -> io::Result<()> {
        self.serve_with_ready(None)
    }

    fn supports_startup_readiness(&self) -> bool {
        true
    }

    fn serve_with_ready(&self, ready: Option<InboundReadySender>) -> io::Result<()> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let mut guard = self.stop_tx.lock().unwrap();
            *guard = Some(tx);
        }
        let cfg = self.cfg.clone();
        let active_connections = self.active_connections.clone();
        let res = if let Ok(handle) = tokio::runtime::Handle::try_current() {
            // Reuse existing runtime to avoid per-inbound runtime cold-start overhead.
            handle.block_on(async {
                run_with_ready_and_active(cfg, rx, ready, active_connections)
                    .await
                    .map_err(io::Error::other)
            })
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(io::Error::other)?;
            rt.block_on(async {
                run_with_ready_and_active(cfg, rx, ready, active_connections)
                    .await
                    .map_err(io::Error::other)
            })
        };
        let _ = self.stop_tx.lock().unwrap().take();
        res
    }

    fn request_shutdown(&self) {
        let mut guard = self.stop_tx.lock().unwrap();
        if let Some(tx) = guard.take() {
            let _ = tx.try_send(());
        }
    }

    fn active_connections(&self) -> Option<u64> {
        Some(self.active_connections.load(Ordering::Relaxed))
    }
}

fn socks_sticky_env_u64(name: &str, default: u64) -> u64 {
    let raw = match std::env::var(name) {
        Ok(v) => v,
        Err(_) => return default,
    };
    match raw.trim().parse::<u64>() {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                "env '{name}' value '{raw}' is not a valid u64; \
                 silent parse fallback is disabled, using default {default}: {err}"
            );
            default
        }
    }
}

fn socks_sticky_env_usize(name: &str, default: usize) -> usize {
    let raw = match std::env::var(name) {
        Ok(v) => v,
        Err(_) => return default,
    };
    match raw.trim().parse::<usize>() {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                "env '{name}' value '{raw}' is not a valid usize; \
                 silent parse fallback is disabled, using default {default}: {err}"
            );
            default
        }
    }
}
