//! HTTP CONNECT Inbound (Routing + Outbound Registry)
//! HTTP CONNECT 入站（路由+出站注册表）
//! - P1.4: Read header timeout
//! - P1.4：读头超时
//! - P1.5: Unified IO metering via sb_core::net::metered
//! - P1.5：IO 计量统一走 sb_core::net::metered。

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use sb_config::ir::Credentials;
use sb_core::obs::access;
use sb_transport::IoStream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::{mpsc, oneshot},
    time::{interval, Duration},
};
// Use existing `async fn respond_403(cli: &mut TcpStream) -> Result<()>` in the file
// 使用文件内已有的 `async fn respond_403(cli: &mut TcpStream) -> Result<()>`
use std::time::Instant;
use tracing::{debug, info, warn};

// NOTE: mainline defaults to off; can be temporarily enabled via env for acceptance/troubleshooting (lazy load).
// NOTE: mainline 默认关闭；验收/排障时可通过环境变量临时开启（惰性读取）。
// SB_HTTP_SMOKE_405=1    -> Return 405 directly after accept (Smoke Mode)
// SB_HTTP_SMOKE_405=1    -> 在 accept 后直接回 405（烟囱模式）
// SB_HTTP_DISABLE_STOP=1 -> Disable stop interruption during debugging (Use with caution)
// SB_HTTP_DISABLE_STOP=1 -> 调试时禁用 stop 打断（谨慎使用）
use std::sync::OnceLock;
#[allow(dead_code)] // Reserved for smoke testing
static HTTP_FLAG_SMOKE_405: OnceLock<bool> = OnceLock::new();
#[allow(dead_code)] // Reserved for graceful shutdown control
static HTTP_FLAG_DISABLE_STOP: OnceLock<bool> = OnceLock::new();
#[inline]
#[cfg(test)]
#[allow(dead_code)]
fn http_flag_smoke_405() -> bool {
    *HTTP_FLAG_SMOKE_405.get_or_init(|| std::env::var("SB_HTTP_SMOKE_405").is_ok())
}
#[inline]
#[cfg(test)]
#[allow(dead_code)]
fn http_flag_disable_stop() -> bool {
    *HTTP_FLAG_DISABLE_STOP.get_or_init(|| std::env::var("SB_HTTP_DISABLE_STOP").is_ok())
}

static HTTP_FLAG_LEGACY_WRITE: OnceLock<bool> = OnceLock::new();
#[inline]
fn http_legacy_write_enabled() -> bool {
    *HTTP_FLAG_LEGACY_WRITE.get_or_init(|| std::env::var("SB_HTTP_LEGACY_WRITE").is_ok())
}

#[cfg(feature = "metrics")]
use std::sync::atomic::AtomicUsize;
use std::{net::SocketAddr, sync::Arc};

#[cfg(feature = "metrics")]
#[deprecated(
    since = "0.1.0",
    note = "kept for compatibility; metrics collection not yet implemented"
)]
#[allow(dead_code)] // Reserved for connection tracking
static HTTP_ACTIVE: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "metrics")]
use metrics::counter;
use once_cell::sync::OnceCell;
use sb_core::outbound::health as ob_health;
use sb_core::outbound::OutboundRegistryHandle;
use sb_core::outbound::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use sb_core::outbound::{health::MultiHealthView, registry, selector::PoolSelector};
use sb_core::outbound::{Endpoint as OutEndpoint, RouteTarget as OutRouteTarget};
use sb_core::router;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::runtime::{default_proxy, ProxyChoice};

static SELECTOR: OnceCell<PoolSelector> = OnceCell::new();

// (Remove unused inbound_parse)
// （删除未使用的 inbound_parse）
// Only effective when feature=metrics is enabled; default build is unaffected
// 只有在 feature=metrics 下才会真正生效，默认构建不受影响

/// NOTE(mainline): Defaults to off, can be temporarily enabled via env for acceptance/troubleshooting.
/// NOTE(mainline): 默认关闭，验收/排障时可通过环境变量临时开启。
fn http_smoke_405_enabled() -> bool {
    *HTTP_FLAG_SMOKE_405.get_or_init(|| {
        matches!(
            std::env::var("SB_HTTP_SMOKE_405").ok().as_deref(),
            Some("1" | "true" | "TRUE")
        )
    })
}
fn http_disable_stop_enabled() -> bool {
    *HTTP_FLAG_DISABLE_STOP.get_or_init(|| {
        matches!(
            std::env::var("SB_HTTP_DISABLE_STOP").ok().as_deref(),
            Some("1" | "true" | "TRUE")
        )
    })
}
/// Rollback switch: Degrade to "Write only + Close"
/// 回滚开关：降级为"只写 + 关"
/// Note: This is already defined above at line 38, removing duplicate
#[cfg(test)]
#[allow(dead_code)]
fn http_legacy_write_enabled_test() -> bool {
    matches!(
        std::env::var("SB_HTTP_LEGACY_WRITE").ok().as_deref(),
        Some("1" | "true" | "TRUE")
    )
}

// NOTE(mainline): "Smoke Mode" returns 405 on short path only when env is on; default off does not trigger.
// NOTE(mainline): "烟囱模式"仅在 env 打开时短路径返回 405；默认关闭不触发。
fn should_short_circuit_405() -> bool {
    http_smoke_405_enabled()
}

/// Read an optional duration (milliseconds) from environment once per process.
#[inline]
fn opt_duration_ms_from_env(key: &str) -> Option<std::time::Duration> {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .and_then(|ms| (ms > 0).then(|| std::time::Duration::from_millis(ms)))
}

#[deprecated(since = "0.1.0", note = "reserved for future header size limits")]
const MAX_HEADER: usize = 8 * 1024;
#[deprecated(since = "0.1.0", note = "reserved for future timeout configuration")]
#[allow(dead_code)] // Reserved for timeout enforcement
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP proxy configuration
/// HTTP 代理配置
#[derive(Clone, Debug)]
pub struct HttpProxyConfig {
    /// Listen address
    /// 监听地址
    pub listen: SocketAddr,
    /// Router handle
    /// 路由句柄
    pub router: Arc<router::RouterHandle>,
    /// Outbound registry handle
    /// 出站注册表句柄
    pub outbounds: Arc<OutboundRegistryHandle>,
    /// Optional TLS configuration
    /// 可选的 TLS 配置
    /// Optional TLS configuration
    /// 可选的 TLS 配置
    pub tls: Option<sb_transport::TlsConfig>,
    /// User credentials for authentication
    pub users: Option<Vec<Credentials>>,
    pub set_system_proxy: bool,
    pub allow_private_network: bool,
}

/// Ready signal notifier - sends when socket binding completes
/// 就绪信号通知器 - 当 socket 绑定完成时发送
pub async fn serve_http(
    cfg: HttpProxyConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "HTTP CONNECT bound");
    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }

    if cfg.set_system_proxy {
        warn!("http: system proxy setting requested but not implemented");
    }

    // Add watcher task for accept loop heartbeat
    let local = listener.local_addr().ok();
    tracing::info!(?local, "http: listener ready");
    let mut hb = interval(Duration::from_millis(500));
    tokio::spawn(async move {
        loop {
            let _ = hb.tick().await;
            // Avoid log spam in production;
            // tracing::debug!("http: accept-loop heartbeat");
        }
    });

    // Add disable stop debug switch
    let disable_stop = http_disable_stop_enabled();

    loop {
        select! {
            _ = stop_rx.recv(), if !disable_stop => {
                eprintln!("serve_http: stop signal received");
                break;
            },
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok((cli, peer)) => {
                        tracing::info!(%peer, "http: accept ok");
                        (cli, peer)
                    }
                    Err(e) => {
                        use std::io::ErrorKind::*;
                        tracing::warn!(error=%e, "http: accept error");
                        // Unified HTTP error classification for metrics
                        sb_core::metrics::http::record_error_display(&e);
                        sb_core::metrics::record_inbound_error_display("http", &e);
                        match e.kind() {
                            Interrupted | WouldBlock | ConnectionAborted | ConnectionReset | TimedOut => {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                                continue;
                            }
                            _ => {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        }
                    }
                };
                // NOTE(mainline): "Smoke Mode" returns 405 on short path only when env is on; default off does not trigger.
                // NOTE(mainline): "烟囱模式"仅在 env 打开时短路径返回 405；默认关闭不触发。
                if should_short_circuit_405() {
                    use tokio::io::AsyncWriteExt;
                    tracing::info!(%peer, "http: SMOKE 405");
                    let mut c = cli; // owned
                    let _ = c.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    let _ = c.flush().await;
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    let _ = c.shutdown().await;
                    continue;
                }
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    // Wrap with TLS if configured
                    let stream: sb_transport::dialer::IoStream = if let Some(ref tls_config) = cfg_clone.tls {
                        let tls_transport = sb_transport::TlsTransport::new(tls_config.clone());
                        match tls_transport.wrap_server(cli).await {
                            Ok(tls_stream) => tls_stream,
                            Err(e) => {
                                warn!(peer=%peer, error=%e, "http: TLS handshake failed");
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("http", &e);
                                return;
                            }
                        }
                    } else {
                        Box::new(cli)
                    };

                    if let Err(e) = serve_conn(stream, peer, &cfg_clone).await {
                        warn!(peer=%peer, error=%e, "http connect session error");
                    }
                });
            }
        }
    }
    Ok(())
}

/// Compatibility alias - run HTTP proxy without ready signal
/// 兼容性别名 - 运行 HTTP 代理（无就绪信号）
pub async fn run_http(cfg: HttpProxyConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {
    serve_http(cfg, stop_rx, None).await
}

/// Compatibility alias - serve HTTP proxy
/// 兼容性别名 - 服务 HTTP 代理
pub async fn serve(cfg: HttpProxyConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {
    serve_http(cfg, stop_rx, None).await
}

/// Compatibility alias - run HTTP proxy
/// 兼容性别名 - 运行 HTTP 代理
pub async fn run(cfg: HttpProxyConfig, stop_rx: mpsc::Receiver<()>) -> Result<()> {
    serve_http(cfg, stop_rx, None).await
}

pub async fn serve_conn<S>(mut cli: S, peer: SocketAddr, cfg: &HttpProxyConfig) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    use tracing::info;
    info!(?peer, "http: accepted");

    // Read request head (including headers) to support auth
    let (method, target, _version, headers) = match read_request_head(&mut cli).await {
        Ok(v) => v,
        Err(e) => {
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("http_respond_total", "code" => "400").increment(1);
                counter!("http_requests_total", "method"=>"_parse_error", "code"=>"400")
                    .increment(1);
            }
            sb_core::metrics::http::record_error_display(&e);
            sb_core::metrics::record_inbound_error_display("http", &e);
            return respond_400(&mut cli, "read_head").await.map(|_| ());
        }
    };

    info!(?peer, method=%method, target=%target, "http: request line");

    if method != "CONNECT" {
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("http_respond_total", "code" => "405").increment(1);
            counter!("http_requests_total", "method"=>method.clone(), "code"=>"405").increment(1);
        }
        sb_core::metrics::http::inc_405_responses();
        access::log(
            "http_bad_method",
            &[("proto", "http".into()), ("method", method.to_string())],
        );
        return respond_405_stream(&mut cli).await.map(|_| ());
    }

    // Handle Authentication
    if let Some(users) = &cfg.users {
        if !users.is_empty() {
            let mut authenticated = false;
            // Parse headers for Proxy-Authorization
            let headers_str = String::from_utf8_lossy(&headers);
            for line in headers_str.lines() {
                if line.to_lowercase().starts_with("proxy-authorization:") {
                    let val = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                    if let Some(cred) = val.strip_prefix("Basic ") {
                        if let Ok(decoded) = general_purpose::STANDARD.decode(cred) {
                            if let Ok(auth_str) = String::from_utf8(decoded) {
                                if let Some((u, p)) = auth_str.split_once(':') {
                                    for user in users {
                                        let expected_u = user
                                            .username
                                            .as_deref()
                                            .or(user.username_env.as_deref())
                                            .unwrap_or("");
                                        let expected_p = user
                                            .password
                                            .as_deref()
                                            .or(user.password_env.as_deref())
                                            .unwrap_or("");
                                        if u == expected_u && p == expected_p {
                                            authenticated = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if authenticated {
                    break;
                }
            }

            if !authenticated {
                // Respond 407
                let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                cli.write_all(resp).await?;
                cli.flush().await?;
                return Ok(());
            }
        }
    }

    // Parse host:port (keep original parsing function/error handling in project)
    // 解析 host:port（保持项目里原有的解析函数/错误处理）
    let (host, port) = split_host_port(&target).ok_or_else(|| anyhow!("bad CONNECT target"))?;

    // Check private network access
    if !cfg.allow_private_network {
         if let Ok(ip) = host.parse::<std::net::IpAddr>() {
             if is_private_ip(ip) {
                 use tokio::io::AsyncWriteExt;
                 warn!(?peer, target=%target, "http: blocked private network access");
                 return respond_403(&mut cli).await.map_err(|e| anyhow::anyhow!(e));
             }
         }
    }
    info!(?peer, host=%host, port=%port, "http: CONNECT route");

    let mut decision = RDecision::Direct;
    let proxy = default_proxy();

    // Runtime rule engine (decide first)
    // 运行态规则引擎（先判决）
    if let Some(eng) = rules_global::global() {
        let ctx = RouteCtx {
            domain: Some(host),
            ip: None,
            transport_udp: false,
            port: Some(port),
            network: Some("tcp"),
            ..Default::default()
        };
        let d = eng.decide(&ctx);
        #[cfg(feature = "metrics")]
        {
            metrics::counter!(
                "router_decide_total",
                "decision" => match &d { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" }
            ).increment(1);
        }
        if matches!(d, RDecision::Reject) {
            // Explicit reject
            // 明确拒绝
            let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
            let _ = cli.write_all(resp).await;
            return Ok(());
        }
        decision = d;
    }

    // Only Direct/Proxy left here; default direct
    // 到这里只剩 Direct/Proxy 两种；默认 direct
    #[cfg(feature="metrics")]
    metrics::counter!("router_route_total",
        "inbound"=>"http",
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
                tracing::warn!("router: proxy unhealthy; fallback to direct (http inbound)");
                #[cfg(feature = "metrics")]
                metrics::counter!(
                    "router_route_fallback_total",
                    "from" => "proxy",
                    "to" => "direct",
                    "inbound" => "http"
                )
                .increment(1);
                // Override routing result to Direct
                decision = RDecision::Direct;
            }
        }
    }

    let opts = ConnectOpts::default();

    // Establish TCP with upstream first (based on decision and default proxy)
    // 先与上游建立 TCP（根据决策与默认代理）
    let mut upstream: IoStream = match decision {
        RDecision::Direct => {
            let s = direct_connect_hostport(host, port, &opts).await?;
            Box::new(s)
        }
        RDecision::Proxy(pool_name) => {
            if let Some(name) = pool_name {
                // Named proxy pool selection
                let sel = SELECTOR.get_or_init(|| {
                    let _ttl = std::env::var("SB_PROXY_STICKY_TTL_MS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(10_000);
                    let _cap = std::env::var("SB_PROXY_STICKY_CAP")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(4096);
                    PoolSelector::new("http_proxy".to_string(), "default".to_string())
                });
                let _health = MultiHealthView;

                if let Some(reg) = registry::global() {
                    if let Some(_pool) = reg.pools.get(&name) {
                        if let Some(ep) =
                            sel.select(&name, peer, &format!("{}:{}", host, port), &())
                        {
                            match ep.kind {
                                sb_core::outbound::endpoint::ProxyKind::Http => {
                                    let s = http_proxy_connect_through_proxy(
                                        &ep.addr.to_string(),
                                        host,
                                        port,
                                        &opts,
                                    )
                                    .await?;
                                    Box::new(s)
                                }
                                sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                    let s = socks5_connect_through_socks5(
                                        &ep.addr.to_string(),
                                        host,
                                        port,
                                        &opts,
                                    )
                                    .await?;
                                    Box::new(s)
                                }
                            }
                        } else {
                            // Pool empty or all endpoints down - try OutboundRegistry named connector
                            if let Ok(s) = cfg
                                .outbounds
                                .connect_io(
                                    &OutRouteTarget::Named(name.clone()),
                                    OutEndpoint::Domain(host.to_string(), port),
                                )
                                .await
                            {
                                s
                            } else {
                                // Fallback to direct or default proxy
                                match fallback_enabled {
                                    true => {
                                        #[cfg(feature = "metrics")]
                                        metrics::counter!("router_route_fallback_total", "from" => "proxy", "to" => "direct", "reason" => "pool_empty").increment(1);
                                        let s = direct_connect_hostport(host, port, &opts).await?;
                                        Box::new(s)
                                    }
                                    false => {
                                        return Err(anyhow!(
                                            "proxy pool '{}' has no available endpoints",
                                            name
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        // Pool not found - try OutboundRegistry named connector
                        if let Ok(s) = cfg
                            .outbounds
                            .connect_io(
                                &OutRouteTarget::Named(name.clone()),
                                OutEndpoint::Domain(host.to_string(), port),
                            )
                            .await
                        {
                            s
                        } else {
                            // Fallback to default proxy or direct
                            match proxy {
                                ProxyChoice::Direct => {
                                    let s = direct_connect_hostport(host, port, &opts).await?;
                                    Box::new(s)
                                }
                                ProxyChoice::Http(addr) => {
                                    let s =
                                        http_proxy_connect_through_proxy(addr, host, port, &opts)
                                            .await?;
                                    Box::new(s)
                                }
                                ProxyChoice::Socks5(addr) => {
                                    let s = socks5_connect_through_socks5(addr, host, port, &opts)
                                        .await?;
                                    Box::new(s)
                                }
                            }
                        }
                    }
                } else {
                    // No proxy pool registry - try OutboundRegistry named connector
                    if let Ok(s) = cfg
                        .outbounds
                        .connect_io(
                            &OutRouteTarget::Named(name.clone()),
                            OutEndpoint::Domain(host.to_string(), port),
                        )
                        .await
                    {
                        s
                    } else {
                        // Fallback to default proxy
                        match proxy {
                            ProxyChoice::Direct => {
                                let s = direct_connect_hostport(host, port, &opts).await?;
                                Box::new(s)
                            }
                            ProxyChoice::Http(addr) => {
                                let s = http_proxy_connect_through_proxy(addr, host, port, &opts)
                                    .await?;
                                Box::new(s)
                            }
                            ProxyChoice::Socks5(addr) => {
                                let s =
                                    socks5_connect_through_socks5(addr, host, port, &opts).await?;
                                Box::new(s)
                            }
                        }
                    }
                }
            } else {
                // Default proxy (no named pool)
                match proxy {
                    ProxyChoice::Direct => {
                        let s = direct_connect_hostport(host, port, &opts).await?;
                        Box::new(s)
                    }
                    ProxyChoice::Http(addr) => {
                        let s = http_proxy_connect_through_proxy(addr, host, port, &opts).await?;
                        Box::new(s)
                    }
                    ProxyChoice::Socks5(addr) => {
                        let s = socks5_connect_through_socks5(addr, host, port, &opts).await?;
                        Box::new(s)
                    }
                }
            }
        }
        RDecision::Reject | RDecision::RejectDrop => {
            // Should be filtered earlier; return explicit error to avoid panic paths.
            return Err(anyhow!("unexpected reject decision in http inbound"));
        }
        RDecision::Hijack { .. } | RDecision::Sniff | RDecision::Resolve => {
            // Not directly handled by HTTP inbound; fall back to direct
            let s = direct_connect_hostport(host, port, &opts).await?;
            Box::new(s)
        }
    };
    // Respond 200, then tunnel forwarding
    // 应答 200，然后做隧道转发
    let resp = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    cli.write_all(resp).await?;
    cli.flush().await?;

    // Tunnel forwarding (metered copy; label=http), unified read/write timeout (from env, optional)
    // 隧道转发（计量 copy；label=http），统一读/写超时（来自环境变量，可选）
    let rt = opt_duration_ms_from_env("SB_TCP_READ_TIMEOUT_MS");
    let wt = opt_duration_ms_from_env("SB_TCP_WRITE_TIMEOUT_MS");
    let _ = sb_core::net::metered::copy_bidirectional_streaming_ctl(
        &mut cli,
        &mut upstream,
        "http",
        std::time::Duration::from_secs(1),
        rt,
        wt,
        None,
    )
    .await?;
    Ok(())
}

#[allow(dead_code)]
async fn read_request_line<S>(cli: &mut S) -> Result<(String, String)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use anyhow::anyhow;
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration, Instant};
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 256];
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(anyhow!("read request line timeout"));
        }
        let n = timeout(left, cli.read(&mut tmp))
            .await
            .map_err(|_| anyhow!("read request line timeout"))??;
        if n == 0 {
            return Err(anyhow!("empty request"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 8192 {
            return Err(anyhow!("request line too long"));
        }
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = &buf[..pos];
            let s = std::str::from_utf8(line).map_err(|_| anyhow!("bad utf8 in request line"))?;
            let mut it = s.split_whitespace();
            let method = it.next().unwrap_or("").to_string();
            let target = it.next().unwrap_or("").to_string();
            return Ok((method, target));
        }
    }
}

async fn read_request_head<S>(cli: &mut S) -> Result<(String, String, String, Vec<u8>)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = cli.read(&mut tmp).await?;
        if n == 0 {
            return Err(anyhow!("client closed while reading header"));
        }
        buf.extend_from_slice(&tmp[..n]);
        #[allow(deprecated)]
        if buf.len() > MAX_HEADER {
            return Err(anyhow!("header too large"));
        }
        if let Some(pos) = find_header_end(&buf) {
            let head = &buf[..pos];
            let (method, target, version) = parse_request_line(head)?;
            return Ok((method, target, version, head.to_vec()));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_request_line(line: &[u8]) -> Result<(String, String, String)> {
    let line =
        std::str::from_utf8(trim_cr(line)).map_err(|_| anyhow!("bad utf8 in request line"))?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("no method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("no target"))?
        .to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    Ok((method, target, version))
}

fn trim_cr(s: &[u8]) -> &[u8] {
    if let Some(&b'\r') = s.last() {
        &s[..s.len() - 1]
    } else {
        s
    }
}

/// Parse `host:port` or `[ipv6]:port`
/// 解析 `host:port` 或 `[ipv6]:port`
fn split_host_port(s: &str) -> Option<(&str, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let (_, port_s) = rest.split_once(':')?;
        Some((host, port_s.parse().ok()?))
    } else {
        let (host, port_s) = s.rsplit_once(':')?;
        Some((host, port_s.parse().ok()?))
    }
}

// (Instant already imported at top of file, removing duplicate import here)
// （已在文件顶部导入 Instant，这里删除重复导入）
async fn respond_405_stream<S>(stream: &mut S) -> anyhow::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let t0 = Instant::now();
    let payload = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(payload).await?;
    stream.flush().await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let _ = stream.shutdown().await;
    if tracing::enabled!(tracing::Level::DEBUG) {
        tracing::debug!(
            "respond_405 bytes={} dur_ms={}",
            payload.len(),
            t0.elapsed().as_millis()
        );
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("http_respond_total", "code" => "405").increment(1);
        }
    }
    Ok(())
}

// Around original respond_405/400: Unified as "Standard Sequence"; legacy controlled by switch
// 原 respond_405/400 附近：统一为"标准序列"；legacy 由开关控制
#[allow(dead_code)]
async fn respond_405<S>(mut s: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let start = Instant::now();
    // Keep header minimal
    // 头部尽量保持最小
    const HDR: &[u8] =
        b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    if http_legacy_write_enabled() {
        s.write_all(HDR).await?;
        // legacy: Direct shutdown (no flush/no sleep)
        // legacy: 直接 shutdown（无 flush/无 sleep）
        #[allow(unused_must_use)]
        {
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;
        }
        // metrics: 405 count
        // metrics: 405 计数
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("http_respond_total", "code" => "405").increment(1);
        }
        debug!(elapsed_ms=%start.elapsed().as_millis(), mode="legacy", kind="405", "http: respond");
        return Ok(());
    }
    // Standard sequence: write_all -> flush -> sleep 10ms -> shutdown
    // 标准序列：write_all → flush → sleep 10ms → shutdown
    s.write_all(HDR).await?;
    tokio::io::AsyncWriteExt::flush(&mut s).await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    #[allow(unused_must_use)]
    {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;
    }
    // metrics: 405 count
    // metrics: 405 计数
    #[cfg(feature = "metrics")]
    {
        metrics::counter!("http_respond_total", "code" => "405").increment(1);
    }
    debug!(elapsed_ms=%start.elapsed().as_millis(), bytes=HDR.len(), mode="std", kind="405", "http: respond");
    Ok(())
}

async fn respond_403<S>(mut s: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let resp = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    use tokio::io::AsyncWriteExt;
    s.write_all(resp).await?;
    s.flush().await
}

fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_unspecified() // 0.0.0.0
        }
        std::net::IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || (ipv6.segments()[0] & 0xfe00) == 0xfc00 || ipv6.is_unspecified()
        }
    }
}

async fn respond_400<S>(stream: &mut S, msg: &str) -> anyhow::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let t0 = Instant::now();
    let body = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(body).await?;
    stream.flush().await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    let _ = stream.shutdown().await;
    if tracing::enabled!(tracing::Level::DEBUG) {
        tracing::debug!(
            "respond_400 dur_ms={} reason={}",
            t0.elapsed().as_millis(),
            msg
        );
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("http_respond_total", "code" => "400").increment(1);
        }
    }
    Ok(())
}

#[allow(dead_code)]
async fn respond_400_generic<S>(mut s: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let start = Instant::now();
    const HDR: &[u8] =
        b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    if http_legacy_write_enabled() {
        s.write_all(HDR).await?;
        #[allow(unused_must_use)]
        {
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;
        }
        debug!(elapsed_ms=%start.elapsed().as_millis(), mode="legacy", kind="400", "http: respond");
        return Ok(());
    }
    s.write_all(HDR).await?;
    tokio::io::AsyncWriteExt::flush(&mut s).await?;
    tokio::time::sleep(Duration::from_millis(10)).await;
    #[allow(unused_must_use)]
    {
        let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;
    }
    debug!(elapsed_ms=%start.elapsed().as_millis(), bytes=HDR.len(), mode="std", kind="400", "http: respond");
    Ok(())
}

#[allow(dead_code)] // Reserved for auth failures
async fn respond_403_tcp(cli: &mut TcpStream) -> Result<()> {
    let body = b"Forbidden";
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    cli.write_all(resp.as_bytes()).await?;
    cli.write_all(body).await?;
    // metrics: 403 count unified via http_respond_total
    // metrics: 403 计数统一走 http_respond_total
    #[cfg(feature = "metrics")]
    {
        metrics::counter!("http_respond_total", "code" => "403").increment(1);
    }
    Ok(())
}

#[allow(dead_code)]
async fn respond_502(cli: &mut TcpStream) -> Result<()> {
    let body = b"Bad Gateway";
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    cli.write_all(resp.as_bytes()).await?;
    cli.write_all(body).await?;
    Ok(())
}
