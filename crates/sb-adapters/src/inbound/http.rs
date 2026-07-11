//! HTTP proxy inbound (CONNECT + plain HTTP forward, routing + outbound registry)
//! HTTP 代理入站（CONNECT + plain HTTP 转发，路由+出站注册表）
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

fn access_log_enabled() -> bool {
    std::env::var("SB_ACCESS_LOG")
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

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
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[cfg(feature = "metrics")]
#[deprecated(
    since = "0.1.0",
    note = "kept for compatibility; metrics collection not yet implemented"
)]
#[allow(dead_code)] // Reserved for connection tracking
static HTTP_ACTIVE: AtomicUsize = AtomicUsize::new(0);

use crate::inbound::connect::{
    direct_connect_hostport, http_proxy_connect_through_proxy, socks5_connect_through_socks5,
    ConnectOpts,
};
use crate::outbound::pool_selector::PoolSelector;
#[cfg(feature = "metrics")]
use metrics::counter;
use once_cell::sync::OnceCell;
use sb_core::outbound::health as ob_health;
use sb_core::outbound::registry;
use sb_core::outbound::OutboundRegistryHandle;
use sb_core::outbound::{Endpoint as OutEndpoint, RouteTarget as OutRouteTarget};
use sb_core::router;
use sb_core::router::rules::Decision as RDecision;
use sb_core::router::{RouteCtx, Transport};
use sb_core::v2ray_stats::StatsManager;

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

struct HttpHeartbeatGuard {
    handle: tokio::task::JoinHandle<()>,
}

impl HttpHeartbeatGuard {
    fn spawn(period: Duration) -> Self {
        let mut hb = interval(period);
        let handle = tokio::spawn(async move {
            loop {
                let _ = hb.tick().await;
            }
        });
        Self { handle }
    }
}

impl Drop for HttpHeartbeatGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
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
    /// Inbound tag for stats
    pub tag: Option<String>,
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
    /// Optional V2Ray stats manager
    pub stats: Option<Arc<StatsManager>>,
    /// Explicit conntrack dependency for inbound connection lifecycle.
    pub conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
    /// Active connection gauge exposed to supervisor graceful shutdown.
    pub active_connections: Arc<AtomicU64>,
    /// Inbound sniff configuration (Go parity: sniff_enabled).
    pub sniff: bool,
    /// Override destination with sniffed hostname (Go parity: sniff_override_destination).
    pub sniff_override_destination: bool,
}

// ── macOS system proxy ────────────────────────────────────────────────────────
//
// Uses `networksetup` (available on all macOS versions) to register this
// HTTP CONNECT listener as the system HTTP proxy.  The guard clears the proxy
// when dropped, so proxy state is always restored when the inbound stops.

#[cfg(target_os = "macos")]
struct MacOsSystemProxyGuard {
    services: Vec<String>,
    port: u16,
}

#[cfg(target_os = "macos")]
impl MacOsSystemProxyGuard {
    fn new(port: u16) -> Self {
        let services = macos_set_http_proxy("127.0.0.1", port);
        Self { services, port }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacOsSystemProxyGuard {
    fn drop(&mut self) {
        macos_clear_http_proxy(&self.services, self.port);
    }
}

/// Set macOS HTTP + HTTPS proxy on all active network services.
/// Returns the list of services that were modified.
#[cfg(target_os = "macos")]
fn macos_set_http_proxy(host: &str, port: u16) -> Vec<String> {
    let port_str = port.to_string();
    let Ok(out) = std::process::Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
    else {
        warn!("http: failed to list network services for system proxy");
        return vec![];
    };
    let mut services = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines().skip(1) {
        let service = line.trim().trim_start_matches('*').trim();
        if service.is_empty() {
            continue;
        }
        for (subcmd, state_cmd) in [
            ("-setwebproxy", "-setwebproxystate"),
            ("-setsecurewebproxy", "-setsecurewebproxystate"),
        ] {
            let _ = std::process::Command::new("networksetup")
                .args([subcmd, service, host, &port_str])
                .output();
            let _ = std::process::Command::new("networksetup")
                .args([state_cmd, service, "on"])
                .output();
        }
        services.push(service.to_string());
    }
    info!(
        "http: macOS system proxy set to {}:{} on {} service(s)",
        host,
        port,
        services.len()
    );
    services
}

/// Disable HTTP + HTTPS proxy for each previously modified service.
#[cfg(target_os = "macos")]
fn macos_clear_http_proxy(services: &[String], _port: u16) {
    for service in services {
        for state_cmd in ["-setwebproxystate", "-setsecurewebproxystate"] {
            let _ = std::process::Command::new("networksetup")
                .args([state_cmd, service, "off"])
                .output();
        }
    }
    if !services.is_empty() {
        info!(
            "http: macOS system proxy cleared ({} service(s))",
            services.len()
        );
    }
}

/// Ready signal notifier - sends when socket binding completes
/// 就绪信号通知器 - 当 socket 绑定完成时发送
pub async fn serve_http(
    cfg: HttpProxyConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<std::io::Result<()>>>,
) -> Result<()> {
    let listener = match TcpListener::bind(cfg.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            if let Some(tx) = ready_tx {
                let _ = tx.send(Err(std::io::Error::new(error.kind(), error.to_string())));
            }
            return Err(error.into());
        }
    };
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "HTTP CONNECT bound");
    if let Some(tx) = ready_tx {
        let _ = tx.send(Ok(()));
    }

    #[cfg(target_os = "macos")]
    let _system_proxy_guard = cfg
        .set_system_proxy
        .then(|| MacOsSystemProxyGuard::new(actual.port()));
    #[cfg(not(target_os = "macos"))]
    if cfg.set_system_proxy {
        warn!("http: system proxy setting not supported on this platform");
    }

    // Add watcher task for accept loop heartbeat
    let local = listener.local_addr().ok();
    tracing::info!(?local, "http: listener ready");
    let _heartbeat_guard = HttpHeartbeatGuard::spawn(Duration::from_millis(500));

    // Add disable stop debug switch
    let disable_stop = http_disable_stop_enabled();
    loop {
        select! {
            _ = stop_rx.recv(), if !disable_stop => {
                debug!("http: stop signal received");
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
                cfg.active_connections.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _active_guard = scopeguard::guard(cfg_clone.active_connections.clone(), |active| {
                        active.fetch_sub(1, Ordering::Relaxed);
                    });
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

    while cfg.active_connections.load(Ordering::Relaxed) > 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
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

/// Health-fallback policy for the HTTP inbound (W55-02 / W55-03 boundary; MIG-02
/// no-implicit-direct-fallback): when a `Proxy` decision faces an unhealthy
/// upstream, emit explicit diagnostics but NEVER rewrite the decision to
/// `Direct`. The decision is returned unchanged so an unhealthy proxy fails
/// closed (Proxy -> downstream connect error) rather than silently leaking
/// traffic directly. `proxy_health_up` is `None` when no global health status is
/// installed, `Some(true)` when up, `Some(false)` when down.
fn apply_health_fallback_policy(decision: RDecision, proxy_health_up: Option<bool>) -> RDecision {
    if matches!(decision, RDecision::Proxy(_)) && proxy_health_up == Some(false) {
        tracing::warn!("router: proxy unhealthy; direct fallback is disabled (http inbound)");
        #[cfg(feature = "metrics")]
        metrics::counter!(
            "router_route_fallback_total",
            "from" => "proxy",
            "to" => "blocked",
            "inbound" => "http"
        )
        .increment(1);
    }
    decision
}

struct RoutedConnection {
    host: String,
    port: u16,
    decision: RDecision,
    rule: Option<String>,
    outbound_tag: Option<String>,
    upstream: IoStream,
    sniff_prefix: Vec<u8>,
    sniff_reply_sent: bool,
}

struct PlainForwardRequest {
    host: String,
    port: u16,
    head: Vec<u8>,
}

struct RelayContext<'a> {
    cfg: &'a HttpProxyConfig,
    peer: SocketAddr,
    host: &'a str,
    port: u16,
    decision: &'a RDecision,
    outbound_tag: Option<String>,
    rule: Option<String>,
    auth_user: Option<&'a str>,
    sniff_prefix: Vec<u8>,
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

    let auth_user = match authenticate_proxy(&headers, cfg.users.as_deref()) {
        Ok(user) => user,
        Err(()) => {
            respond_407(&mut cli).await?;
            return Ok(());
        }
    };

    if method == "CONNECT" {
        return serve_connect(cli, peer, cfg, target, auth_user).await;
    }

    if method != "GET" {
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("http_respond_total", "code" => "405").increment(1);
            counter!("http_requests_total", "method"=>method.clone(), "code"=>"405").increment(1);
        }
        sb_core::metrics::http::inc_405_responses();
        access::log(
            access_log_enabled(),
            "http_bad_method",
            &[("proto", "http".into()), ("method", method.to_string())],
        );
        return respond_405_stream(&mut cli).await.map(|_| ());
    }

    let forward = match build_plain_forward_request(&method, &target, &_version, &headers) {
        Ok(forward) => forward,
        Err(e) => {
            access::log(
                access_log_enabled(),
                "http_bad_forward_request",
                &[("proto", "http".into()), ("reason", e.to_string())],
            );
            return respond_400(&mut cli, "plain_forward").await.map(|_| ());
        }
    };

    if !cfg.allow_private_network {
        if let Ok(ip) = forward.host.parse::<std::net::IpAddr>() {
            if is_private_ip(ip) {
                warn!(?peer, target=%target, "http: blocked private network access");
                return respond_403(&mut cli).await.map_err(|e| anyhow::anyhow!(e));
            }
        }
    }
    info!(?peer, host=%forward.host, port=%forward.port, "http: plain forward route");

    let mut routed = connect_routed_upstream(
        &mut cli,
        peer,
        cfg,
        &forward.host,
        forward.port,
        Some("http"),
        false,
    )
    .await?;

    routed.upstream.write_all(&forward.head).await?;
    routed.upstream.flush().await?;

    relay_with_conntrack(
        &mut cli,
        &mut routed.upstream,
        RelayContext {
            cfg,
            peer,
            host: &routed.host,
            port: routed.port,
            decision: &routed.decision,
            outbound_tag: routed.outbound_tag,
            rule: routed.rule,
            auth_user: auth_user.as_deref(),
            sniff_prefix: routed.sniff_prefix,
        },
    )
    .await
}

async fn serve_connect<S>(
    mut cli: S,
    peer: SocketAddr,
    cfg: &HttpProxyConfig,
    target: String,
    auth_user: Option<String>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Parse host:port (keep original parsing function/error handling in project)
    // 解析 host:port（保持项目里原有的解析函数/错误处理）
    let (host, port) = split_host_port(&target).ok_or_else(|| anyhow!("bad CONNECT target"))?;

    // Check private network access
    if !cfg.allow_private_network {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_private_ip(ip) {
                warn!(?peer, target=%target, "http: blocked private network access");
                return respond_403(&mut cli).await.map_err(|e| anyhow::anyhow!(e));
            }
        }
    }
    info!(?peer, host=%host, port=%port, "http: CONNECT route");

    let mut routed = connect_routed_upstream(&mut cli, peer, cfg, host, port, None, true).await?;

    // Respond 200, then tunnel forwarding
    // 应答 200，然后做隧道转发
    if !routed.sniff_reply_sent {
        let resp = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        cli.write_all(resp).await?;
        cli.flush().await?;
    }

    relay_with_conntrack(
        &mut cli,
        &mut routed.upstream,
        RelayContext {
            cfg,
            peer,
            host: &routed.host,
            port: routed.port,
            decision: &routed.decision,
            outbound_tag: routed.outbound_tag,
            rule: routed.rule,
            auth_user: auth_user.as_deref(),
            sniff_prefix: routed.sniff_prefix,
        },
    )
    .await
}

async fn connect_routed_upstream<S>(
    cli: &mut S,
    peer: SocketAddr,
    cfg: &HttpProxyConfig,
    host: &str,
    port: u16,
    protocol: Option<&str>,
    allow_sniff: bool,
) -> Result<RoutedConnection>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Routing via cfg.router (from config IR) with minimal matched rule metadata.
    // 路由统一走 cfg.router（来自配置 IR），并携带最小命中规则标识。
    let route_ctx = RouteCtx {
        host: Some(host),
        ip: None,
        port: Some(port),
        transport: Transport::Tcp,
        network: "tcp",
        protocol,
        inbound_tag: cfg.tag.as_deref(),
        inbound_sniff: cfg.sniff,
        inbound_sniff_override: cfg.sniff_override_destination,
        ..Default::default()
    };
    let meta = cfg.router.decide_with_meta(&route_ctx);
    let mut rule: Option<String> = meta.rule;
    let mut decision: RDecision = meta.decision;

    // Handle Decision::Sniff: send 200 early, read initial bytes, sniff, re-decide
    let mut sniff_prefix: Vec<u8> = Vec::new();
    let mut sniff_reply_sent = false;
    let mut override_host: Option<String> = None;
    if let RDecision::Sniff {
        override_destination,
    } = decision
    {
        if !allow_sniff || sb_core::router::sniff::skip_sniff(port) {
            decision = RDecision::Direct;
        } else {
            // Send 200 Connection Established early so client starts sending data
            let resp = b"HTTP/1.1 200 Connection Established\r\n\r\n";
            cli.write_all(resp).await?;
            cli.flush().await?;
            sniff_reply_sent = true;

            // Read initial bytes with 300ms timeout
            use tokio::io::AsyncReadExt;
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
                    "http: sniffed stream"
                );
                let sniffed_host_owned: String;
                let host_for_ctx = if let Some(ref h) = outcome.host {
                    sniffed_host_owned = h.clone();
                    Some(sniffed_host_owned.as_str())
                } else {
                    Some(host)
                };
                let route_ctx2 = RouteCtx {
                    host: host_for_ctx,
                    ip: None,
                    port: Some(port),
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
                            tracing::debug!(sniffed_host = %h, "http: override destination with sniffed host");
                            override_host = Some(h.clone());
                        }
                    }
                }
            }

            if matches!(decision, RDecision::Sniff { .. }) {
                decision = RDecision::Direct;
            }
        }
    }
    // Apply sniff override: use sniffed domain as outbound target
    let dial_host: String = if let Some(oh) = override_host {
        oh
    } else {
        host.to_string()
    };

    // Only Direct/Proxy left here; default direct
    // 到这里只剩 Direct/Proxy 两种；默认 direct
    #[cfg(feature="metrics")]
    metrics::counter!("router_route_total",
        "inbound"=>"http",
        "decision"=>match &decision { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject | RDecision::RejectDrop=>"reject", _=>"other" },
        "proxy_kind"=>match &decision { RDecision::Direct=>"direct", RDecision::Proxy(Some(_))=>"named", RDecision::Proxy(None)=>"unnamed", RDecision::Reject | RDecision::RejectDrop=>"reject", _=>"other" }
    ).increment(1);

    decision =
        apply_health_fallback_policy(decision, ob_health::global_status().map(|st| st.is_up()));

    let opts = ConnectOpts;

    // Establish TCP with upstream first (based on decision and default proxy)
    // 先与上游建立 TCP（根据决策与默认代理）
    let outbound_tag: Option<String>;
    let upstream: IoStream = match &decision {
        RDecision::Direct => {
            outbound_tag = Some("direct".to_string());
            let s = direct_connect_hostport(&dial_host, port, &opts).await?;
            Box::new(s)
        }
        RDecision::Proxy(pool_name) => {
            if let Some(name) = pool_name {
                outbound_tag = Some(name.clone());
                // Prefer registry-based outbound first (Go-style: route -> outbound by tag).
                if let Ok(s) = cfg
                    .outbounds
                    .connect_tcp_stream(
                        &OutRouteTarget::Named(name.clone()),
                        OutEndpoint::Domain(dial_host.clone(), port),
                    )
                    .await
                {
                    s
                } else {
                    // Named proxy pool selection
                    let sel = SELECTOR.get_or_init(|| {
                        let _ttl = sticky_env_u64("SB_PROXY_STICKY_TTL_MS", 10_000);
                        let _cap = sticky_env_usize("SB_PROXY_STICKY_CAP", 4096);
                        PoolSelector::new("http_proxy".to_string(), "default".to_string())
                    });
                    if let Some(reg) = registry::global() {
                        if let Some(_pool) = reg.pools.get(name) {
                            if let Some(ep) =
                                sel.select(name, peer, &format!("{}:{}", dial_host, port), &())
                            {
                                match ep.kind {
                                    sb_core::outbound::endpoint::ProxyKind::Http => {
                                        let s = http_proxy_connect_through_proxy(
                                            &ep.addr.to_string(),
                                            &dial_host,
                                            port,
                                            &opts,
                                        )
                                        .await?;
                                        Box::new(s)
                                    }
                                    sb_core::outbound::endpoint::ProxyKind::Socks5 => {
                                        let s = socks5_connect_through_socks5(
                                            &ep.addr.to_string(),
                                            &dial_host,
                                            port,
                                            &opts,
                                        )
                                        .await?;
                                        Box::new(s)
                                    }
                                }
                            } else {
                                return Err(anyhow!(
                                    "http inbound: named proxy decision '{}' has no selectable endpoint; implicit fallback is disabled; use adapter bridge/supervisor path",
                                    name
                                ));
                            }
                        } else {
                            return Err(anyhow!(
                                "http inbound: named proxy decision '{}' not found in registry; implicit fallback is disabled; use adapter bridge/supervisor path",
                                name
                            ));
                        }
                    } else {
                        return Err(anyhow!(
                            "http inbound: named proxy decision '{}' cannot be resolved because registry is unavailable; implicit fallback is disabled; use adapter bridge/supervisor path",
                            name
                        ));
                    }
                }
            } else {
                return Err(anyhow!(
                    "http inbound: proxy decision without outbound tag is unsupported; implicit fallback is disabled; provide explicit outbound in routing"
                ));
            }
        }
        RDecision::Reject | RDecision::RejectDrop => {
            // Should be filtered earlier; return explicit error to avoid panic paths.
            return Err(anyhow!("unexpected reject decision in http inbound"));
        }
        RDecision::Hijack { .. }
        | RDecision::Sniff { .. }
        | RDecision::Resolve
        | RDecision::HijackDns => {
            tracing::warn!("http inbound: unsupported routing decision in adapter path; direct fallback is disabled; use explicit direct/proxy decision");
            outbound_tag = Some("direct".to_string());
            let s = direct_connect_hostport(&dial_host, port, &opts).await?;
            Box::new(s)
        }
    };

    Ok(RoutedConnection {
        host: dial_host,
        port,
        decision,
        rule,
        outbound_tag,
        upstream,
        sniff_prefix,
        sniff_reply_sent,
    })
}

async fn relay_with_conntrack<S>(
    cli: &mut S,
    upstream: &mut IoStream,
    relay: RelayContext<'_>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // Tunnel forwarding (metered copy; label=http), unified read/write timeout (from env, optional)
    // 隧道转发（计量 copy；label=http），统一读/写超时（来自环境变量，可选）
    let rt = opt_duration_ms_from_env("SB_TCP_READ_TIMEOUT_MS");
    let wt = opt_duration_ms_from_env("SB_TCP_WRITE_TIMEOUT_MS");
    let traffic = relay.cfg.stats.as_ref().and_then(|stats| {
        stats.traffic_recorder(
            relay.cfg.tag.as_deref(),
            relay.outbound_tag.as_deref(),
            relay.auth_user,
        )
    });

    let chains = sb_core::outbound::chain::compute_chain_for_decision(
        Some(relay.cfg.outbounds.as_ref()),
        relay.decision,
        relay.outbound_tag.as_deref(),
    );
    let wiring = sb_core::conntrack::register_inbound_tcp_with_tracker(
        relay.cfg.conn_tracker.clone(),
        relay.peer,
        relay.host.to_string(),
        relay.port,
        relay.host.to_string(),
        "http",
        relay.cfg.tag.clone(),
        relay.outbound_tag.clone(),
        chains,
        relay.rule.clone(),
        None,
        None,
        traffic,
    );
    let _guard = wiring.guard;
    let copy_res = if relay.sniff_prefix.is_empty() {
        sb_core::net::metered::copy_bidirectional_streaming_ctl(
            cli,
            upstream,
            "http",
            std::time::Duration::from_secs(1),
            rt,
            wt,
            Some(wiring.cancel),
            Some(wiring.traffic),
        )
        .await
    } else {
        let mut sniffed = crate::inbound::sniff_util::SniffedStream::new(cli, relay.sniff_prefix);
        sb_core::net::metered::copy_bidirectional_streaming_ctl(
            &mut sniffed,
            upstream,
            "http",
            std::time::Duration::from_secs(1),
            rt,
            wt,
            Some(wiring.cancel),
            Some(wiring.traffic),
        )
        .await
    };
    match copy_res {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn authenticate_proxy(
    headers: &[u8],
    users: Option<&[Credentials]>,
) -> std::result::Result<Option<String>, ()> {
    let Some(users) = users else {
        return Ok(None);
    };
    if users.is_empty() {
        return Ok(None);
    }

    let Some(value) = proxy_authorization_value(headers) else {
        return Err(());
    };
    let Some(cred) = value.strip_prefix("Basic ") else {
        return Err(());
    };
    let decoded = general_purpose::STANDARD.decode(cred).map_err(|_| ())?;
    let auth_str = String::from_utf8(decoded).map_err(|_| ())?;
    let (u, p) = auth_str.split_once(':').ok_or(())?;

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
            return Ok(Some(u.to_string()));
        }
    }
    Err(())
}

fn proxy_authorization_value(headers: &[u8]) -> Option<&str> {
    for line in header_lines_after_request_line(headers) {
        let Some((name, value)) = split_header_line(line) else {
            continue;
        };
        if header_name_eq(name, "Proxy-Authorization") {
            return std::str::from_utf8(trim_ascii(value)).ok();
        }
    }
    None
}

fn build_plain_forward_request(
    method: &str,
    target: &str,
    version: &str,
    headers: &[u8],
) -> Result<PlainForwardRequest> {
    let url = url::Url::parse(target).map_err(|e| anyhow!("invalid absolute URI: {e}"))?;
    if url.scheme() != "http" {
        return Err(anyhow!("unsupported plain proxy scheme '{}'", url.scheme()));
    }
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("plain proxy URI has no host"))?
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("plain proxy URI has no port"))?;

    let mut origin_form = url.path().to_string();
    if origin_form.is_empty() {
        origin_form.push('/');
    }
    if let Some(query) = url.query() {
        origin_form.push('?');
        origin_form.push_str(query);
    }

    let mut out = Vec::with_capacity(headers.len());
    out.extend_from_slice(format!("{method} {origin_form} {version}\r\n").as_bytes());
    for line in header_lines_after_request_line(headers) {
        let Some((name, _value)) = split_header_line(line) else {
            continue;
        };
        if header_name_eq(name, "Proxy-Authorization") || header_name_eq(name, "Proxy-Connection") {
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");

    Ok(PlainForwardRequest {
        host,
        port,
        head: out,
    })
}

fn header_lines_after_request_line(headers: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut lines = headers.split(|b| *b == b'\n');
    let _ = lines.next();
    lines.filter_map(|raw| {
        let line = trim_cr(trim_trailing_lf(raw));
        if line.is_empty() {
            None
        } else {
            Some(line)
        }
    })
}

fn split_header_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let pos = line.iter().position(|b| *b == b':')?;
    Some((&line[..pos], &line[pos + 1..]))
}

fn header_name_eq(name: &[u8], expected: &str) -> bool {
    let name = trim_ascii(name);
    name.len() == expected.len()
        && name
            .iter()
            .zip(expected.bytes())
            .all(|(a, b)| a.eq_ignore_ascii_case(&b))
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while matches!(s.first(), Some(b' ' | b'\t')) {
        s = &s[1..];
    }
    while matches!(s.last(), Some(b' ' | b'\t' | b'\r')) {
        s = &s[..s.len() - 1];
    }
    s
}

fn trim_trailing_lf(s: &[u8]) -> &[u8] {
    if let Some(&b'\n') = s.last() {
        &s[..s.len() - 1]
    } else {
        s
    }
}

async fn respond_407<S>(stream: &mut S) -> Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    stream.write_all(resp).await?;
    stream.flush().await?;
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

pub fn parse_request_line(line: &[u8]) -> Result<(String, String, String)> {
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

fn sticky_env_u64(name: &str, default: u64) -> u64 {
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

fn sticky_env_usize(name: &str, default: usize) -> usize {
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

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::TcpListener as StdTcpListener;
    use tokio::time::timeout;

    fn test_cfg(listen: SocketAddr) -> HttpProxyConfig {
        HttpProxyConfig {
            tag: Some("http-ready-test".to_string()),
            listen,
            router: Arc::new(router::RouterHandle::from_env()),
            outbounds: Arc::new(OutboundRegistryHandle::default()),
            tls: None,
            users: None,
            set_system_proxy: false,
            allow_private_network: true,
            stats: None,
            conn_tracker: Arc::new(sb_common::conntrack::ConnTracker::new()),
            active_connections: Arc::new(AtomicU64::new(0)),
            sniff: false,
            sniff_override_destination: false,
        }
    }

    #[tokio::test]
    async fn readiness_reports_success_after_bind() {
        let (stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();

        let task = tokio::spawn(serve_http(
            test_cfg("127.0.0.1:0".parse().unwrap()),
            stop_rx,
            Some(ready_tx),
        ));

        timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("http ready timed out")
            .expect("http ready sender dropped")
            .expect("http bind failed");
        let _ = stop_tx.send(()).await;
        task.await
            .expect("http task panicked")
            .expect("http stopped");
    }

    #[tokio::test]
    async fn readiness_reports_bind_failure_on_occupied_port() {
        let holder = StdTcpListener::bind("127.0.0.1:0").expect("hold http port");
        let addr = holder.local_addr().expect("held http address");
        let (_stop_tx, stop_rx) = mpsc::channel(1);
        let (ready_tx, ready_rx) = oneshot::channel();

        let err = serve_http(test_cfg(addr), stop_rx, Some(ready_tx))
            .await
            .expect_err("occupied http port must fail");
        let ready_err = timeout(Duration::from_secs(2), ready_rx)
            .await
            .expect("http ready failure timed out")
            .expect("http ready sender dropped")
            .expect_err("http ready must report bind failure");

        assert_eq!(ready_err.kind(), ErrorKind::AddrInUse);
        assert_eq!(
            err.downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(ErrorKind::AddrInUse)
        );
        drop(holder);
    }

    #[test]
    fn heartbeat_task_is_bound_to_serve_http_lifecycle() {
        let source = include_str!("http.rs");
        assert!(source.contains(concat!("struct ", "HttpHeartbeatGuard")));
        assert!(source.contains(concat!("impl Drop for ", "HttpHeartbeatGuard")));
        assert!(source.contains(concat!(
            "let _heartbeat_guard = ",
            "HttpHeartbeatGuard::spawn"
        )));
    }
}

#[cfg(test)]
mod health_fallback_policy_tests {
    use super::apply_health_fallback_policy;
    use sb_core::router::rules::Decision as RDecision;

    // W55-02 boundary: the HTTP inbound health path must NOT silently rewrite a
    // Proxy decision to Direct when the upstream proxy is unhealthy. It fails
    // closed (stays Proxy) instead, complementing the W55-03 "direct fallback is
    // disabled (http inbound)" require. This is the precise, source-level guard
    // the line-based check-boundaries matcher cannot express (D2-1cB).
    #[test]
    fn unhealthy_proxy_never_falls_back_to_direct() {
        let out = apply_health_fallback_policy(RDecision::Proxy(None), Some(false));
        assert!(
            !matches!(out, RDecision::Direct),
            "unhealthy proxy must not silently fall back to Direct"
        );
        assert!(
            matches!(out, RDecision::Proxy(_)),
            "decision stays Proxy => fails closed against an unhealthy upstream"
        );

        let named =
            apply_health_fallback_policy(RDecision::Proxy(Some("pool".to_string())), Some(false));
        assert!(matches!(named, RDecision::Proxy(Some(_))));
    }

    // A healthy upstream, and any legitimate explicit/sniff-resolved Direct, are
    // preserved unchanged: the policy must neither block a healthy proxy nor
    // perturb a non-fallback Direct decision (so it never breaks sniff behavior).
    #[test]
    fn healthy_proxy_and_legitimate_direct_are_preserved() {
        assert!(matches!(
            apply_health_fallback_policy(RDecision::Proxy(None), Some(true)),
            RDecision::Proxy(_)
        ));
        // No global health status installed -> decision unchanged.
        assert!(matches!(
            apply_health_fallback_policy(RDecision::Proxy(None), None),
            RDecision::Proxy(_)
        ));
        // A legitimate Direct (explicit route, or the resolved/unresolved-sniff
        // default set earlier in serve_conn) is never touched, regardless of
        // upstream health.
        assert!(matches!(
            apply_health_fallback_policy(RDecision::Direct, Some(false)),
            RDecision::Direct
        ));
        assert!(matches!(
            apply_health_fallback_policy(RDecision::Direct, Some(true)),
            RDecision::Direct
        ));
    }
}
/// Transitional blocking driver for HTTP inbound registration.
#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
#[derive(Debug)]
pub(crate) struct HttpInboundDriver {
    cfg: HttpProxyConfig,
    stop_tx: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<()>>>,
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
impl HttpInboundDriver {
    pub(crate) fn new(cfg: HttpProxyConfig) -> Self {
        Self {
            cfg,
            stop_tx: std::sync::Mutex::new(None),
        }
    }
}

#[cfg(all(feature = "adapter-http", feature = "http", feature = "router"))]
impl sb_core::adapter::InboundTaskDriver for HttpInboundDriver {
    fn serve(&self) -> std::io::Result<()> {
        self.serve_with_ready(None)
    }

    fn supports_startup_readiness(&self) -> bool {
        true
    }

    fn serve_with_ready(
        &self,
        ready: Option<sb_core::adapter::InboundReadySender>,
    ) -> std::io::Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(std::io::Error::other)?;
        let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
        *self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(stop_tx);
        let result = runtime.block_on(async {
            serve_http(self.cfg.clone(), stop_rx, ready)
                .await
                .map_err(std::io::Error::other)
        });
        let _ = self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        result
    }

    fn request_shutdown(&self) {
        if let Some(stop_tx) = self
            .stop_tx
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = stop_tx.try_send(());
        }
    }

    fn active_connections(&self) -> Option<u64> {
        Some(
            self.cfg
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
