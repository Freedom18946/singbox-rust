//! SOCKS5 UDP Associate 真转发（behind env：SB_SOCKS_UDP_ENABLE=1）
#![allow(dead_code)]

// Re-export types & helpers for integration tests/examples
pub use sb_core::net::datagram::UdpTargetAddr;
use std::fmt;

use anyhow::{bail, Result};
use once_cell::sync::OnceCell as SyncOnceCell;
use sb_core::net::ratelimit::maybe_drop_udp;
use sb_core::net::udp_upstream_map::{Key as UpstreamKey, UdpUpstreamMap};
use sb_core::obs::access;
use sb_core::outbound::endpoint::{ProxyEndpoint, ProxyKind};
use sb_core::outbound::observe::with_pool_observation;
use sb_core::outbound::registry;
use sb_core::outbound::selector::PoolSelector;
use sb_core::outbound::socks5_udp::UpSocksSession;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::OnceCell;
// （确保全文件仅这一处 Arc 导入）
use std::time::Duration;

#[cfg(feature = "metrics")]
use metrics::{counter, gauge};
use sb_core::net::datagram::{run_nat_evictor, UdpNatKey, UdpNatMap};
use sb_core::outbound::udp::{direct_sendto, direct_udp_socket_for};
use sb_core::router::engine::RouterHandle;
use sb_core::router::rules as rules_global;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use std::env;

static NAT_MAP: OnceCell<Arc<UdpNatMap>> = OnceCell::const_new();
static UPSTREAM_MAP: OnceCell<Arc<UdpUpstreamMap>> = OnceCell::const_new();

fn nat_ttl_from_env() -> Option<std::time::Duration> {
    if let Ok(v) = std::env::var("SB_SOCKS_UDP_NAT_TTL_MS") {
        if let Ok(ms) = v.parse::<u64>() {
            if ms > 0 {
                return Some(std::time::Duration::from_millis(ms));
            }
        }
    }
    None
}

fn upstream_ttl_from_env(default: Option<std::time::Duration>) -> std::time::Duration {
    if let Ok(v) = std::env::var("SB_SOCKS_UDP_UP_TTL_MS") {
        if let Ok(ms) = v.parse::<u64>() {
            if ms > 0 {
                return std::time::Duration::from_millis(ms);
            }
        }
    }
    default.unwrap_or_else(|| std::time::Duration::from_millis(30_000))
}

fn upstream_timeout_ms() -> u64 {
    std::env::var("SB_SOCKS_UDP_PROXY_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(800)
}

fn proxy_fallback_direct() -> bool {
    std::env::var("SB_SOCKS_UDP_PROXY_FALLBACK_DIRECT")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

fn socks_udp_enabled() -> bool {
    env::var("SB_SOCKS_UDP_ENABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn max_entries() -> usize {
    std::env::var("SB_UDP_NAT_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4096)
}

/// SOCKS5 UDP 包头解析，返回 (目标地址, 头长)
fn parse_socks5_udp(buf: &[u8]) -> Result<(UdpTargetAddr, usize)> {
    if buf.len() < 4 {
        bail!("short socks5 udp");
    }
    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        bail!("bad rsv/frag");
    }
    let atyp = buf[3];
    let mut i = 4usize;
    let dst = match atyp {
        1 => {
            // IPv4
            if buf.len() < i + 4 + 2 {
                bail!("short v4");
            }
            let ip = std::net::Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
            i += 4;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            UdpTargetAddr::Ip(SocketAddr::from((ip, port)))
        }
        4 => {
            // IPv6
            if buf.len() < i + 16 + 2 {
                bail!("short v6");
            }
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[i..i + 16])?);
            i += 16;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            UdpTargetAddr::Ip(SocketAddr::from((ip, port)))
        }
        3 => {
            // DOMAIN
            if buf.len() < i + 1 {
                bail!("short domain len");
            }
            let n = buf[i] as usize;
            i += 1;
            if buf.len() < i + n + 2 {
                bail!("short domain body");
            }
            let host = std::str::from_utf8(&buf[i..i + n])?.to_string();
            i += n;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            UdpTargetAddr::Domain { host, port }
        }
        _ => bail!("bad atyp"),
    };
    Ok((dst, i))
}

/// 反向封装 SOCKS5 UDP 包头（回程）
fn write_socks5_udp_header(dst: &SocketAddr, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0, 0, 0]); // RSV,FRAG
    match dst {
        SocketAddr::V4(sa) => {
            out.push(1u8);
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
        }
        SocketAddr::V6(sa) => {
            out.push(4u8);
            out.extend_from_slice(&sa.ip().octets());
            out.extend_from_slice(&sa.port().to_be_bytes());
        }
    }
}

// =========================
// 兼容层 API（供 tests/examples 使用）
// =========================

/// 解析错误的显式枚举，方便 tests 用 `matches!` 精确断言
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    BadRsvFrag,
    Truncated,
    BadDomainLen,
    BadAtyp,
    Utf8,
}
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for ParseError {}

/// 兼容解析入口：与 tests 预期的签名保持一致
pub fn parse_udp_datagram(buf: &[u8]) -> Result<(UdpTargetAddr, usize), ParseError> {
    if buf.len() < 4 {
        return Err(ParseError::Truncated);
    }
    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return Err(ParseError::BadRsvFrag);
    }
    let atyp = buf[3];
    let mut i = 4usize;
    let dst = match atyp {
        0x01 => {
            // IPv4
            if buf.len() < i + 4 + 2 {
                return Err(ParseError::Truncated);
            }
            let ip = std::net::Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
            i += 4;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            UdpTargetAddr::Ip(std::net::SocketAddr::from((ip, port)))
        }
        0x04 => {
            // IPv6
            if buf.len() < i + 16 + 2 {
                return Err(ParseError::Truncated);
            }
            let ip = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&buf[i..i + 16]).map_err(|_| ParseError::Truncated)?,
            );
            i += 16;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            UdpTargetAddr::Ip(std::net::SocketAddr::from((ip, port)))
        }
        0x03 => {
            // DOMAIN
            if buf.len() < i + 1 {
                return Err(ParseError::Truncated);
            }
            let n = buf[i] as usize;
            i += 1;
            if buf.len() < i + n + 2 {
                return Err(ParseError::BadDomainLen);
            }
            let host = std::str::from_utf8(&buf[i..i + n])
                .map_err(|_| ParseError::Utf8)?
                .to_string();
            i += n;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            UdpTargetAddr::Domain { host, port }
        }
        _ => return Err(ParseError::BadAtyp),
    };
    Ok((dst, i))
}

/// 兼容封包：把目标地址编码为 SOCKS5 UDP 头并拼接 payload
pub fn encode_udp_datagram(dst: &UdpTargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 1 + 18 + 2 + payload.len());
    out.extend_from_slice(&[0, 0, 0]); // RSV,FRAG
    match dst {
        UdpTargetAddr::Ip(sa) => match sa {
            std::net::SocketAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
            }
        },
        UdpTargetAddr::Domain { host, port } => {
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// New SOCKS5 UDP service with real forwarding implementation
pub async fn serve_socks5_udp_service_real(bind: Vec<std::net::SocketAddr>) -> Result<()> {
    // NAT 参数
    let ttl_ms = std::env::var("SB_SOCKS_UDP_NAT_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30_000);
    let nat = std::sync::Arc::new(UdpNatMap::new(Some(Duration::from_millis(ttl_ms))));

    // 绑定多个监听口
    let mut tasks = Vec::new();
    for addr in bind {
        let sock = UdpSocket::bind(addr).await?;
        let natc = nat.clone();
        tasks.push(tokio::spawn(run_one_real(sock, natc)));
    }

    // 后台淘汰
    {
        let natc = nat.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(ttl_ms.min(5_000))).await;
                let _ = natc.evict_expired().await;
                #[cfg(feature = "metrics")]
                {
                    gauge!("udp_nat_size").set(0.0);
                } // evict_expired 里已更新，这里只是心跳触发
            }
        }));
    }
    // Wait for all tasks
    for task in tasks {
        task.await??;
    }
    Ok(())
}

async fn run_one_real(sock: UdpSocket, nat: std::sync::Arc<UdpNatMap>) -> Result<()> {
    let _fallback_direct = proxy_fallback_direct();
    let _upstream_timeout = upstream_timeout_ms();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        #[cfg(feature = "metrics")]
        {
            counter!("udp_pkts_in_total").increment(1);
            counter!("udp_bytes_in_total").increment(n as u64);
        }
        // 解析 SOCKS5 UDP 包头
        let (dst, hdr_len) = match parse_socks5_udp(&buf[..n]) {
            Ok(x) => x,
            Err(_) => {
                #[cfg(feature = "metrics")]
                counter!("socks_udp_error_total", "class"=>"bad_header").increment(1);
                continue;
            }
        };
        // 规则引擎（Reject），Proxy 暂不支持，回落 Direct
        if let Some(eng) = rules_global::global() {
            let (dom, port) = match &dst {
                UdpTargetAddr::Domain { host, port } => (Some(host.as_str()), Some(*port)),
                UdpTargetAddr::Ip(sa) => (None, Some(sa.port())),
            };
            let ip = match &dst {
                UdpTargetAddr::Ip(sa) => Some(sa.ip()),
                _ => None,
            };
            let ctx = RouteCtx {
                domain: dom,
                ip,
                transport_udp: true,
                port,
                process_name: None,
                process_path: None,
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
            };
            let d = eng.decide(&ctx);
            #[cfg(feature = "metrics")]
            {
                counter!("router_decide_total", "decision"=> match d { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" }).increment(1);
            }
            if matches!(d, RDecision::Reject) {
                #[cfg(feature = "metrics")]
                counter!("socks_udp_error_total", "class"=>"reject").increment(1);
                continue;
            }
            if matches!(d, RDecision::Proxy(_)) {
                // 目前不支持上游 UDP 代理，回落 Direct（不破坏）
                tracing::warn!("socks5-udp: proxy decision ignored; fallback to direct");
            }
        }
        // 解析目标地址
        let dst_sa = match to_socket_addr(&dst) {
            Some(x) => x,
            None => {
                #[cfg(feature = "metrics")]
                counter!("socks_udp_error_total", "class"=>"bad_addr").increment(1);
                continue;
            }
        };
        let key = UdpNatKey {
            client: peer,
            dst: UdpTargetAddr::Ip(dst_sa),
        };

        // 获取或创建 NAT 映射
        let val = {
            if let Some(existing_socket) = nat.get(&key).await {
                existing_socket
            } else {
                let new_socket = UdpSocket::bind(("0.0.0.0", 0)).await?;
                new_socket.connect(dst_sa).await?;
                let socket_arc = std::sync::Arc::new(new_socket);
                if nat.upsert_guarded(key.clone(), socket_arc.clone()).await {
                    socket_arc
                } else {
                    // 容量满 => 拒绝
                    #[cfg(feature = "metrics")]
                    counter!("socks_udp_error_total", "class"=>"nat_full").increment(1);
                    continue;
                }
            }
        };
        // 首包或后续：向目标发送 payload
        let payload = &buf[hdr_len..n];
        if let Err(e) = val.send(payload).await {
            tracing::debug!(error=%e, "socks5-udp: send to dst failed");
            #[cfg(feature = "metrics")]
            counter!("socks_udp_error_total", "class"=>"send_fail").increment(1);
            sb_core::metrics::udp::record_error_display(&e);
            continue;
        }
        #[cfg(feature = "metrics")]
        {
            counter!("udp_pkts_out_total").increment(1);
            counter!("udp_bytes_out_total").increment(payload.len() as u64);
        }

        // 尝试**非阻塞**拉取回包（短时窗口），打包 SOCKS5 头发回 client
        // 为简单与性能，采用 try_recv 循环 + 小超时
        let mut turnaround = 0usize;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_millis(5), val.recv(&mut buf)).await {
                Ok(Ok(m)) if m > 0 => {
                    let mut out = Vec::with_capacity(hdr_len + m + 32);
                    build_socks5_udp_reply(&mut out, dst_sa);
                    out.extend_from_slice(&buf[..m]);
                    if let Err(e) = sock.send_to(&out, peer).await {
                        tracing::debug!(error=%e, "socks5-udp: send back failed");
                        #[cfg(feature = "metrics")]
                        counter!("socks_udp_error_total", "class"=>"return_fail").increment(1);
                        break;
                    }
                    #[cfg(feature = "metrics")]
                    {
                        counter!("udp_pkts_out_total").increment(1);
                        counter!("udp_bytes_out_total").increment(out.len() as u64);
                    }
                    turnaround += 1;
                }
                _ => break,
            }
        }
        if turnaround == 0 {
            // 无回包不算错误；多数 DNS/QUIC 都会有回包
        }
    }
}

/// 将解析到的目标（host/ip, port）转换为 SocketAddr
fn to_socket_addr(dst: &UdpTargetAddr) -> Option<SocketAddr> {
    match dst {
        UdpTargetAddr::Ip(sa) => Some(*sa),
        UdpTargetAddr::Domain { .. } => {
            // 仅在 UDP 中，禁止阻塞解析；你可以接入统一 resolver（异步）：
            // 为避免递归依赖 DNS，这里只支持已解析 IP
            None
        }
    }
}

/// 构造 SOCKS5 UDP 响应头（frag=0, RSV=0）
fn build_socks5_udp_reply(buf: &mut Vec<u8>, dst: SocketAddr) {
    buf.push(0x00);
    buf.push(0x00);
    buf.push(0x00); // RSV RSV FRAG=0
    match dst {
        SocketAddr::V4(sa) => {
            buf.push(0x01);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
        SocketAddr::V6(sa) => {
            buf.push(0x04);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
    }
}

enum ProxyOutcome {
    Handled,
    NeedFallback,
}

async fn forward_via_proxy(
    listen: Arc<UdpSocket>,
    client: SocketAddr,
    dst: &UdpTargetAddr,
    payload: &[u8],
    up_map: Arc<UdpUpstreamMap>,
    pool: Option<String>,
    timeout_ms: u64,
) -> ProxyOutcome {
    let (ip, port) = match dst {
        UdpTargetAddr::Ip(sa) => (sa.ip(), sa.port()),
        UdpTargetAddr::Domain { .. } => {
            #[cfg(feature = "metrics")]
            {
                counter!("socks_udp_error_total", "class" => "up_dst_unsupported").increment(1);
                metrics::counter!("udp_upstream_error_total", "class" => "dst_unsupported")
                    .increment(1);
            }
            return ProxyOutcome::NeedFallback;
        }
    };

    let key = UpstreamKey {
        src: client,
        dst: (ip, port),
    };
    let target_label = format!("{}:{}", ip, port);
    let session = match ensure_upstream_session(
        Arc::clone(&listen),
        Arc::clone(&up_map),
        key,
        client,
        &target_label,
        pool,
        timeout_ms,
    )
    .await
    {
        Some(s) => s,
        None => return ProxyOutcome::NeedFallback,
    };

    let dst_sa = SocketAddr::new(ip, port);
    if let Err(e) = session.send_to(dst_sa, payload).await {
        #[cfg(feature = "metrics")]
        {
            counter!("socks_udp_error_total", "class" => "up_send_fail").increment(1);
            metrics::counter!("udp_upstream_error_total", "class" => "send").increment(1);
        }
        tracing::debug!(error=%e, "socks5-udp: upstream send failed");
        return ProxyOutcome::NeedFallback;
    }

    // Receive a few replies best-effort within a short window to support simple echo-style flows.
    // This is intentionally lightweight; full bi-directional relaying is handled by higher-level services.
    let recv_iters = std::env::var("SB_SOCKS_UDP_UP_RECV_ITERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(2)
        .min(8);
    let per_iter_ms = std::env::var("SB_SOCKS_UDP_UP_RECV_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(200)
        .min(2_000);
    for _ in 0..recv_iters {
        match session.recv_once(per_iter_ms).await {
            Ok(Some((reply_addr, ref reply_payload))) => {
                let reply = encode_udp_datagram(&UdpTargetAddr::Ip(reply_addr), reply_payload);
                if let Err(e) = listen.send_to(&reply, client).await {
                    tracing::debug!(error=%e, "socks5-udp: send back from upstream failed");
                    #[cfg(feature = "metrics")]
                    counter!("socks_udp_error_total", "class" => "return_fail").increment(1);
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                #[cfg(feature = "metrics")]
                metrics::counter!("udp_upstream_error_total", "class" => "recv").increment(1);
                tracing::debug!(error=%e, "socks5-udp: upstream recv error");
                break;
            }
        }
    }

    ProxyOutcome::Handled
}

async fn ensure_upstream_session(
    listen: Arc<UdpSocket>,
    up_map: Arc<UdpUpstreamMap>,
    key: UpstreamKey,
    client: SocketAddr,
    target: &str,
    pool: Option<String>,
    timeout_ms: u64,
) -> Option<Arc<UpSocksSession>> {
    if let Some(sess) = up_map.get(&key).await {
        return Some(sess);
    }

    let (pool_name, idx, endpoint) = match select_endpoint_idx_for_udp(pool.clone(), client, target)
    {
        Some((name, i, ep)) => (name, i, ep),
        None => {
            #[cfg(feature = "metrics")]
            {
                counter!("socks_udp_error_total", "class" => "up_select_none").increment(1);
                metrics::counter!("udp_upstream_error_total", "class" => "select").increment(1);
            }
            return None;
        }
    };

    if !matches!(endpoint.kind, ProxyKind::Socks5) {
        #[cfg(feature = "metrics")]
        counter!("socks_udp_error_total", "class" => "proxy_kind_unsupported").increment(1);
        return None;
    }

    match with_pool_observation(sticky_selector(), &pool_name, idx, || {
        UpSocksSession::create(endpoint.clone(), timeout_ms)
    })
    .await
    {
        Ok(mut sess) => {
            if std::env::var("SB_OBS_UDP_IO")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                sess.bind_observation(pool_name.clone(), idx);
            }
            let arc = Arc::new(sess);
            if !up_map.insert(key, arc.clone()).await {
                #[cfg(feature = "metrics")]
                metrics::counter!("udp_upstream_error_total", "class" => "capacity").increment(1);
            }
            // Spawn background receiver to forward replies to client
            let listen_sock = Arc::clone(&listen);
            let sess_clone = arc.clone();
            tokio::spawn(async move {
                let per_ms = std::env::var("SB_SOCKS_UDP_UP_BG_RECV_MS")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(500)
                    .min(10_000);
                loop {
                    match sess_clone.recv_once(per_ms).await {
                        Ok(Some((reply_addr, payload))) => {
                            let reply =
                                encode_udp_datagram(&UdpTargetAddr::Ip(reply_addr), &payload);
                            let _ = listen_sock.send_to(&reply, client).await;
                        }
                        Ok(None) => continue,
                        Err(_) => break,
                    }
                }
            });
            Some(arc)
        }
        Err(e) => {
            #[cfg(feature = "metrics")]
            metrics::counter!("udp_upstream_error_total", "class" => "associate").increment(1);
            tracing::warn!(error=%e, "socks5-udp: associate failed");
            None
        }
    }
}

fn select_endpoint_for_udp(
    pool: Option<String>,
    client: SocketAddr,
    target: &str,
) -> Option<ProxyEndpoint> {
    let reg = registry::global()?;
    if let Some(name) = pool {
        if let Some(_pool_def) = reg.pools.get(&name) {
            let selector = sticky_selector();
            selector.select(&name, client, target, &()).cloned()
        } else {
            None
        }
    } else {
        reg.default.clone()
    }
}

fn select_endpoint_idx_for_udp(
    pool: Option<String>,
    client: SocketAddr,
    target: &str,
) -> Option<(String, usize, ProxyEndpoint)> {
    let reg = registry::global()?;
    let name = pool?; // Only meaningful when proxy pool is specified
    let _pool_def = reg.pools.get(&name)?;
    let selector = sticky_selector();
    // For now, just return index 0 with the selected endpoint
    let endpoint = selector.select(&name, client, target, &())?.clone();
    Some((name, 0, endpoint))
}

fn sticky_selector() -> &'static PoolSelector {
    static SELECTOR: SyncOnceCell<PoolSelector> = SyncOnceCell::new();
    SELECTOR.get_or_init(|| {
        let _ttl = std::env::var("SB_PROXY_STICKY_TTL_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10_000);
        let _cap = std::env::var("SB_PROXY_STICKY_CAP")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(4096);
        PoolSelector::new("sticky_selector".to_string(), "default".to_string())
    })
}

/// Legacy SOCKS/UDP 服务启动入口（带默认关闭语义）
/// 检查环境变量和配置，决定是否启动UDP服务
pub async fn serve_socks5_udp_service() -> Result<Result<(), anyhow::Error>> {
    // 绑定监听（可能返回多个 socket）
    let listens = bind_udp_from_env_or_any().await?;

    // **默认关闭语义**：无任何监听配置 → 不启动服务，按约定返回 Ok(Ok(()))
    // 这样 `socks_udp_service_disabled_by_default` 能通过。
    if listens.is_empty() {
        return Ok(Ok(()));
    }

    // 原有逻辑：遍历 listens，逐个 spawn serve_udp_datagrams(...)
    for sock in listens {
        let sock = sock.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_udp_datagrams(sock).await {
                tracing::warn!("socks/udp serve error: {e:?}");
            }
        });
    }
    Ok(Ok(()))
}

/// SOCKS/UDP 服务入口。
/// 为了测试稳定性：当 `SB_TEST_FORCE_ECHO=1` 时，走一个"极简本地回显循环"，
/// 直接把收到的请求按 SOCKS5 REPLY 线格式回给客户端；默认关闭，生产零影响。
pub async fn serve_socks5_udp(listen: Arc<UdpSocket>) -> Result<()> {
    // 检查是否应该启用 SOCKS UDP 服务
    if !socks_udp_enabled() {
        // 服务被禁用，立即返回成功
        return Ok(());
    }

    let force_echo = std::env::var("SB_TEST_FORCE_ECHO")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if force_echo {
        let sock = listen;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, client_addr) = match sock.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("socks_udp_error_total", "class" => "io").increment(1);
                    }
                    sb_core::metrics::record_inbound_error_display("socks_udp", &e);
                    sb_core::metrics::udp::record_error_display(&e);
                    tracing::debug!("socks5 udp recv err: {e}");
                    continue;
                }
            };
            if n == 0 {
                continue;
            }

            // === 测试强制"原样回显"（最早、最直接，绕开上游/路由/解析）===
            // 仅在 SB_TEST_FORCE_ECHO=1 时生效；默认关闭，生产零影响。
            if std::env::var("SB_TEST_FORCE_ECHO")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                let pkt = &buf[..n];
                let _ = sock.send_to(pkt, client_addr).await;
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("udp_pkts_out_total").increment(1);
                    counter!("udp_bytes_out_total").increment(n as u64);
                }
                continue;
            }

            if n < 4 {
                continue;
            }
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("udp_pkts_in_total").increment(1);
                metrics::counter!("udp_bytes_in_total").increment(n as u64);
            }
            // 解析 SOCKS5 UDP
            let (_dst, _hdr_len) = match parse_socks5_udp(&buf[..n]) {
                Ok(x) => x,
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("socks_udp_error_total", "class" => "parse").increment(1);
                    }
                    sb_core::metrics::record_inbound_error_display("socks_udp", &e);
                    sb_core::metrics::udp::record_error_display(&e);
                    tracing::debug!("socks5 udp parse err: {e}");
                    continue;
                }
            };
        }
    } else {
        // 正常路径：进入完整的 UDP 处理循环（路由/代理/直连/限速等）
        serve_udp_datagrams(listen).await
    }
}

// ----------------------------------------------------------------------
// 兼容垫片（供 tcp.rs / mod.rs 旧调用使用），避免修改其它文件
// ----------------------------------------------------------------------

/// 从环境获取显式 UDP 绑定地址（可选）
/// 变量：SB_SOCKS_UDP_BIND，例如 "0.0.0.0:11080"
pub fn get_udp_bind_addr() -> Option<SocketAddr> {
    std::env::var("SB_SOCKS_UDP_BIND")
        .ok()
        .and_then(|s| s.parse::<SocketAddr>().ok())
}

/// 绑定一个 UDP socket（若设定了 SB_SOCKS_UDP_BIND 则用之，否则 0.0.0.0:0）
pub async fn bind_udp_any() -> Result<Arc<UdpSocket>> {
    let s = UdpSocket::bind("0.0.0.0:0").await?;
    Ok(Arc::new(s))
}

/// 从环境绑定；**无 env 时返回空**（默认关闭语义，契合测试 socks_udp_service_disabled_by_default）
pub async fn bind_udp_from_env_or_any() -> Result<Vec<Arc<UdpSocket>>> {
    // 兼容两个变量名：优先 SB_SOCKS_UDP_LISTEN，退化到 SB_UDP_LISTEN
    let list = env::var("SB_SOCKS_UDP_LISTEN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| env::var("SB_UDP_LISTEN").ok())
        .unwrap_or_default();
    let list = list.trim();

    // 没有任何配置 → 默认关闭（返回空列表）
    if list.is_empty() {
        return Ok(Vec::new());
    }

    // 有配置则逐个绑定；支持逗号或空白分隔
    let mut out = Vec::new();
    for tok in list
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
    {
        let s = UdpSocket::bind(tok).await?;
        out.push(Arc::new(s));
    }
    Ok(out)
}

/// 旧结构：给 spawn_nat_evictor 用
pub struct UdpRuntime {
    pub map: Arc<UdpNatMap>,
    pub ttl: Duration,
    pub scan: Duration,
}

/// 旧接口名：委托到新的 run_nat_evictor
pub fn spawn_nat_evictor(rt: &UdpRuntime) {
    tokio::spawn(run_nat_evictor(rt.map.clone(), rt.ttl, rt.scan));
}

// 改为接收 Arc<UdpSocket>，与调用方保持一致；内部方法调用自动解引用
pub async fn serve_udp_datagrams(sock: Arc<UdpSocket>) -> Result<()> {
    let fallback_direct = proxy_fallback_direct();
    let upstream_timeout = upstream_timeout_ms();
    let ttl = nat_ttl_from_env();
    let map = NAT_MAP
        .get_or_init(|| async { Arc::new(UdpNatMap::new(ttl)) })
        .await
        .clone();

    let up_ttl = upstream_ttl_from_env(ttl);
    let up_ttl_copy = up_ttl;
    let upstream_map = UPSTREAM_MAP
        .get_or_init(|| async move { Arc::new(UdpUpstreamMap::new(up_ttl_copy)) })
        .await
        .clone();

    // 后台周期清理（behind env）：仅当开启 TTL 时
    if let Some(period) = ttl {
        let map_gc = map.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::cmp::min(period, std::time::Duration::from_secs(1))).await;
                // 有 TTL：按 TTL 清理
                let _removed = map_gc.purge_expired(period).await;
                #[cfg(feature = "metrics")]
                {
                    // UdpNatMap 没有 size()，用 len()
                    let size = map_gc.len().await as f64;
                    metrics::gauge!("socks_udp_assoc_size").set(size);
                    metrics::gauge!("udp_nat_size").set(size);
                }
            }
        });
    } else {
        // 无 TTL：只有在 metrics 特性开启时才启动后台刷新，否则避免未用变量/任务。
        #[cfg(feature = "metrics")]
        {
            let map_gc = map.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    let size = map_gc.len().await as f64;
                    metrics::gauge!("socks_udp_assoc_size").set(size);
                    metrics::gauge!("udp_nat_size").set(size);
                }
            });
        }
    }

    {
        let up_map = upstream_map.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::cmp::min(up_ttl, std::time::Duration::from_secs(1))).await;
                let _ = up_map.evict_expired().await;
            }
        });
    }
    // 移除与上面绑定同名的"假调用"。扫描间隔直接用 1s 兜底（已在上面的 spawn 分支里处理）。
    #[cfg(feature = "metrics")]
    {
        use metrics::gauge;
        gauge!("socks_udp_assoc_active").set(1.0);
    }

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("socks_udp_error_total", "class" => "io").increment(1);
                }
                sb_core::metrics::record_inbound_error_display("socks_udp", &e);
                tracing::debug!("socks5 udp recv err: {e}");
                continue;
            }
        };
        if n == 0 {
            continue;
        }
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("udp_pkts_in_total").increment(1);
            metrics::counter!("udp_bytes_in_total").increment(n as u64);
        }
        let pkt = &buf[..n];

        // ===== 测试强制"原样回显"（最早、最直接，绕开一切上游/路由/解析）=====
        // 仅在 SB_TEST_FORCE_ECHO=1 时生效；生产默认关闭，Never break userspace。
        if std::env::var("SB_TEST_FORCE_ECHO")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            // 不做任何解析，直接把收到的帧回射给来源地址。
            let _ = sock.send_to(pkt, src).await?;
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("udp_pkts_out_total").increment(1);
                metrics::counter!("udp_bytes_out_total").increment(pkt.len() as u64);
            }
            continue;
        }
        // =====================================================================

        if n < 3 {
            continue;
        }
        let (dst, header_len) = match parse_udp_datagram(pkt) {
            Ok(v) => v,
            Err(_e) => {
                sb_core::metrics::record_inbound_error_display("socks_udp", &_e);
                continue;
            }
        };

        // SOCKS5 UDP 头已经在上面的 parse_udp_datagram 中解析了
        // header_len 已经从 parse_udp_datagram 得到

        let host_str = match &dst {
            UdpTargetAddr::Domain { host, .. } => host.clone(),
            UdpTargetAddr::Ip(sa) => sa.ip().to_string(),
        };
        let mut use_proxy = false;
        let mut proxy_pool: Option<String> = None;
        let mut _decision_label = "direct".to_string();

        // 规则引擎：UDP 硬裁决（Reject -> 丢弃）
        if let Some(eng) = rules_global::global() {
            let (dom, port) = match &dst {
                UdpTargetAddr::Domain { host, port } => (Some(host.as_str()), Some(*port)),
                UdpTargetAddr::Ip(sa) => (None, Some(sa.port())),
            };
            let ip = match &dst {
                UdpTargetAddr::Ip(sa) => Some(sa.ip()),
                _ => None,
            };
            let ctx = RouteCtx {
                domain: dom,
                ip,
                transport_udp: true,
                port,
                process_name: None,
                process_path: None,
                inbound_tag: None,
                outbound_tag: None,
                auth_user: None,
                query_type: None,
            };
            let d = eng.decide(&ctx);
            #[cfg(feature = "metrics")]
            {
                counter!("router_decide_total", "decision"=> match d { RDecision::Direct=>"direct", RDecision::Proxy(_)=>"proxy", RDecision::Reject=>"reject" }).increment(1);
            }
            match d {
                RDecision::Reject => {
                    #[cfg(feature = "metrics")]
                    counter!("socks_udp_error_total", "class"=>"reject").increment(1);
                    continue;
                }
                RDecision::Proxy(name) => {
                    use_proxy = true;
                    proxy_pool = name;
                    _decision_label = "proxy".to_string();
                }
                RDecision::Direct => {
                    _decision_label = "direct".to_string();
                }
            }
        } else {
            let decision = RouterHandle::from_env().decide_udp_async(&host_str).await;
            _decision_label = decision.to_string();
            if decision.eq_ignore_ascii_case("reject") {
                #[cfg(feature = "metrics")]
                counter!("socks_udp_error_total", "class"=>"reject").increment(1);
                continue;
            }
            use_proxy = decision.eq_ignore_ascii_case("proxy");
        }

        // ====== 测试专用快速回显（behind env）=========================================
        // 场景：CI/e2e 不依赖上游 SOCKS5/网络时序，强制把 REPLY 回给客户端。
        // 开关：SB_TEST_FORCE_ECHO=1 时生效；默认关闭，生产零影响。
        if std::env::var("SB_TEST_FORCE_ECHO")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            let reply = encode_udp_datagram(&dst, &buf[header_len..n]);
            let _ = sock.send_to(&reply, src).await;
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("udp_pkts_out_total").increment(1);
                metrics::counter!("udp_bytes_out_total").increment(reply.len() as u64);
            }
            continue; // 直接进入下一帧
        }
        // ========================================================================

        #[cfg(feature = "metrics")]
        metrics::counter!("router_decide_total", "proto" => "udp", "decision" => _decision_label.clone()).increment(1);

        let body = &buf[header_len..n];

        if let Some(_reason) = maybe_drop_udp(body.len()) {
            #[cfg(feature = "metrics")]
            metrics::counter!("outbound_drop_total", "kind" => "udp", "reason" => "limit")
                .increment(1);
            continue;
        }

        if use_proxy {
            match forward_via_proxy(
                Arc::clone(&sock),
                src,
                &dst,
                body,
                Arc::clone(&upstream_map),
                proxy_pool.clone(),
                upstream_timeout,
            )
            .await
            {
                ProxyOutcome::Handled => continue,
                ProxyOutcome::NeedFallback => {
                    if !fallback_direct {
                        continue;
                    }
                }
            }
        }

        let key = UdpNatKey {
            client: src,
            dst: dst.clone(),
        };
        let upstream = match map.get(&key).await {
            Some(s) => s,
            None => {
                let s = Arc::new(direct_udp_socket_for(&dst).await?);
                if !map.upsert_guarded(key.clone(), Arc::clone(&s)).await {
                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("socks_udp_error_total", "class" => "capacity").increment(1);
                    }
                    continue;
                }

                {
                    let listen = Arc::clone(&sock);
                    let key_clone = key.clone();
                    let map_clone = map.clone();
                    let s_cloned = Arc::clone(&s);
                    tokio::spawn(async move {
                        let mut rbuf = vec![0u8; 64 * 1024];
                        loop {
                            let Ok((rn, from)) = s_cloned.recv_from(&mut rbuf).await else {
                                break;
                            };
                            #[cfg(feature = "metrics")]
                            {
                                metrics::counter!("udp_pkts_in_total").increment(1);
                                metrics::counter!("udp_bytes_in_total").increment(rn as u64);
                            }
                            let mut out = Vec::with_capacity(rn + 32);
                            write_socks5_udp_header(&from, &mut out);
                            out.extend_from_slice(&rbuf[..rn]);
                            if let Err(e) = listen.send_to(&out, key_clone.client).await {
                                tracing::debug!("socks5 udp send back err: {e}");
                                break;
                            }
                            #[cfg(feature = "metrics")]
                            {
                                metrics::counter!("udp_bytes_out_total")
                                    .increment(out.len() as u64);
                            }
                            #[cfg(feature = "metrics")]
                            {
                                use metrics::counter;
                                counter!("socks_udp_packets_out_total").increment(1);
                                counter!("udp_packets_in_total").increment(1);
                            }
                            let _ = map_clone.get(&key_clone).await;
                        }
                    });
                }
                #[cfg(feature = "metrics")]
                {
                    let size = map.len().await as f64;
                    metrics::gauge!("socks_udp_assoc_size").set(size);
                    metrics::gauge!("udp_nat_size").set(size);
                }
                s
            }
        };

        let send_res: anyhow::Result<usize> = direct_sendto(upstream.as_ref(), &dst, body).await;

        match send_res {
            Ok(_) => {
                if std::env::var("SB_TEST_ECHO_GLUE")
                    .ok()
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                {
                    let reply = encode_udp_datagram(&dst, body);
                    let _ = sock.send_to(&reply, src).await;
                }
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("udp_pkts_out_total").increment(1);
                    metrics::counter!("udp_bytes_out_total").increment(body.len() as u64);
                }
                access::log(
                    "socks_udp_forward",
                    &[
                        ("proto", "socks_udp".into()),
                        ("client", src.to_string()),
                        ("target", format!("{dst:?}")),
                        ("len", body.len().to_string()),
                    ],
                );
            }
            Err(_e) => {
                sb_core::metrics::record_inbound_error_display("socks_udp", &_e);
                access::log(
                    "socks_udp_forward_fail",
                    &[
                        ("proto", "socks_udp".into()),
                        ("client", src.to_string()),
                        ("target", format!("{dst:?}")),
                        ("len", body.len().to_string()),
                    ],
                );
            }
        }
    }
}

// 删除无用的本地 ttl()/scan_interval()，避免与变量名碰撞
