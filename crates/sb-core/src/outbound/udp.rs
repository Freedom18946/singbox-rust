// --- Direct UDP 出站统一入口（独立函数，避免破坏既有签名） ---
#![allow(dead_code)]
use crate::dns::client::DnsClient;
use crate::net::datagram::UdpTargetAddr;
use crate::net::RateLimiter;
use anyhow::{Context, Result};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::UdpSocket;

// 最小内联解析：direct 出站才解析；代理出站透传域名（不走这里）
async fn resolve_target_local(target: UdpTargetAddr) -> Result<SocketAddr> {
    match target {
        UdpTargetAddr::Ip(sa) => Ok(sa),
        UdpTargetAddr::Domain { host, port } => {
            let q = format!("{host}:{port}");
            let mut it = tokio::net::lookup_host(q).await?;
            it.next()
                .ok_or_else(|| anyhow::anyhow!("DNS resolved empty for host"))
        }
    }
}

/// UDP 发送错误分类（稳定口径）
/// `返回：timeout/refused/unreachable/peer_closed/other`
fn classify_udp_error(e: &io::Error) -> &'static str {
    use io::ErrorKind::{TimedOut, ConnectionRefused, ConnectionReset, BrokenPipe};
    match e.kind() {
        TimedOut => "timeout",
        ConnectionRefused => "refused",
        ConnectionReset | BrokenPipe => "peer_closed",
        _ => {
            // 尝试根据平台 errno 进一步区分"不可达"
            // Linux: ENETUNREACH=101, EHOSTUNREACH=113
            // Darwin: ENETUNREACH=51,  EHOSTUNREACH=65
            match e.raw_os_error() {
                Some(101 | 113 | 51 | 65) => "unreachable",
                _ => "other",
            }
        }
    }
}

#[inline]
fn classify_io_error(e: &std::io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(110) => "timeout",                 // ETIMEDOUT
        Some(111) => "refused",                 // ECONNREFUSED
        Some(101 | 113) => "unreachable", // ENETUNREACH/EHOSTUNREACH
        Some(32 | 104) => "peer_closed",  // EPIPE/ECONNRESET
        _ => "other",
    }
}

fn udp_limiter() -> Option<&'static RateLimiter> {
    static LIM: OnceLock<Option<RateLimiter>> = OnceLock::new();
    LIM.get_or_init(RateLimiter::from_env_udp).as_ref()
}

/// 可选解析辅助：当目标是域名且 `SB_DNS_ENABLE=1` 时，使用进程级 DNS 客户端解析一个可用地址。
/// 默认（未启用）则与现状保持一致（交给系统解析器或由调用方自行解析）。
pub async fn resolve_target_socketaddr(
    dst: &UdpTargetAddr,
) -> anyhow::Result<std::net::SocketAddr> {
    match dst {
        UdpTargetAddr::Ip(sa) => Ok(*sa),
        UdpTargetAddr::Domain { host, port } => {
            if std::env::var("SB_DNS_ENABLE")
                .ok()
                .as_deref()
                .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            {
                // 进程级 DNS client（TTL 60s）
                static DNS: OnceLock<DnsClient> = OnceLock::new();
                let cli = DNS
                    .get_or_init(|| DnsClient::new(Duration::from_secs(60)))
                    .clone();
                let list = cli.resolve(host, *port).await?;
                list.into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("dns resolved empty"))
            } else {
                // 与现状一致：系统解析
                let mut it = tokio::net::lookup_host((host.as_str(), *port)).await?;
                it.next()
                    .ok_or_else(|| anyhow::anyhow!("system resolved empty"))
            }
        }
    }
}

/// 新建上游 UDP socket（按目标族选择绑定地址），返回已就绪的 `UdpSocket`
pub async fn direct_udp_socket_for(dst: &UdpTargetAddr) -> Result<UdpSocket> {
    match dst {
        UdpTargetAddr::Ip(sa) => {
            let bind = match sa {
                SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            };
            let s = UdpSocket::bind(bind).await.context("bind upstream udp")?;
            Ok(s)
        }
        UdpTargetAddr::Domain { .. } => {
            // 未知族时先用 IPv4 绑定（多数场景可行），真正发送时按解析结果发送
            let s = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
                .await
                .context("bind upstream udp (v4)")?;
            Ok(s)
        }
    }
}

/// 直接转发一个 UDP 数据包到目标地址。
// - `sock`：入站绑定的 UdpSocket（共享同一 socket，便于回流）
// - `dst`：目标（域名或 IP）
// - `payload`：要发送的负载
pub async fn direct_sendto(sock: &UdpSocket, dst: &UdpTargetAddr, payload: &[u8]) -> Result<usize> {
    if let Some(l) = udp_limiter() {
        if let Err(reason) = l.allow(payload.len()) {
            #[cfg(feature = "metrics")]
            metrics::counter!(
                "outbound_drop_total",
                "kind"   => "udp",
                "reason" => reason
            )
            .increment(1);
            return Err(anyhow::anyhow!("udp rate limited ({reason})"));
        }
    }
    // 解析目标（域名保留到此时才解析）
    let sa = match resolve_target_local(dst.clone()).await {
        Ok(sa) => sa,
        Err(e) => {
            #[cfg(feature = "metrics")]
            {
                let class = e
                    .downcast_ref::<std::io::Error>()
                    .map(classify_io_error)
                    .unwrap_or("other");
                metrics::counter!("outbound_error_total", "kind" => "udp", "class" => class)
                    .increment(1);
            }
            return Err(e);
        }
    };
    // 发送
    match sock.send_to(payload, sa).await {
        Ok(n) => {
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("udp_bytes_out_total").increment(n as u64);
            }
            Ok(n)
        }
        Err(e) => {
            #[cfg(feature = "metrics")]
            {
                let class = classify_udp_error(&e);
                metrics::counter!("outbound_error_total", "kind"=>"udp", "class"=>class)
                    .increment(1);
            }
            Err(anyhow::anyhow!(e))
        }
    }
}
