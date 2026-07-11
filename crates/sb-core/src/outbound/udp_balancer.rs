//! Legacy direct UDP helper retained until WP12 assigns generic balancer ownership.
//!
//! SOCKS5 proxy transport moved to sb-adapters. Core never falls back to direct when
//! router selected a proxy path.

use crate::net::datagram::UdpTargetAddr;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

async fn resolve_dst(dst: &UdpTargetAddr) -> anyhow::Result<SocketAddr> {
    match dst {
        UdpTargetAddr::Ip(address) => Ok(*address),
        UdpTargetAddr::Domain { host, port } => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("resolve empty for {host}")),
    }
}

async fn send_direct(payload: &[u8], destination: SocketAddr) -> anyhow::Result<usize> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let size = socket.send_to(payload, destination).await?;
    #[cfg(feature = "metrics")]
    {
        metrics::counter!("udp_bytes_out_total").increment(payload.len() as u64);
        metrics::counter!(
            "outbound_connect_total",
            "kind" => "udp",
            "mode" => "direct",
            "result" => "ok"
        )
        .increment(1);
    }
    Ok(size)
}

/// Send one direct datagram only when routing selected a non-proxy path.
pub async fn send_balanced(
    payload: &[u8],
    destination: &UdpTargetAddr,
    decision: &str,
) -> anyhow::Result<usize> {
    if decision == "proxy" {
        return Err(anyhow::anyhow!(
            "core UDP proxy transport was removed; use canonical sb-adapters PacketConn"
        ));
    }
    send_direct(payload, resolve_dst(destination).await?).await
}
