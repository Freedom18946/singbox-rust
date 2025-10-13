#![cfg(feature = "scaffold")]

use crate::inbound::socks5::{decode_udp_reply, encode_udp_request, greet_noauth, udp_associate};
use crate::net::datagram::UdpTargetAddr;
use crate::net::ratelimit::maybe_drop_udp;
use std::{net::SocketAddr, sync::OnceLock, time::Duration};
use tokio::net::{TcpStream, UdpSocket};

fn proxy_addr() -> anyhow::Result<SocketAddr> {
    // Prefer SB_UDP_SOCKS5_ADDR if set; fallback to SB_UDP_PROXY_ADDR for backward compat
    let s = std::env::var("SB_UDP_SOCKS5_ADDR")
        .or_else(|_| std::env::var("SB_UDP_PROXY_ADDR"))
        .map_err(|_| anyhow::anyhow!("SB_UDP_PROXY_ADDR not set"))?;
    s.parse()
        .map_err(|e| anyhow::anyhow!("bad SB_UDP_PROXY_ADDR: {e}"))
}

fn proxy_mode_is_socks5() -> bool {
    std::env::var("SB_UDP_PROXY_MODE")
        .ok()
        .map(|v| v.eq_ignore_ascii_case("socks5"))
        .unwrap_or(false)
}

/// Create a fresh ephemeral UDP socket for an association.
pub async fn create_upstream_socket() -> anyhow::Result<UdpSocket> {
    Ok(UdpSocket::bind("0.0.0.0:0").await?)
}

fn cached_udp_relay() -> &'static OnceLock<SocketAddr> {
    static R: OnceLock<SocketAddr> = OnceLock::new();
    &R
}

pub async fn ensure_udp_relay() -> anyhow::Result<SocketAddr> {
    if let Some(addr) = cached_udp_relay().get() {
        return Ok(*addr);
    }
    let proxy = proxy_addr()?;
    // Establish TCP control to learn UDP relay endpoint
    let timeout_ms = std::env::var("SB_SOCKS5_CTRL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(8000);
    let mut s = tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(proxy))
        .await??;
    greet_noauth(&mut s).await?;
    // Bind hint: zero (infallible constructor)
    let hint: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 0));
    let relay = udp_associate(&mut s, Some(hint)).await?;
    let _ = cached_udp_relay().set(relay);
    #[cfg(feature = "metrics")]
    metrics::counter!("socks5_udp_assoc_total", "result"=>"ok").increment(1);
    Ok(relay)
}

/// Establish a UDP relay at a specific upstream SOCKS5 server (without global cache).
pub async fn ensure_udp_relay_at(proxy: SocketAddr) -> anyhow::Result<SocketAddr> {
    let timeout_ms = std::env::var("SB_SOCKS5_CTRL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(8000);
    let mut s = tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(proxy))
        .await??;
    greet_noauth(&mut s).await?;
    let hint: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 0));
    let relay = udp_associate(&mut s, Some(hint)).await?;
    #[cfg(feature = "metrics")]
    metrics::counter!("socks5_udp_assoc_total", "result"=>"ok").increment(1);
    Ok(relay)
}

fn to_socket_addr(dst: &UdpTargetAddr) -> anyhow::Result<SocketAddr> {
    match dst {
        UdpTargetAddr::Ip(sa) => Ok(*sa),
        UdpTargetAddr::Domain { host, port } => {
            // best-effort system resolve (callers可提前走 DnsClient)
            let mut it = tokio::runtime::Handle::current()
                .block_on(tokio::net::lookup_host((host.as_str(), *port)))
                .map_err(|e| anyhow::anyhow!(e))?;
            it.next()
                .ok_or_else(|| anyhow::anyhow!("resolve empty for {host}"))
        }
    }
}

/// Send a single UDP datagram to `dst` via SOCKS5 UDP relay.
/// NOTE: receive path is not handled here; callers负责接收（未来版本再补）。
pub async fn sendto_via_socks5(
    _listen_sock: &UdpSocket,
    buf: &[u8],
    dst: &UdpTargetAddr,
) -> anyhow::Result<usize> {
    if !proxy_mode_is_socks5() {
        return Err(anyhow::anyhow!("proxy mode not socks5"));
    }
    let relay = ensure_udp_relay().await?;
    let dst_sa = to_socket_addr(dst)?;
    let sock = create_upstream_socket().await?;
    let n = sendto_via_socks5_on(&sock, buf, &dst_sa, relay).await?;
    #[cfg(feature = "metrics")]
    {
        metrics::counter!("udp_bytes_out_total").increment(buf.len() as u64);
        metrics::counter!("outbound_connect_total", "kind"=>"udp", "mode"=>"socks5", "result"=>"ok").increment(1);
    }
    Ok(n)
}

/// Send a datagram via a specified upstream SOCKS5 proxy address (single-shot).
pub async fn sendto_via_socks5_addr(
    proxy: SocketAddr,
    payload: &[u8],
    dst: &SocketAddr,
) -> anyhow::Result<usize> {
    let relay = match ensure_udp_relay_at(proxy).await {
        Ok(relay) => relay,
        Err(e) => {
            #[cfg(feature = "metrics")]
            metrics::counter!("outbound_error_total", "kind"=>"udp", "class"=>"connect")
                .increment(1);
            return Err(e);
        }
    };
    let sock = create_upstream_socket().await?;
    match sendto_via_socks5_on(&sock, payload, dst, relay).await {
        Ok(result) => Ok(result),
        Err(e) => {
            #[cfg(feature = "metrics")]
            metrics::counter!("outbound_error_total", "kind"=>"udp", "class"=>"send").increment(1);
            Err(e)
        }
    }
}

/// Helper: 自动选择 direct / socks5（基于 decision 与 env），便于上层后续接线。
pub async fn send_auto(
    _listen_sock: &UdpSocket,
    buf: &[u8],
    dst: &UdpTargetAddr,
    decision: &str,
) -> anyhow::Result<usize> {
    if decision == "proxy" && proxy_mode_is_socks5() {
        match sendto_via_socks5(_listen_sock, buf, dst).await {
            Ok(n) => return Ok(n),
            Err(e) => {
                #[cfg(feature = "metrics")]
                metrics::counter!("router_proxy_fallback_total", "proto"=>"udp", "mode"=>"direct")
                    .increment(1);
                return Err(e);
            }
        }
    }
    Err(anyhow::anyhow!("proxy not selected"))
}

/// Send using a given UDP socket (per-client assoc).
pub async fn sendto_via_socks5_on(
    sock: &UdpSocket,
    payload: &[u8],
    dst: &SocketAddr,
    relay: SocketAddr,
) -> anyhow::Result<usize> {
    if let Some(reason) = maybe_drop_udp(payload.len()) {
        #[cfg(feature = "metrics")]
        metrics::counter!("outbound_drop_total", "kind"=>"udp", "reason"=>reason).increment(1);
        return Err(anyhow::anyhow!("udp drop by limiter: {reason}"));
    }
    let packet = encode_udp_request(dst, payload);
    Ok(sock.send_to(&packet, relay).await?)
}

/// Receive one datagram from relay and decode.
pub async fn recv_from_via_socks5(sock: &UdpSocket) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
    let mut buf = vec![0u8; 2048];
    let (n, _from) = match sock.recv_from(&mut buf).await {
        Ok(result) => result,
        Err(e) => {
            #[cfg(feature = "metrics")]
            metrics::counter!("outbound_error_total", "kind"=>"udp", "class"=>"recv").increment(1);
            return Err(e.into());
        }
    };
    let (dst, payload) = decode_udp_reply(&buf[..n])?;
    Ok((dst, payload.to_vec()))
}
