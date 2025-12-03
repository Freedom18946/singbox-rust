use std::{io, net::SocketAddr, time::Duration};

use sb_core::{net::Address, pipeline::Outbound};
use tokio::{
    net::TcpStream,
    time::{sleep, timeout},
};

/// 直连出站：直接向目标地址发起 TCP 连接。
/// Direct outbound with Happy Eyeballs (RFC 8305) support for dual-stack connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectOutbound;

impl DirectOutbound {
    /// Create a new direct outbound instance
    #[inline]
    pub fn new() -> Self {
        DirectOutbound
    }

    /// Per-attempt connection timeout
    fn per_attempt_timeout() -> Duration {
        Duration::from_secs(2)
    }

    /// Happy Eyeballs IPv6 stagger delay (RFC 8305 recommends 250-300ms)
    fn ipv6_stagger_delay() -> Duration {
        Duration::from_millis(300)
    }

    /// Implement Happy Eyeballs algorithm for dual-stack connection attempts
    async fn happy_eyeballs_connect(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
        if addrs.is_empty() {
            return Err(io::Error::other("no addresses to connect"));
        }

        // Separate IPv4 and IPv6 addresses
        let (ipv6_addrs, ipv4_addrs): (Vec<_>, Vec<_>) =
            addrs.into_iter().partition(|addr| addr.is_ipv6());

        // If only one address family, use simple sequential fallback
        if ipv6_addrs.is_empty() {
            return Self::sequential_connect(ipv4_addrs).await;
        }
        if ipv4_addrs.is_empty() {
            return Self::sequential_connect(ipv6_addrs).await;
        }

        // Happy Eyeballs: race IPv4 and IPv6 with stagger
        tokio::select! {
            // Try IPv4 immediately
            result = Self::sequential_connect(ipv4_addrs.clone()) => {
                result
            }
            // Try IPv6 after stagger delay
            result = async {
                sleep(Self::ipv6_stagger_delay()).await;
                Self::sequential_connect(ipv6_addrs.clone()).await
            } => {
                result
            }
        }
    }

    /// Sequential connection attempts with timeout per address
    async fn sequential_connect(addrs: Vec<SocketAddr>) -> io::Result<TcpStream> {
        let mut last_err: Option<io::Error> = None;
        for addr in addrs {
            match timeout(Self::per_attempt_timeout(), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last_err = Some(e),
                Err(_) => last_err = Some(io::Error::other("connect timeout")),
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("no address resolved")))
    }
}

#[async_trait::async_trait]
impl Outbound for DirectOutbound {
    async fn connect(&self, target: Address) -> io::Result<TcpStream> {
        match target {
            Address::Ip(sock) => {
                // Direct IP connection
                timeout(Self::per_attempt_timeout(), TcpStream::connect(sock))
                    .await
                    .map_err(|_| io::Error::other("connect timeout"))?
            }
            Address::Domain(host, port) => {
                // Resolve all addresses and use Happy Eyeballs
                let addrs: Vec<SocketAddr> =
                    tokio::net::lookup_host((host.as_str(), port))
                        .await?
                        .collect();
                Self::happy_eyeballs_connect(addrs).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_direct_outbound_creation() {
        let outbound = DirectOutbound::new();
        assert!(matches!(outbound, DirectOutbound));
    }
}
