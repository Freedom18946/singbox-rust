//! UDP Upstream 传输
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::{net::UdpSocket, time};
use tracing::trace;

use super::DnsTransport;

/// UDP 上游描述
#[derive(Clone, Debug)]
pub struct UdpUpstream {
    pub addr: SocketAddr,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct UdpTransport {
    upstream: UdpUpstream,
}

impl UdpTransport {
    pub fn new(upstream: UdpUpstream) -> Self {
        Self { upstream }
    }
}

#[async_trait::async_trait]
impl DnsTransport for UdpTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        // 0.0.0.0:0 绑定；不做复用，后续可引入连接池/复用
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .context("dns/udp: bind 0.0.0.0:0 failed")?;
        let peer = self.upstream.addr;

        // 发送
        sock.send_to(packet, peer)
            .await
            .context("dns/udp: send_to")?;
        // 接收（带超时）
        let mut buf = vec![0u8; 4096];
        let n = time::timeout(self.upstream.timeout, sock.recv(&mut buf))
            .await
            .context("dns/udp: timeout")?
            .context("dns/udp: recv")?;
        buf.truncate(n);
        trace!(upstream=%peer, len=n, "dns/udp: recv");
        Ok(buf)
    }

    fn name(&self) -> &'static str {
        "udp"
    }
}
