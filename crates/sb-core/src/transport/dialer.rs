//! 拨号抽象：统一 TCP/UDP 连接与主机解析
use std::{io, net::SocketAddr, time::Duration};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    time,
};
use tracing::trace;

// 新增：引入内部 DNS 解析入口（带缓存/并发闸门；behind env）
use crate::dns::resolve as dns_resolve;

/// 连接选项
#[derive(Clone, Debug)]
pub struct ConnectOpts {
    /// 连接超时（单地址尝试）
    pub timeout: Option<Duration>,
    /// 绑定地址（本地出接口/源 IP）
    pub bind: Option<SocketAddr>,
    /// 是否设置 TCP_NODELAY
    pub nodelay: bool,
    /// TCP keepalive
    pub keepalive: Option<Duration>,
    /// 接收缓冲（可选，未指定则使用系统默认）
    pub recv_buffer_size: Option<u32>,
    /// 发送缓冲
    pub send_buffer_size: Option<u32>,
}

impl Default for ConnectOpts {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10)),
            bind: None,
            nodelay: true,
            keepalive: Some(Duration::from_secs(30)),
            recv_buffer_size: None,
            send_buffer_size: None,
        }
    }
}

impl ConnectOpts {
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }
    pub fn nodelay(mut self, on: bool) -> Self {
        self.nodelay = on;
        self
    }
    pub fn keepalive(mut self, d: Option<Duration>) -> Self {
        self.keepalive = d;
        self
    }
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind = Some(addr);
        self
    }
    pub fn recv_buffer_size(mut self, v: Option<u32>) -> Self {
        self.recv_buffer_size = v;
        self
    }
    pub fn send_buffer_size(mut self, v: Option<u32>) -> Self {
        self.send_buffer_size = v;
        self
    }
}

/// 拨号接口：供上层 outbound 使用
#[async_trait]
pub trait Dialer: Send + Sync {
    async fn tcp_connect(&self, addr: SocketAddr, opts: &ConnectOpts) -> Result<TcpStream>;
    async fn udp_bind(&self, addr: SocketAddr) -> Result<UdpSocket>;
    async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>>;

    /// 便利函数：解析主机并连接首个可用地址
    async fn tcp_connect_host(
        &self,
        host: &str,
        port: u16,
        opts: &ConnectOpts,
    ) -> Result<TcpStream> {
        let addrs = self.resolve_host(host, port).await?;
        let mut last_err: Option<anyhow::Error> = None;
        for sa in addrs {
            match self.tcp_connect(sa, opts).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("tcp_connect_host: no address succeeded")))
    }

    /// 便利函数：解析 host:port 格式的地址
    async fn resolve_host_hostport(&self, hostport: &str) -> Result<Vec<SocketAddr>> {
        // 允许形如 "127.0.0.1:8080" 或 "proxy.example.com:8080"
        if let Ok(sa) = hostport.parse::<SocketAddr>() {
            return Ok(vec![sa]);
        }
        let (h, p) = hostport
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("bad host:port format"))?;
        let p: u16 = p.parse().map_err(|_| anyhow!("bad port"))?;
        self.resolve_host(h, p).await
    }
}

/// 系统默认拨号器
#[derive(Clone, Debug, Default)]
pub struct SystemDialer;

#[async_trait]
impl Dialer for SystemDialer {
    async fn tcp_connect(&self, addr: SocketAddr, opts: &ConnectOpts) -> Result<TcpStream> {
        let sock = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(bind) = opts.bind {
            sock.bind(bind)?;
        }
        if let Some(sz) = opts.recv_buffer_size {
            sock.set_recv_buffer_size(sz as u32)?;
        }
        if let Some(sz) = opts.send_buffer_size {
            sock.set_send_buffer_size(sz as u32)?;
        }
        // Tokio 的 TcpSocket::set_keepalive 仅接受 bool；这里把 Some(_) 视为开启，忽略时长。
        sock.set_keepalive(opts.keepalive.is_some())?;

        let fut = sock.connect(addr);
        let stream = match opts.timeout {
            Some(t) => time::timeout(t, fut)
                .await
                .map_err(|_| anyhow!("tcp connect timeout to {addr}"))??,
            None => fut.await?,
        };

        stream.set_nodelay(opts.nodelay)?;
        trace!(remote=%addr, nodelay=?opts.nodelay, "tcp connected");
        Ok(stream)
    }

    async fn udp_bind(&self, addr: SocketAddr) -> Result<UdpSocket> {
        let sock = UdpSocket::bind(addr).await?;
        trace!(local=%sock.local_addr()?, "udp bound");
        Ok(sock)
    }

    async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        // 现在统一走 dns::resolve::resolve_all（内部根据 SB_DNS_MODE 选择/回退）
        dns_resolve::resolve_all(host, port)
            .await
            .with_context(|| format!("dns.resolve_all {host}:{port}"))
    }
}

/// 一些 TcpStream 的通用扩展
pub trait TcpStreamExt {
    /// 尝试设置 linger（关闭时尽快发送 FIN）
    fn set_linger_ms(&self, ms: Option<u64>) -> io::Result<()>;
}

impl TcpStreamExt for TcpStream {
    fn set_linger_ms(&self, _ms: Option<u64>) -> io::Result<()> {
        // 简化：默认不改 LINGER；如需平台特性，后续可改用 socket2 做跨平台设置。
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connect_example_http11() {
        let dialer = SystemDialer::default();
        let opts = ConnectOpts::default()
            .timeout(Duration::from_secs(5))
            .nodelay(true);
        let mut s = dialer
            .tcp_connect_host("example.com", 80, &opts)
            .await
            .unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![];
        s.read_to_end(&mut buf).await.unwrap();
        assert!(std::str::from_utf8(&buf).unwrap().starts_with("HTTP/1.1"));
    }
}
