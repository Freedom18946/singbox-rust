
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use async_trait::async_trait;
use sb_core::net::Address;
use sb_core::router::{RequestMeta, Router, Transport};
use tokio::net::TcpStream;
use sb_core::session::ConnectParams;
use crate::inbound::http::{Connector, AUTH_USER};

/// A connector that uses the router to select an outbound and establish a connection.
#[derive(Clone)]
pub struct RouterConnector {
    pub router: Arc<dyn Router>,
}

impl RouterConnector {
    /// 新增：带完整会话上下文的拨号（不改 Connector trait，避免连锁修改）
    pub async fn connect_with(&self, p: &ConnectParams) -> std::io::Result<TcpStream> {
        // 组装 Router 元信息
        let meta = RequestMeta {
            dst: p.target.clone(),
            transport: p.transport,
            inbound_tag: None,
            user: p.user.clone().map(Into::into),
            sniff_host: p.sniff_host.clone(),
        };
        let outbound = self.router.select(&meta);
        // 让出站优先吃到 ConnectParams；未实现 connect_ex 的出站会走默认回退
        outbound
            .connect_ex(p)
            .await
            .map_err(|e| std::io::Error::other(e))
    }
}

#[async_trait]
impl Connector for RouterConnector {
    async fn connect(&self, target: &str) -> io::Result<TcpStream> {
        // 1. Parse target string to sb_core::net::Address
        let dest = parse_target(target)?;

        // 2. Construct metadata for the router
        // 从 task-local 尝试读取用户名，并写入 Router 元数据
        let user: Option<String> = AUTH_USER.try_with(|u| u.clone()).ok().flatten();
        let meta = RequestMeta {
            dst: dest.clone(),
            transport: Transport::Tcp,
            inbound_tag: None,
            user: user.map(Into::into),
            sniff_host: None,
        };

        // 3. Select an outbound and connect
        let outbound = self.router.select(&meta);
        outbound
            .connect(dest)
            .await
            .map_err(|e| io::Error::other(e))
    }

    /// 优先走新接口：使用 ConnectParams 里的 user/transport/target
    async fn connect_ex(&self, p: &ConnectParams) -> io::Result<TcpStream> {
        // 优先取 params.user；若为空，再尝试 task-local 保持兼容
        let user = if p.user.is_some() {
            p.user.clone()
        } else {
            AUTH_USER.try_with(|u| u.clone()).ok().flatten()
        };
        let meta = RequestMeta {
            dst: p.target.clone(),
            transport: p.transport,
            inbound_tag: None,
            user: user.map(Into::into),
            sniff_host: p.sniff_host.clone(),
        };
        let outbound = self.router.select(&meta);
        outbound
            .connect(p.target.clone())
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

fn parse_target(target: &str) -> io::Result<Address> {
    // Try to parse as a socket address first (e.g., "1.2.3.4:80" or "[::1]:80")
    if let Ok(mut addrs) = target.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(Address::Ip(addr));
        }
    }

    // Fallback to parsing as "host:port"
    let Some((host, port_str)) = target.rsplit_once(':') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid target format, expected host:port",
        ));
    };

    let port = port_str
        .parse::<u16>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port"))?;

    // Handle IPv6 literal addresses like "[::1]"
    let host = host.trim_start_matches('[').trim_end_matches(']');

    Ok(Address::Domain(host.to_string(), port))
}
