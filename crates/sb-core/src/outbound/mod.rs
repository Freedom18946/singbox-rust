// crates/sb-core/src/outbound/mod.rs
//! Outbound 抽象 & 注册表（P1.6）
//!
//! - 统一的连接/握手超时（默认 10s/10s）
//! - Direct / SOCKS5 / HTTP CONNECT 出站增加可观测性指标：
//!   - `sb_outbound_connect_total{kind="direct|socks5|http", result="ok|timeout|error"}`
//!   - `sb_outbound_handshake_total{kind="socks5|http", result="ok|timeout|error"}`
//! - Direct 成功后设置 `TCP_NODELAY`（keepalive 改为后续用 socket2/TcpSocket 实现）
//!
//! 数据结构与对外接口保持不变：Router/Inbound 端无需改动。

pub mod direct_connector;
#[cfg(feature = "scaffold")]
pub mod direct_simple;
pub mod endpoint;
pub mod health;
#[cfg(feature = "scaffold")]
pub mod http_upstream;
pub mod manager;
pub mod observe;
pub mod registry;
pub mod selector;
pub mod socks5_udp;
#[cfg(feature = "scaffold")]
pub mod socks_upstream;
pub mod tcp;
pub mod traits;
pub mod types;
pub mod udp;
pub mod udp_balancer;
pub mod udp_direct;
pub mod udp_proxy_glue;
pub mod udp_socks5;
// P3评分选择器
#[cfg(feature = "selector_p3")]
pub mod selector_p3;
// 统一反馈入口（选择/拨号回报）
#[cfg(feature = "selector_p3")]
pub mod feedback;
// 简化P3选择器
pub mod p3_selector;

// Encrypted outbound protocols
pub mod address;
pub mod crypto_types;
pub mod ss {
    #[cfg(feature = "out_ss")]
    pub mod aead_tcp;
    #[cfg(feature = "out_ss")]
    pub mod aead_udp;
    pub mod hkdf;
}
#[cfg(feature = "out_naive")]
pub mod naive_h2;
#[cfg(feature = "out_ss")]
pub mod shadowsocks;
#[cfg(feature = "out_shadowtls")]
pub mod shadowtls;
#[cfg(feature = "out_trojan")]
pub mod trojan;
#[cfg(feature = "out_vless")]
pub mod vless;
#[cfg(feature = "out_vmess")]
pub mod vmess;
// QUIC types are included in crypto_types
#[cfg(feature = "out_quic")]
pub mod quic {
    pub mod common;
    pub mod io;
}
#[cfg(feature = "out_hysteria2")]
pub mod hysteria2;
#[cfg(feature = "out_ssh")]
pub mod ssh_stub;
#[cfg(feature = "out_tuic")]
pub mod tuic;
#[cfg(feature = "out_wireguard")]
pub mod wireguard_stub;

use crate::telemetry::{err_kind, outbound_connect, outbound_handshake};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

// Re-export the standard traits and implementations
pub use direct_connector::{DirectConnector, DirectUdpTransport};
pub use manager::OutboundManager;
pub use traits::{OutboundConnector, UdpTransport};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpSocket, TcpStream},
    time::{timeout, Duration},
};
// 公开拨号工具，便于上层/调用方在不改动出站实现的前提下就地使用
pub use crate::net::dial::{
    dial_all, dial_hostport, dial_pref, dial_socketaddrs, per_attempt_timeout,
};

///（预备）出站便捷拨号包装：现在先提供 API，不直接替换现有实现。
/// 调用示例：`let s = sb_core::outbound::connect("example.com", 443).await?;`
#[allow(dead_code)]
pub async fn connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    dial_pref(host, port).await
}

use socket2::{SockRef, TcpKeepalive};

use base64::Engine; // 关键：引入 trait，启用 .encode()
                    // metrics 通过 telemetry helpers 间接使用，无需直接导入
                    // 预埋：握手错误维度统计（不改变现有总量计数语义）
#[cfg(feature = "metrics")]
const _HANDSHAKE_ERR_METRIC_HINT: &str = "sb_outbound_handshake_error_total";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

async fn connect_with_keepalive(
    addr: SocketAddr,
    timeout: Duration,
    keepalive: Option<Duration>,
) -> io::Result<TcpStream> {
    let sock = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    let _ = sock.set_nodelay(true);
    // 连接前仅开启 keepalive，时长在连接成功后通过 socket2 写入
    let _ = sock.set_keepalive(keepalive.is_some());
    match tokio::time::timeout(timeout, sock.connect(addr)).await {
        Ok(Ok(s)) => {
            // 连接成功后，按平台尽力设置 time/interval（失败不致命）
            if let Some(d) = keepalive {
                let sref = SockRef::from(&s);
                // 再次确保启用（跨平台一致性）
                let _ = sref.set_keepalive(true);
                let ka = TcpKeepalive::new().with_time(d).with_interval(d);
                // Linux/Android 支持 retries；其他平台忽略该设置
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    ka = ka.with_retries(5);
                }
                let _ = sref.set_tcp_keepalive(&ka);
            }
            Ok(s)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "tcp connect timeout",
        )),
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum OutboundKind {
    #[default]
    Direct,
    Block,
    Socks,
    Http,
    #[cfg(feature = "out_trojan")]
    Trojan,
    #[cfg(feature = "out_ss")]
    Shadowsocks,
    #[cfg(feature = "out_shadowtls")]
    ShadowTls,
    #[cfg(feature = "out_naive")]
    Naive,
    #[cfg(feature = "out_vless")]
    Vless,
    #[cfg(feature = "out_vmess")]
    Vmess,
    #[cfg(feature = "out_tuic")]
    Tuic,
    #[cfg(feature = "out_hysteria2")]
    Hysteria2,
    #[cfg(feature = "out_wireguard")]
    WireGuard,
    #[cfg(feature = "out_ssh")]
    Ssh,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTarget {
    Kind(OutboundKind),
    Named(String),
}

impl RouteTarget {
    pub fn direct() -> Self {
        RouteTarget::Kind(OutboundKind::Direct)
    }
    pub fn block() -> Self {
        RouteTarget::Kind(OutboundKind::Block)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Clone, Debug)]
pub enum OutboundImpl {
    Direct,
    Block,
    Socks5(Socks5Config),
    HttpProxy(HttpProxyConfig),
    #[cfg(feature = "out_trojan")]
    Trojan(trojan::TrojanConfig),
    #[cfg(feature = "out_ss")]
    Shadowsocks(shadowsocks::ShadowsocksConfig),
    #[cfg(feature = "out_shadowtls")]
    ShadowTls(shadowtls::ShadowTlsConfig),
    #[cfg(feature = "out_naive")]
    Naive(naive_h2::NaiveH2Config),
    #[cfg(feature = "out_vless")]
    Vless(vless::VlessConfig),
    #[cfg(feature = "out_vmess")]
    Vmess(vmess::VmessConfig),
    #[cfg(feature = "out_tuic")]
    Tuic(tuic::TuicConfig),
    #[cfg(feature = "out_hysteria2")]
    Hysteria2(hysteria2::Hysteria2Config),
    #[cfg(feature = "out_wireguard")]
    WireGuard(wireguard_stub::WireGuardConfig),
    #[cfg(feature = "out_ssh")]
    Ssh(ssh_stub::SshConfig),
}

#[derive(Clone, Debug, Default)]
pub struct OutboundRegistry {
    map: HashMap<String, OutboundImpl>,
}
impl OutboundRegistry {
    pub fn new(map: HashMap<String, OutboundImpl>) -> Self {
        Self { map }
    }
    pub fn get(&self, name: &str) -> Option<&OutboundImpl> {
        self.map.get(name)
    }
    pub fn insert(&mut self, name: String, v: OutboundImpl) {
        self.map.insert(name, v);
    }
}

#[derive(Clone, Debug)]
pub struct OutboundRegistryHandle {
    inner: Arc<RwLock<OutboundRegistry>>,
}
impl Default for OutboundRegistryHandle {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(OutboundRegistry::default())),
        }
    }
}
impl OutboundRegistryHandle {
    pub fn new(reg: OutboundRegistry) -> Self {
        Self {
            inner: Arc::new(RwLock::new(reg)),
        }
    }
    pub fn replace(&self, reg: OutboundRegistry) {
        if let Ok(mut w) = self.inner.write() {
            *w = reg;
        }
    }
    pub async fn connect_tcp(&self, target: &RouteTarget, ep: Endpoint) -> io::Result<TcpStream> {
        match target {
            RouteTarget::Kind(k) => connect_tcp_builtin(k, ep).await,
            RouteTarget::Named(name) => {
                let imp = {
                    match self.inner.read() {
                        Ok(r) => r.get(name).cloned(),
                        Err(_) => None,
                    }
                };
                match imp {
                    Some(OutboundImpl::Direct) => direct_connect(ep).await,
                    Some(OutboundImpl::Block) => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "blocked by rule",
                    )),
                    Some(OutboundImpl::Socks5(cfg)) => socks5_connect(&cfg, ep).await,
                    Some(OutboundImpl::HttpProxy(cfg)) => http_connect(&cfg, ep).await,
                    #[cfg(feature = "out_trojan")]
                    Some(OutboundImpl::Trojan(cfg)) => trojan_connect(&cfg, ep).await,
                    #[cfg(feature = "out_ss")]
                    Some(OutboundImpl::Shadowsocks(cfg)) => shadowsocks_connect(&cfg, ep).await,
                    #[cfg(feature = "out_shadowtls")]
                    Some(OutboundImpl::ShadowTls(cfg)) => shadowtls_connect(&cfg, ep).await,
                    #[cfg(feature = "out_naive")]
                    Some(OutboundImpl::Naive(cfg)) => naive_connect(&cfg, ep).await,
                    #[cfg(feature = "out_vless")]
                    Some(OutboundImpl::Vless(cfg)) => vless_connect(&cfg, ep).await,
                    #[cfg(feature = "out_vmess")]
                    Some(OutboundImpl::Vmess(cfg)) => vmess_connect(&cfg, ep).await,
                    #[cfg(feature = "out_tuic")]
                    Some(OutboundImpl::Tuic(cfg)) => tuic_connect(&cfg, ep).await,
                    #[cfg(feature = "out_hysteria2")]
                    Some(OutboundImpl::Hysteria2(cfg)) => hysteria2_connect(&cfg, ep).await,
                    #[cfg(feature = "out_wireguard")]
                    Some(OutboundImpl::WireGuard(cfg)) => wireguard_connect(&cfg, ep).await,
                    #[cfg(feature = "out_ssh")]
                    Some(OutboundImpl::Ssh(cfg)) => ssh_connect(&cfg, ep).await,
                    None => Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "outbound not found",
                    )),
                }
            }
        }
    }
}

async fn connect_tcp_builtin(kind: &OutboundKind, ep: Endpoint) -> io::Result<TcpStream> {
    match kind {
        OutboundKind::Direct => direct_connect(ep).await,
        OutboundKind::Block => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "blocked by router",
        )),
        OutboundKind::Socks | OutboundKind::Http => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin proxy not wired",
        )),
        #[cfg(feature = "out_trojan")]
        OutboundKind::Trojan => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin trojan not wired",
        )),
        #[cfg(feature = "out_ss")]
        OutboundKind::Shadowsocks => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin shadowsocks not wired",
        )),
        #[cfg(feature = "out_shadowtls")]
        OutboundKind::ShadowTls => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin shadowtls not wired",
        )),
        #[cfg(feature = "out_naive")]
        OutboundKind::Naive => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin naive not wired",
        )),
        #[cfg(feature = "out_vless")]
        OutboundKind::Vless => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin vless not wired",
        )),
        #[cfg(feature = "out_vmess")]
        OutboundKind::Vmess => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin vmess not wired",
        )),
        #[cfg(feature = "out_tuic")]
        OutboundKind::Tuic => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin tuic not wired",
        )),
        #[cfg(feature = "out_hysteria2")]
        OutboundKind::Hysteria2 => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin hysteria2 not wired",
        )),
        #[cfg(feature = "out_wireguard")]
        OutboundKind::WireGuard => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin wireguard not wired",
        )),
        #[cfg(feature = "out_ssh")]
        OutboundKind::Ssh => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin ssh not wired",
        )),
    }
}

async fn direct_connect(ep: Endpoint) -> io::Result<TcpStream> {
    let addr = match ep {
        Endpoint::Ip(sa) => sa,
        Endpoint::Domain(host, port) => {
            let query = format!("{}:{}", host, port);
            let mut it = lookup_host(query).await?;
            if let Some(sa) = it.next() {
                sa
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "resolve empty",
                ));
            }
        }
    };

    match connect_with_keepalive(addr, CONNECT_TIMEOUT, Some(Duration::from_secs(30))).await {
        Err(e) => {
            let res = if e.kind() == io::ErrorKind::TimedOut {
                "timeout"
            } else {
                "error"
            };
            outbound_connect("direct", res, Some(err_kind(&e)));
            Err(e)
        }
        Ok(s) => {
            outbound_connect("direct", "ok", None);
            Ok(s)
        }
    }
}

#[derive(Clone, Debug)]
pub struct Socks5Config {
    pub proxy_addr: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

async fn socks5_connect(cfg: &Socks5Config, ep: Endpoint) -> io::Result<TcpStream> {
    let mut s = match connect_with_keepalive(
        cfg.proxy_addr,
        CONNECT_TIMEOUT,
        Some(Duration::from_secs(30)),
    )
    .await
    {
        Err(e) => {
            let res = if e.kind() == io::ErrorKind::TimedOut {
                "timeout"
            } else {
                "error"
            };
            outbound_connect("socks5", res, Some(err_kind(&e)));
            return Err(e);
        }
        Ok(s) => {
            outbound_connect("socks5", "ok", None);
            s
        }
    };

    match timeout(HANDSHAKE_TIMEOUT, async {
        if cfg.username.is_some() {
            s.write_all(&[0x05, 0x01, 0x02]).await?;
        } else {
            s.write_all(&[0x05, 0x01, 0x00]).await?;
        }
        let mut rep = [0u8; 2];
        s.read_exact(&mut rep).await?;
        if rep[0] != 0x05 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "socks ver"));
        }
        if rep[1] == 0x02 {
            let (u, p) = (
                cfg.username.as_deref().unwrap_or(""),
                cfg.password.as_deref().unwrap_or(""),
            );
            let (u_b, p_b) = (u.as_bytes(), p.as_bytes());
            if u_b.len() > 255 || p_b.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "socks auth too long",
                ));
            }
            let mut buf = Vec::with_capacity(3 + u_b.len() + p_b.len());
            buf.push(0x01);
            buf.push(u_b.len() as u8);
            buf.extend_from_slice(u_b);
            buf.push(p_b.len() as u8);
            buf.extend_from_slice(p_b);
            s.write_all(&buf).await?;
            let mut r2 = [0u8; 2];
            s.read_exact(&mut r2).await?;
            if r2[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socks auth failed",
                ));
            }
        } else if rep[1] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "socks method not acceptable",
            ));
        }

        let mut req = Vec::with_capacity(22);
        req.push(0x05);
        req.push(0x01);
        req.push(0x00);
        match ep {
            Endpoint::Ip(sa) => {
                match sa.ip() {
                    IpAddr::V4(v4) => {
                        req.push(0x01);
                        req.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        req.push(0x04);
                        req.extend_from_slice(&v6.octets());
                    }
                }
                req.push((sa.port() >> 8) as u8);
                req.push((sa.port() & 0xff) as u8);
            }
            Endpoint::Domain(host, port) => {
                let hb = host.as_bytes();
                if hb.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "domain too long",
                    ));
                }
                req.push(0x03);
                req.push(hb.len() as u8);
                req.extend_from_slice(hb);
                req.push((port >> 8) as u8);
                req.push((port & 0xff) as u8);
            }
        }
        s.write_all(&req).await?;

        let mut head = [0u8; 4];
        s.read_exact(&mut head).await?;
        if head[0] != 0x05 || head[1] != 0x00 {
            return Err(io::Error::new(io::ErrorKind::Other, "socks connect failed"));
        }
        match head[3] {
            0x01 => {
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).await?;
                let mut d = vec![0; len[0] as usize];
                s.read_exact(&mut d).await?;
            }
            0x04 => {
                let mut b = [0u8; 16];
                s.read_exact(&mut b).await?;
            }
            _ => {}
        }
        let mut _port = [0u8; 2];
        s.read_exact(&mut _port).await?;
        io::Result::Ok(())
    })
    .await
    {
        Err(_) => {
            outbound_handshake("socks5", "timeout", Some("timeout"));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "socks5 handshake timeout",
            ));
        }
        Ok(Err(e)) => {
            outbound_handshake("socks5", "error", Some(err_kind(&e)));
            return Err(e);
        }
        Ok(Ok(())) => {
            outbound_handshake("socks5", "ok", None);
        }
    }
    Ok(s)
}

#[derive(Clone, Debug)]
pub struct HttpProxyConfig {
    pub proxy_addr: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

async fn http_connect(cfg: &HttpProxyConfig, ep: Endpoint) -> io::Result<TcpStream> {
    let mut s = match connect_with_keepalive(
        cfg.proxy_addr,
        CONNECT_TIMEOUT,
        Some(Duration::from_secs(30)),
    )
    .await
    {
        Err(e) => {
            let res = if e.kind() == io::ErrorKind::TimedOut {
                "timeout"
            } else {
                "error"
            };
            outbound_connect("http", res, Some(err_kind(&e)));
            return Err(e);
        }
        Ok(s) => {
            outbound_connect("http", "ok", None);
            s
        }
    };

    match timeout(HANDSHAKE_TIMEOUT, async {
        use Endpoint::*;
        let host_port = match ep {
            Ip(sa) => format!(
                "{}:{}",
                match sa.ip() {
                    IpAddr::V4(v4) => v4.to_string(),
                    IpAddr::V6(v6) => format!("[{}]", v6),
                },
                sa.port()
            ),
            Domain(host, port) => format!("{}:{}", host, port),
        };

        let mut req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", host_port, host_port);
        if let Some(user) = &cfg.username {
            let pass = cfg.password.as_deref().unwrap_or("");
            let raw = format!("{}:{}", user, pass);
            let auth = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", auth));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).await?;

        let mut buf = Vec::with_capacity(256);
        let mut tmp = [0u8; 128];
        loop {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "proxy closed"));
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy header too large",
                ));
            }
        }
        let ok = buf.starts_with(b"HTTP/1.1 200") || buf.starts_with(b"HTTP/1.0 200");
        if !ok {
            return Err(io::Error::new(io::ErrorKind::Other, "http connect failed"));
        }
        io::Result::Ok(())
    })
    .await
    {
        Err(_) => {
            outbound_handshake("http", "timeout", Some("timeout"));
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "http handshake timeout",
            ));
        }
        Ok(Err(e)) => {
            outbound_handshake("http", "error", Some(err_kind(&e)));
            return Err(e);
        }
        Ok(Ok(())) => {
            outbound_handshake("http", "ok", None);
        }
    }
    Ok(s)
}

// 为入站适配器提供的便捷连接函数
#[derive(Clone, Debug, Default)]
pub struct ConnectOpts {
    // 将来可以添加更多选项，比如超时设置等
}

/// 直连到目标（无代理）
pub async fn direct_connect_hostport(
    host: &str,
    port: u16,
    _opts: &ConnectOpts,
) -> io::Result<TcpStream> {
    direct_connect(Endpoint::Domain(host.to_string(), port)).await
}

/// 通过HTTP代理连接到目标
pub async fn http_proxy_connect_through_proxy(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    _opts: &ConnectOpts,
) -> io::Result<TcpStream> {
    let proxy_sa: SocketAddr = proxy_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy address"))?;
    let cfg = HttpProxyConfig {
        proxy_addr: proxy_sa,
        username: None,
        password: None,
    };
    http_connect(&cfg, Endpoint::Domain(target_host.to_string(), target_port)).await
}

/// 通过SOCKS5代理连接到目标
pub async fn socks5_connect_through_socks5(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
    _opts: &ConnectOpts,
) -> io::Result<TcpStream> {
    let proxy_sa: SocketAddr = proxy_addr
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid proxy address"))?;
    let cfg = Socks5Config {
        proxy_addr: proxy_sa,
        username: None,
        password: None,
    };
    socks5_connect(&cfg, Endpoint::Domain(target_host.to_string(), target_port)).await
}

// Adapter functions for encrypted protocols
#[cfg(feature = "out_trojan")]
async fn trojan_connect(cfg: &trojan::TrojanConfig, ep: Endpoint) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = trojan::TrojanOutbound::new(cfg.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Trojan setup failed: {}", e)))?;

    // Connect and convert to TcpStream
    match outbound.connect(&target).await {
        Ok(_tls_stream) => {
            // For compatibility with existing code that expects TcpStream,
            // we need to wrap or extract the underlying stream
            // This is a simplification - in practice you might need a proper wrapper
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Trojan connection established but stream conversion not implemented",
            ))
        }
        Err(e) => Err(e),
    }
}

#[cfg(feature = "out_ss")]
async fn shadowsocks_connect(
    cfg: &shadowsocks::ShadowsocksConfig,
    ep: Endpoint,
) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = shadowsocks::ShadowsocksOutbound::new(cfg.clone());

    // Connect and convert to TcpStream
    match outbound.connect(&target).await {
        Ok(_ss_stream) => {
            // For compatibility with existing code that expects TcpStream,
            // we need to wrap or extract the underlying stream
            // This is a simplification - in practice you might need a proper wrapper
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Shadowsocks connection established but stream conversion not implemented",
            ))
        }
        Err(e) => Err(e),
    }
}

// Adapter functions for new encrypted protocols
#[cfg(feature = "out_shadowtls")]
async fn shadowtls_connect(
    cfg: &shadowtls::ShadowTlsConfig,
    ep: Endpoint,
) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = shadowtls::ShadowTlsOutbound::new(cfg.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("ShadowTLS setup failed: {}", e),
        )
    })?;

    // Note: ShadowTLS returns a TLS stream, not a TcpStream
    // For now, return an error indicating this needs proper handling
    Err(io::Error::new(
        io::ErrorKind::Other,
        "ShadowTLS connection requires TLS stream handling",
    ))
}

#[cfg(feature = "out_naive")]
async fn naive_connect(cfg: &naive_h2::NaiveH2Config, ep: Endpoint) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = naive_h2::NaiveH2Outbound::new(cfg.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Naive setup failed: {}", e)))?;

    // Note: Naive returns a compat stream, not a TcpStream
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Naive HTTP/2 connection requires compat stream handling",
    ))
}

#[cfg(feature = "out_vless")]
async fn vless_connect(cfg: &vless::VlessConfig, ep: Endpoint) -> io::Result<TcpStream> {
    use crate::outbound::types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = vless::VlessOutbound::new(cfg.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("VLESS setup failed: {}", e)))?;

    outbound.connect(&target).await
}

#[cfg(feature = "out_vmess")]
async fn vmess_connect(cfg: &vmess::VmessConfig, ep: Endpoint) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = vmess::VmessOutbound::new(cfg.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("VMess setup failed: {}", e)))?;

    outbound.connect(&target).await
}

#[cfg(feature = "out_tuic")]
async fn tuic_connect(cfg: &tuic::TuicConfig, ep: Endpoint) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = tuic::TuicOutbound::new(cfg.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("TUIC setup failed: {}", e)))?;

    // Note: TUIC returns a compat stream, not a TcpStream
    Err(io::Error::new(
        io::ErrorKind::Other,
        "TUIC connection requires compat stream handling",
    ))
}

#[cfg(feature = "out_hysteria2")]
async fn hysteria2_connect(
    cfg: &hysteria2::Hysteria2Config,
    ep: Endpoint,
) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = hysteria2::Hysteria2Outbound::new(cfg.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Hysteria2 setup failed: {}", e),
        )
    })?;

    // Note: Hysteria2 returns a compat stream, not a TcpStream
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Hysteria2 connection requires compat stream handling",
    ))
}

#[cfg(feature = "out_wireguard")]
async fn wireguard_connect(
    cfg: &wireguard_stub::WireGuardConfig,
    ep: Endpoint,
) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = wireguard_stub::WireGuardOutbound::new(cfg.clone()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("WireGuard setup failed: {}", e),
        )
    })?;

    outbound.connect(&target).await
}

#[cfg(feature = "out_ssh")]
async fn ssh_connect(cfg: &ssh_stub::SshConfig, ep: Endpoint) -> io::Result<TcpStream> {
    use crypto_types::{HostPort, OutboundTcp};

    let target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let outbound = ssh_stub::SshOutbound::new(cfg.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("SSH setup failed: {}", e)))?;

    outbound.connect(&target).await
}
