// crates/sb-core/src/outbound/mod.rs
//! Outbound Abstraction & Registry (P1.6)
//! Outbound 抽象与注册表 (P1.6)
//!
//! # Outbound Layer / 出站层
//! The outbound layer handles the actual connection to the destination.
//! 出站层处理到目的地的实际连接。
//!
//! ## Key Features / 关键特性
//! - **Unified Connection/Handshake Timeout**: Default 10s/10s.
//!   统一的连接/握手超时（默认 10s/10s）。
//! - **Observability / 可观测性**: Metrics for Direct / SOCKS5 / HTTP CONNECT outbounds.
//!   Direct / SOCKS5 / HTTP CONNECT 出站的指标。
//!   - `sb_outbound_connect_total{kind="direct|socks5|http", result="ok|timeout|error"}`
//!   - `sb_outbound_handshake_total{kind="socks5|http", result="ok|timeout|error"}`
//! - **TCP Optimization**: `TCP_NODELAY` set after Direct success.
//!   Direct 成功后设置 `TCP_NODELAY`。
//!
//! Data structures and external interfaces remain compatible: No changes needed for Router/Inbound side.
//! 数据结构与对外接口保持不变：Router/Inbound 端无需改动。

#[cfg(feature = "router")]
pub mod chain;
pub mod direct_connector;
pub mod endpoint;
pub mod health;
#[cfg(feature = "out_http")]
pub mod http_upstream;
pub mod manager;
pub mod observe;
pub mod registry;
pub mod selector;
pub mod selector_group;
pub mod socks5_udp;
#[cfg(feature = "out_socks")]
pub mod socks_upstream;
pub mod tcp;
pub mod types;
pub mod udp;
pub mod udp_balancer;
pub mod udp_direct;
pub mod udp_proxy_glue;
pub mod udp_socks5;
// P3 Score Selector
// P3 评分选择器
#[cfg(feature = "selector_p3")]
pub mod selector_p3;
// Unified Feedback Entry (Selection/Dial Report)
// 统一反馈入口（选择/拨号回报）
#[cfg(feature = "selector_p3")]
pub mod feedback;
// Simplified P3 Selector
// 简化 P3 选择器
pub mod p3_selector;

// Encrypted outbound protocols
pub mod address;
pub mod crypto_types;
pub mod ss {
    pub mod hkdf;
}
#[cfg(feature = "out_naive")]
pub mod naive_h2;
// QUIC types are included in crypto_types
#[cfg(feature = "out_quic")]
pub mod quic {
    pub mod common;
    pub mod io;
}
#[cfg(feature = "out_hysteria")]
pub mod hysteria;
#[cfg(feature = "out_hysteria2")]
pub mod hysteria2;

// Performance optimizations for P0 protocols
pub mod optimizations;

use crate::telemetry::{err_kind, outbound_connect, outbound_handshake};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

// Re-export the standard traits and implementations
pub use direct_connector::{DirectConnector, DirectUdpTransport};
pub use manager::OutboundManager;
pub use sb_types::{Outbound, PacketConn};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpSocket, TcpStream},
    time::{timeout, Duration},
};
// Public dial utilities, allowing upper layers/callers to use them in-place without modifying outbound implementations
// 公开拨号工具，便于上层/调用方在不改动出站实现的前提下就地使用
pub use crate::net::dial::{
    dial_all, dial_hostport, dial_pref, dial_socketaddrs, per_attempt_timeout,
};

/// (Experimental) Outbound convenient dial wrapper: Currently provided as API, not directly replacing existing implementations.
/// （预备）出站便捷拨号包装：现在先提供 API，不直接替换现有实现。
///
/// Example call: `let s = sb_core::outbound::connect("example.com", 443).await?;`
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

async fn dial_canonical_outbound(
    outbound: &dyn sb_types::Outbound,
    endpoint: Endpoint,
) -> io::Result<sb_transport::IoStream> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let session = canonical_session(endpoint);
    let stream = outbound.dial(&session).await.map_err(core_error_to_io)?;
    Ok(Box::new(stream.compat()))
}

fn canonical_session(endpoint: Endpoint) -> sb_types::Session {
    let target = match endpoint {
        Endpoint::Ip(address) => sb_types::TargetAddr::Socket(address),
        Endpoint::Domain(host, port) => sb_types::TargetAddr::domain(host, port),
    };
    sb_types::Session::new(
        0,
        sb_types::InboundTag::new("core-outbound-registry"),
        target,
    )
}

fn core_error_to_io(error: sb_types::CoreError) -> io::Error {
    let kind = match &error {
        sb_types::CoreError::Connect { kind, .. } => match kind {
            sb_types::ConnectErrorKind::Refused => io::ErrorKind::ConnectionRefused,
            sb_types::ConnectErrorKind::Reset => io::ErrorKind::ConnectionReset,
            sb_types::ConnectErrorKind::Unreachable => io::ErrorKind::NotConnected,
            sb_types::ConnectErrorKind::Unsupported => io::ErrorKind::Unsupported,
            sb_types::ConnectErrorKind::InvalidConfig => io::ErrorKind::InvalidInput,
        },
        sb_types::CoreError::Timeout { .. } => io::ErrorKind::TimedOut,
        sb_types::CoreError::Policy { .. } => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum OutboundKind {
    #[default]
    Direct,
    Block,
    Socks,
    Http,
    #[cfg(feature = "out_naive")]
    Naive,
    #[cfg(feature = "out_hysteria2")]
    Hysteria2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteTarget {
    Kind(OutboundKind),
    Named(String),
}

impl RouteTarget {
    pub const fn direct() -> Self {
        Self::Kind(OutboundKind::Direct)
    }
    pub const fn block() -> Self {
        Self::Kind(OutboundKind::Block)
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
    #[cfg(feature = "out_naive")]
    Naive(naive_h2::NaiveH2Config),
    #[cfg(feature = "out_hysteria2")]
    Hysteria2(hysteria2::Hysteria2Config),
    /// Generic trait-based connector (e.g., `SelectorGroup`)
    Connector(Arc<dyn sb_types::Outbound>),
}

#[derive(Clone, Debug, Default)]
pub struct OutboundRegistry {
    map: HashMap<String, OutboundImpl>,
}
impl OutboundRegistry {
    pub const fn new(map: HashMap<String, OutboundImpl>) -> Self {
        Self { map }
    }
    pub fn get(&self, name: &str) -> Option<&OutboundImpl> {
        self.map.get(name)
    }
    pub fn insert(&mut self, name: String, v: OutboundImpl) {
        self.map.insert(name, v);
    }
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
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
        *self.inner.write() = reg;
    }
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, OutboundRegistry> {
        self.inner.read()
    }
    pub fn resolve(&self, name: &str) -> Option<OutboundImpl> {
        self.inner.read().get(name).cloned()
    }

    pub async fn connect_tcp(&self, target: &RouteTarget, ep: Endpoint) -> io::Result<TcpStream> {
        match target {
            RouteTarget::Kind(k) => connect_tcp_builtin(k, ep).await,
            RouteTarget::Named(name) => match self.resolve(name) {
                Some(OutboundImpl::Direct) => direct_connect(ep).await,
                Some(OutboundImpl::Block) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "blocked by rule",
                )),
                Some(OutboundImpl::Socks5(cfg)) => socks5_connect(&cfg, ep).await,
                Some(OutboundImpl::HttpProxy(cfg)) => http_connect(&cfg, ep).await,
                Some(OutboundImpl::Connector(conn)) => {
                    let _ = conn;
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "canonical outbound requires connect_tcp_stream",
                    ))
                }
                #[cfg(feature = "out_naive")]
                Some(OutboundImpl::Naive(cfg)) => naive_connect(&cfg, ep).await,
                #[cfg(feature = "out_hysteria2")]
                Some(OutboundImpl::Hysteria2(cfg)) => hysteria2_connect(&cfg, ep).await,
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "outbound not found",
                )),
            },
        }
    }

    /// Establish a UDP transport to `ep` through the selected outbound.
    ///
    /// This is the UDP counterpart of [`connect_tcp`](Self::connect_tcp), used by the
    /// Enhanced TUN datapath's lightweight UDP NAT. Only `direct` is wired today;
    /// proxy outbounds that could support UDP associate (SOCKS5, Hysteria2) return a
    /// loud `Unsupported` error so callers can drop the datagram explicitly instead of
    /// silently black-holing it. A general UDP NAT layer is owned by P1313-09; this
    /// keeps the surface minimal and reusable.
    pub async fn connect_udp(
        &self,
        target: &RouteTarget,
        session: sb_types::Session,
    ) -> io::Result<sb_types::BoxedPacketConn> {
        use crate::outbound::direct_connector::DirectConnector;

        let connect_direct = || async {
            DirectConnector::new()
                .listen_packet(&session)
                .await
                .map_err(core_error_to_io)
        };

        match target {
            RouteTarget::Kind(OutboundKind::Direct) => connect_direct().await,
            RouteTarget::Kind(OutboundKind::Block) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "blocked by router",
            )),
            RouteTarget::Kind(other) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("builtin outbound {other:?} does not support UDP"),
            )),
            RouteTarget::Named(name) => match self.resolve(name) {
                Some(OutboundImpl::Direct) => connect_direct().await,
                Some(OutboundImpl::Block) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "blocked by rule",
                )),
                Some(OutboundImpl::Connector(connector)) => connector
                    .listen_packet(&session)
                    .await
                    .map_err(core_error_to_io),
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound '{name}' does not support UDP associate"),
                )),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "outbound not found",
                )),
            },
        }
    }

    /// Establish a byte stream to `ep` through the selected outbound, returning a
    /// boxed `AsyncRead + AsyncWrite` stream.
    ///
    /// Unlike [`connect_tcp`](Self::connect_tcp) (which returns a raw `TcpStream` and
    /// therefore cannot represent proxy/CONNECT-tunnelled or layered transports), this
    /// uses each outbound's CONNECT-aware path. This is what the TUN datapath uses so
    /// that TUN traffic can egress through HTTP/SOCKS/adapter outbounds, not only
    /// `direct`. `Connector` outbounds (the adapter registry, e.g. the GUI's HTTP/SOCKS
    /// outbounds) are dialed through the canonical boxed-stream contract.
    pub async fn connect_tcp_stream(
        &self,
        target: &RouteTarget,
        ep: Endpoint,
    ) -> io::Result<sb_transport::IoStream> {
        fn boxed<S>(s: S) -> sb_transport::IoStream
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        {
            Box::new(s)
        }

        match target {
            RouteTarget::Kind(k) => Ok(boxed(connect_tcp_builtin(k, ep).await?)),
            RouteTarget::Named(name) => match self.resolve(name) {
                Some(OutboundImpl::Direct) => Ok(boxed(direct_connect(ep).await?)),
                Some(OutboundImpl::Block) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "blocked by rule",
                )),
                Some(OutboundImpl::Socks5(cfg)) => Ok(boxed(socks5_connect(&cfg, ep).await?)),
                Some(OutboundImpl::HttpProxy(cfg)) => Ok(boxed(http_connect(&cfg, ep).await?)),
                Some(OutboundImpl::Connector(conn)) => {
                    dial_canonical_outbound(conn.as_ref(), ep).await
                }
                #[cfg(feature = "out_naive")]
                Some(OutboundImpl::Naive(cfg)) => Ok(boxed(naive_connect(&cfg, ep).await?)),
                #[cfg(feature = "out_hysteria2")]
                Some(OutboundImpl::Hysteria2(cfg)) => Ok(boxed(hysteria2_connect(&cfg, ep).await?)),
                None => Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "outbound not found",
                )),
            },
        }
    }

    /// Preferred connection helper. Always uses canonical boxed-stream dialing.
    pub async fn connect_preferred(
        &self,
        target: &RouteTarget,
        ep: Endpoint,
    ) -> io::Result<sb_transport::IoStream> {
        self.connect_tcp_stream(target, ep).await
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
        #[cfg(feature = "out_naive")]
        OutboundKind::Naive => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin naive not wired",
        )),
        #[cfg(feature = "out_hysteria2")]
        OutboundKind::Hysteria2 => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "builtin hysteria2 not wired",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn registry_handle_resolve_uses_dedicated_query_seam() {
        let mut registry = OutboundRegistry::default();
        registry.insert("direct".to_string(), OutboundImpl::Direct);
        let handle = OutboundRegistryHandle::new(registry);

        assert!(matches!(
            handle.resolve("direct"),
            Some(OutboundImpl::Direct)
        ));
        assert!(handle.resolve("missing").is_none());
    }

    #[test]
    fn registry_handle_source_pin_uses_owner_first_lookup_helper() {
        let src = include_str!("mod.rs");
        assert!(src.contains("pub fn resolve(&self, name: &str) -> Option<OutboundImpl>"));
        assert!(src.contains("inner: Arc<RwLock<OutboundRegistry>>"));
        assert!(src
            .contains("pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, OutboundRegistry>"));
        assert!(src.contains("RouteTarget::Named(name) => match self.resolve(name)"));
    }

    #[derive(Debug)]
    struct DummyConnector {
        opened: Arc<AtomicUsize>,
    }

    impl sb_types::Outbound for DummyConnector {
        fn r#type(&self) -> &str {
            "dummy"
        }
        fn tag(&self) -> sb_types::OutboundTag {
            sb_types::OutboundTag::new("dummy")
        }
        fn network(&self) -> &[sb_types::NetworkKind] {
            &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
        }
        fn dial<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
            Box::pin(async {
                Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "tcp unused",
                ))
            })
        }
        fn listen_packet<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
        {
            let opened = self.opened.clone();
            Box::pin(async move {
                opened.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(MockPacketConn) as sb_types::BoxedPacketConn)
            })
        }
    }

    #[derive(Debug)]
    struct MockPacketConn;

    impl sb_types::PacketConn for MockPacketConn {
        fn send_to<'a>(
            &'a self,
            data: &'a [u8],
            _: &'a sb_types::TargetAddr,
        ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
            Box::pin(async move { Ok(data.len()) })
        }
        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> sb_types::BoxFuture<'a, Result<(usize, sb_types::TargetAddr), sb_types::CoreError>>
        {
            Box::pin(async move {
                buffer[..2].copy_from_slice(b"ok");
                Ok((
                    2,
                    sb_types::TargetAddr::socket("127.0.0.1:53".parse().unwrap()),
                ))
            })
        }
        fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn local_addr(&self) -> Option<sb_types::TargetAddr> {
            None
        }
        fn set_deadline(&self, _: Option<std::time::Instant>) -> Result<(), sb_types::CoreError> {
            Ok(())
        }
        fn set_read_deadline(
            &self,
            _: Option<std::time::Instant>,
        ) -> Result<(), sb_types::CoreError> {
            Ok(())
        }
        fn set_write_deadline(
            &self,
            _: Option<std::time::Instant>,
        ) -> Result<(), sb_types::CoreError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn registry_connect_udp_uses_canonical_named_connector() {
        let opened = Arc::new(AtomicUsize::new(0));
        let mut registry = OutboundRegistry::default();
        registry.insert(
            "wg".to_string(),
            OutboundImpl::Connector(Arc::new(DummyConnector {
                opened: opened.clone(),
            })),
        );
        let handle = OutboundRegistryHandle::new(registry);

        let transport = handle
            .connect_udp(
                &RouteTarget::Named("wg".to_string()),
                sb_types::Session::new(
                    0,
                    sb_types::InboundTag::new("test"),
                    sb_types::TargetAddr::socket("10.7.0.1:53".parse().unwrap()),
                ),
            )
            .await
            .expect("named connector should use canonical PacketConn");

        let n = transport
            .send_to(
                b"hello",
                &sb_types::TargetAddr::socket("10.7.0.1:53".parse().unwrap()),
            )
            .await
            .expect("factory transport send");
        assert_eq!(n, 5);

        let mut buf = [0u8; 8];
        let (n, src) = transport
            .recv_from(&mut buf)
            .await
            .expect("factory transport recv");
        assert_eq!(&buf[..n], b"ok");
        assert_eq!(
            src,
            sb_types::TargetAddr::socket("127.0.0.1:53".parse().unwrap())
        );
        assert_eq!(opened.load(Ordering::SeqCst), 1);
    }
}

pub(crate) async fn resolve_host_for_direct(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Some(resolver) = crate::dns::global::get() {
        match resolver.resolve(host).await {
            Ok(answer) => {
                let addrs: Vec<_> = answer
                    .ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect();
                if !addrs.is_empty() {
                    return Ok(addrs);
                }
                tracing::warn!(
                    host = %host,
                    "global dns resolver returned an empty answer for direct connect; falling back to system lookup"
                );
            }
            Err(error) => {
                tracing::debug!(
                    host = %host,
                    %error,
                    "global dns resolver failed for direct connect; falling back to system lookup"
                );
            }
        }
    }

    let query = format!("{host}:{port}");
    let addrs: Vec<_> = lookup_host(query).await?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "resolve empty",
        ));
    }
    Ok(addrs)
}

async fn direct_connect(ep: Endpoint) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = match ep {
        Endpoint::Ip(sa) => vec![sa],
        Endpoint::Domain(host, port) => resolve_host_for_direct(&host, port).await?,
    };

    let mut last_err: Option<io::Error> = None;
    for addr in &addrs {
        match connect_with_keepalive(*addr, CONNECT_TIMEOUT, Some(Duration::from_secs(30))).await {
            Ok(s) => {
                outbound_connect("direct", "ok", None);
                return Ok(s);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    let e = last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address to connect"));
    let res = if e.kind() == io::ErrorKind::TimedOut {
        "timeout"
    } else {
        "error"
    };
    outbound_connect("direct", res, Some(err_kind(&e)));
    Err(e)
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
            return Err(io::Error::other("socks method not acceptable"));
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
            return Err(io::Error::other("socks connect failed"));
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
        use Endpoint::{Domain, Ip};
        let host_port = match ep {
            Ip(sa) => format!(
                "{}:{}",
                match sa.ip() {
                    IpAddr::V4(v4) => v4.to_string(),
                    IpAddr::V6(v6) => format!("[{v6}]"),
                },
                sa.port()
            ),
            Domain(host, port) => format!("{host}:{port}"),
        };

        let mut req = format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n");
        if let Some(user) = &cfg.username {
            let pass = cfg.password.as_deref().unwrap_or("");
            let raw = format!("{user}:{pass}");
            let auth = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
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
            return Err(io::Error::other("http connect failed"));
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

// Adapter functions for retained encrypted protocols

#[cfg(feature = "out_naive")]
async fn naive_connect(cfg: &naive_h2::NaiveH2Config, ep: Endpoint) -> io::Result<TcpStream> {
    use crypto_types::HostPort;

    let _target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let _outbound = naive_h2::NaiveH2Outbound::new(cfg.clone())
        .map_err(|e| io::Error::other(format!("Naive setup failed: {}", e)))?;

    // Note: Naive returns a compat stream, not a TcpStream
    Err(io::Error::other(
        "Naive HTTP/2 connection requires compat stream handling",
    ))
}

#[cfg(feature = "out_hysteria2")]
async fn hysteria2_connect(
    cfg: &hysteria2::Hysteria2Config,
    ep: Endpoint,
) -> io::Result<TcpStream> {
    use crypto_types::HostPort;

    let _target = match ep {
        Endpoint::Ip(sa) => HostPort::new(sa.ip().to_string(), sa.port()),
        Endpoint::Domain(host, port) => HostPort::new(host, port),
    };

    let _outbound = hysteria2::Hysteria2Outbound::new(cfg.clone())
        .map_err(|e| io::Error::other(format!("Hysteria2 setup failed: {}", e)))?;

    // Note: Hysteria2 returns a compat stream, not a TcpStream
    Err(io::Error::other(
        "Hysteria2 connection requires compat stream handling",
    ))
}
