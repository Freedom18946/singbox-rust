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

pub mod chain;
pub mod endpoint;
pub mod health;
pub mod manager;
pub mod registry;
pub mod tcp;
pub mod types;
pub mod udp;
pub mod udp_direct;

// Encrypted outbound protocols
pub mod address;
pub mod crypto_types;
// Performance optimizations for P0 protocols
pub mod optimizations;

use parking_lot::RwLock;
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

// Re-export the standard traits and implementations
pub use manager::OutboundManager;
pub use sb_types::{Outbound, PacketConn};

// Public dial utilities, allowing upper layers/callers to use them in-place without modifying outbound implementations
// 公开拨号工具，便于上层/调用方在不改动出站实现的前提下就地使用
pub use crate::net::dial::{
    dial_all, dial_hostport, dial_pref, dial_socketaddrs, per_attempt_timeout,
};

#[cfg(feature = "metrics")]
const _HANDSHAKE_ERR_METRIC_HINT: &str = "sb_outbound_handshake_error_total";

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

    Naive,

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
    /// Canonical protocol connector built by sb-adapters.
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
    pub fn insert(&mut self, name: String, value: OutboundImpl) {
        self.map.insert(name, value);
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
    pub fn new(registry: OutboundRegistry) -> Self {
        Self {
            inner: Arc::new(RwLock::new(registry)),
        }
    }
    pub fn replace(&self, registry: OutboundRegistry) {
        *self.inner.write() = registry;
    }
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, OutboundRegistry> {
        self.inner.read()
    }
    pub fn resolve(&self, name: &str) -> Option<OutboundImpl> {
        self.inner.read().get(name).cloned()
    }

    fn resolve_target(&self, target: &RouteTarget) -> io::Result<Arc<dyn sb_types::Outbound>> {
        let name = match target {
            RouteTarget::Named(name) => name.as_str(),
            RouteTarget::Kind(OutboundKind::Direct) => "direct",
            RouteTarget::Kind(OutboundKind::Block) => "block",
            RouteTarget::Kind(other) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("builtin outbound {other:?} was removed; use a named adapter registry entry"),
                ));
            }
        };
        match self.resolve(name) {
            Some(OutboundImpl::Connector(connector)) => Ok(connector),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("outbound '{name}' not found in adapter registry"),
            )),
        }
    }

    /// Establish UDP through canonical adapter registry connector.
    pub async fn connect_udp(
        &self,
        target: &RouteTarget,
        session: sb_types::Session,
    ) -> io::Result<sb_types::BoxedPacketConn> {
        self.resolve_target(target)?
            .listen_packet(&session)
            .await
            .map_err(core_error_to_io)
    }

    /// Establish byte stream through canonical adapter registry connector.
    pub async fn connect_tcp_stream(
        &self,
        target: &RouteTarget,
        endpoint: Endpoint,
    ) -> io::Result<sb_transport::IoStream> {
        let connector = self.resolve_target(target)?;
        dial_canonical_outbound(connector.as_ref(), endpoint).await
    }

    /// Preferred connection helper. Always uses canonical boxed-stream dialing.
    pub async fn connect_preferred(
        &self,
        target: &RouteTarget,
        endpoint: Endpoint,
    ) -> io::Result<sb_transport::IoStream> {
        self.connect_tcp_stream(target, endpoint).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn registry_handle_resolve_uses_dedicated_query_seam() {
        let mut registry = OutboundRegistry::default();
        registry.insert(
            "direct".to_string(),
            OutboundImpl::Connector(Arc::new(DummyConnector {
                opened: Arc::new(AtomicUsize::new(0)),
            })),
        );
        let handle = OutboundRegistryHandle::new(registry);

        assert!(matches!(
            handle.resolve("direct"),
            Some(OutboundImpl::Connector(_))
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
        assert!(src.contains("fn resolve_target(&self, target: &RouteTarget)"));
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
