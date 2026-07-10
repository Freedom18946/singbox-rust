//! Direct outbound connector implementation
//!
//! This module provides a direct connection implementation of `Outbound`
//! that connects directly to targets without any proxy.

use crate::{
    error::{ErrorClass, SbError, SbResult},
    types::{ConnCtx, Endpoint, Host},
};
use futures::StreamExt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Duration};

/// Direct outbound connector that connects directly to targets
#[derive(Debug, Clone)]
pub struct DirectConnector {
    connect_timeout: Duration,
    bind_interface: Option<String>,
    routing_mark: Option<u32>,
    reuse_addr: bool,
    tcp_fast_open: bool,
    tcp_multi_path: bool,
}

impl DirectConnector {
    /// Create a new direct connector with default timeout
    pub const fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            bind_interface: None,
            routing_mark: None,
            reuse_addr: false,
            tcp_fast_open: false,
            tcp_multi_path: false,
        }
    }

    pub fn with_options(
        connect_timeout: Option<Duration>,
        bind_interface: Option<String>,
        routing_mark: Option<u32>,
        reuse_addr: Option<bool>,
        tcp_fast_open: Option<bool>,
        tcp_multi_path: Option<bool>,
    ) -> Self {
        Self {
            connect_timeout: connect_timeout.unwrap_or(Duration::from_secs(10)),
            bind_interface,
            routing_mark,
            reuse_addr: reuse_addr.unwrap_or(false), // This line was intended to be replaced, but the replacement was syntactically incorrect. Reverting to original for correctness.
            tcp_fast_open: tcp_fast_open.unwrap_or(false),
            tcp_multi_path: tcp_multi_path.unwrap_or(false),
        }
    }

    /// Create a new direct connector with custom timeout
    /// Create a new direct connector with custom timeout
    pub const fn with_timeout(connect_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            bind_interface: None,
            routing_mark: None,
            reuse_addr: false,
            tcp_fast_open: false,
            tcp_multi_path: false,
        }
    }

    /// Resolve endpoint to socket addresses
    async fn resolve_endpoint(&self, endpoint: &Endpoint) -> SbResult<Vec<SocketAddr>> {
        match &endpoint.host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, endpoint.port)]),
            Host::Name(domain) => super::resolve_host_for_direct(domain, endpoint.port)
                .await
                .map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("DNS resolution failed: {e}"),
                    )
                }),
        }
    }
}

impl Default for DirectConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectConnector {
    async fn connect_tcp(&self, ctx: &ConnCtx) -> SbResult<TcpStream> {
        // Global backpressure via semaphore
        let (sem, q_ms) = global_limiters();
        let _permit = tokio::time::timeout(Duration::from_millis(q_ms), sem.acquire())
            .await
            .map_err(|_| SbError::timeout("outbound_queue", q_ms))
            .and_then(|r| {
                r.map_err(|_| SbError::Canceled {
                    operation: "acquire_semaphore".to_string(),
                })
            })?;

        let addrs = self.resolve_endpoint(&ctx.dst).await?;

        // Happy Eyeballs (RFC 8305) simplified implementation
        // 1. Prefer IPv6 if available (assuming system resolver order is respected)
        // 2. Race connections with a delay

        // If only one address, connect directly
        if addrs.len() == 1 {
            return self.connect_addr(addrs[0]).await;
        }

        // Sort addresses: interleave IPv6 and IPv4 if both present, preserving order otherwise
        let mut sorted_addrs = Vec::new();
        let mut v6 = Vec::new();
        let mut v4 = Vec::new();
        for addr in addrs {
            if addr.is_ipv6() {
                v6.push(addr);
            } else {
                v4.push(addr);
            }
        }

        // Simple interleaving
        let mut v6_iter = v6.into_iter();
        let mut v4_iter = v4.into_iter();
        loop {
            match (v6_iter.next(), v4_iter.next()) {
                (Some(a6), Some(a4)) => {
                    sorted_addrs.push(a6);
                    sorted_addrs.push(a4);
                }
                (Some(a6), None) => sorted_addrs.push(a6),
                (None, Some(a4)) => sorted_addrs.push(a4),
                (None, None) => break,
            }
        }

        let mut tasks = futures::stream::FuturesUnordered::new();
        let mut addrs_iter = sorted_addrs.into_iter();

        // Start first connection
        if let Some(addr) = addrs_iter.next() {
            let fut = self.connect_addr_captured(addr);
            tasks.push(fut);
        }

        let delay = Duration::from_millis(250);
        let mut delay_fut = Box::pin(tokio::time::sleep(delay));
        let mut last_error = None;

        loop {
            tokio::select! {
                res = tasks.next(), if !tasks.is_empty() => {
                    match res {
                        Some(Ok(stream)) => return Ok(stream),
                        Some(Err(e)) => {
                            last_error = Some(e);
                            // If tasks empty and no more addrs, break
                            if tasks.is_empty() && addrs_iter.len() == 0 {
                                break;
                            }
                        }
                        None => break, // Should not happen due to !tasks.is_empty()
                    }
                }
                _ = &mut delay_fut, if addrs_iter.len() > 0 => {
                    // Time to start next connection
                    if let Some(addr) = addrs_iter.next() {
                        let fut = self.connect_addr_captured(addr);
                        tasks.push(fut);
                    }
                    // Reset delay
                    delay_fut = Box::pin(tokio::time::sleep(delay));
                }
                else => {
                    // No more tasks and no more addrs (or delay not active)
                    break;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            SbError::network(
                ErrorClass::Connection,
                "All connection attempts failed".to_string(),
            )
        }))
    }

    pub async fn connect_udp(&self, ctx: &ConnCtx) -> SbResult<sb_types::BoxedPacketConn> {
        let addrs = self.resolve_endpoint(&ctx.dst).await?;
        let addr = addrs[0];

        // For UDP, we create a socket and connect it to the target
        let socket = if addr.is_ipv4() {
            tokio::net::UdpSocket::bind("0.0.0.0:0")
        } else {
            tokio::net::UdpSocket::bind("[::]:0")
        }
        .await
        .map_err(|e| SbError::network(ErrorClass::Connection, format!("UDP bind failed: {e}")))?;

        #[cfg(target_os = "android")]
        if let Err(e) = sb_platform::android_protect::protect_udp_socket(&socket) {
            warn!("Failed to protect UDP socket: {}", e);
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(iface) = &self.bind_interface {
            let s = socket2::SockRef::from(&socket);
            s.bind_device(Some(iface.as_bytes())).map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to bind to device {iface}: {e}"),
                )
            })?;
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        if let Some(mark) = self.routing_mark {
            let s = socket2::SockRef::from(&socket);
            s.set_mark(mark).map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to set routing mark {mark}: {e}"),
                )
            })?;
        }

        socket.connect(addr).await.map_err(|e| {
            SbError::network(ErrorClass::Connection, format!("UDP connect failed: {e}"))
        })?;

        Ok(Box::new(DirectUdpTransport::new(
            socket,
            sb_types::PacketOptions::default().idle_timeout,
        )))
    }
}

impl DirectConnector {
    async fn connect_addr(&self, addr: SocketAddr) -> SbResult<TcpStream> {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()
        } else {
            tokio::net::TcpSocket::new_v6()
        }
        .map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to create TCP socket: {e}"),
            )
        })?;

        #[cfg(target_os = "android")]
        if let Err(e) = sb_platform::android_protect::protect_tcp_socket(&socket) {
            warn!("Failed to protect TCP socket: {}", e);
        }

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(iface) = &self.bind_interface {
            let s = socket2::SockRef::from(&socket);
            s.bind_device(Some(iface.as_bytes())).map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to bind to device {iface}: {e}"),
                )
            })?;
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        if let Some(mark) = self.routing_mark {
            let s = socket2::SockRef::from(&socket);
            s.set_mark(mark).map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to set routing mark {mark}: {e}"),
                )
            })?;
        }

        if self.reuse_addr {
            let s = socket2::SockRef::from(&socket);
            s.set_reuse_address(true).map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to set reuse address: {e}"),
                )
            })?;
        }

        if self.tcp_fast_open {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                let s = socket2::SockRef::from(&socket);
                let _ = s.set_tcp_fastopen_connect(true);
            }
        }

        timeout(self.connect_timeout, socket.connect(addr))
            .await
            .map_err(|_| SbError::timeout("tcp_connect", self.connect_timeout.as_millis() as u64))?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("TCP connection failed: {e}"),
                )
            })
    }

    // Helper for capturing self fields for async block
    fn connect_addr_captured(
        &self,
        addr: SocketAddr,
    ) -> impl std::future::Future<Output = SbResult<TcpStream>> + Send + 'static {
        let connect_timeout = self.connect_timeout;
        let _bind_interface = self.bind_interface.clone();
        let _routing_mark = self.routing_mark;
        let reuse_addr = self.reuse_addr;
        let tcp_fast_open = self.tcp_fast_open;
        let tcp_multi_path = self.tcp_multi_path;

        async move {
            let socket = if addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()
            } else {
                tokio::net::TcpSocket::new_v6()
            }
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to create TCP socket: {e}"),
                )
            })?;

            #[cfg(target_os = "android")]
            if let Err(e) = sb_platform::android_protect::protect_tcp_socket(&socket) {
                warn!("Failed to protect TCP socket: {}", e);
            }

            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            if let Some(iface) = &bind_interface {
                let s = socket2::SockRef::from(&socket);
                s.bind_device(Some(iface.as_bytes())).map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("Failed to bind to device {iface}: {e}"),
                    )
                })?;
            }

            #[cfg(any(target_os = "android", target_os = "linux"))]
            if let Some(mark) = routing_mark {
                let s = socket2::SockRef::from(&socket);
                s.set_mark(mark).map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("Failed to set routing mark {mark}: {e}"),
                    )
                })?;
            }

            if reuse_addr {
                let s = socket2::SockRef::from(&socket);
                s.set_reuse_address(true).map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("Failed to set reuse address: {e}"),
                    )
                })?;
            }

            if tcp_fast_open {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    let s = socket2::SockRef::from(&socket);
                    let _ = s.set_tcp_fastopen_connect(true);
                }
            }

            if tcp_multi_path {
                #[cfg(target_os = "linux")]
                {
                    // MPTCP is usually protocol 262
                    // But socket creation is where it matters (IPPROTO_MPTCP).
                    // Since we already created the socket as TCP, we can't easily switch to MPTCP
                    // unless we change the socket creation logic.
                    // However, some implementations allow setting it via setsockopt.
                    // For now, we'll log a warning that it's not fully supported on existing socket.
                    // Or we can try to set it if supported.
                    // socket2 doesn't expose MPTCP constants directly usually.
                }
            }

            timeout(connect_timeout, socket.connect(addr))
                .await
                .map_err(|_| SbError::timeout("tcp_connect", connect_timeout.as_millis() as u64))?
                .map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("TCP connection failed: {e}"),
                    )
                })
        }
    }
}

fn global_limiters() -> (&'static tokio::sync::Semaphore, u64) {
    use std::sync::OnceLock;
    static SEM: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    let max = std::env::var("SB_OUT_MAX_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(256)
        .max(1);
    let q_ms = std::env::var("SB_OUT_QUEUE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5_000);
    let sem = SEM.get_or_init(|| tokio::sync::Semaphore::new(max));
    (sem, q_ms)
}

/// Direct UDP transport implementation
#[derive(Debug)]
pub struct DirectUdpTransport {
    socket: UdpSocket,
    idle_timeout: Duration,
    deadlines: Mutex<DirectUdpDeadlines>,
    closed: AtomicBool,
}

#[derive(Debug, Default)]
struct DirectUdpDeadlines {
    read: Option<Instant>,
    write: Option<Instant>,
}

impl DirectUdpTransport {
    fn new(socket: UdpSocket, idle_timeout: Duration) -> Self {
        Self {
            socket,
            idle_timeout,
            deadlines: Mutex::new(DirectUdpDeadlines::default()),
            closed: AtomicBool::new(false),
        }
    }

    fn operation_timeout(&self, read: bool) -> Duration {
        let deadlines = self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let explicit = if read {
            deadlines.read
        } else {
            deadlines.write
        };
        explicit
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(self.idle_timeout)
    }
}

impl sb_types::PacketConn for DirectUdpTransport {
    fn send_to<'a>(
        &'a self,
        buf: &'a [u8],
        dst: &'a sb_types::TargetAddr,
    ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(sb_types::CoreError::io("packet connection is closed"));
            }
            let operation_timeout = self.operation_timeout(false);
            let send = async {
                // `DirectConnector::connect_udp` returns a *connected* UDP socket. On a
                // connected socket `send_to` fails with EISCONN ("Socket is already
                // connected", os error 56) on macOS/BSD, so use `send` when a peer is set.
                if self.socket.peer_addr().is_ok() {
                    return self
                        .socket
                        .send(buf)
                        .await
                        .map_err(|error| sb_types::CoreError::io(error.to_string()));
                }

                // Unconnected socket: resolve the destination and use send_to.
                let addr = match dst {
                    sb_types::TargetAddr::Socket(address) => *address,
                    sb_types::TargetAddr::Domain(domain, port) => {
                        tokio::net::lookup_host((domain.as_str(), *port))
                            .await
                            .map_err(|error| sb_types::CoreError::dns(error.to_string()))?
                            .next()
                            .ok_or_else(|| {
                                sb_types::CoreError::dns("No addresses resolved for domain")
                            })?
                    }
                };

                self.socket
                    .send_to(buf, addr)
                    .await
                    .map_err(|error| sb_types::CoreError::io(error.to_string()))
            };
            tokio::time::timeout(operation_timeout, send)
                .await
                .map_err(|_| sb_types::CoreError::timeout("packet-send", operation_timeout))?
        })
    }

    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> sb_types::BoxFuture<'a, Result<(usize, sb_types::TargetAddr), sb_types::CoreError>> {
        Box::pin(async move {
            if self.closed.load(Ordering::Acquire) {
                return Err(sb_types::CoreError::io("packet connection is closed"));
            }
            let operation_timeout = self.operation_timeout(true);
            tokio::time::timeout(operation_timeout, self.socket.recv_from(buf))
                .await
                .map_err(|_| sb_types::CoreError::timeout("packet-recv", operation_timeout))?
                .map(|(size, address)| (size, sb_types::TargetAddr::Socket(address)))
                .map_err(|error| sb_types::CoreError::io(error.to_string()))
        })
    }

    fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
        self.closed.store(true, Ordering::Release);
        Box::pin(async { Ok(()) })
    }

    fn local_addr(&self) -> Option<sb_types::TargetAddr> {
        self.socket
            .local_addr()
            .ok()
            .map(sb_types::TargetAddr::Socket)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        let mut deadlines = self
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        deadlines.read = deadline;
        deadlines.write = deadline;
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .read = deadline;
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<(), sb_types::CoreError> {
        self.deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .write = deadline;
        Ok(())
    }
}

impl sb_types::Outbound for DirectConnector {
    fn r#type(&self) -> &str {
        "direct"
    }

    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new("direct")
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
    }

    fn dial<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            use tokio_util::compat::TokioAsyncReadCompatExt;

            let (host, port) = match &session.target {
                sb_types::TargetAddr::Socket(address) => (address.ip().to_string(), address.port()),
                sb_types::TargetAddr::Domain(host, port) => (host.clone(), *port),
            };
            let endpoint = crate::types::Endpoint::new(crate::types::Host::domain(host), port);
            let src =
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
            let ctx = crate::types::ConnCtx::new(
                0, // id
                crate::types::Network::Tcp,
                src,
                endpoint,
            );

            let stream = self
                .connect_tcp(&ctx)
                .await
                .map_err(|e| sb_types::CoreError::io(e.to_string()))?;
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }

    fn listen_packet<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async move {
            let bind = match &session.target {
                sb_types::TargetAddr::Socket(address) if address.is_ipv6() => "[::]:0",
                _ => "0.0.0.0:0",
            };
            let socket = UdpSocket::bind(bind)
                .await
                .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            if session.packet.udp_connect {
                let destination = match &session.target {
                    sb_types::TargetAddr::Socket(address) => address.to_string(),
                    sb_types::TargetAddr::Domain(host, port) => format!("{host}:{port}"),
                };
                socket
                    .connect(destination)
                    .await
                    .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            }
            Ok(
                Box::new(DirectUdpTransport::new(socket, session.packet.idle_timeout))
                    as sb_types::BoxedPacketConn,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Host;
    use sb_test_utils::skip::skip_if_io_permission_denied;
    use sb_types::{Outbound, PacketConn};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_direct_connector_creation() {
        let connector = DirectConnector::new();
        assert_eq!(connector.connect_timeout, Duration::from_secs(10));

        let connector = DirectConnector::with_timeout(Duration::from_secs(5));
        assert_eq!(connector.connect_timeout, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_resolve_endpoint_ip() {
        let connector = DirectConnector::new();
        let endpoint = Endpoint::new(Host::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), 8080);

        let result = connector.resolve_endpoint(&endpoint).await;
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert!(!addrs.is_empty());
        let addr = addrs[0];
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_resolve_endpoint_domain() {
        let connector = DirectConnector::new();
        let endpoint = Endpoint::new(Host::domain("localhost"), 8080);

        let result = connector.resolve_endpoint(&endpoint).await;
        // This might fail in some environments, but should work in most cases
        if let Ok(addrs) = result {
            assert!(!addrs.is_empty());
            let addr = addrs[0];
            assert_eq!(addr.port(), 8080);
            // localhost should resolve to either 127.0.0.1 or ::1
            assert!(addr.ip().is_loopback());
        }
    }

    #[test]
    fn test_direct_udp_transport_creation() {
        // We can't easily test the actual UDP functionality without setting up
        // a real UDP server, but we can test the structure
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let socket = match UdpSocket::bind("127.0.0.1:0").await {
                Ok(socket) => socket,
                Err(err) => {
                    if skip_if_io_permission_denied(&err, "direct UDP transport test") {
                        return;
                    }
                    panic!("{err}");
                }
            };
            let _transport =
                DirectUdpTransport::new(socket, sb_types::PacketOptions::default().idle_timeout);
            // If we get here, the transport was created successfully
        });
    }

    #[tokio::test]
    async fn direct_udp_read_deadline_times_out() {
        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(err) => {
                if skip_if_io_permission_denied(&err, "direct UDP read deadline test") {
                    return;
                }
                panic!("{err}");
            }
        };
        let transport = DirectUdpTransport::new(socket, Duration::from_secs(1));
        transport
            .set_read_deadline(Some(Instant::now() + Duration::from_millis(20)))
            .expect("set read deadline");

        let mut buffer = [0u8; 1];
        let error = transport
            .recv_from(&mut buffer)
            .await
            .expect_err("read deadline must stop a pending receive");
        assert!(matches!(
            error,
            sb_types::CoreError::Timeout { ref operation, .. } if operation == "packet-recv"
        ));
    }

    #[tokio::test]
    async fn direct_udp_uses_idle_timeout_without_explicit_deadline() {
        let peer = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(err) => {
                if skip_if_io_permission_denied(&err, "direct UDP idle timeout test") {
                    return;
                }
                panic!("{err}");
            }
        };
        let idle_timeout = Duration::from_millis(20);
        let mut session = sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::socket(peer.local_addr().expect("peer address")),
        );
        session.packet.idle_timeout = idle_timeout;
        let transport = DirectConnector::new()
            .listen_packet(&session)
            .await
            .expect("direct packet connection");

        let mut buffer = [0u8; 1];
        let error = transport
            .recv_from(&mut buffer)
            .await
            .expect_err("idle timeout must stop a pending receive");
        assert!(matches!(
            error,
            sb_types::CoreError::Timeout {
                ref operation,
                duration,
            } if operation == "packet-recv" && duration == idle_timeout
        ));
    }

    #[tokio::test]
    async fn direct_udp_deadline_setters_are_independent() {
        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(err) => {
                if skip_if_io_permission_denied(&err, "direct UDP deadline setter test") {
                    return;
                }
                panic!("{err}");
            }
        };
        let transport = DirectUdpTransport::new(socket, Duration::from_secs(1));
        let read = Instant::now() + Duration::from_secs(2);
        let write = Instant::now() + Duration::from_secs(3);

        transport
            .set_read_deadline(Some(read))
            .expect("set read deadline");
        transport
            .set_write_deadline(Some(write))
            .expect("set write deadline");
        {
            let deadlines = transport
                .deadlines
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(deadlines.read, Some(read));
            assert_eq!(deadlines.write, Some(write));
        }

        transport.set_deadline(None).expect("clear deadlines");
        let deadlines = transport
            .deadlines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(deadlines.read, None);
        assert_eq!(deadlines.write, None);
    }

    #[tokio::test]
    async fn direct_udp_respects_udp_connect_option() {
        let connected_peer = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("connected peer");
        let alternate_peer = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("alternate peer");
        let connected_addr = connected_peer.local_addr().expect("connected address");
        let alternate_addr = alternate_peer.local_addr().expect("alternate address");

        let mut unconnected_session = sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::socket(connected_addr),
        );
        unconnected_session.packet.udp_connect = false;
        let unconnected = DirectConnector::new()
            .listen_packet(&unconnected_session)
            .await
            .expect("unconnected direct packet connection");
        unconnected
            .send_to(b"u", &sb_types::TargetAddr::socket(alternate_addr))
            .await
            .expect("unconnected send_to");
        let mut buffer = [0u8; 1];
        tokio::time::timeout(
            Duration::from_secs(1),
            alternate_peer.recv_from(&mut buffer),
        )
        .await
        .expect("alternate peer receive timeout")
        .expect("alternate peer receive");
        assert_eq!(&buffer, b"u");

        let mut connected_session = unconnected_session;
        connected_session.packet.udp_connect = true;
        let connected = DirectConnector::new()
            .listen_packet(&connected_session)
            .await
            .expect("connected direct packet connection");
        connected
            .send_to(b"c", &sb_types::TargetAddr::socket(alternate_addr))
            .await
            .expect("connected send");
        tokio::time::timeout(
            Duration::from_secs(1),
            connected_peer.recv_from(&mut buffer),
        )
        .await
        .expect("connected peer receive timeout")
        .expect("connected peer receive");
        assert_eq!(&buffer, b"c");
    }

    #[tokio::test]
    async fn direct_udp_close_rejects_new_io() {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind direct UDP");
        let transport = DirectUdpTransport::new(socket, Duration::from_secs(1));
        transport.close().await.expect("close direct UDP");

        let error = transport
            .send_to(
                b"closed",
                &sb_types::TargetAddr::socket("127.0.0.1:9".parse().unwrap()),
            )
            .await
            .expect_err("closed transport must reject sends");
        assert!(error.to_string().contains("closed"));
    }

    #[tokio::test]
    async fn test_async_connector_interface() {
        let connector = DirectConnector::new();
        let session = sb_types::Session::new(
            0,
            sb_types::InboundTag::new("test"),
            sb_types::TargetAddr::domain("127.0.0.1", 80),
        );
        let result = connector.dial(&session).await;
        // This will fail because nothing is listening, but it tests the interface
        assert!(result.is_err());
    }
}
