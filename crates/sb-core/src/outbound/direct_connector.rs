//! Direct outbound connector implementation
//!
//! This module provides a direct connection implementation of `OutboundConnector`
//! that connects directly to targets without any proxy.

use crate::{
    error::{ErrorClass, SbError, SbResult},
    outbound::traits::{OutboundConnector as AsyncOutboundConnector, UdpTransport},
    types::{ConnCtx, Endpoint, Host},
};
use async_trait::async_trait;
use futures::StreamExt;
use std::net::SocketAddr;
use tokio::net::{lookup_host, TcpStream, UdpSocket};
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
            Host::Name(domain) => {
                let addr_str = format!("{}:{}", domain, endpoint.port);
                let addrs = lookup_host(&addr_str).await.map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("DNS resolution failed: {e}"),
                    )
                })?;

                let addrs: Vec<_> = addrs.collect();
                if addrs.is_empty() {
                    return Err(SbError::network(
                        ErrorClass::Connection,
                        "No addresses resolved for domain".to_string(),
                    ));
                }
                Ok(addrs)
            }
        }
    }
}

impl Default for DirectConnector {
    fn default() -> Self {
        Self::new()
    }
}

// Implementation for the async OutboundConnector trait
#[async_trait]
impl AsyncOutboundConnector for DirectConnector {
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

    async fn connect_udp(&self, ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>> {
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

        Ok(Box::new(DirectUdpTransport::new(socket)))
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
            #[cfg(any(
                target_os = "android",
                target_os = "linux",
                target_os = "macos",
                target_os = "ios"
            ))]
            {
                let s = socket2::SockRef::from(&socket);
                // let _ = s.set_tcp_fastopen_connect(true);
                // TODO: Enable TFO when supported by socket2/platform
                let _ = s; // suppress unused warning
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
                // Note: TFO connect support varies by platform and tokio version.
                // socket2 provides set_tcp_fastopen_connect on some platforms.
                #[cfg(any(
                    target_os = "android",
                    target_os = "linux",
                    target_os = "macos",
                    target_os = "ios"
                ))]
                {
                    let s = socket2::SockRef::from(&socket);
                    // On some platforms/versions this might be missing or named differently.
                    // We'll try to use what's available or log a warning if not supported.
                    // For now, we assume standard socket2 support if compiled.
                    // let _ = s.set_tcp_fastopen_connect(true);
                    // TODO: Enable TFO when supported by socket2/platform
                    let _ = s; // suppress unused warning
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
pub struct DirectUdpTransport {
    socket: UdpSocket,
}

impl DirectUdpTransport {
    const fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }
}

#[async_trait]
impl UdpTransport for DirectUdpTransport {
    async fn send_to(&self, buf: &[u8], dst: &Endpoint) -> SbResult<usize> {
        // For connected UDP socket, we can use send instead of send_to
        // But we'll implement send_to for flexibility
        let addr = match &dst.host {
            Host::Ip(ip) => SocketAddr::new(*ip, dst.port),
            Host::Name(domain) => {
                let addr_str = format!("{}:{}", domain, dst.port);
                let mut addrs = lookup_host(&addr_str).await.map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("DNS resolution failed: {e}"),
                    )
                })?;

                addrs.next().ok_or_else(|| {
                    SbError::network(
                        ErrorClass::Connection,
                        "No addresses resolved for domain".to_string(),
                    )
                })?
            }
        };

        self.socket
            .send_to(buf, addr)
            .await
            .map_err(|e| SbError::network(ErrorClass::Connection, format!("UDP send failed: {e}")))
    }

    async fn recv_from(&self, buf: &mut [u8]) -> SbResult<(usize, SocketAddr)> {
        self.socket
            .recv_from(buf)
            .await
            .map_err(|e| SbError::network(ErrorClass::Connection, format!("UDP recv failed: {e}")))
    }
}

// Implementation for the async OutboundConnector trait used by adapter
#[async_trait::async_trait]
impl crate::adapter::OutboundConnector for DirectConnector {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        let endpoint =
            crate::types::Endpoint::new(crate::types::Host::domain(host.to_string()), port);
        let src =
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let ctx = crate::types::ConnCtx::new(
            0, // id
            crate::types::Network::Tcp,
            src,
            endpoint,
        );

        self.connect_tcp(&ctx)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Host;
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
        if result.is_ok() {
            let addrs = result.unwrap();
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
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let _transport = DirectUdpTransport::new(socket);
            // If we get here, the transport was created successfully
        });
    }

    #[tokio::test]
    async fn test_async_connector_interface() {
        use crate::adapter::OutboundConnector;
        let connector = DirectConnector::new();
        let result = connector.connect("127.0.0.1", 80).await;
        // This will fail because nothing is listening, but it tests the interface
        assert!(result.is_err());
    }
}
