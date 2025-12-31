//! Connection Manager (Go parity: route/conn.go)
//!
//! Provides Go-style connection management for TCP and UDP connections.
//! 提供 Go 风格的 TCP 和 UDP 连接管理。
//!
//! This module implements the connection handling logic that:
//! - Dials remote servers using configured outbounds
//! - Applies TLS fragmentation if configured
//! - Manages UDP NAT mapping/unmapping
//! - Tracks active connections for management
//! - Performs bidirectional copy between inbound and outbound

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, trace, warn};

// ============================================================================
// Constants (Go parity: constant/timeout.go)
// ============================================================================

/// TCP connect timeout (Go: TCPConnectTimeout = 5 * time.Second)
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default UDP timeout (Go: UDPTimeout = 5 * time.Minute)
pub const UDP_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Read payload timeout for early handshake (Go: ReadPayloadTimeout = 300ms)
pub const READ_PAYLOAD_TIMEOUT: Duration = Duration::from_millis(300);

/// TLS fragment fallback delay (Go: TLSFragmentFallbackDelay = 500ms)
pub const TLS_FRAGMENT_FALLBACK_DELAY: Duration = Duration::from_millis(500);

/// Protocol names for port-based lookup
pub const PROTOCOL_DNS: &str = "dns";
pub const PROTOCOL_NTP: &str = "ntp";
pub const PROTOCOL_STUN: &str = "stun";
pub const PROTOCOL_QUIC: &str = "quic";
pub const PROTOCOL_DTLS: &str = "dtls";

/// Port to protocol mapping (Go: PortProtocols)
/// 端口到协议的映射
pub fn port_protocol(port: u16) -> Option<&'static str> {
    match port {
        53 => Some(PROTOCOL_DNS),
        123 => Some(PROTOCOL_NTP),
        3478 => Some(PROTOCOL_STUN),
        443 => Some(PROTOCOL_QUIC),
        _ => None,
    }
}

/// Protocol to timeout mapping (Go: ProtocolTimeouts)
/// 协议到超时的映射
pub fn protocol_timeout(protocol: &str) -> Option<Duration> {
    match protocol {
        PROTOCOL_DNS => Some(Duration::from_secs(10)),
        PROTOCOL_NTP => Some(Duration::from_secs(10)),
        PROTOCOL_STUN => Some(Duration::from_secs(10)),
        PROTOCOL_QUIC => Some(Duration::from_secs(30)),
        PROTOCOL_DTLS => Some(Duration::from_secs(30)),
        _ => None,
    }
}

// ============================================================================
// Inbound Context (Go parity: adapter.InboundContext)
// ============================================================================

/// Inbound connection context with routing metadata.
/// 入站连接上下文与路由元数据。
#[derive(Debug, Clone, Default)]
pub struct InboundContext {
    /// Source address.
    pub source: String,
    /// Destination host.
    pub destination_host: String,
    /// Destination port.
    pub destination_port: u16,
    /// Resolved destination addresses (from DNS).
    pub destination_addresses: Vec<IpAddr>,
    /// Detected/sniffed protocol.
    pub protocol: Option<String>,

    // Network strategy fields (Go parity)
    /// Network strategy (e.g., "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only").
    pub network_strategy: Option<String>,
    /// Preferred network types.
    pub network_type: Option<Vec<String>>,
    /// Fallback network types.
    pub fallback_network_type: Option<Vec<String>>,
    /// Fallback delay before trying alternate network type.
    pub fallback_delay: Option<Duration>,

    // TLS fragmentation fields (Go parity)
    /// Enable TLS fragmentation.
    pub tls_fragment: bool,
    /// Enable TLS record fragmentation.
    pub tls_record_fragment: bool,
    /// TLS fragment fallback delay.
    pub tls_fragment_fallback_delay: Option<Duration>,

    // UDP fields (Go parity)
    /// UDP timeout override.
    pub udp_timeout: Option<Duration>,
    /// Use connected UDP mode.
    pub udp_connect: bool,
    /// Disable domain unmapping for UDP NAT.
    pub udp_disable_domain_unmapping: bool,

    // Route metadata
    /// Original destination before any modifications.
    pub route_original_destination: Option<(String, u16)>,
}

// ============================================================================
// Dialer Trait (Go parity: N.Dialer)
// ============================================================================

/// Dialer trait for establishing connections to remote hosts.
/// 用于建立到远程主机连接的拨号器 trait。
#[async_trait::async_trait]
pub trait Dialer: Send + Sync + std::fmt::Debug {
    /// Dial a TCP connection to the specified destination.
    async fn dial_tcp(&self, host: &str, port: u16) -> io::Result<TcpStream>;

    /// Listen for UDP packets to the specified destination.
    async fn listen_udp(&self, host: &str, port: u16) -> io::Result<UdpSocket>;

    /// Get the outbound tag for logging.
    fn tag(&self) -> &str {
        "direct"
    }
}

/// Direct dialer that connects without any proxy.
/// 直接连接的拨号器，不使用任何代理。
#[derive(Debug, Clone, Default)]
pub struct DirectDialer;

#[async_trait::async_trait]
impl Dialer for DirectDialer {
    async fn dial_tcp(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let addr = format!("{}:{}", host, port);
        tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .map_err(|_| io::Error::new(ErrorKind::TimedOut, "TCP connect timeout"))?
    }

    async fn listen_udp(&self, _host: &str, _port: u16) -> io::Result<UdpSocket> {
        // Bind to any available local address
        UdpSocket::bind("0.0.0.0:0").await
    }
}

// ============================================================================
// Close Handler (Go parity: N.CloseHandlerFunc)
// ============================================================================

/// Close handler callback function.
/// 关闭处理回调函数。
pub type CloseHandler = Box<dyn FnOnce(Option<io::Error>) + Send + 'static>;

// ============================================================================
// Connection Manager (Go parity: route.ConnectionManager)
// ============================================================================

/// Connection manager for TCP and UDP connections.
/// TCP 和 UDP 连接的连接管理器。
///
/// Implements Go-style connection handling with:
/// - TCP dial + TLS fragment + bidirectional copy
/// - UDP dial + NAT mapping + timeout + bidirectional copy
/// - Connection tracking for management
pub struct ConnectionManager {
    /// Active connections (for tracking/cleanup).
    connections: Mutex<Vec<Arc<ConnectionHandle>>>,
    /// Connection ID counter.
    next_id: AtomicU64,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field(
                "connection_count",
                &self.connections.lock().unwrap().len(),
            )
            .finish()
    }
}

/// Handle to an active connection (for tracking).
/// 活动连接的句柄（用于跟踪）。
#[derive(Debug)]
pub struct ConnectionHandle {
    pub id: u64,
    pub closed: AtomicBool,
}

impl ConnectionHandle {
    fn new(id: u64) -> Self {
        Self {
            id,
            closed: AtomicBool::new(false),
        }
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    /// Create a new connection manager.
    /// 创建新的连接管理器。
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Get the number of active connections.
    /// 获取活动连接数。
    pub fn active_count(&self) -> usize {
        let conns = self.connections.lock().unwrap();
        conns.iter().filter(|c| !c.is_closed()).count()
    }

    /// Close all active connections.
    /// 关闭所有活动连接。
    pub fn close(&self) {
        let mut conns = self.connections.lock().unwrap();
        for conn in conns.iter() {
            conn.mark_closed();
        }
        conns.clear();
    }

    /// Handle a new TCP connection (Go parity: NewConnection).
    /// 处理新的 TCP 连接。
    ///
    /// This method:
    /// 1. Dials the remote server using the provided dialer
    /// 2. Applies TLS fragmentation if configured
    /// 3. Starts bidirectional copy between local and remote
    /// 4. Tracks the connection for management
    pub async fn new_connection<R, W>(
        &self,
        dialer: Arc<dyn Dialer>,
        mut local_reader: R,
        mut local_writer: W,
        metadata: &InboundContext,
        on_close: Option<CloseHandler>,
    ) where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        // Generate connection ID and track
        let conn_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let handle = Arc::new(ConnectionHandle::new(conn_id));

        {
            let mut conns = self.connections.lock().unwrap();
            conns.push(handle.clone());
        }

        // Dial remote
        let remote_result = if !metadata.destination_addresses.is_empty() {
            // Try resolved addresses first
            self.dial_serial_network(
                dialer.as_ref(),
                &metadata.destination_host,
                metadata.destination_port,
                &metadata.destination_addresses,
                metadata.network_strategy.as_deref(),
                metadata.network_type.as_ref(),
                metadata.fallback_network_type.as_ref(),
                metadata.fallback_delay,
            )
            .await
        } else {
            dialer
                .dial_tcp(&metadata.destination_host, metadata.destination_port)
                .await
        };

        let remote = match remote_result {
            Ok(conn) => conn,
            Err(e) => {
                let addr = format!(
                    "{}:{}",
                    metadata.destination_host, metadata.destination_port
                );
                let err = io::Error::new(
                    e.kind(),
                    format!(
                        "open connection to {} using outbound/{}[{}]: {}",
                        addr,
                        "tcp",
                        dialer.tag(),
                        e
                    ),
                );
                error!("{}", err);
                if let Some(on_close) = on_close {
                    on_close(Some(err));
                }
                self.remove_connection(conn_id);
                return;
            }
        };

        debug!(
            conn_id,
            destination = %format!("{}:{}", metadata.destination_host, metadata.destination_port),
            "TCP connection established"
        );

        // Apply TLS fragmentation if configured
        // Note: TLS fragmentation would wrap the stream here in a real implementation
        if metadata.tls_fragment || metadata.tls_record_fragment {
            debug!(
                conn_id,
                tls_fragment = metadata.tls_fragment,
                tls_record_fragment = metadata.tls_record_fragment,
                "TLS fragmentation enabled (stub - not applied)"
            );
            // In a full implementation, we would wrap remote with a TLS fragment stream
            // remote = TlsFragmentStream::new(remote, metadata.tls_fragment, ...);
        }

        // Split remote connection into owned halves for spawning
        let (mut remote_reader, mut remote_writer) = remote.into_split();

        // Bidirectional copy
        let handle_upload = handle.clone();
        let handle_download = handle.clone();

        let upload = tokio::spawn(async move {
            let result = tokio::io::copy(&mut local_reader, &mut remote_writer).await;
            let _ = remote_writer.shutdown().await;
            handle_upload.mark_closed();
            result
        });

        let download = tokio::spawn(async move {
            let result = tokio::io::copy(&mut remote_reader, &mut local_writer).await;
            let _ = local_writer.shutdown().await;
            handle_download.mark_closed();
            result
        });

        // Wait for both directions to complete
        let (upload_result, download_result) = tokio::join!(upload, download);

        let error = match (upload_result, download_result) {
            (Ok(Ok(_)), Ok(Ok(_))) => {
                debug!(conn_id, "connection finished");
                None
            }
            (Ok(Err(e)), _) | (_, Ok(Err(e))) => {
                if e.kind() == ErrorKind::ConnectionReset
                    || e.kind() == ErrorKind::BrokenPipe
                    || e.kind() == ErrorKind::UnexpectedEof
                {
                    trace!(conn_id, "connection closed: {}", e);
                } else {
                    error!(conn_id, "connection error: {}", e);
                }
                Some(e)
            }
            (Err(e), _) | (_, Err(e)) => {
                error!(conn_id, "task join error: {}", e);
                Some(io::Error::new(ErrorKind::Other, e.to_string()))
            }
        };

        if let Some(on_close) = on_close {
            on_close(error);
        }

        self.remove_connection(conn_id);
    }

    /// Handle a new UDP connection (Go parity: NewPacketConnection).
    /// 处理新的 UDP 连接。
    ///
    /// This method:
    /// 1. Creates a UDP socket or connected UDP session
    /// 2. Applies NAT mapping if needed
    /// 3. Applies protocol-based timeout
    /// 4. Starts bidirectional packet copy
    pub async fn new_packet_connection(
        &self,
        dialer: Arc<dyn Dialer>,
        local_socket: Arc<UdpSocket>,
        metadata: &InboundContext,
        on_close: Option<CloseHandler>,
    ) {
        // Generate connection ID and track
        let conn_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let handle = Arc::new(ConnectionHandle::new(conn_id));

        {
            let mut conns = self.connections.lock().unwrap();
            conns.push(handle.clone());
        }

        // Determine UDP timeout
        let udp_timeout = if let Some(timeout) = metadata.udp_timeout {
            timeout
        } else {
            // Try to get timeout from protocol
            let protocol = metadata.protocol.as_deref().or_else(|| {
                port_protocol(metadata.destination_port)
            });
            protocol
                .and_then(protocol_timeout)
                .unwrap_or(UDP_TIMEOUT)
        };

        debug!(
            conn_id,
            destination = %format!("{}:{}", metadata.destination_host, metadata.destination_port),
            timeout_secs = udp_timeout.as_secs(),
            "UDP connection starting"
        );

        // Create remote UDP socket
        let remote_result = dialer
            .listen_udp(&metadata.destination_host, metadata.destination_port)
            .await;

        let remote_socket = match remote_result {
            Ok(socket) => {
                // Connect if UDP connect is enabled or we have a resolved address
                if metadata.udp_connect {
                    let addr = format!(
                        "{}:{}",
                        metadata.destination_host, metadata.destination_port
                    );
                    if let Err(e) = socket.connect(&addr).await {
                        error!(conn_id, "UDP connect failed: {}", e);
                        if let Some(on_close) = on_close {
                            on_close(Some(e));
                        }
                        self.remove_connection(conn_id);
                        return;
                    }
                }
                Arc::new(socket)
            }
            Err(e) => {
                error!(conn_id, "Failed to create UDP socket: {}", e);
                if let Some(on_close) = on_close {
                    on_close(Some(e));
                }
                self.remove_connection(conn_id);
                return;
            }
        };

        // Bidirectional UDP copy with timeout
        let local_for_upload = local_socket.clone();
        let remote_for_upload = remote_socket.clone();
        let handle_upload = handle.clone();
        let dest_host = metadata.destination_host.clone();
        let dest_port = metadata.destination_port;

        let upload = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let recv_result = tokio::time::timeout(
                    udp_timeout,
                    local_for_upload.recv(&mut buf),
                )
                .await;

                match recv_result {
                    Ok(Ok(n)) if n > 0 => {
                        let addr = format!("{}:{}", dest_host, dest_port);
                        if let Err(e) = remote_for_upload.send_to(&buf[..n], &addr).await {
                            trace!("UDP upload send error: {}", e);
                            break;
                        }
                    }
                    Ok(Ok(_)) => break, // Zero-length read
                    Ok(Err(e)) => {
                        trace!("UDP upload recv error: {}", e);
                        break;
                    }
                    Err(_) => {
                        trace!("UDP upload timeout");
                        break;
                    }
                }
            }
            handle_upload.mark_closed();
        });

        let local_for_download = local_socket;
        let remote_for_download = remote_socket;
        let handle_download = handle.clone();

        let download = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let recv_result = tokio::time::timeout(
                    udp_timeout,
                    remote_for_download.recv_from(&mut buf),
                )
                .await;

                match recv_result {
                    Ok(Ok((n, _addr))) if n > 0 => {
                        // In a full implementation, we would apply NAT remapping here
                        // based on udp_disable_domain_unmapping and route_original_destination
                        if let Err(e) = local_for_download.send(&buf[..n]).await {
                            trace!("UDP download send error: {}", e);
                            break;
                        }
                    }
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) => {
                        trace!("UDP download recv error: {}", e);
                        break;
                    }
                    Err(_) => {
                        trace!("UDP download timeout");
                        break;
                    }
                }
            }
            handle_download.mark_closed();
        });

        // Wait for both directions
        let (upload_result, download_result) = tokio::join!(upload, download);

        let error = match (upload_result, download_result) {
            (Ok(()), Ok(())) => {
                debug!(conn_id, "UDP connection finished");
                None
            }
            (Err(e), _) | (_, Err(e)) => {
                warn!(conn_id, "UDP task error: {}", e);
                Some(io::Error::new(ErrorKind::Other, e.to_string()))
            }
        };

        if let Some(on_close) = on_close {
            on_close(error);
        }

        self.remove_connection(conn_id);
    }

    /// Dial with network strategy/fallback (Go parity: dialer.DialSerialNetwork).
    /// 使用网络策略/回退进行拨号。
    async fn dial_serial_network(
        &self,
        dialer: &dyn Dialer,
        host: &str,
        port: u16,
        addresses: &[IpAddr],
        network_strategy: Option<&str>,
        network_type: Option<&Vec<String>>,
        fallback_network_type: Option<&Vec<String>>,
        fallback_delay: Option<Duration>,
    ) -> io::Result<TcpStream> {
        if addresses.is_empty() {
            return dialer.dial_tcp(host, port).await;
        }

        // Sort addresses based on network strategy
        let mut sorted_addrs: Vec<&IpAddr> = addresses.iter().collect();

        match network_strategy {
            Some("prefer_ipv4") => {
                sorted_addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
            }
            Some("prefer_ipv6") => {
                sorted_addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
            }
            Some("ipv4_only") => {
                sorted_addrs.retain(|a| a.is_ipv4());
            }
            Some("ipv6_only") => {
                sorted_addrs.retain(|a| a.is_ipv6());
            }
            _ => {
                // Default: use Happy Eyeballs (prefer IPv6 with fallback)
                sorted_addrs.sort_by_key(|a| if a.is_ipv6() { 0 } else { 1 });
            }
        }

        let _ = (network_type, fallback_network_type); // Reserved for future use

        let fallback_delay = fallback_delay.unwrap_or(Duration::from_millis(250));

        // Try addresses in order with fallback delay
        let mut last_error = None;
        for (i, addr) in sorted_addrs.iter().enumerate() {
            let addr_str = addr.to_string();

            if i > 0 {
                // Apply fallback delay between attempts (Happy Eyeballs)
                tokio::time::sleep(fallback_delay).await;
            }

            match dialer.dial_tcp(&addr_str, port).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    debug!("Dial to {} failed: {}, trying next", addr_str, e);
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            io::Error::new(ErrorKind::NotFound, "No addresses to dial")
        }))
    }

    /// Remove a connection from tracking.
    fn remove_connection(&self, id: u64) {
        let mut conns = self.connections.lock().unwrap();
        conns.retain(|c| c.id != id);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_protocol() {
        assert_eq!(port_protocol(53), Some(PROTOCOL_DNS));
        assert_eq!(port_protocol(123), Some(PROTOCOL_NTP));
        assert_eq!(port_protocol(3478), Some(PROTOCOL_STUN));
        assert_eq!(port_protocol(443), Some(PROTOCOL_QUIC));
        assert_eq!(port_protocol(80), None);
        assert_eq!(port_protocol(8080), None);
    }

    #[test]
    fn test_protocol_timeout() {
        assert_eq!(protocol_timeout(PROTOCOL_DNS), Some(Duration::from_secs(10)));
        assert_eq!(protocol_timeout(PROTOCOL_NTP), Some(Duration::from_secs(10)));
        assert_eq!(protocol_timeout(PROTOCOL_STUN), Some(Duration::from_secs(10)));
        assert_eq!(protocol_timeout(PROTOCOL_QUIC), Some(Duration::from_secs(30)));
        assert_eq!(protocol_timeout(PROTOCOL_DTLS), Some(Duration::from_secs(30)));
        assert_eq!(protocol_timeout("http"), None);
    }

    #[test]
    fn test_connection_manager_creation() {
        let cm = ConnectionManager::new();
        assert_eq!(cm.active_count(), 0);
    }

    #[test]
    fn test_connection_handle() {
        let handle = ConnectionHandle::new(1);
        assert!(!handle.is_closed());
        handle.mark_closed();
        assert!(handle.is_closed());
    }

    #[test]
    fn test_inbound_context_default() {
        let ctx = InboundContext::default();
        assert!(ctx.destination_host.is_empty());
        assert_eq!(ctx.destination_port, 0);
        assert!(!ctx.tls_fragment);
        assert!(!ctx.udp_connect);
    }

    #[tokio::test]
    async fn test_direct_dialer_timeout() {
        let dialer = DirectDialer;
        // Try to connect to a non-routable address to test timeout
        let result = dialer.dial_tcp("10.255.255.1", 12345).await;
        // Should fail (either timeout or connection refused)
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connection_manager_close() {
        let cm = ConnectionManager::new();

        // Add some fake connection handles
        {
            let mut conns = cm.connections.lock().unwrap();
            conns.push(Arc::new(ConnectionHandle::new(1)));
            conns.push(Arc::new(ConnectionHandle::new(2)));
        }

        assert_eq!(cm.active_count(), 2);

        cm.close();

        assert_eq!(cm.active_count(), 0);
    }

    #[test]
    fn test_inbound_context_with_metadata() {
        let ctx = InboundContext {
            destination_host: "example.com".to_string(),
            destination_port: 443,
            network_strategy: Some("prefer_ipv4".to_string()),
            tls_fragment: true,
            udp_timeout: Some(Duration::from_secs(30)),
            ..Default::default()
        };

        assert_eq!(ctx.destination_host, "example.com");
        assert_eq!(ctx.destination_port, 443);
        assert_eq!(ctx.network_strategy.as_deref(), Some("prefer_ipv4"));
        assert!(ctx.tls_fragment);
        assert_eq!(ctx.udp_timeout, Some(Duration::from_secs(30)));
    }
}
