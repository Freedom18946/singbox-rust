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

use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::net::metered::TrafficRecorder;
use crate::services::v2ray_api::StatsManager;

use once_cell::sync::Lazy;
use publicsuffix::{List, Psl};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

// TLS fragmentation helpers (Go parity: common/tlsfragment)
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 6;
const TLS_RANDOM_LEN: usize = 32;
const TLS_SESSION_ID_HEADER_LEN: usize = 1;
const TLS_CIPHER_SUITE_HEADER_LEN: usize = 2;
const TLS_COMPRESS_METHOD_HEADER_LEN: usize = 1;
const TLS_EXTENSIONS_HEADER_LEN: usize = 2;
const TLS_EXTENSION_HEADER_LEN: usize = 4;
const TLS_SNI_EXTENSION_HEADER_LEN: usize = 5;
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const TLS_SNI_EXTENSION_TYPE: u16 = 0;
const TLS_SNI_NAME_DNS_HOSTNAME_TYPE: u8 = 0;
const TLS_VERSION_BITMASK: u16 = 0xFFFC;
const TLS_VERSION_13: u16 = 0x0304;

#[derive(Debug)]
struct TlsServerName {
    index: usize,
    name: String,
}

fn load_public_suffix_list() -> List {
    if let Ok(path) = std::env::var("SB_PUBLIC_SUFFIX_LIST") {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(list) = List::from_bytes(&bytes) {
                return list;
            }
        }
    }
    const DEFAULT_PSL: &[u8] = include_bytes!("../../resources/public_suffix_list.dat");
    if let Ok(list) = List::from_bytes(DEFAULT_PSL) {
        return list;
    }
    List::default()
}

fn is_valid_dns_name(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return false;
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return false;
        }
    }
    true
}

fn has_public_suffix(name: &str) -> bool {
    static PUBLIC_SUFFIX_LIST: Lazy<List> = Lazy::new(load_public_suffix_list);
    if !is_valid_dns_name(name) {
        return false;
    }
    PUBLIC_SUFFIX_LIST.suffix(name.as_bytes()).is_some()
}

fn index_tls_server_name(payload: &[u8]) -> Option<TlsServerName> {
    if payload.len() < TLS_RECORD_HEADER_LEN || payload[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return None;
    }
    let segment_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
    if payload.len() < TLS_RECORD_HEADER_LEN + segment_len {
        return None;
    }
    let mut server_name = index_tls_server_name_from_handshake(&payload[TLS_RECORD_HEADER_LEN..])?;
    server_name.index += TLS_RECORD_HEADER_LEN;
    Some(server_name)
}

fn index_tls_server_name_from_handshake(handshake: &[u8]) -> Option<TlsServerName> {
    if handshake.len() < TLS_HANDSHAKE_HEADER_LEN + TLS_RANDOM_LEN + TLS_SESSION_ID_HEADER_LEN {
        return None;
    }
    if handshake[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }
    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len().saturating_sub(4) != handshake_len {
        return None;
    }
    let tls_version = u16::from_be_bytes([handshake[4], handshake[5]]);
    if (tls_version & TLS_VERSION_BITMASK) != 0x0300 && tls_version != TLS_VERSION_13 {
        return None;
    }
    let session_id_len = handshake[38] as usize;
    let mut current_index =
        TLS_HANDSHAKE_HEADER_LEN + TLS_RANDOM_LEN + TLS_SESSION_ID_HEADER_LEN + session_id_len;
    if handshake.len() < current_index {
        return None;
    }
    let cipher_suites = &handshake[current_index..];
    if cipher_suites.len() < TLS_CIPHER_SUITE_HEADER_LEN {
        return None;
    }
    let cs_len = u16::from_be_bytes([cipher_suites[0], cipher_suites[1]]) as usize;
    if cipher_suites.len() < TLS_CIPHER_SUITE_HEADER_LEN + cs_len + TLS_COMPRESS_METHOD_HEADER_LEN {
        return None;
    }
    let compress_method_len = cipher_suites[TLS_CIPHER_SUITE_HEADER_LEN + cs_len] as usize;
    current_index +=
        TLS_CIPHER_SUITE_HEADER_LEN + cs_len + TLS_COMPRESS_METHOD_HEADER_LEN + compress_method_len;
    if handshake.len() < current_index {
        return None;
    }
    let mut server_name = index_tls_server_name_from_extensions(&handshake[current_index..])?;
    server_name.index += current_index;
    Some(server_name)
}

fn index_tls_server_name_from_extensions(exts: &[u8]) -> Option<TlsServerName> {
    if exts.is_empty() || exts.len() < TLS_EXTENSIONS_HEADER_LEN {
        return None;
    }
    let exts_len = u16::from_be_bytes([exts[0], exts[1]]) as usize;
    let mut rest = &exts[TLS_EXTENSIONS_HEADER_LEN..];
    if rest.len() < exts_len {
        return None;
    }
    let mut current_index = TLS_EXTENSIONS_HEADER_LEN;
    while !rest.is_empty() {
        if rest.len() < TLS_EXTENSION_HEADER_LEN {
            return None;
        }
        let ex_type = u16::from_be_bytes([rest[0], rest[1]]);
        let ex_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < TLS_EXTENSION_HEADER_LEN + ex_len {
            return None;
        }
        let ex_body = &rest[TLS_EXTENSION_HEADER_LEN..TLS_EXTENSION_HEADER_LEN + ex_len];
        if ex_type == TLS_SNI_EXTENSION_TYPE {
            if ex_body.len() < TLS_SNI_EXTENSION_HEADER_LEN {
                return None;
            }
            let sni_type = ex_body[2];
            if sni_type != TLS_SNI_NAME_DNS_HOSTNAME_TYPE {
                return None;
            }
            let sni_len = u16::from_be_bytes([ex_body[3], ex_body[4]]) as usize;
            let sni = &ex_body[TLS_SNI_EXTENSION_HEADER_LEN..];
            if sni.len() < sni_len {
                return None;
            }
            let name = String::from_utf8_lossy(&sni[..sni_len]).to_string();
            return Some(TlsServerName {
                index: current_index + TLS_EXTENSION_HEADER_LEN + TLS_SNI_EXTENSION_HEADER_LEN,
                name,
            });
        }
        rest = &rest[TLS_EXTENSION_HEADER_LEN + ex_len..];
        current_index += TLS_EXTENSION_HEADER_LEN + ex_len;
    }
    None
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
    /// Inbound tag for stats tracking.
    pub inbound_tag: Option<String>,
    /// Authenticated user for stats tracking.
    pub auth_user: Option<String>,
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
    /// Optional stats manager for V2Ray traffic tracking.
    stats: Option<Arc<StatsManager>>,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field("connection_count", &self.connections.lock().unwrap().len())
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
            stats: None,
        }
    }

    pub fn with_stats(mut self, stats: Option<Arc<StatsManager>>) -> Self {
        self.stats = stats;
        self
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

        // Register with global connection tracker
        let tracker = sb_common::conntrack::global_tracker();
        let tracker_id = tracker.next_id();
        let conn_meta = sb_common::conntrack::ConnMetadata::new(
            tracker_id,
            sb_common::conntrack::Network::Tcp,
            metadata.source.parse().unwrap_or_else(|_| {
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                )
            }),
            metadata.destination_host.clone(),
            metadata.destination_port,
        )
        .with_host(metadata.destination_host.clone())
        .with_inbound_tag(metadata.inbound_tag.clone().unwrap_or_default())
        .with_outbound_tag(dialer.tag().to_string());

        let conn_handle = tracker.register(conn_meta);
        let cancel_token = conn_handle.cancel.clone();
        let upload_counter = conn_handle.upload_bytes.clone();
        let download_counter = conn_handle.download_bytes.clone();

        if metadata.tls_fragment {
            if let Err(err) = remote.set_nodelay(true) {
                warn!(conn_id, error = %err, "failed to enable TCP_NODELAY for TLS fragment");
            }
        }

        let traffic = self.stats.as_ref().and_then(|stats| {
            stats.traffic_recorder(
                metadata.inbound_tag.as_deref(),
                Some(dialer.tag()),
                metadata.auth_user.as_deref(),
            )
        });

        // Split remote connection into owned halves for spawning
        let (mut remote_reader, mut remote_writer) = remote.into_split();

        // Bidirectional copy
        let handle_upload = handle.clone();
        let handle_download = handle.clone();

        let tls_fragment = metadata.tls_fragment;
        let tls_record_fragment = metadata.tls_record_fragment;
        let fallback_delay = metadata
            .tls_fragment_fallback_delay
            .unwrap_or(TLS_FRAGMENT_FALLBACK_DELAY);
        if tls_fragment || tls_record_fragment {
            debug!(
                conn_id,
                tls_fragment, tls_record_fragment, "TLS fragmentation enabled"
            );
        }

        let traffic_upload = traffic.clone();
        let traffic_download = traffic.clone();

        let upload_ctr = upload_counter.clone();
        let download_ctr = download_counter.clone();
        let cancel_up = cancel_token.clone();
        let cancel_down = cancel_token.clone();

        let upload = tokio::spawn(async move {
            #[cfg(unix)]
            let tcp_fd = Some(remote_writer.as_ref().as_raw_fd());
            #[cfg(windows)]
            let tcp_fd = Some(remote_writer.as_ref().as_raw_socket());
            #[cfg(not(any(unix, windows)))]
            let tcp_fd = None;
            let result = tokio::select! {
                r = async {
                    if tls_fragment || tls_record_fragment {
                        copy_with_tls_fragment(
                            &mut local_reader,
                            &mut remote_writer,
                            tls_fragment,
                            tls_record_fragment,
                            fallback_delay,
                            tcp_fd,
                            traffic_upload.clone(),
                            Some(upload_ctr),
                        )
                        .await
                    } else {
                        copy_with_recording(
                            &mut local_reader,
                            &mut remote_writer,
                            traffic_upload.clone(),
                            true,
                            Some(upload_ctr),
                        )
                        .await
                    }
                } => r,
                _ = cancel_up.cancelled() => {
                    Err(io::Error::new(io::ErrorKind::Interrupted, "connection closed by API"))
                }
            };
            let _ = remote_writer.shutdown().await;
            handle_upload.mark_closed();
            result
        });

        let download = tokio::spawn(async move {
            let result = tokio::select! {
                r = copy_with_recording(
                    &mut remote_reader,
                    &mut local_writer,
                    traffic_download,
                    false,
                    Some(download_ctr),
                ) => r,
                _ = cancel_down.cancelled() => {
                    Err(io::Error::new(io::ErrorKind::Interrupted, "connection closed by API"))
                }
            };
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
                Some(io::Error::other(e.to_string()))
            }
        };

        if let Some(on_close) = on_close {
            on_close(error);
        }

        // Unregister from global connection tracker
        tracker.unregister(tracker_id);

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
            let protocol = metadata
                .protocol
                .as_deref()
                .or_else(|| port_protocol(metadata.destination_port));
            protocol.and_then(protocol_timeout).unwrap_or(UDP_TIMEOUT)
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

        let traffic = self.stats.as_ref().and_then(|stats| {
            stats.traffic_recorder(
                metadata.inbound_tag.as_deref(),
                Some(dialer.tag()),
                metadata.auth_user.as_deref(),
            )
        });

        // Register with global connection tracker
        let tracker = sb_common::conntrack::global_tracker();
        let tracker_id = tracker.next_id();
        let conn_meta = sb_common::conntrack::ConnMetadata::new(
            tracker_id,
            sb_common::conntrack::Network::Udp,
            metadata.source.parse().unwrap_or_else(|_| {
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    0,
                )
            }),
            metadata.destination_host.clone(),
            metadata.destination_port,
        )
        .with_host(metadata.destination_host.clone())
        .with_inbound_tag(metadata.inbound_tag.clone().unwrap_or_default())
        .with_outbound_tag(dialer.tag().to_string());

        let conn_handle_track = tracker.register(conn_meta);
        let cancel_token = conn_handle_track.cancel.clone();
        let upload_counter = conn_handle_track.upload_bytes.clone();
        let download_counter = conn_handle_track.download_bytes.clone();

        // Bidirectional UDP copy with timeout
        let local_for_upload = local_socket.clone();
        let remote_for_upload = remote_socket.clone();
        let handle_upload = handle.clone();
        let dest_host = metadata.destination_host.clone();
        let dest_port = metadata.destination_port;
        let traffic_upload = traffic.clone();
        let upload_ctr = upload_counter;
        let cancel_up = cancel_token.clone();

        let upload = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let recv_result = tokio::select! {
                    r = tokio::time::timeout(udp_timeout, local_for_upload.recv(&mut buf)) => r,
                    _ = cancel_up.cancelled() => {
                        trace!("UDP upload cancelled by API");
                        break;
                    }
                };

                match recv_result {
                    Ok(Ok(n)) if n > 0 => {
                        if let Some(ref recorder) = traffic_upload {
                            recorder.record_up(n as u64);
                            recorder.record_up_packet(1);
                        }
                        upload_ctr.fetch_add(n as u64, Ordering::Relaxed);
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
        let traffic_download = traffic;
        let download_ctr = download_counter;
        let cancel_down = cancel_token;

        let download = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                let recv_result = tokio::select! {
                    r = tokio::time::timeout(udp_timeout, remote_for_download.recv_from(&mut buf)) => r,
                    _ = cancel_down.cancelled() => {
                        trace!("UDP download cancelled by API");
                        break;
                    }
                };

                match recv_result {
                    Ok(Ok((n, _addr))) if n > 0 => {
                        if let Err(e) = local_for_download.send(&buf[..n]).await {
                            trace!("UDP download send error: {}", e);
                            break;
                        }
                        if let Some(ref recorder) = traffic_download {
                            recorder.record_down(n as u64);
                            recorder.record_down_packet(1);
                        }
                        download_ctr.fetch_add(n as u64, Ordering::Relaxed);
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
                Some(io::Error::other(e.to_string()))
            }
        };

        if let Some(on_close) = on_close {
            on_close(error);
        }

        // Unregister from global connection tracker
        tracker.unregister(tracker_id);

        self.remove_connection(conn_id);
    }

    /// Dial with network strategy/fallback (Go parity: dialer.DialSerialNetwork).
    /// 使用网络策略/回退进行拨号。
    #[allow(clippy::too_many_arguments)]
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

        Err(last_error
            .unwrap_or_else(|| io::Error::new(ErrorKind::NotFound, "No addresses to dial")))
    }

    /// Remove a connection from tracking.
    fn remove_connection(&self, id: u64) {
        let mut conns = self.connections.lock().unwrap();
        conns.retain(|c| c.id != id);
    }
}

fn tls_split_indexes(server_name: &TlsServerName) -> Vec<usize> {
    if server_name.name.is_empty() {
        return Vec::new();
    }
    let mut splits: Vec<&str> = server_name.name.split('.').collect();
    let dot_count = server_name.name.matches('.').count();
    if dot_count > 0 && has_public_suffix(&server_name.name) {
        let keep = splits.len().saturating_sub(dot_count);
        if keep > 0 && keep < splits.len() {
            splits.truncate(keep);
        }
    }

    let mut current_index = server_name.index;
    if splits.len() > 1 && splits[0] == "..." {
        current_index += splits[0].len() + 1;
        splits.remove(0);
    }

    let mut rng = rand::thread_rng();
    let mut indexes = Vec::new();
    for (i, split) in splits.iter().enumerate() {
        if split.is_empty() {
            continue;
        }
        let split_at = rng.gen_range(0..split.len());
        indexes.push(current_index + split_at);
        current_index += split.len();
        if i != splits.len().saturating_sub(1) {
            current_index += 1;
        }
    }
    indexes
}

#[cfg(unix)]
type TcpFd = std::os::unix::io::RawFd;
#[cfg(windows)]
type TcpFd = std::os::windows::io::RawSocket;
#[cfg(not(any(unix, windows)))]
type TcpFd = i32;

async fn write_tls_fragments<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    split_indexes: &[usize],
    split_packet: bool,
    split_record: bool,
    fallback_delay: Duration,
    tcp_fd: Option<TcpFd>,
) -> io::Result<()> {
    if split_indexes.is_empty()
        || split_indexes
            .iter()
            .any(|idx| *idx == 0 || *idx >= data.len())
    {
        writer.write_all(data).await?;
        return Ok(());
    }

    if split_record && data.len() < TLS_RECORD_HEADER_LEN {
        writer.write_all(data).await?;
        return Ok(());
    }

    let mut buffer = Vec::new();
    for i in 0..=split_indexes.len() {
        let segment = if i == 0 {
            &data[..split_indexes[i]]
        } else if i == split_indexes.len() {
            &data[split_indexes[i - 1]..]
        } else {
            &data[split_indexes[i - 1]..split_indexes[i]]
        };

        if split_record {
            let payload = if i == 0 {
                if segment.len() <= TLS_RECORD_HEADER_LEN {
                    &[]
                } else {
                    &segment[TLS_RECORD_HEADER_LEN..]
                }
            } else {
                segment
            };

            let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
            record.extend_from_slice(&data[..3]);
            record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            record.extend_from_slice(payload);

            if split_packet {
                if let Some(fd) = tcp_fd {
                    if i != split_indexes.len() {
                        write_and_wait_ack(writer, fd, &record, fallback_delay).await?;
                    } else {
                        writer.write_all(&record).await?;
                    }
                } else {
                    writer.write_all(&record).await?;
                    if i != split_indexes.len() {
                        tokio::time::sleep(fallback_delay).await;
                    }
                }
            } else {
                buffer.extend_from_slice(&record);
            }
        } else if split_packet {
            if let Some(fd) = tcp_fd {
                if i != split_indexes.len() {
                    write_and_wait_ack(writer, fd, segment, fallback_delay).await?;
                } else {
                    writer.write_all(segment).await?;
                }
            } else {
                writer.write_all(segment).await?;
                if i != split_indexes.len() {
                    tokio::time::sleep(fallback_delay).await;
                }
            }
        } else {
            buffer.extend_from_slice(segment);
        }
    }

    if !split_packet {
        if buffer.is_empty() {
            writer.write_all(data).await?;
        } else {
            writer.write_all(&buffer).await?;
        }
    }

    Ok(())
}

async fn copy_with_tls_fragment<R, W>(
    reader: &mut R,
    writer: &mut W,
    split_packet: bool,
    split_record: bool,
    fallback_delay: Duration,
    tcp_fd: Option<TcpFd>,
    traffic: Option<Arc<dyn TrafficRecorder>>,
    conn_counter: Option<Arc<AtomicU64>>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut first = true;
    let mut buf = vec![0u8; 18 * 1024];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }

        if first {
            first = false;
            if let Some(server_name) = index_tls_server_name(&buf[..n]) {
                let indexes = tls_split_indexes(&server_name);
                if !indexes.is_empty() {
                    write_tls_fragments(
                        writer,
                        &buf[..n],
                        &indexes,
                        split_packet,
                        split_record,
                        fallback_delay,
                        tcp_fd,
                    )
                    .await?;
                    if let Some(ref recorder) = traffic {
                        recorder.record_up(n as u64);
                    }
                    if let Some(ref counter) = conn_counter {
                        counter.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    total += n as u64;
                    continue;
                }
            }
        }

        writer.write_all(&buf[..n]).await?;
        if let Some(ref recorder) = traffic {
            recorder.record_up(n as u64);
        }
        if let Some(ref counter) = conn_counter {
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
        total += n as u64;
    }
}

async fn copy_with_recording<R, W>(
    reader: &mut R,
    writer: &mut W,
    traffic: Option<Arc<dyn TrafficRecorder>>,
    is_up: bool,
    conn_counter: Option<Arc<AtomicU64>>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
        if let Some(ref recorder) = traffic {
            if is_up {
                recorder.record_up(n as u64);
            } else {
                recorder.record_down(n as u64);
            }
        }
        if let Some(ref counter) = conn_counter {
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
    }
}

async fn write_and_wait_ack<W: AsyncWrite + Unpin>(
    writer: &mut W,
    tcp_fd: TcpFd,
    payload: &[u8],
    fallback_delay: Duration,
) -> io::Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    writer.write_all(payload).await?;
    wait_for_ack(tcp_fd, fallback_delay).await
}

#[cfg(target_os = "linux")]
async fn wait_for_ack(tcp_fd: TcpFd, fallback_delay: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                tcp_fd,
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                &mut info as *mut _ as *mut _,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        if info.tcpi_unacked == 0 {
            if start.elapsed() <= Duration::from_millis(20) {
                tokio::time::sleep(fallback_delay).await;
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
async fn wait_for_ack(tcp_fd: TcpFd, fallback_delay: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        let mut value: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                tcp_fd,
                libc::SOL_SOCKET,
                libc::SO_NWRITE,
                &mut value as *mut _ as *mut _,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        if value == 0 {
            if start.elapsed() <= Duration::from_millis(20) {
                tokio::time::sleep(fallback_delay).await;
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(target_os = "windows")]
async fn wait_for_ack(tcp_fd: TcpFd, fallback_delay: Duration) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{
        TCP_INFO_v0, WSAGetLastError, WSAIoctl, SIO_TCP_INFO, SOCKET_ERROR, WSAEACCES, WSAEINVAL,
        WSAEOPNOTSUPP,
    };

    let start = Instant::now();
    loop {
        let mut info = TCP_INFO_v0::default();
        let mut bytes_returned = 0u32;
        // SAFETY: WSAIoctl reads from a valid socket into a properly sized output buffer.
        let ret = unsafe {
            WSAIoctl(
                tcp_fd,
                SIO_TCP_INFO,
                std::ptr::null(),
                0,
                std::ptr::addr_of_mut!(info).cast(),
                std::mem::size_of::<TCP_INFO_v0>() as u32,
                std::ptr::addr_of_mut!(bytes_returned),
                std::ptr::null_mut(),
                None,
            )
        };
        if ret == SOCKET_ERROR {
            // SAFETY: WSAGetLastError returns the last socket error for this thread.
            let err = unsafe { WSAGetLastError() };
            if err == WSAEACCES || err == WSAEOPNOTSUPP || err == WSAEINVAL {
                tokio::time::sleep(fallback_delay).await;
                return Ok(());
            }
            return Err(io::Error::from_raw_os_error(err));
        }
        if info.BytesInFlight == 0 {
            if start.elapsed() <= Duration::from_millis(20) {
                tokio::time::sleep(fallback_delay).await;
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "windows"
)))]
async fn wait_for_ack(_tcp_fd: TcpFd, fallback_delay: Duration) -> io::Result<()> {
    tokio::time::sleep(fallback_delay).await;
    Ok(())
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
        assert_eq!(
            protocol_timeout(PROTOCOL_DNS),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            protocol_timeout(PROTOCOL_NTP),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            protocol_timeout(PROTOCOL_STUN),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            protocol_timeout(PROTOCOL_QUIC),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            protocol_timeout(PROTOCOL_DTLS),
            Some(Duration::from_secs(30))
        );
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

    /// Test that the dialer handles unreachable addresses appropriately.
    /// This test is environment-dependent (network routing varies by system).
    /// Run manually with: cargo test -p sb-core --lib test_direct_dialer_timeout -- --ignored
    #[tokio::test]
    #[ignore = "network-dependent: dial behavior varies by system routing"]
    async fn test_direct_dialer_timeout() {
        let dialer = DirectDialer;
        // RFC 5737 TEST-NET-1: should be non-routable per specification
        let result =
            tokio::time::timeout(Duration::from_secs(2), dialer.dial_tcp("192.0.2.1", 12345)).await;
        // Should timeout or connection should fail on standard networks
        assert!(result.is_err() || result.unwrap().is_err());
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

    #[test]
    fn test_index_tls_server_name_payload() {
        let payload = hex::decode("16030105f8010005f403036e35de7389a679c54029cf452611f2211c70d9ac3897271de589ab6155f8e4ab20637d225f1ef969ad87ed78bfb9d171300bcb1703b6f314ccefb964f79b7d0961002a0a0a130213031301c02cc02bcca9c030c02fcca8c00ac009c014c013009d009c0035002fc008c012000a01000581baba00000000000f000d00000a6769746875622e636f6d00170000ff01000100000a000e000c3a3a11ec001d001700180019000b000201000010000e000c02683208687474702f312e31000500050100000000000d00160014040308040401050308050805050108060601020100120000003304ef04ed3a3a00010011ec04c0aeb2250c092a3463161cccb29d9183331a424964248579507ed23a180b0ceab2a5f5d9ce41547e497a89055471ea572867ba3a1fc3c9e45025274a20f60c6b60e62476b6afed0403af59ab83660ef4112ae20386a602010d0a5d454c0ed34c84ed4423e750213e6a2baab1bf9c4367a6007ab40a33d95220c2dcaa44f257024a5626b545db0510f4311b1a60714154909c6a61fdfca011fb2626d657aeb6070bf078508babe3b584555013e34acc56198ed4663742b3155a664a9901794c4586820a7dc162c01827291f3792e1237f801a8d1ef096013c181c4a58d2f6859ba75022d18cc4418bd4f351d5c18f83a58857d05af860c4b9ac018a5b63f17184e591532c6bc2cf2215d4a282c8a8a4f6f7aee110422c8bc9ebd3b1d609c568523aaae555db320e6c269473d87af38c256cbb9febc20aea6380c32a8916f7a373c8b1e37554e3260bf6621f6b804ee80b3c516b1d01985bf4c603b6daa9a5991de6a7a29f3a7122b8afb843a7660110fce62b43c615f5bcc2db688ba012649c0952b0a2c031e732d2b454c6b2968683cb8d244be2c9a7fa163222979eaf92722b92b862d81a3d94450c2b60c318421ebb4307c42d1f0473592a5c30e42039cc68cda9721e61aa63f49def17c15221680ed444896340133bbee67556f56b9f9d78a4df715f926a12add0cc9c862e46ea8b7316ae468282c18601b2771c9c9322f982228cf93effaacd3f80cbd12bce5fc36f56e2a3caf91e578a5fae00c9b23a8ed1a66764f4433c3628a70b8f0a6196adc60a4cb4226f07ba4c6b363fe9065563bfc1347452946386bab488686e837ab979c64f9047417fca635fe1bb4f074f256cc8af837c7b455e280426547755af90a61640169ef180aea3a77e662bb6dac1b6c3696027129b1a5edf495314e9c7f4b6110e16378ec893fa24642330a40aba1a85326101acb97c620fd8d71389e69eaed7bdb01bbe1fd428d66191150c7b2cd1ad4257391676a82ba8ce07fb2667c3b289f159003a7c7bc31d361b7b7f49a802961739d950dfcc0fa1c7abce5abdd2245101da391151490862028110465950b9e9c03d08a90998ab83267838d2e74a0593bc81f74cdf734519a05b351c0e5488c68dd810e6e9142ccc1e2f4a7f464297eb340e27acc6b9d64e12e38cce8492b3d939140b5a9e149a75597f10a23874c84323a07cdd657274378f887c85c4259b9c04cd33ba58ed630ef2a744f8e19dd34843dff331d2a6be7e2332c599289cd248a611c73d7481cd4a9bd43449a3836f14b2af18a1739e17999e4c67e85cc5bcecabb14185e5bcaff3c96098f03dc5aba819f29587758f49f940585354a2a780830528d68ccd166920dadcaa25cab5fc1907272a826aba3f08bc6b88757776812ecb6c7cec69a223ec0a13a7b62a2349a0f63ed7a27a3b15ba21d71fe6864ec6e089ae17cadd433fa3138f7ee24353c11365818f8fc34f43a05542d18efaac24bfccc1f748a0cc1a67ad379468b76fd34973dba785f5c91d618333cd810fe0700d1bbc8422029782628070a624c52c5309a4a64d625b11f8033ab28df34a1add297517fcc06b92b6817b3c5144438cf260867c57bde68c8c4b82e6a135ef676a52fbae5708002a404e6189a60e2836de565ad1b29e3819e5ed49f6810bcb28e1bd6de57306f94b79d9dae1cc4624d2a068499beef81cd5fe4b76dcbfff2a2008001d002001976128c6d5a934533f28b9914d2480aab2a8c1ab03d212529ce8b27640a716002d00020101002b000706caca03040303001b00030200015a5a000100").expect("decode tls payload");
        let server_name = index_tls_server_name(&payload).expect("server name");
        assert_eq!(server_name.name, "github.com");
        assert_eq!(
            &payload[server_name.index..server_name.index + server_name.name.len()],
            server_name.name.as_bytes()
        );
    }

    #[test]
    fn test_tls_split_indexes_publicsuffix_behavior() {
        let known = TlsServerName {
            index: 0,
            name: "github.com".to_string(),
        };
        let known_indexes = tls_split_indexes(&known);
        assert_eq!(known_indexes.len(), 1);

        let unknown = TlsServerName {
            index: 0,
            name: "bad domain.example".to_string(),
        };
        let unknown_indexes = tls_split_indexes(&unknown);
        assert_eq!(unknown_indexes.len(), 2);
    }

    #[test]
    fn test_public_suffix_validation() {
        assert!(is_valid_dns_name("github.com"));
        assert!(!is_valid_dns_name("bad domain.example"));
        assert!(!is_valid_dns_name("-bad.example"));
        assert!(!is_valid_dns_name("bad-.example"));
        assert!(!is_valid_dns_name("bad..example"));

        assert!(has_public_suffix("github.com"));
        assert!(!has_public_suffix("bad domain.example"));
    }

    #[tokio::test]
    async fn test_write_tls_fragments_empty_indexes() {
        // When split_indexes is empty, data should be written as-is
        let mut output = Vec::new();
        let data = b"hello world";
        let fallback_delay = Duration::from_millis(10);

        write_tls_fragments(
            &mut output,
            data,
            &[],   // empty indexes
            true,  // split_packet
            false, // split_record
            fallback_delay,
            None,
        )
        .await
        .expect("write should succeed");

        assert_eq!(output, data);
    }

    #[tokio::test]
    async fn test_write_tls_fragments_with_fallback_delay() {
        // Test that fragmentation works with fallback delay (no ACK wait)
        use std::time::Instant;

        let mut output = Vec::new();
        let data = b"0123456789";
        let split_indexes = vec![3, 7]; // Split at positions 3 and 7
        let fallback_delay = Duration::from_millis(50);

        let start = Instant::now();
        write_tls_fragments(
            &mut output,
            data,
            &split_indexes,
            true,  // split_packet
            false, // split_record
            fallback_delay,
            None, // No TCP fd - uses fallback delay
        )
        .await
        .expect("write should succeed");
        let elapsed = start.elapsed();

        // Output should contain all original data
        assert_eq!(output, data);

        // Should have applied fallback delay for each split (2 splits)
        // Allow some timing variance
        assert!(
            elapsed >= Duration::from_millis(80),
            "Expected at least 80ms (2 * 50ms delay), got {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_write_tls_fragments_buffer_mode() {
        // Test non-split_packet mode (buffer and write at once)
        let mut output = Vec::new();
        let data = b"0123456789";
        let split_indexes = vec![3, 7];

        write_tls_fragments(
            &mut output,
            data,
            &split_indexes,
            false, // split_packet = false (buffer mode)
            false, // split_record
            Duration::from_millis(10),
            None,
        )
        .await
        .expect("write should succeed");

        // Output should be the same as input (just reassembled)
        assert_eq!(output, data);
    }

    #[tokio::test]
    async fn test_write_tls_fragments_invalid_index() {
        // Test that invalid indexes (0 or >= data.len()) cause direct write
        let mut output = Vec::new();
        let data = b"hello";

        // Index 0 is invalid
        write_tls_fragments(
            &mut output,
            data,
            &[0],
            true,
            false,
            Duration::from_millis(10),
            None,
        )
        .await
        .expect("write should succeed");
        assert_eq!(output, data);

        // Index >= len is invalid
        output.clear();
        write_tls_fragments(
            &mut output,
            data,
            &[10],
            true,
            false,
            Duration::from_millis(10),
            None,
        )
        .await
        .expect("write should succeed");
        assert_eq!(output, data);
    }

    #[test]
    fn test_tls_split_indexes_empty_name() {
        let empty = TlsServerName {
            index: 0,
            name: String::new(),
        };
        let indexes = tls_split_indexes(&empty);
        assert!(indexes.is_empty());
    }

    #[test]
    fn test_tls_split_indexes_single_label() {
        let single = TlsServerName {
            index: 0,
            name: "localhost".to_string(),
        };
        let indexes = tls_split_indexes(&single);
        // Single label should produce one split index within the name
        assert_eq!(indexes.len(), 1);
        assert!(indexes[0] < single.name.len());
    }

    #[test]
    fn test_tls_split_indexes_multi_label_domain() {
        // Test multi-label domain splitting (e.g., www.example.com)
        let multi = TlsServerName {
            index: 10, // Offset in original TLS payload
            name: "www.example.com".to_string(),
        };
        let indexes = tls_split_indexes(&multi);

        // Should produce multiple split indexes for multi-label domain
        assert!(
            !indexes.is_empty(),
            "Multi-label domain should produce split indexes"
        );

        // All indexes should be within valid range (starting from offset)
        for idx in &indexes {
            assert!(
                *idx >= 10 && *idx < 10 + multi.name.len(),
                "Index {} should be within range [10, {})",
                idx,
                10 + multi.name.len()
            );
        }
    }

    #[tokio::test]
    async fn test_write_tls_fragments_record_mode() {
        // Test split_record=true mode which rewraps TLS records
        // Simulate a minimal TLS ClientHello-like structure
        // TLS record header: 5 bytes (type=0x16, version=0x0301, length)
        let tls_record_header = [0x16, 0x03, 0x01, 0x00, 0x10]; // TLS handshake, length=16
        let tls_payload = b"0123456789ABCDEF"; // 16 bytes of payload
        let mut data = Vec::new();
        data.extend_from_slice(&tls_record_header);
        data.extend_from_slice(tls_payload);

        let mut output = Vec::new();
        let split_indexes = vec![10]; // Split within the payload (after header + 5 bytes of payload)

        write_tls_fragments(
            &mut output,
            &data,
            &split_indexes,
            false, // split_packet = false (buffer first)
            true,  // split_record = true (rewrap TLS records)
            Duration::from_millis(10),
            None,
        )
        .await
        .expect("write should succeed");

        // In record mode, each fragment gets its own TLS record header
        // Output should be larger than input due to additional headers
        assert!(
            output.len() >= data.len(),
            "Record mode output ({}) should be at least as large as input ({})",
            output.len(),
            data.len()
        );

        // First 3 bytes of output should match TLS record type and version
        assert_eq!(output[0], 0x16, "Should be TLS handshake record type");
        assert_eq!(output[1], 0x03, "Should be TLS major version 3");
        assert_eq!(output[2], 0x01, "Should be TLS minor version 1");
    }

    #[tokio::test]
    async fn test_write_tls_fragments_short_tls_record() {
        // Test that short TLS records (< 5 bytes header) are written as-is
        let mut output = Vec::new();
        let data = b"abc"; // Too short to be a valid TLS record

        write_tls_fragments(
            &mut output,
            data,
            &[1],
            false, // split_packet
            true,  // split_record = true (but data is too short)
            Duration::from_millis(10),
            None,
        )
        .await
        .expect("write should succeed");

        // Short data should be written as-is
        assert_eq!(output, data);
    }
}
