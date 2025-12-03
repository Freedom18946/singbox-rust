//! UDP DNS Transport Implementation
//! UDP DNS 传输实现
//!
//! This module provides UDP-based DNS transport with Go-parity features:
//! 本模块提供基于 UDP 的 DNS 传输，具有与 Go 对等的功能：
//! - Connection reuse with ID remapping / 连接复用与 ID 重映射
//! - EDNS0 payload size detection / EDNS0 载荷大小检测
//! - Dynamic buffer growth / 动态缓冲区增长
//! - TCP fallback on truncation / 截断时回退到 TCP
//! - Configurable dialer for detour support / 可配置的 dialer 用于 detour 支持
//! - Lifecycle management (start/close) / 生命周期管理（启动/关闭）

use std::{
    cmp,
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use tokio::sync::{oneshot, Mutex, Notify};
use tokio::{net::UdpSocket, time};
use tracing::{debug, trace};

use super::{tcp::TcpTransport, DnsStartStage, DnsTransport, DnsTransportError};

/// UDP upstream configuration.
/// UDP 上游配置。
#[derive(Clone, Debug)]
pub struct UdpUpstream {
    /// Server address.
    /// 服务器地址。
    pub addr: SocketAddr,
    /// Query timeout.
    /// 查询超时。
    pub timeout: Duration,
}

/// Optional dialer trait for UDP connections.
/// UDP 连接的可选 dialer trait。
///
/// This allows customizing how UDP sockets are created (e.g., binding to specific
/// interfaces, using detour routing).
/// 这允许自定义 UDP 套接字的创建方式（例如，绑定到特定接口，使用 detour 路由）。
#[async_trait::async_trait]
pub trait UdpDialer: Send + Sync {
    /// Create a UDP socket connected to the target address.
    /// 创建连接到目标地址的 UDP 套接字。
    async fn dial_udp(&self, target: SocketAddr) -> Result<UdpSocket>;

    /// Initialize the dialer (called during Start stage).
    /// 初始化 dialer（在 Start 阶段调用）。
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
}

/// Default UDP dialer implementation.
/// 默认 UDP dialer 实现。
#[derive(Clone, Debug, Default)]
pub struct DefaultUdpDialer;

#[async_trait::async_trait]
impl UdpDialer for DefaultUdpDialer {
    async fn dial_udp(&self, target: SocketAddr) -> Result<UdpSocket> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .context("dns/udp: bind 0.0.0.0:0 failed")?;
        socket
            .connect(target)
            .await
            .context("dns/udp: connect failed")?;
        Ok(socket)
    }
}

/// UDP DNS transport with connection reuse and lifecycle management.
/// 具有连接复用和生命周期管理的 UDP DNS 传输。
#[derive(Clone)]
pub struct UdpTransport {
    upstream: UdpUpstream,
    shared: Arc<Mutex<Option<Arc<SharedUdpConn>>>>,
    default_buf: usize,
    dialer: Arc<dyn UdpDialer>,
    done: Arc<Notify>,
    started: Arc<AtomicBool>,
}

impl std::fmt::Debug for UdpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpTransport")
            .field("upstream", &self.upstream)
            .field("default_buf", &self.default_buf)
            .field("started", &self.started.load(Ordering::SeqCst))
            .finish()
    }
}

#[derive(Debug)]
struct SharedUdpConn {
    socket: Arc<UdpSocket>,
    callbacks: Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>,
    query_id: AtomicU16,
    closed: AtomicBool,
    max_buf: AtomicUsize,
    done: Arc<Notify>,
}

impl SharedUdpConn {
    fn new(socket: UdpSocket, initial_buf: usize, done: Arc<Notify>) -> Arc<Self> {
        let conn = Arc::new(Self {
            socket: Arc::new(socket),
            callbacks: Mutex::new(HashMap::new()),
            query_id: AtomicU16::new(0),
            closed: AtomicBool::new(false),
            max_buf: AtomicUsize::new(initial_buf),
            done,
        });
        Self::spawn_reader(conn.clone());
        conn
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn next_id(&self) -> u16 {
        let mut id = self
            .query_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        if id == 0 {
            self.query_id.store(1, Ordering::Relaxed);
            id = 1;
        }
        id
    }

    fn update_buf(&self, size: usize) {
        let mut current = self.max_buf.load(Ordering::Relaxed);
        while size > current {
            match self
                .max_buf
                .compare_exchange(current, size, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(now) => current = now,
            }
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn spawn_reader(conn: Arc<Self>) {
        let done = conn.done.clone();
        tokio::spawn(async move {
            loop {
                let buf_len = conn.max_buf.load(Ordering::Relaxed);
                let mut buf = vec![0u8; buf_len];

                tokio::select! {
                    result = conn.socket.recv(&mut buf) => {
                        match result {
                            Ok(n) => {
                                buf.truncate(n);
                                // Grow buffer if response hints larger payload (EDNS0 or observed length)
                                let hinted = edns_udp_payload_size(&buf).unwrap_or(buf.len());
                                conn.update_buf(cmp::max(hinted, buf.len()));
                                if buf.len() < 2 {
                                    continue;
                                }
                                let id = u16::from_be_bytes([buf[0], buf[1]]);
                                if let Some(tx) = conn.callbacks.lock().await.remove(&id) {
                                    let _ = tx.send(buf);
                                }
                            }
                            Err(err) => {
                                conn.closed.store(true, Ordering::SeqCst);
                                let mut callbacks = conn.callbacks.lock().await;
                                for (_, tx) in callbacks.drain() {
                                    let _ = tx.send(Vec::new());
                                }
                                trace!(error=%err, "dns/udp: recv loop closed");
                                break;
                            }
                        }
                    }
                    _ = done.notified() => {
                        conn.closed.store(true, Ordering::SeqCst);
                        let mut callbacks = conn.callbacks.lock().await;
                        for (_, tx) in callbacks.drain() {
                            let _ = tx.send(Vec::new());
                        }
                        trace!("dns/udp: recv loop cancelled by done signal");
                        break;
                    }
                }
            }
        });
    }
}

impl UdpTransport {
    /// Create a new UDP transport with default dialer.
    /// 使用默认 dialer 创建新的 UDP 传输。
    pub fn new(upstream: UdpUpstream) -> Self {
        Self {
            upstream,
            shared: Arc::new(Mutex::new(None)),
            default_buf: 2048,
            dialer: Arc::new(DefaultUdpDialer),
            done: Arc::new(Notify::new()),
            started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a UDP transport with a custom dialer.
    /// 使用自定义 dialer 创建 UDP 传输。
    pub fn with_dialer(upstream: UdpUpstream, dialer: Arc<dyn UdpDialer>) -> Self {
        Self {
            upstream,
            shared: Arc::new(Mutex::new(None)),
            default_buf: 2048,
            dialer,
            done: Arc::new(Notify::new()),
            started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Set the default buffer size.
    /// 设置默认缓冲区大小。
    #[must_use]
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.default_buf = size;
        self
    }

    /// Check if the transport has been started.
    /// 检查传输是否已启动。
    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::SeqCst)
    }

    fn buffer_size(&self, packet: &[u8]) -> usize {
        const DEFAULT: usize = 2048;
        const MAX: usize = 65535;
        edns_udp_payload_size(packet)
            .map(|size| cmp::max(size, DEFAULT))
            .unwrap_or(DEFAULT)
            .min(MAX)
    }

    async fn ensure_conn(&self, buf_size: usize) -> Result<Arc<SharedUdpConn>> {
        let mut guard = self.shared.lock().await;
        if let Some(conn) = guard.as_ref() {
            if !conn.is_closed() {
                conn.update_buf(buf_size);
                return Ok(conn.clone());
            }
        }

        // Use dialer to create socket
        let socket = self.dialer.dial_udp(self.upstream.addr).await?;
        let conn = SharedUdpConn::new(
            socket,
            cmp::max(buf_size, self.default_buf),
            self.done.clone(),
        );
        *guard = Some(conn.clone());
        Ok(conn)
    }

    /// Internal query implementation with error classification.
    /// 带错误分类的内部查询实现。
    async fn query_impl(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() < 2 {
            return Err(anyhow!("dns/udp: packet too short (missing ID)"));
        }

        let buf_size = self.buffer_size(packet);
        let conn = self.ensure_conn(buf_size).await?;
        let peer = self.upstream.addr;

        let mut outbound = packet.to_vec();
        let original_id = u16::from_be_bytes([outbound[0], outbound[1]]);
        let query_id = conn.next_id();
        outbound[0..2].copy_from_slice(&query_id.to_be_bytes());

        let (tx, rx) = oneshot::channel();
        {
            let mut callbacks = conn.callbacks.lock().await;
            callbacks.insert(query_id, tx);
        }

        if let Err(e) = conn.socket.send(&outbound).await {
            let mut callbacks = conn.callbacks.lock().await;
            callbacks.remove(&query_id);
            return Err(e).context("dns/udp: send");
        }

        let done = self.done.clone();
        let result = tokio::select! {
            result = time::timeout(self.upstream.timeout, rx) => {
                match result {
                    Ok(Ok(buf)) => {
                        if buf.is_empty() {
                            Err(anyhow!("dns/udp: connection closed"))
                        } else {
                            Ok(buf)
                        }
                    }
                    Ok(Err(_)) => {
                        Err(anyhow!("dns/udp: response channel dropped"))
                    }
                    Err(_) => {
                        let mut callbacks = conn.callbacks.lock().await;
                        callbacks.remove(&query_id);
                        Err(anyhow!("dns/udp: timeout"))
                    }
                }
            }
            _ = done.notified() => {
                let mut callbacks = conn.callbacks.lock().await;
                callbacks.remove(&query_id);
                Err(anyhow!("dns/udp: transport closed"))
            }
        };

        let mut buf = result?;

        if buf.len() >= 2 {
            buf[0..2].copy_from_slice(&original_id.to_be_bytes());
        }

        // If response is truncated, fallback to TCP DNS
        let truncated = buf.len() >= 4 && (u16::from_be_bytes([buf[2], buf[3]]) & 0x0200) != 0;
        if truncated {
            debug!(upstream=%peer, "dns/udp: truncated response, retrying via TCP");
            let tcp = TcpTransport::new(peer).with_timeout(self.upstream.timeout);
            return tcp
                .query(packet)
                .await
                .context("dns/tcp: retry after UDP truncation");
        }

        trace!(upstream=%peer, len=%buf.len(), "dns/udp: recv");
        Ok(buf)
    }

    /// Close the shared UDP connection (internal).
    /// 关闭共享的 UDP 连接（内部）。
    async fn close_internal(&self) {
        // Signal done to all waiters
        self.done.notify_waiters();

        let mut guard = self.shared.lock().await;
        if let Some(conn) = guard.take() {
            conn.close();
            // Notify all pending callbacks
            let mut callbacks = conn.callbacks.lock().await;
            for (_, tx) in callbacks.drain() {
                let _ = tx.send(Vec::new());
            }
        }
    }
}

#[async_trait::async_trait]
impl DnsTransport for UdpTransport {
    async fn query(&self, packet: &[u8]) -> Result<Vec<u8>> {
        self.query_impl(packet).await.map_err(|e| {
            let error_type = DnsTransportError::classify(&e);
            trace!(error_type=?error_type, error=%e, "dns/udp: query failed");
            e
        })
    }

    fn name(&self) -> &'static str {
        "udp"
    }

    async fn start(&self, stage: DnsStartStage) -> Result<()> {
        match stage {
            DnsStartStage::Initialize => {
                debug!(upstream=?self.upstream.addr, "dns/udp: initializing");
                Ok(())
            }
            DnsStartStage::Start => {
                debug!(upstream=?self.upstream.addr, "dns/udp: starting");
                // Initialize dialer (for detour support)
                self.dialer.initialize().await?;
                self.started.store(true, Ordering::SeqCst);
                Ok(())
            }
            DnsStartStage::PostStart => {
                debug!(upstream=?self.upstream.addr, "dns/udp: post-start");
                Ok(())
            }
        }
    }

    async fn close(&self) -> Result<()> {
        debug!(upstream=?self.upstream.addr, "dns/udp: closing");
        self.started.store(false, Ordering::SeqCst);
        self.close_internal().await;
        Ok(())
    }
}

/// Extract EDNS0 UDP payload size from DNS packet.
/// 从 DNS 报文中提取 EDNS0 UDP 载荷大小。
fn edns_udp_payload_size(packet: &[u8]) -> Option<usize> {
    const DNS_HEADER_LEN: usize = 12;
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    let mut offset = DNS_HEADER_LEN;

    // Skip question section
    for _ in 0..qdcount {
        offset = skip_name(packet, offset)?;
        if offset + 4 > packet.len() {
            return None;
        }
        offset += 4; // QTYPE + QCLASS
    }

    // Iterate through additional records looking for OPT record (TYPE 41)
    // Its CLASS field contains the UDP payload size
    for _ in 0..arcount {
        offset = skip_name(packet, offset)?;
        if offset + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return None;
        }
        if rtype == 41 {
            return Some(class as usize);
        }
        offset += rdlen;
    }

    None
}

/// Skip a DNS name in packet (supports compression pointers).
/// 跳过 DNS 报文中的域名（支持压缩指针）。
fn skip_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    while offset < packet.len() {
        let len = *packet.get(offset)?;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer takes 2 bytes
            offset += 1;
            break;
        }
        offset = offset.checked_add(len as usize)?;
    }
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_edns_payload_size() {
        // Construct minimal query with OPT record, UDP payload size = 1232
        let mut packet = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x01, // ARCOUNT
        ];
        // QNAME: example.com
        packet.extend_from_slice(&[7]);
        packet.extend_from_slice(b"example");
        packet.extend_from_slice(&[3]);
        packet.extend_from_slice(b"com");
        packet.push(0);
        // QTYPE/QCLASS
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // OPT record name (root)
        packet.push(0);
        // TYPE (41)
        packet.extend_from_slice(&[0x00, 0x29]);
        // CLASS = udp payload size (1232)
        packet.extend_from_slice(&1232u16.to_be_bytes());
        // TTL + RDLEN = 0
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(edns_udp_payload_size(&packet), Some(1232));
    }

    #[test]
    fn test_dns_transport_error_classification() {
        let timeout_err = anyhow!("dns/udp: timeout");
        assert_eq!(
            DnsTransportError::classify(&timeout_err),
            DnsTransportError::Timeout
        );

        let closed_err = anyhow!("dns/udp: connection closed");
        assert_eq!(
            DnsTransportError::classify(&closed_err),
            DnsTransportError::Closed
        );

        let network_err = anyhow!("dns/udp: network unreachable");
        assert_eq!(
            DnsTransportError::classify(&network_err),
            DnsTransportError::Network
        );

        let protocol_err = anyhow!("dns/udp: invalid response");
        assert_eq!(
            DnsTransportError::classify(&protocol_err),
            DnsTransportError::Protocol
        );
    }

    #[tokio::test]
    async fn test_lifecycle_stages() {
        let upstream = UdpUpstream {
            addr: "8.8.8.8:53".parse().unwrap(),
            timeout: Duration::from_secs(5),
        };
        let transport = UdpTransport::new(upstream);

        // Test start stages
        assert!(!transport.is_started());
        transport.start(DnsStartStage::Initialize).await.unwrap();
        assert!(!transport.is_started());
        transport.start(DnsStartStage::Start).await.unwrap();
        assert!(transport.is_started());
        transport.start(DnsStartStage::PostStart).await.unwrap();

        // Test close
        transport.close().await.unwrap();
        assert!(!transport.is_started());
    }
}
