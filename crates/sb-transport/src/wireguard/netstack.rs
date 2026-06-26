//! Userspace TCP/IP network stack for WireGuard, built on smoltcp over the
//! boringtun `Tunn`.
//!
//! This mirrors Go sing-box's gVisor `netstack` (`transport/wireguard/device_stack.go`)
//! and the proven boringtun+smoltcp design of `onetun`: a WireGuard tunnel carries
//! raw IP packets, so this module runs a smoltcp `Interface` *inside* the tunnel to
//! synthesize real TCP/UDP flows. `WireGuardTransport::connect` therefore returns a
//! genuine, proxyable stream — instead of feeding raw application bytes straight into
//! `Tunn::encapsulate`, which expects a full IP packet and silently drops anything
//! else (the pre-post004 data-plane bug).
//!
//! Bridge shape (mirrors Go `wireEndpoint` ↔ gVisor):
//! - egress: smoltcp emits an IP packet → `Tunn::encapsulate` → UDP `send_to(peer)`.
//! - ingress: UDP `recv_from` → `Tunn::decapsulate` → inject the decrypted IP packet
//!   into smoltcp.
//!
//! Routing: the netstack is the WireGuard *client*. We initiate connections to
//! arbitrary in-tunnel targets, so smoltcp needs a default route to emit the SYN; on
//! `Medium::Ip` the gateway is never used for L2 resolution (`has_neighbor` returns
//! true unconditionally, smoltcp 0.11 `interface/mod.rs`), so we point the default
//! route at our own WG address. Reply packets are addressed to our interface address,
//! so `set_any_ip` is unnecessary.
//!
//! `reserved` (the 3 bytes after the WG message type) is handled at the UDP boundary
//! exactly like Go's `transport/wireguard/client_bind.go`: written into `packet[1..4]`
//! on send, cleared on receive before handing the datagram to boringtun.
//!
//! Architecture: a single driver task owns the `Tunn`, the UDP socket, the smoltcp
//! `Interface`/`SocketSet` and the `WgPhy` device — no locking around the tunnel.
//! Callers talk to it over channels; each `WgTcpStream` is an mpsc pair plus a shared
//! `Notify` that wakes the driver to flush writes.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};
use tracing::{debug, trace, warn};

use crate::dialer::DialError;

/// Max UDP datagram / decrypted IP packet buffer.
const WG_MAX_PACKET: usize = 65535;
/// Per-socket smoltcp tx/rx ring size.
const TCP_BUF: usize = 64 * 1024;
/// Bounded depth for driver→caller payload delivery (TCP back-pressure point).
const TO_CALLER_CAP: usize = 64;
/// Driver poll cadence; also services boringtun timers (keepalive/rekey/retransmit).
const WG_POLL_MS: u64 = 50;

/// Convert a std `IpAddr` to a smoltcp `IpAddress`.
fn to_smol_addr(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets())),
        IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())),
    }
}

/// Convert a smoltcp `IpAddress` back to a std `IpAddr`.
fn from_smol_addr(addr: IpAddress) -> IpAddr {
    let bytes = addr.as_bytes();
    if bytes.len() == 16 {
        let mut a = [0u8; 16];
        a.copy_from_slice(bytes);
        IpAddr::V6(Ipv6Addr::from(a))
    } else {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }
}

/// Apply the WireGuard `reserved` bytes to an outgoing datagram, mirroring Go's
/// `client_bind.go` `Send`: `if len(buf) > 3 { copy(buf[1:4], reserved) }`.
fn apply_reserved(buf: &mut [u8], reserved: [u8; 3]) {
    if buf.len() > 3 && reserved != [0u8; 3] {
        buf[1..4].copy_from_slice(&reserved);
    }
}

/// Clear the `reserved` bytes of an incoming datagram before handing it to boringtun,
/// mirroring Go's `client_bind.go` `receive`: `if n > 3 { clear(b[1:4]) }`.
fn clear_reserved(buf: &mut [u8]) {
    if buf.len() > 3 {
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
    }
}

// ===================== smoltcp PHY device over the WG tunnel =====================

/// A smoltcp `Device` whose link layer is the WireGuard tunnel.
///
/// `rx_queue` holds decrypted inbound IP packets (fed by the driver before each
/// `iface.poll`); `tx_queue` collects IP packets smoltcp wants to send (drained by
/// the driver after each poll, then encrypted via `Tunn::encapsulate`).
struct WgPhy {
    mtu: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl WgPhy {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }
}

impl Device for WgPhy {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // `pop_front` releases the rx_queue borrow before the tx token borrows the
        // whole device (same pattern as sb-core's TunPhy).
        self.rx_queue
            .pop_front()
            .map(move |buf| (WgRxToken(buf), WgTxToken(self)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps
    }
}

struct WgRxToken(Vec<u8>);

impl RxToken for WgRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.0)
    }
}

struct WgTxToken<'a>(&'a mut WgPhy);

impl<'a> TxToken for WgTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.0.tx_queue.push_back(buf);
        result
    }
}

// ===================== caller-facing stream =====================

/// An incoming TCP connection accepted by a netstack listener.
///
/// Carries the established `WgTcpStream` plus the local and remote addresses so
/// the endpoint can build an `InboundContext` for routing.
#[derive(Debug)]
pub struct TcpAccept {
    /// The established stream inside the WG tunnel.
    pub stream: WgTcpStream,
    /// The local (WG interface) address the connection arrived at.
    pub local: SocketAddr,
    /// The remote (in-tunnel peer) address that initiated the connection.
    pub remote: SocketAddr,
}

/// A TCP stream flowing through the WireGuard tunnel's userspace netstack.
#[derive(Debug)]
pub struct WgTcpStream {
    /// driver → caller (decrypted payload). Bounded for TCP back-pressure.
    rx: mpsc::Receiver<Vec<u8>>,
    /// caller → driver (payload to send).
    tx: mpsc::UnboundedSender<Vec<u8>>,
    wake: Arc<Notify>,
    /// leftover bytes from a previous `rx` chunk not yet copied to the caller.
    read_residual: Vec<u8>,
    read_pos: usize,
}

impl WgTcpStream {
    fn new(
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::UnboundedSender<Vec<u8>>,
        wake: Arc<Notify>,
    ) -> Self {
        Self {
            rx,
            tx,
            wake,
            read_residual: Vec::new(),
            read_pos: 0,
        }
    }
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_pos < self.read_residual.len() {
            let n = buf
                .remaining()
                .min(self.read_residual.len() - self.read_pos);
            let start = self.read_pos;
            buf.put_slice(&self.read_residual[start..start + n]);
            self.read_pos += n;
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = buf.remaining().min(data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_residual = data;
                    self.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            // Channel closed → clean EOF.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.tx.send(buf.to_vec()) {
            Ok(()) => {
                self.wake.notify_one();
                Poll::Ready(Ok(buf.len()))
            }
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WireGuard netstack driver stopped",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // Dropping `tx` (on stream drop) tells the driver to close the socket (FIN);
        // an explicit shutdown just nudges a poll.
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ===================== caller-facing UDP datagram socket =====================

/// A UDP datagram socket flowing through the WireGuard tunnel's netstack.
///
/// Mirrors the `UdpTransport` / `net.PacketConn` shape: `send_to(buf, dst)` and
/// `recv_from(buf) -> (n, src)`. One socket talks to many in-tunnel peers.
pub struct WgUdpSocket {
    to_driver: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    from_driver: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    wake: Arc<Notify>,
    local_v4: bool,
    local_v6: bool,
}

impl std::fmt::Debug for WgUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgUdpSocket").finish_non_exhaustive()
    }
}

impl WgUdpSocket {
    /// Send a datagram to an in-tunnel destination.
    pub async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        if dst.is_ipv4() && !self.local_v4 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard netstack has no local IPv4 address to source UDP",
            ));
        }
        if dst.is_ipv6() && !self.local_v6 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "WireGuard netstack has no local IPv6 address to source UDP",
            ));
        }
        self.to_driver.send((buf.to_vec(), dst)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WireGuard netstack driver stopped",
            )
        })?;
        self.wake.notify_one();
        Ok(buf.len())
    }

    /// Receive a datagram, returning the payload size and source address.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.from_driver.lock().await;
        match rx.recv().await {
            Some((data, src)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, src))
            }
            None => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WireGuard netstack udp closed",
            )),
        }
    }
}

// ===================== driver =====================

/// A control message to the driver task.
enum Control {
    /// Open a TCP connection to a tunnel-internal target.
    Tcp {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<WgTcpStream, DialError>>,
    },
    /// Roaming: update the peer endpoint the tunnel sends to.
    SetPeerEndpoint(SocketAddr),
    /// Proactively (re)initiate the Noise handshake (warm-up).
    Handshake,
    /// Open a UDP datagram socket sourced at the WG interface address(es).
    Udp {
        reply: oneshot::Sender<Result<WgUdpSocket, DialError>>,
    },
}

/// Per-socket driver-side bookkeeping.
struct TcpEntry {
    handle: SocketHandle,
    local_port: u16,
    to_caller: mpsc::Sender<Vec<u8>>,
    from_caller: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Fired once the socket is established (or `Err` if it dies first).
    connect_done: Option<oneshot::Sender<Result<WgTcpStream, DialError>>>,
    /// Stream handed to the caller on establishment.
    pending_stream: Option<WgTcpStream>,
    /// Bytes accepted from the caller but not yet pushed into smoltcp's tx ring.
    tx_pending: VecDeque<u8>,
    /// Caller dropped the write half → close the socket once tx_pending drains.
    caller_closed: bool,
}

/// A listening socket inside the WG netstack, waiting for incoming TCP from the
/// tunnel. Mirrors Go gvisor's `SetTransportProtocolHandler` but for specific
/// ports (smoltcp does not support catch-all-port listening).
struct TcpListenerEntry {
    handle: SocketHandle,
    local: SocketAddr,
}

/// Per-UDP-socket driver-side bookkeeping.
struct UdpEntry {
    handle: SocketHandle,
    local_port: u16,
    to_caller: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    from_caller: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
}

/// The single task that owns the tunnel and netstack.
struct Driver {
    tunn: Tunn,
    socket: Arc<UdpSocket>,
    peer_endpoint: SocketAddr,
    reserved: [u8; 3],
    iface: Interface,
    device: WgPhy,
    sockets: SocketSet<'static>,
    ctrl_rx: mpsc::Receiver<Control>,
    wake: Arc<Notify>,
    local_v4: Option<Ipv4Addr>,
    local_v6: Option<Ipv6Addr>,
    /// Next ephemeral source port to hand out (smoltcp `connect` rejects port 0).
    next_ephemeral: u16,
    /// Ports currently handed out to live TCP/UDP sockets; used to skip
    /// collisions in `alloc_ephemeral_port` and reclaimed on socket reap.
    in_use_ports: HashSet<u16>,
    /// Reused scratch buffer for `pump_udp_recv` (avoids a 64KB alloc per poll).
    udp_rxbuf: Vec<u8>,
    entries: Vec<TcpEntry>,
    udp_entries: Vec<UdpEntry>,
    /// TCP listeners inside the tunnel (incoming connections from WG peers).
    listeners: Vec<TcpListenerEntry>,
    /// Channel to deliver accepted incoming TCP connections to the endpoint.
    /// `None` when no listener was requested → incoming TCP is dropped.
    tcp_accept_tx: Option<mpsc::Sender<TcpAccept>>,
    /// Ports to listen on inside the tunnel (consumed at driver start).
    listen_ports: Vec<u16>,
}

impl Driver {
    /// Apply `reserved` and send a finished WG datagram to the peer.
    async fn send_packet(
        socket: &UdpSocket,
        peer: SocketAddr,
        reserved: [u8; 3],
        buf: &mut [u8],
        len: usize,
    ) {
        apply_reserved(&mut buf[..len], reserved);
        if let Err(e) = socket.send_to(&buf[..len], peer).await {
            trace!("WireGuard netstack send error: {}", e);
        }
    }

    async fn run(mut self) {
        let mut udp_buf = vec![0u8; WG_MAX_PACKET];
        let mut scratch = vec![0u8; WG_MAX_PACKET];
        let mut poll_timer = tokio::time::interval(Duration::from_millis(WG_POLL_MS));
        poll_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Open TCP listeners inside the tunnel for each configured listen port.
        // smoltcp listeners are port-specific (no catch-all like gvisor's
        // SetTransportProtocolHandler). Each listener binds to all WG interface
        // addresses (wildcard) so incoming connections to any local IP on that
        // port are accepted.
        for &port in &self.listen_ports {
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
                tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            );
            let listen_ep = IpListenEndpoint { addr: None, port };
            match sock.listen(listen_ep) {
                Ok(()) => {
                    let handle = self.sockets.add(sock);
                    let local = SocketAddr::new(
                        self.local_v4
                            .map(IpAddr::V4)
                            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                        port,
                    );
                    debug!(
                        "WireGuard netstack: listening inside tunnel on port {} (handle {})",
                        port, handle
                    );
                    self.listeners.push(TcpListenerEntry { handle, local });
                }
                Err(e) => {
                    warn!(
                        "WireGuard netstack: failed to listen on port {} inside tunnel: {:?}",
                        port, e
                    );
                }
            }
        }
        self.listen_ports.clear(); // consumed

        // Warm up: kick the Noise handshake so keys are usually ready before the first
        // dial (the SYN would trigger it anyway, but this shaves the first-connect RTT).
        self.do_handshake(&mut scratch).await;

        loop {
            let recv_sock = self.socket.clone();
            tokio::select! {
                biased;
                maybe_ctrl = self.ctrl_rx.recv() => {
                    match maybe_ctrl {
                        Some(Control::Tcp { remote, reply }) => self.on_dial_tcp(remote, reply),
                        Some(Control::SetPeerEndpoint(addr)) => {
                            debug!("WireGuard netstack peer endpoint → {}", addr);
                            self.peer_endpoint = addr;
                        }
                        Some(Control::Handshake) => self.do_handshake(&mut scratch).await,
                        Some(Control::Udp { reply }) => self.on_open_udp(reply),
                        None => {
                            debug!("WireGuard netstack: all handles dropped, driver exiting");
                            return;
                        }
                    }
                }
                r = recv_sock.recv_from(&mut udp_buf) => {
                    match r {
                        Ok((n, src)) => {
                            clear_reserved(&mut udp_buf[..n]);
                            self.on_udp_in(n, src.ip(), &udp_buf, &mut scratch).await;
                        }
                        Err(e) => warn!("WireGuard netstack udp recv error: {}", e),
                    }
                }
                _ = self.wake.notified() => {}
                _ = poll_timer.tick() => self.service_timers(&mut scratch).await,
            }

            self.pump_caller_writes();
            self.pump_udp_writes();
            let _ = self
                .iface
                .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
            self.flush_tx(&mut scratch).await;
            self.pump_sockets();
            self.pump_listeners();
            self.pump_udp_recv();
        }
    }

    /// Decrypt an inbound WG datagram and inject resulting IP packets into smoltcp.
    async fn on_udp_in(&mut self, n: usize, src: IpAddr, udp_buf: &[u8], scratch: &mut [u8]) {
        // First call consumes the datagram; subsequent calls with empty input drain
        // any packets boringtun has queued (e.g. handshake responses).
        let mut first = true;
        loop {
            let input: &[u8] = if first { &udp_buf[..n] } else { &[] };
            first = false;
            match self.tunn.decapsulate(Some(src), input, scratch) {
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    self.device.rx_queue.push_back(pkt.to_vec());
                }
                TunnResult::WriteToNetwork(resp) => {
                    let len = resp.len();
                    Self::send_packet(
                        &self.socket,
                        self.peer_endpoint,
                        self.reserved,
                        scratch,
                        len,
                    )
                    .await;
                    // keep draining queued packets
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    trace!("WireGuard decapsulate: {:?}", e);
                    break;
                }
            }
        }
    }

    /// Drain smoltcp's outbound IP packets, encrypt and send to the peer.
    async fn flush_tx(&mut self, scratch: &mut [u8]) {
        while let Some(ip_pkt) = self.device.tx_queue.pop_front() {
            let send_len = match self.tunn.encapsulate(&ip_pkt, scratch) {
                TunnResult::WriteToNetwork(packet) => Some(packet.len()),
                TunnResult::Err(e) => {
                    warn!("WireGuard encapsulate: {:?}", e);
                    None
                }
                _ => None,
            };
            if let Some(len) = send_len {
                Self::send_packet(
                    &self.socket,
                    self.peer_endpoint,
                    self.reserved,
                    scratch,
                    len,
                )
                .await;
            }
        }
    }

    /// Service boringtun timers (keepalive, rekey, retransmit).
    async fn service_timers(&mut self, scratch: &mut [u8]) {
        let send_len = match self.tunn.update_timers(scratch) {
            TunnResult::WriteToNetwork(packet) => Some(packet.len()),
            TunnResult::Err(e) => {
                trace!("WireGuard update_timers: {:?}", e);
                None
            }
            _ => None,
        };
        if let Some(len) = send_len {
            Self::send_packet(
                &self.socket,
                self.peer_endpoint,
                self.reserved,
                scratch,
                len,
            )
            .await;
        }
    }

    /// Initiate the Noise handshake.
    async fn do_handshake(&mut self, scratch: &mut [u8]) {
        let send_len = match self.tunn.format_handshake_initiation(scratch, false) {
            TunnResult::WriteToNetwork(packet) => Some(packet.len()),
            TunnResult::Err(e) => {
                trace!("WireGuard handshake init: {:?}", e);
                None
            }
            _ => None,
        };
        if let Some(len) = send_len {
            Self::send_packet(
                &self.socket,
                self.peer_endpoint,
                self.reserved,
                scratch,
                len,
            )
            .await;
            debug!("WireGuard netstack handshake initiated");
        }
    }

    /// Hand out a fresh ephemeral source port in the IANA dynamic range,
    /// skipping any port still in use by a live socket. The range wraps at
    /// `u16::MAX` → `EPHEMERAL_LO`. If the entire range is exhausted (16384
    /// ports all live, extremely unlikely in proxy workloads), returns 0 which
    /// smoltcp rejects loudly at `connect`/`bind`.
    fn alloc_ephemeral_port(&mut self) -> u16 {
        const EPHEMERAL_LO: u16 = 49152;
        for _ in 0..(u16::MAX - EPHEMERAL_LO + 1) {
            let port = self.next_ephemeral;
            self.next_ephemeral = if self.next_ephemeral == u16::MAX {
                EPHEMERAL_LO
            } else {
                self.next_ephemeral + 1
            };
            if !self.in_use_ports.contains(&port) {
                return port;
            }
        }
        0
    }

    fn reclaim_port(&mut self, port: u16) {
        self.in_use_ports.remove(&port);
    }

    fn on_dial_tcp(
        &mut self,
        remote: SocketAddr,
        reply: oneshot::Sender<Result<WgTcpStream, DialError>>,
    ) {
        let local_ip = match remote.ip() {
            IpAddr::V4(_) => self.local_v4.map(IpAddr::V4),
            IpAddr::V6(_) => self.local_v6.map(IpAddr::V6),
        };
        let Some(local_ip) = local_ip else {
            let _ = reply.send(Err(DialError::Other(format!(
                "WireGuard netstack has no local {} address to source the connection",
                if remote.is_ipv4() { "IPv4" } else { "IPv6" }
            ))));
            return;
        };

        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
        );
        let remote_ep = IpEndpoint::new(to_smol_addr(remote.ip()), remote.port());
        // smoltcp's `connect` rejects a zero local port, so we allocate an ephemeral
        // source port ourselves.
        let local_port = self.alloc_ephemeral_port();
        if local_port == 0 {
            let _ = reply.send(Err(DialError::Other(
                "WireGuard netstack ephemeral port range exhausted".into(),
            )));
            return;
        }
        self.in_use_ports.insert(local_port);
        let local_ep = IpListenEndpoint {
            addr: Some(to_smol_addr(local_ip)),
            port: local_port,
        };
        if let Err(e) = sock.connect(self.iface.context(), remote_ep, local_ep) {
            self.reclaim_port(local_port);
            let _ = reply.send(Err(DialError::Other(format!("WireGuard connect: {e}"))));
            return;
        }

        let handle = self.sockets.add(sock);
        let (to_caller_tx, to_caller_rx) = mpsc::channel(TO_CALLER_CAP);
        let (from_caller_tx, from_caller_rx) = mpsc::unbounded_channel();
        let stream = WgTcpStream::new(to_caller_rx, from_caller_tx, self.wake.clone());

        self.entries.push(TcpEntry {
            handle,
            local_port,
            to_caller: to_caller_tx,
            from_caller: from_caller_rx,
            connect_done: Some(reply),
            pending_stream: Some(stream),
            tx_pending: VecDeque::new(),
            caller_closed: false,
        });
        self.wake.notify_one();
    }

    /// Open a UDP datagram socket bound to an ephemeral port at the WG interface.
    fn on_open_udp(&mut self, reply: oneshot::Sender<Result<WgUdpSocket, DialError>>) {
        if self.local_v4.is_none() && self.local_v6.is_none() {
            let _ = reply.send(Err(DialError::Other(
                "WireGuard netstack has no local address to source UDP".into(),
            )));
            return;
        }
        let mut sock = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 32],
                vec![0u8; WG_MAX_PACKET],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 32],
                vec![0u8; WG_MAX_PACKET],
            ),
        );
        let local_port = self.alloc_ephemeral_port();
        if local_port == 0 {
            let _ = reply.send(Err(DialError::Other(
                "WireGuard netstack ephemeral port range exhausted".into(),
            )));
            return;
        }
        // Wildcard local address: smoltcp picks the iface source matching each dst family.
        if let Err(e) = sock.bind(IpListenEndpoint {
            addr: None,
            port: local_port,
        }) {
            self.reclaim_port(local_port);
            let _ = reply.send(Err(DialError::Other(format!("WireGuard udp bind: {e}"))));
            return;
        }
        self.in_use_ports.insert(local_port);

        let handle = self.sockets.add(sock);
        let (to_caller_tx, to_caller_rx) = mpsc::channel(TO_CALLER_CAP);
        let (from_caller_tx, from_caller_rx) = mpsc::unbounded_channel();
        let udp_sock = WgUdpSocket {
            to_driver: from_caller_tx,
            from_driver: Mutex::new(to_caller_rx),
            wake: self.wake.clone(),
            local_v4: self.local_v4.is_some(),
            local_v6: self.local_v6.is_some(),
        };
        self.udp_entries.push(UdpEntry {
            handle,
            local_port,
            to_caller: to_caller_tx,
            from_caller: from_caller_rx,
        });
        let _ = reply.send(Ok(udp_sock));
        self.wake.notify_one();
    }

    /// Move caller-submitted bytes into each socket's tx ring.
    fn pump_caller_writes(&mut self) {
        let sockets = &mut self.sockets;
        for entry in self.entries.iter_mut() {
            let sock = sockets.get_mut::<tcp::Socket>(entry.handle);
            loop {
                match entry.from_caller.try_recv() {
                    Ok(data) => entry.tx_pending.extend(data),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        entry.caller_closed = true;
                        break;
                    }
                }
            }
            while !entry.tx_pending.is_empty() && sock.can_send() {
                let (a, b) = entry.tx_pending.as_slices();
                let chunk = if !a.is_empty() { a } else { b };
                match sock.send_slice(chunk) {
                    Ok(0) => break,
                    Ok(written) => {
                        entry.tx_pending.drain(..written);
                    }
                    Err(_) => break,
                }
            }
            if entry.caller_closed && entry.tx_pending.is_empty() && sock.may_send() {
                sock.close();
            }
        }
    }

    /// Deliver socket reads to callers, fire establishment, and reap dead sockets.
    fn pump_sockets(&mut self) {
        let sockets = &mut self.sockets;
        let mut reap: Vec<usize> = Vec::new();

        for (idx, entry) in self.entries.iter_mut().enumerate() {
            let sock = sockets.get_mut::<tcp::Socket>(entry.handle);
            let state = sock.state();

            // Establishment gating: hand the stream back once we can move data.
            if entry.connect_done.is_some() && sock.may_send() {
                if let (Some(done), Some(stream)) =
                    (entry.connect_done.take(), entry.pending_stream.take())
                {
                    let _ = done.send(Ok(stream));
                }
            }

            // Deliver inbound data (bounded → TCP back-pressure when the caller is slow).
            while sock.can_recv() {
                match entry.to_caller.try_reserve() {
                    Ok(permit) => {
                        let chunk = sock.recv(|data| {
                            let n = data.len();
                            (n, data.to_vec())
                        });
                        match chunk {
                            Ok(bytes) if !bytes.is_empty() => permit.send(bytes),
                            _ => break,
                        }
                    }
                    Err(_) => break, // caller queue full/gone; leave in socket buffer
                }
            }

            // Connection died before establishing → surface a real dial error.
            if entry.connect_done.is_some() && state == tcp::State::Closed {
                if let Some(done) = entry.connect_done.take() {
                    let _ = done.send(Err(DialError::Other(
                        "WireGuard tunnel connection closed before established".into(),
                    )));
                }
                reap.push(idx);
                continue;
            }

            // Socket fully closed and the caller side is gone → reap.
            if state == tcp::State::Closed && (entry.caller_closed || entry.to_caller.is_closed()) {
                reap.push(idx);
            }
        }

        for idx in reap.into_iter().rev() {
            let entry = self.entries.swap_remove(idx);
            self.reclaim_port(entry.local_port);
            self.sockets.remove(entry.handle);
        }
    }

    /// Move caller-submitted datagrams into their UDP sockets; reap closed callers.
    fn pump_udp_writes(&mut self) {
        let sockets = &mut self.sockets;
        let mut reap: Vec<usize> = Vec::new();
        for (idx, entry) in self.udp_entries.iter_mut().enumerate() {
            let sock = sockets.get_mut::<udp::Socket>(entry.handle);
            loop {
                match entry.from_caller.try_recv() {
                    Ok((data, dst)) => {
                        let ep = IpEndpoint::new(to_smol_addr(dst.ip()), dst.port());
                        if let Err(e) = sock.send_slice(&data, ep) {
                            trace!("WireGuard udp send_slice: {:?}", e);
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        reap.push(idx);
                        break;
                    }
                }
            }
        }
        for idx in reap.into_iter().rev() {
            let entry = self.udp_entries.swap_remove(idx);
            self.reclaim_port(entry.local_port);
            self.sockets.remove(entry.handle);
        }
    }

    /// Check listening sockets for accepted incoming TCP connections from the
    /// tunnel. On accept, the listener socket becomes the established connection,
    /// so a new listener is created for the same port. The accepted stream is
    /// sent to the endpoint via `tcp_accept_tx`.
    fn pump_listeners(&mut self) {
        // Collect indices of listeners that have accepted a connection.
        // smoltcp's `accept()` returns Ok(remote) when the socket has
        // transitioned from LISTEN to ESTABLISHED.
        let mut accepts: Vec<(usize, SocketAddr, SocketAddr)> = Vec::new();
        for (idx, listener) in self.listeners.iter().enumerate() {
            let sock = self.sockets.get_mut::<tcp::Socket>(listener.handle);
            // smoltcp 0.11 has no `accept()` method. A listening socket
            // transitions from LISTEN to ESTABLISHED when a SYN arrives.
            // `remote_endpoint()` returns `Some` only when established.
            if let Some(remote_ep) = sock.remote_endpoint() {
                let local = sock
                    .local_endpoint()
                    .map(|ep| SocketAddr::new(from_smol_addr(ep.addr), ep.port))
                    .unwrap_or(listener.local);
                let remote = SocketAddr::new(from_smol_addr(remote_ep.addr), remote_ep.port);
                accepts.push((idx, local, remote));
            }
        }

        // Process accepts in reverse to keep indices valid during swap_remove.
        for (idx, local, remote) in accepts.into_iter().rev() {
            let listener = self.listeners.swap_remove(idx);
            // The listener's socket handle is now the established connection.

            // Create the caller-facing stream channels.
            let (to_caller_tx, to_caller_rx) = mpsc::channel(TO_CALLER_CAP);
            let (from_caller_tx, from_caller_rx) = mpsc::unbounded_channel();
            let stream = WgTcpStream::new(to_caller_rx, from_caller_tx, self.wake.clone());

            // Move the accepted socket into the entries vector for I/O servicing.
            // `local_port: 0` means no ephemeral port to reclaim (the listener
            // port is fixed and always in use by the next listener).
            self.entries.push(TcpEntry {
                handle: listener.handle,
                local_port: 0,
                to_caller: to_caller_tx,
                from_caller: from_caller_rx,
                connect_done: None, // already established
                pending_stream: None,
                tx_pending: VecDeque::new(),
                caller_closed: false,
            });

            // Deliver the accept to the endpoint.
            if let Some(tx) = &self.tcp_accept_tx {
                if let Err(error) = tx.try_send(TcpAccept {
                    stream,
                    local,
                    remote,
                }) {
                    warn!(
                        "WireGuard netstack: failed to deliver accepted TCP connection from {} to {}: {}",
                        remote, local, error
                    );
                }
            }

            // Create a new listener for the same port to accept more connections.
            let mut new_sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
                tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            );
            let listen_ep = IpListenEndpoint {
                addr: None,
                port: local.port(),
            };
            if let Err(e) = new_sock.listen(listen_ep) {
                warn!(
                    "WireGuard netstack: failed to re-listen on port {}: {:?}",
                    local.port(),
                    e
                );
            } else {
                let new_handle = self.sockets.add(new_sock);
                self.listeners.push(TcpListenerEntry {
                    handle: new_handle,
                    local,
                });
            }
        }
    }

    /// Deliver inbound datagrams to callers; reap sockets whose caller is gone.
    fn pump_udp_recv(&mut self) {
        let sockets = &mut self.sockets;
        let mut reap: Vec<usize> = Vec::new();
        // Reuse the driver-owned rxbuf instead of allocating 64KB per poll.
        let rxbuf = &mut self.udp_rxbuf;
        for (idx, entry) in self.udp_entries.iter_mut().enumerate() {
            if entry.to_caller.is_closed() {
                reap.push(idx);
                continue;
            }
            let sock = sockets.get_mut::<udp::Socket>(entry.handle);
            while sock.can_recv() {
                match entry.to_caller.try_reserve() {
                    Ok(permit) => match sock.recv_slice(rxbuf) {
                        Ok((n, meta)) => {
                            let src = SocketAddr::new(
                                from_smol_addr(meta.endpoint.addr),
                                meta.endpoint.port,
                            );
                            permit.send((rxbuf[..n].to_vec(), src));
                        }
                        Err(_) => break,
                    },
                    Err(_) => break, // caller queue full/gone; leave in socket buffer
                }
            }
        }
        for idx in reap.into_iter().rev() {
            let entry = self.udp_entries.swap_remove(idx);
            self.reclaim_port(entry.local_port);
            self.sockets.remove(entry.handle);
        }
    }
}

// ===================== public handle =====================

/// A cloneable handle to a running WireGuard userspace netstack.
#[derive(Clone)]
pub(crate) struct WgNetStack {
    ctrl_tx: mpsc::Sender<Control>,
}

impl WgNetStack {
    /// Build the netstack and spawn its driver task.
    ///
    /// `tunn` and `socket` are moved into the driver (single-owner, no locking).
    /// `local_addrs` are the WireGuard interface addresses used as the source for
    /// outgoing connections; without one matching the target family, `connect_tcp`
    /// fails loudly rather than leaking. `reserved` is applied/cleared per Go's
    /// `client_bind.go`.
    pub(crate) fn new(
        tunn: Tunn,
        socket: Arc<UdpSocket>,
        peer_endpoint: SocketAddr,
        local_addrs: &[IpAddr],
        mtu: usize,
        reserved: [u8; 3],
        listen_ports: &[u16],
    ) -> (Self, Option<mpsc::Receiver<TcpAccept>>) {
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut device = WgPhy::new(mtu);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        iface.update_ip_addrs(|addrs| {
            for ip in local_addrs {
                let cidr = match ip {
                    IpAddr::V4(v4) => IpCidr::new(to_smol_addr(IpAddr::V4(*v4)), 32),
                    IpAddr::V6(v6) => IpCidr::new(to_smol_addr(IpAddr::V6(*v6)), 128),
                };
                let _ = addrs.push(cidr);
            }
        });

        let local_v4 = local_addrs.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        });
        let local_v6 = local_addrs.iter().find_map(|ip| match ip {
            IpAddr::V6(v6) => Some(*v6),
            _ => None,
        });

        // Default routes so the client can reach any in-tunnel destination. On
        // `Medium::Ip` the gateway is never used for L2 resolution, so pointing it at
        // our own WG address is sufficient and correct.
        if let Some(v4) = local_v4 {
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::from_bytes(&v4.octets()));
        }
        if let Some(v6) = local_v6 {
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::from_bytes(&v6.octets()));
        }

        let (ctrl_tx, ctrl_rx) = mpsc::channel(64);
        let wake = Arc::new(Notify::new());
        let (tcp_accept_tx, tcp_accept_rx) = if listen_ports.is_empty() {
            (None, None)
        } else {
            let (tx, rx) = mpsc::channel::<TcpAccept>(64);
            (Some(tx), Some(rx))
        };

        let driver = Driver {
            tunn,
            socket,
            peer_endpoint,
            reserved,
            iface,
            device,
            sockets: SocketSet::new(vec![]),
            ctrl_rx,
            wake,
            local_v4,
            local_v6,
            next_ephemeral: 49152,
            in_use_ports: HashSet::new(),
            udp_rxbuf: vec![0u8; WG_MAX_PACKET],
            entries: Vec::new(),
            udp_entries: Vec::new(),
            listeners: Vec::new(),
            tcp_accept_tx,
            listen_ports: listen_ports.to_vec(),
        };

        tokio::spawn(driver.run());

        (Self { ctrl_tx }, tcp_accept_rx)
    }

    /// Open a TCP connection to `host:port` inside the tunnel.
    ///
    /// `host` must already be a resolved IP literal; callers resolve FQDNs.
    pub(crate) async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<WgTcpStream, DialError> {
        let ip: IpAddr = host.parse().map_err(|_| {
            DialError::Other(format!(
                "WireGuard netstack expects a resolved IP, got non-IP host {host:?}"
            ))
        })?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.ctrl_tx
            .send(Control::Tcp {
                remote: SocketAddr::new(ip, port),
                reply: reply_tx,
            })
            .await
            .map_err(|_| DialError::Other("WireGuard netstack driver stopped".into()))?;

        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(DialError::Other("WireGuard netstack dial cancelled".into())),
            Err(_) => Err(DialError::Other("WireGuard netstack dial timeout".into())),
        }
    }

    /// Open a UDP datagram socket inside the tunnel (send_to/recv_from to arbitrary
    /// in-tunnel destinations).
    pub(crate) async fn connect_udp(&self) -> Result<WgUdpSocket, DialError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.ctrl_tx
            .send(Control::Udp { reply: reply_tx })
            .await
            .map_err(|_| DialError::Other("WireGuard netstack driver stopped".into()))?;
        reply_rx
            .await
            .map_err(|_| DialError::Other("WireGuard netstack udp open cancelled".into()))?
    }

    /// Roaming: update the peer endpoint the tunnel sends to.
    pub(crate) async fn set_peer_endpoint(&self, addr: SocketAddr) {
        let _ = self.ctrl_tx.send(Control::SetPeerEndpoint(addr)).await;
    }

    /// Proactively (re)initiate the Noise handshake.
    pub(crate) async fn handshake(&self) {
        let _ = self.ctrl_tx.send(Control::Handshake).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_apply_sets_bytes_1_to_3() {
        let mut pkt = vec![0x01, 0, 0, 0, 0xaa, 0xbb];
        apply_reserved(&mut pkt, [0x11, 0x22, 0x33]);
        assert_eq!(&pkt[1..4], &[0x11, 0x22, 0x33]);
        // message type and payload untouched
        assert_eq!(pkt[0], 0x01);
        assert_eq!(&pkt[4..], &[0xaa, 0xbb]);
    }

    #[test]
    fn reserved_apply_noop_when_zero_or_short() {
        let mut pkt = vec![0x04, 0x09, 0x09, 0x09];
        apply_reserved(&mut pkt, [0, 0, 0]);
        assert_eq!(
            &pkt[1..4],
            &[0x09, 0x09, 0x09],
            "zero reserved must not overwrite"
        );
        let mut short = vec![0x01, 0x02];
        apply_reserved(&mut short, [1, 2, 3]);
        assert_eq!(short, vec![0x01, 0x02], "len<=3 untouched");
    }

    #[test]
    fn reserved_clear_zeros_bytes_1_to_3() {
        let mut pkt = vec![0x02, 0x77, 0x88, 0x99, 0xde];
        clear_reserved(&mut pkt);
        assert_eq!(&pkt[1..4], &[0, 0, 0]);
        assert_eq!(pkt[0], 0x02);
        assert_eq!(pkt[4], 0xde);
    }

    #[test]
    fn wgphy_receive_pops_rx_and_collects_tx() {
        let mut phy = WgPhy::new(1408);
        phy.rx_queue.push_back(vec![1, 2, 3]);
        let now = SmolInstant::from_millis(0);
        let (rx, tx) = phy.receive(now).expect("one packet queued");
        let got = rx.consume(|b| b.to_vec());
        assert_eq!(got, vec![1, 2, 3]);
        tx.consume(2, |b| {
            b.copy_from_slice(&[9, 9]);
        });
        assert_eq!(phy.tx_queue.pop_front().unwrap(), vec![9, 9]);
        assert!(phy.receive(now).is_none(), "rx queue now empty");
    }

    fn test_keys() -> (String, String) {
        // Example WireGuard keys (not secrets) — valid base64, 32 bytes.
        (
            "YAnz5TF+lXXJte14tji3zlbzbm+JFHYa74LLQDzOjG0=".to_string(),
            "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=".to_string(),
        )
    }

    async fn build_stack(local_addrs: &[IpAddr]) -> WgNetStack {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let (priv_b64, peer_b64) = test_keys();
        let priv_arr: [u8; 32] = B64.decode(&priv_b64).unwrap().try_into().unwrap();
        let peer_arr: [u8; 32] = B64.decode(&peer_b64).unwrap().try_into().unwrap();
        let tunn = Tunn::new(
            boringtun::x25519::StaticSecret::from(priv_arr),
            boringtun::x25519::PublicKey::from(peer_arr),
            None,
            Some(25),
            0,
            None,
        );
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        // peer endpoint points at an unused loopback port (no real peer in unit tests).
        let peer = "127.0.0.1:1".parse().unwrap();
        let (stack, _accept_rx) =
            WgNetStack::new(tunn, socket, peer, local_addrs, 1408, [0, 0, 0], &[]);
        stack
    }

    fn keypair_a() -> (&'static str, &'static str) {
        (
            "IPCEEDl2GPOfgm3dOWpu60ukWO0ixOEr7vN8kN92Sm8=",
            "rJwEZnkVL9bdiicGfKitXhif7bCvqm0NOjeI1QSM5gU=",
        )
    }

    fn keypair_b() -> (&'static str, &'static str) {
        (
            "GKaTjB3F8RpZJdd10plIlncr36M/Oxml/pkR5doSqHI=",
            "tjXnHkpr2ZR9MI2udxlxDBpiRbQj1ABu9ZvZcWCPOBc=",
        )
    }

    fn tunn_from_keys(private_b64: &str, peer_public_b64: &str) -> Tunn {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let priv_arr: [u8; 32] = B64.decode(private_b64).unwrap().try_into().unwrap();
        let peer_arr: [u8; 32] = B64.decode(peer_public_b64).unwrap().try_into().unwrap();
        Tunn::new(
            boringtun::x25519::StaticSecret::from(priv_arr),
            boringtun::x25519::PublicKey::from(peer_arr),
            None,
            Some(25),
            0,
            None,
        )
    }

    #[tokio::test]
    async fn listen_ports_open_accept_receiver_only_when_configured() {
        let (priv_a, _pub_a) = keypair_a();
        let (_priv_b, pub_b) = keypair_b();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = "127.0.0.1:1".parse().unwrap();
        let local_addrs = [IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))];

        let (_stack, accept_rx) = WgNetStack::new(
            tunn_from_keys(priv_a, pub_b),
            socket,
            peer,
            &local_addrs,
            1408,
            [0, 0, 0],
            &[18080],
        );

        assert!(accept_rx.is_some(), "listen_ports creates accept receiver");
    }

    #[tokio::test]
    async fn paired_netstacks_accept_incoming_tcp_and_echo() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (priv_a, pub_a) = keypair_a();
        let (priv_b, pub_b) = keypair_b();
        let socket_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let outer_a = socket_a.local_addr().unwrap();
        let outer_b = socket_b.local_addr().unwrap();

        let local_a = [IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))];
        let local_b = [IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2))];
        let (_stack_a, accept_rx) = WgNetStack::new(
            tunn_from_keys(priv_a, pub_b),
            socket_a,
            outer_b,
            &local_a,
            1408,
            [0, 0, 0],
            &[18080],
        );
        let (stack_b, _accept_rx_b) = WgNetStack::new(
            tunn_from_keys(priv_b, pub_a),
            socket_b,
            outer_a,
            &local_b,
            1408,
            [0, 0, 0],
            &[],
        );
        let mut accept_rx = accept_rx.expect("listener accept receiver");

        let mut client = stack_b
            .connect_tcp("10.9.0.1", 18080, Duration::from_secs(5))
            .await
            .expect("client connects to listener through WG");
        let accept = tokio::time::timeout(Duration::from_secs(5), accept_rx.recv())
            .await
            .expect("accept should arrive")
            .expect("accept channel open");

        assert_eq!(accept.local, "10.9.0.1:18080".parse().unwrap());
        assert_eq!(accept.remote.ip(), IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2)));

        let mut server = accept.stream;
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.unwrap();
        let mut reply = [0u8; 4];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
    }

    #[tokio::test]
    async fn connect_to_wrong_family_fails_loudly() {
        // Only an IPv4 local address; connecting to an IPv6 target must loud-fail
        // (no silent leak), and quickly (no timeout wait).
        let stack = build_stack(&[IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))]).await;
        let err = stack
            .connect_tcp("fd00::1", 80, Duration::from_secs(5))
            .await
            .expect_err("must fail: no IPv6 source");
        match err {
            DialError::Other(msg) => assert!(msg.contains("IPv6"), "got: {msg}"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn connect_non_ip_host_fails_loudly() {
        let stack = build_stack(&[IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))]).await;
        let err = stack
            .connect_tcp("example.com", 80, Duration::from_secs(5))
            .await
            .expect_err("netstack requires a resolved IP");
        assert!(matches!(err, DialError::Other(_)));
    }

    #[tokio::test]
    async fn connect_without_peer_times_out() {
        // With a valid source but no real peer answering, the SYN can never complete;
        // the driver must surface a Timeout (proving the driver runs + connect path +
        // timeout gating are wired, not a hang).
        let stack = build_stack(&[IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))]).await;
        let err = stack
            .connect_tcp("10.7.0.1", 80, Duration::from_millis(300))
            .await
            .expect_err("no peer → no establishment");
        match err {
            DialError::Other(msg) => assert!(msg.contains("timeout"), "got: {msg}"),
            other => panic!("expected Other(timeout), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn udp_open_without_local_addr_fails_loudly() {
        let stack = build_stack(&[]).await;
        let err = stack
            .connect_udp()
            .await
            .expect_err("no local addr → no UDP source");
        assert!(matches!(err, DialError::Other(_)));
    }

    #[tokio::test]
    async fn udp_send_to_queues_and_recv_times_out_without_peer() {
        let stack = build_stack(&[IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))]).await;
        let sock = stack.connect_udp().await.expect("udp socket");
        let n = sock
            .send_to(b"hello", "10.7.0.1:53".parse().unwrap())
            .await
            .expect("datagram queued");
        assert_eq!(n, 5);
        // No peer answers → recv must not return; proves the socket works without hang/panic.
        let mut buf = [0u8; 64];
        let r = tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        assert!(r.is_err(), "recv_from should time out with no peer");
    }

    #[tokio::test]
    async fn udp_send_to_wrong_family_fails_loudly() {
        let stack = build_stack(&[IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))]).await;
        let sock = stack.connect_udp().await.expect("udp socket");
        let err = sock
            .send_to(b"hello", "[fd00::1]:53".parse().unwrap())
            .await
            .expect_err("no IPv6 source must fail before queueing");
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        assert!(err.to_string().contains("IPv6"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn udp_dual_stack_send_to_both_families_queues() {
        // A dual-source WG interface (v4 + v6) must accept datagrams to both
        // families, exercising both `local_v4` and `local_v6` flags on the happy
        // path. Existing tests only cover the v4-positive and v4-only→v6-negative
        // cases; this pins the dual-stack positive path.
        let stack = build_stack(&[
            IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)),
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        ])
        .await;
        let sock = stack.connect_udp().await.expect("dual-stack udp socket");

        let n4 = sock
            .send_to(b"v4", "10.7.0.1:53".parse().unwrap())
            .await
            .expect("v4 datagram queued");
        assert_eq!(n4, 2);

        let n6 = sock
            .send_to(b"v6", "[fd00::1]:53".parse().unwrap())
            .await
            .expect("v6 datagram queued");
        assert_eq!(n6, 2);

        // No peer answers → recv must not return prematurely.
        let mut buf = [0u8; 64];
        let r = tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        assert!(r.is_err(), "recv_from should time out with no peer");
    }

    #[tokio::test]
    async fn udp_many_concurrent_sockets_no_port_collision() {
        // Open many UDP sockets concurrently on one tunnel. The ephemeral port
        // allocator must skip in-use ports (P3-3); none of the opens should fail
        // with a bind error. We keep the sockets alive for the duration of the
        // check by holding them in a Vec.
        let stack = build_stack(&[IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))]).await;
        const N: usize = 64;
        let mut socks = Vec::with_capacity(N);
        for _ in 0..N {
            let sock = stack
                .connect_udp()
                .await
                .expect("udp socket open must not collide");
            socks.push(sock);
        }
        // All 64 sockets are live with distinct ephemeral ports; send a datagram
        // from each to confirm they're independently usable.
        for sock in &socks {
            sock.send_to(b"x", "10.7.0.1:53".parse().unwrap())
                .await
                .expect("each socket must send");
        }
        // Dropping all sockets reclaims their ports (driver reaps on next poll).
        drop(socks);
        tokio::time::sleep(Duration::from_millis(120)).await;
        // After reaping, a fresh open must succeed (ports were reclaimed).
        let _again = stack
            .connect_udp()
            .await
            .expect("port reclaimed after drop");
    }

    #[tokio::test]
    async fn tcp_many_concurrent_dials_all_timeout_distinctly() {
        // P3-6: N concurrent TCP dials on one tunnel with no peer answering.
        // Each must get its own ephemeral port (no collision) and surface a
        // timeout rather than hanging or colliding. This is the TCP stress
        // counterpart to the UDP collision test.
        let stack = build_stack(&[IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2))]).await;
        const N: usize = 16;
        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let s = stack.clone();
            handles.push(tokio::spawn(async move {
                // Distinct target ports so smoltcp doesn't dedup; all time out
                // (no real peer) but the point is each dial gets a port.
                let r = s
                    .connect_tcp("10.7.0.1", 1000 + i as u16, Duration::from_millis(300))
                    .await;
                assert!(r.is_err(), "dial {i} must time out, not hang");
                r
            }));
        }
        for (i, h) in handles.into_iter().enumerate() {
            let r = h.await.expect("task {i} panicked");
            match r {
                Err(DialError::Other(msg)) => assert!(
                    msg.contains("timeout"),
                    "dial {i}: expected timeout, got {msg}"
                ),
                other => panic!("dial {i}: expected Other(timeout), got {other:?}"),
            }
        }
    }
}
