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

use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};
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
}

/// Per-socket driver-side bookkeeping.
struct TcpEntry {
    handle: SocketHandle,
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
    entries: Vec<TcpEntry>,
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
            let _ = self
                .iface
                .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
            self.flush_tx(&mut scratch).await;
            self.pump_sockets();
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

    /// Hand out a wrapping ephemeral source port in the IANA dynamic range.
    fn alloc_ephemeral_port(&mut self) -> u16 {
        const EPHEMERAL_LO: u16 = 49152;
        let port = self.next_ephemeral;
        self.next_ephemeral = if self.next_ephemeral == u16::MAX {
            EPHEMERAL_LO
        } else {
            self.next_ephemeral + 1
        };
        port
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
        let local_ep = IpListenEndpoint {
            addr: Some(to_smol_addr(local_ip)),
            port: local_port,
        };
        if let Err(e) = sock.connect(self.iface.context(), remote_ep, local_ep) {
            let _ = reply.send(Err(DialError::Other(format!("WireGuard connect: {e}"))));
            return;
        }

        let handle = self.sockets.add(sock);
        let (to_caller_tx, to_caller_rx) = mpsc::channel(TO_CALLER_CAP);
        let (from_caller_tx, from_caller_rx) = mpsc::unbounded_channel();
        let stream = WgTcpStream::new(to_caller_rx, from_caller_tx, self.wake.clone());

        self.entries.push(TcpEntry {
            handle,
            to_caller: to_caller_tx,
            from_caller: from_caller_rx,
            connect_done: Some(reply),
            pending_stream: Some(stream),
            tx_pending: VecDeque::new(),
            caller_closed: false,
        });
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
    ) -> Self {
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
            entries: Vec::new(),
        };

        tokio::spawn(driver.run());

        Self { ctrl_tx }
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
        WgNetStack::new(tunn, socket, peer, local_addrs, 1408, [0, 0, 0])
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
}
