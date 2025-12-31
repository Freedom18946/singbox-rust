use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use serde::Deserialize;
use tokio::sync::{mpsc, Mutex, RwLock};

use sb_core::outbound::OutboundConnector;
use sb_core::types::{ConnCtx, Endpoint, Host, Network, Protocol};
use sb_platform::tun::{AsyncTunDevice, TunConfig, TunError};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp, Socket};
use smoltcp::time::Instant as SmolTimestamp;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};

/// Enhanced TUN configuration
#[derive(Debug, Clone, Deserialize)]
pub struct EnhancedTunConfig {
    pub name: String,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
    #[serde(default)]
    pub auto_route: bool,
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout_ms: u64,
    #[serde(default = "default_udp_timeout")]
    pub udp_timeout_ms: u64,
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
}

fn default_mtu() -> u32 { 1500 }
fn default_tcp_timeout() -> u64 { 30_000 }
fn default_udp_timeout() -> u64 { 60_000 }
fn default_buffer_size() -> usize { 65536 }
fn default_max_tcp_connections() -> usize { 1024 }

impl Default for EnhancedTunConfig {
    fn default() -> Self {
        Self {
            name: "tun0".to_string(),
            mtu: default_mtu(),
            ipv4: None,
            ipv6: None,
            auto_route: false,
            tcp_timeout_ms: default_tcp_timeout(),
            udp_timeout_ms: default_udp_timeout(),
            buffer_size: default_buffer_size(),
            max_tcp_connections: default_max_tcp_connections(),
        }
    }
}

/// A smoltcp Device backed by in-memory queues.
/// Allows "pushing" packets from AsyncTunDevice into the queue for smoltcp to consume (rx),
/// and "pulling" packets smoltcp wrote (tx) to write to AsyncTunDevice.
struct TunPhy {
    rx_queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
    tx_queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
    mtu: usize,
}

impl TunPhy {
    fn new(
        rx_queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
        tx_queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
        mtu: usize,
    ) -> Self {
        Self { rx_queue, tx_queue, mtu }
    }
}

impl<'a> Device<'a> for TunPhy {
    type RxToken = VecRxToken;
    type TxToken = VecTxToken;

    fn receive(&'a mut self, _timestamp: SmolTimestamp) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut rx = self.rx_queue.borrow_mut();
        if let Some(buffer) = rx.pop_front() {
            Some((
                VecRxToken { buffer },
                VecTxToken { queue: self.tx_queue.clone() }
            ))
        } else {
            None
        }
    }

    fn transmit(&'a mut self, _timestamp: SmolTimestamp) -> Option<Self::TxToken> {
        Some(VecTxToken { queue: self.tx_queue.clone() })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct VecRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VecRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct VecTxToken {
    queue: Rc<RefCell<VecDeque<Vec<u8>>>>,
}

impl TxToken for VecTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.borrow_mut().push_back(buffer);
        result
    }
}

/// Event for the main loop
enum LoopEvent {
    // TunPacket is handled directly in select!
    InboundData(SocketHandle, Option<IpEndpoint>, Vec<u8>), // Endpoint required for UDP
    ConnectionClosed(SocketHandle, Option<IpEndpoint>),     // Endpoint optional for UDP session cleanup
}

enum ConnectionType {
    Tcp(mpsc::UnboundedSender<Vec<u8>>),
    Udp(HashMap<IpEndpoint, mpsc::UnboundedSender<Vec<u8>>>),
}

struct ConnectionState {
    conn_type: ConnectionType,
    _handle: SocketHandle,
}

/// Main Inbound Structure
pub struct EnhancedTunInbound {
    config: EnhancedTunConfig,
    outbound: Arc<dyn OutboundConnector>,
    router: Option<Arc<sb_core::router::RouterHandle>>,
}

impl EnhancedTunInbound {
    pub fn new(config: EnhancedTunConfig, outbound: Arc<dyn OutboundConnector>) -> Self {
        Self { config, outbound, router: None }
    }

    pub fn with_router(
        config: EnhancedTunConfig,
        outbound: Arc<dyn OutboundConnector>,
        router: Arc<sb_core::router::RouterHandle>,
    ) -> Self {
        let mut inbound = Self::new(config, outbound);
        inbound.router = Some(router);
        inbound
    }

    pub async fn start(&mut self) -> Result<(), TunError> {
        let tun_cfg = TunConfig {
            name: self.config.name.clone(),
            mtu: self.config.mtu,
            ipv4: self.config.ipv4,
            ipv6: self.config.ipv6,
            auto_route: self.config.auto_route,
            table: None,
        };

        // Create the device
        let mut device = AsyncTunDevice::new(&tun_cfg)?;
        let outbound = self.outbound.clone();
        let config = self.config.clone();
        let router = self.router.clone();

        // Queues using std::sync::Mutex for synchronous access inside smoltcp logic
        let rx_queue = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let tx_queue = Arc::new(std::sync::Mutex::new(VecDeque::new()));

        struct SharedTunPhy {
            rx: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
            tx: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
            mtu: usize,
        }

        impl<'a> Device<'a> for SharedTunPhy {
            type RxToken = VecRxToken;
            type TxToken = SharedVecTxToken;

            fn receive(&'a mut self, _timestamp: SmolTimestamp) -> Option<(Self::RxToken, Self::TxToken)> {
                let mut rx = self.rx.lock().unwrap();
                if let Some(buffer) = rx.pop_front() {
                    Some((
                        VecRxToken { buffer },
                        SharedVecTxToken { queue: self.tx.clone() }
                    ))
                } else {
                    None
                }
            }

            fn transmit(&'a mut self, _timestamp: SmolTimestamp) -> Option<Self::TxToken> {
                Some(SharedVecTxToken { queue: self.tx.clone() })
            }

            fn capabilities(&self) -> DeviceCapabilities {
                let mut caps = DeviceCapabilities::default();
                caps.medium = Medium::Ip;
                caps.max_transmission_unit = self.mtu;
                caps
            }
        }

        struct SharedVecTxToken {
            queue: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
        }

        impl TxToken for SharedVecTxToken {
            fn consume<R, F>(self, len: usize, f: F) -> R
            where
                F: FnOnce(&mut [u8]) -> R,
            {
                let mut buffer = vec![0u8; len];
                let result = f(&mut buffer);
                self.queue.lock().unwrap().push_back(buffer);
                result
            }
        }

        // Channel for events from Outbound tasks to Main Loop
        let (loop_ingress_tx, mut loop_ingress_rx) = mpsc::unbounded_channel::<LoopEvent>();

        // Spawn the main processor
        tokio::spawn(async move {
            let mut sockets = SocketSet::new(vec![]);
            let mut iface_config = Config::new(smoltcp::wire::HardwareAddress::Ip);
            iface_config.random_seed = rand::random();
            
            let mut device_phy = SharedTunPhy {
                rx: rx_queue.clone(),
                tx: tx_queue.clone(),
                mtu: config.mtu as usize,
            };

            let mut iface = Interface::new(iface_config, &mut device_phy, SmolTimestamp::now());
            
            if let Some(ip) = config.ipv4 {
                iface.update_ip_addrs(|addrs| {
                    addrs.push(IpCidr::new(IpAddress::from(ip), 24)).ok(); 
                });
                iface.update_routes(|routes| {
                   routes.add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(0, 0, 0, 0)).ok();
                });
            }
            if let Some(ip) = config.ipv6 {
                iface.update_ip_addrs(|addrs| {
                    addrs.push(IpCidr::new(IpAddress::from(ip), 64)).ok();
                });
            }

            let mut buffer = vec![0u8; config.buffer_size];
            // Track mapping of SocketHandle -> ConnectionState
            let mut connection_map: HashMap<SocketHandle, ConnectionState> = HashMap::new();
            // Fast lookup: IpEndpoint -> SocketHandle for UDP JIT (O(1) instead of O(n) iteration)
            let mut udp_handles: HashMap<IpEndpoint, SocketHandle> = HashMap::new();
            
            loop {
                // 1. SELECT: Read from TUN or Rx Channel or Timeout
                let mut did_work = false;
                
                tokio::select! {
                    res = device.read(&mut buffer) => {
                        match res {
                            Ok(n) => {
                                let pkt_data = buffer[..n].to_vec();
                                
                                // JIT Socket Creation Logic
                                if let Ok(mut ipv4_packet) = Ipv4Packet::new_checked(&pkt_data) {
                                    let src_addr = IpAddress::Ipv4(ipv4_packet.src_addr());
                                    let dst_addr = IpAddress::Ipv4(ipv4_packet.dst_addr());
                                    let protocol = ipv4_packet.next_header();
                                    let payload = ipv4_packet.payload();

                                    if protocol == IpProtocol::Tcp {
                                        if let Ok(tcp_packet) = TcpPacket::new_checked(payload) {
                                            if tcp_packet.syn() && !tcp_packet.ack() {
                                                let dst_port = tcp_packet.dst_port();
                                                let src_port = tcp_packet.src_port();
                                                
                                                let rx_buf = tcp::SocketBuffer::new(vec![0; 65535]);
                                                let tx_buf = tcp::SocketBuffer::new(vec![0; 65535]);
                                                let mut socket = tcp::Socket::new(rx_buf, tx_buf);
                                                
                                                if socket.listen((dst_addr, dst_port)).is_ok() {
                                                    let handle = sockets.add(socket);
                                                    tracing::debug!("Created JIT TCP socket {} for {}:{} -> {}:{}", handle, src_addr, src_port, dst_addr, dst_port);
                                                    
                                                    // Spawn Outbound Task
                                                    let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                                                    let loop_tx = loop_ingress_tx.clone();
                                                    let outbound_conn = outbound.clone();
                                                    
                                                    let std_src = match src_addr {
                                                        IpAddress::Ipv4(a) => IpAddr::V4(a.into()),
                                                        IpAddress::Ipv6(a) => IpAddr::V6(a.into()),
                                                    };
                                                    let std_dst = match dst_addr {
                                                        IpAddress::Ipv4(a) => IpAddr::V4(a.into()),
                                                        IpAddress::Ipv6(a) => IpAddr::V6(a.into()),
                                                    };
                                                    
                                                    connection_map.insert(handle, ConnectionState {
                                                        conn_type: ConnectionType::Tcp(outbound_tx),
                                                        _handle: handle,
                                                    });

                                                    tokio::spawn(async move {
                                                        let ctx = ConnCtx {
                                                            src: SocketAddr::new(std_src, src_port),
                                                            dst: Endpoint::from((std_dst, dst_port)),
                                                            ..Default::default()
                                                        };
                                                        
                                                        match outbound_conn.connect(ctx).await {
                                                            Ok(mut stream) => {
                                                                let mut buf = vec![0u8; 4096];
                                                                loop {
                                                                    tokio::select! {
                                                                        msg = outbound_rx.recv() => {
                                                                            if let Some(data) = msg {
                                                                                use tokio::io::AsyncWriteExt;
                                                                                if stream.write_all(&data).await.is_err() { break; }
                                                                            } else { break; }
                                                                        }
                                                                        res = stream.read(&mut buf) => {
                                                                            use tokio::io::AsyncReadExt;
                                                                            match res {
                                                                                Ok(0) => break, 
                                                                                Ok(n) => {
                                                                                    if loop_tx.send(LoopEvent::InboundData(handle, None, buf[..n].to_vec())).is_err() { break; }
                                                                                }
                                                                                Err(_) => break,
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                let _ = loop_tx.send(LoopEvent::ConnectionClosed(handle, None));
                                                            }
                                                            Err(e) => {
                                                                tracing::error!("TCP Outbound connect failed: {}", e);
                                                                let _ = loop_tx.send(LoopEvent::ConnectionClosed(handle, None));
                                                            }
                                                        }
                                                    });
                                                }
                                            }
                                        }
                                    } else if protocol == IpProtocol::Udp {
                                         if let Ok(udp_packet) = UdpPacket::new_checked(payload) {
                                            let dst_port = udp_packet.dst_port();
                                            // Check if we already have a socket for (dst_addr, dst_port) using O(1) lookup
                                            let dest_endpoint = IpEndpoint::new(dst_addr, dst_port);
                                            
                                            if !udp_handles.contains_key(&dest_endpoint) {
                                                // Create socket
                                                let mut rx_meta = vec![udp::PacketMetadata::EMPTY; 10];
                                                let mut rx_payload = vec![0; 65535];
                                                let mut tx_meta = vec![udp::PacketMetadata::EMPTY; 10];
                                                let mut tx_payload = vec![0; 65535];
                                                let mut socket = udp::Socket::new(
                                                    udp::PacketBuffer::new(&mut rx_meta[..], &mut rx_payload[..]),
                                                    udp::PacketBuffer::new(&mut tx_meta[..], &mut tx_payload[..])
                                                );
                                                
                                                if socket.bind(dest_endpoint).is_ok() {
                                                     let handle = sockets.add(socket);
                                                     tracing::debug!("Created JIT UDP socket {} for {}", handle, dest_endpoint);
                                                     
                                                     // Register in both maps for fast lookup
                                                     udp_handles.insert(dest_endpoint, handle);
                                                     connection_map.insert(handle, ConnectionState {
                                                         conn_type: ConnectionType::Udp(HashMap::new()),
                                                         _handle: handle,
                                                     });
                                                }
                                            }
                                         }
                                    }
                                }
                                // Repeat for IPv6 Logic (omitted for brevity)
                                
                                rx_queue.lock().unwrap().push_back(pkt_data);
                                did_work = true;
                            },
                            Err(e) => {
                                tracing::error!("TUN read error: {}", e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                    // Handle events from Outbound tasks
                    evt = loop_ingress_rx.recv() => {
                        if let Some(event) = evt {
                            match event {
                                LoopEvent::InboundData(handle, endpoint, data) => {
                                    if let Some(socket) = sockets.get_mut::<tcp::Socket>(handle) {
                                        let _ = socket.send_slice(&data); 
                                        did_work = true;
                                    } else if let Some(socket) = sockets.get_mut::<udp::Socket>(handle) {
                                        if let Some(ep) = endpoint {
                                            let _ = socket.send_slice(&data, ep);
                                            did_work = true;
                                        }
                                    }
                                }
                                LoopEvent::ConnectionClosed(handle, endpoint) => {
                                    if let Some(ep) = endpoint {
                                        // UDP Session closed
                                        if let Some(state) = connection_map.get_mut(&handle) {
                                            if let ConnectionType::Udp(sessions) = &mut state.conn_type {
                                                sessions.remove(&ep);
                                            }
                                        }
                                    } else {
                                        // TCP or Socket closed
                                        if let Some(socket) = sockets.get_mut::<tcp::Socket>(handle) {
                                            socket.close();
                                            connection_map.remove(&handle); 
                                        } else if let Some(socket) = sockets.get_mut::<udp::Socket>(handle) {
                                             socket.close();
                                             connection_map.remove(&handle);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_millis(10)) => {
                        // Just wake up to poll
                    }
                }

                // 2. Poll Interface
                let timestamp = SmolTimestamp::now();
                iface.poll(timestamp, &mut device_phy, &mut sockets);

                // 3. Flush tx_queue to TUN
                loop {
                    let pkt = {
                        let mut q = tx_queue.lock().unwrap();
                        q.pop_front()
                    };
                    if let Some(pkt) = pkt {
                         if let Err(e) = device.write(&pkt).await {
                             tracing::warn!("TUN write error: {}", e);
                         }
                    } else {
                        break;
                    }
                }
                
                // 4. Socket Management (Bridge smoltcp socket -> Outbound)
                let mut closed_handles = Vec::new();
                for (handle, state) in connection_map.iter_mut() {
                    let mut remove_socket = false;
                    
                    match &mut state.conn_type {
                        ConnectionType::Tcp(tx) => {
                            if let Some(socket) = sockets.get_mut::<tcp::Socket>(*handle) {
                                 if socket.can_recv() {
                                    while let Ok(data) = socket.recv(|buf| (buf.len(), buf.to_vec())) {
                                        if data.is_empty() { break; }
                                        if tx.send(data).is_err() { remove_socket = true; break; }
                                    }
                                }
                                if socket.state() == tcp::State::Closed { remove_socket = true; }
                            } else { remove_socket = true; }
                        }
                        ConnectionType::Udp(sessions) => {
                            if let Some(socket) = sockets.get_mut::<udp::Socket>(*handle) {
                                // Drain packets
                                while let Ok((data, meta)) = socket.recv() {
                                    let src_endpoint = meta.endpoint;
                                    let payload = data.to_vec();
                                    
                                    // Find or create session
                                    if !sessions.contains_key(&src_endpoint) {
                                        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                                        let loop_tx = loop_ingress_tx.clone();
                                        let outbound_conn = outbound.clone();
                                        let socket_handle = *handle;
                                        let ep = src_endpoint; // Capture for task
                                        
                                        // Metadata from socket bind endpoint?
                                        let dst_endpoint = socket.endpoint(); // Local bound endpoint (Dst)
                                        
                                         // Convert smoltcp endpoints to std
                                        let std_src = match src_endpoint.addr {
                                            IpAddress::Ipv4(a) => IpAddr::V4(a.into()),
                                            IpAddress::Ipv6(a) => IpAddr::V6(a.into()),
                                        };
                                        let std_dst = match dst_endpoint.addr {
                                            IpAddress::Ipv4(a) => IpAddr::V4(a.into()),
                                            IpAddress::Ipv6(a) => IpAddr::V6(a.into()),
                                        };
                                        let ctx = ConnCtx {
                                            src: SocketAddr::new(std_src, src_endpoint.port),
                                            dst: Endpoint::from((std_dst, dst_endpoint.port)),
                                            protocol: sb_core::types::Protocol::Udp, // Assume UDP
                                            ..Default::default()
                                        };
                                        
                                        tokio::spawn(async move {
                                            match outbound_conn.connect(ctx).await {
                                                Ok(mut stream) => {
                                                    let mut buf = vec![0u8; 4096];
                                                    // Flush initial packet
                                                    if stream.write_all(&payload).await.is_ok() {
                                                        loop {
                                                            tokio::select! {
                                                                msg = outbound_rx.recv() => {
                                                                    if let Some(data) = msg {
                                                                        use tokio::io::AsyncWriteExt;
                                                                        if stream.write_all(&data).await.is_err() { break; }
                                                                    } else { break; }
                                                                }
                                                                res = stream.read(&mut buf) => {
                                                                    use tokio::io::AsyncReadExt;
                                                                    match res {
                                                                        Ok(0) => break, 
                                                                        Ok(n) => {
                                                                            if loop_tx.send(LoopEvent::InboundData(socket_handle, Some(ep), buf[..n].to_vec())).is_err() { break; }
                                                                        }
                                                                        Err(_) => break,
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    let _ = loop_tx.send(LoopEvent::ConnectionClosed(socket_handle, Some(ep)));
                                                }
                                                Err(e) => {
                                                     tracing::error!("UDP Outbound connect failed: {}", e);
                                                     let _ = loop_tx.send(LoopEvent::ConnectionClosed(socket_handle, Some(ep)));
                                                }
                                            }
                                        });
                                        
                                        sessions.insert(src_endpoint, outbound_tx);
                                    } else {
                                        // Send to existing session
                                        if let Some(tx) = sessions.get(&src_endpoint) {
                                            let _ = tx.send(payload);
                                        }
                                    }
                                }
                            } else { remove_socket = true; }
                        }
                    }
                    
                    if remove_socket {
                        closed_handles.push(*handle);
                    }
                }
                
                for h in closed_handles {
                     connection_map.remove(&h);
                     sockets.remove(h);
                }
            }
        });
        Ok(())
    }
}


