//! macOS transparent proxy runtime driven by utun + tun2socks.
//!
//! This module wires the platform TUN implementation with a lightweight
//! local SOCKS5 bridge that forwards traffic through the standard
//! outbound connector stack. Both TCP CONNECT and UDP ASSOCIATE are
//! supported so that tun2socks can tunnel arbitrary traffic.

#![cfg(all(target_os = "macos", feature = "tun_macos"))]

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::io::{AsRawFd, FromRawFd},
    sync::Arc,
    thread,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{oneshot, Mutex, RwLock},
};

use sb_core::outbound::{OutboundConnector, UdpTransport};
use sb_core::types::{ConnCtx, Endpoint, Host, Network};

use sb_platform::tun::{AsyncTunDevice, MacOsTun, TunConfig, TunDevice, TunError};

use crate::inbound::tun_process_aware::{ProcessAwareTunConfig, ProcessAwareTunStatistics};

use sb_core::router::process_router::ProcessRouter;
use sb_platform::process::{ConnectionInfo, ProcessMatcher, Protocol as ProcessProtocol};

use tracing::{debug, error, info, warn};

/// Runtime handle for the macOS TUN + tun2socks pipeline.
pub struct TunMacosRuntime {
    #[allow(dead_code)]
    tun: Arc<Mutex<MacOsTun>>,
    _tun_async: AsyncTunDevice,
    socks_addr: SocketAddr,
    socks_task: tokio::task::JoinHandle<()>,
    tun2socks_thread: Option<thread::JoinHandle<()>>,
    stop_tx: Option<oneshot::Sender<()>>,
}

impl TunMacosRuntime {
    /// Bootstrap the runtime.
    pub async fn start(
        config: &ProcessAwareTunConfig,
        outbound: Arc<dyn OutboundConnector>,
        process_router: Option<Arc<ProcessRouter>>,
        process_matcher: Option<Arc<ProcessMatcher>>,
        stats: Arc<ProcessAwareTunStatistics>,
    ) -> Result<Self, TunError> {
        let tun_cfg = TunConfig {
            name: config.name.clone(),
            mtu: config.mtu,
            ipv4: config.ipv4,
            ipv6: config.ipv6,
            auto_route: config.auto_route,
            table: None,
        };

        let tun = <MacOsTun as TunDevice>::create(&tun_cfg)?;
        let mut tun_async = AsyncTunDevice::new(&tun_cfg)?;
        let tun_arc = Arc::new(Mutex::new(tun));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|e| {
                TunError::OperationFailed(format!("failed to bind local SOCKS listener: {e}"))
            })?;
        let socks_addr = listener.local_addr().map_err(|e| {
            TunError::OperationFailed(format!("failed to fetch listener addr: {e}"))
        })?;
        info!(addr=?socks_addr, "tun(macos): SOCKS bridge listening");

        let (stop_tx, stop_rx) = oneshot::channel::<()>();

        let bridge = Arc::new(SocksBridge {
            outbound,
            process_router,
            process_matcher,
            stats,
        });

        let socks_task = tokio::spawn(run_socks_server(listener, stop_rx, bridge.clone()));

        let yaml = build_tun2socks_config(config, socks_addr);
        let fd = {
            let guard = tun_arc.lock().await;
            guard.raw_fd()
        };
        let tun2socks_thread = thread::Builder::new()
            .name("sb-tun2socks".to_string())
            .spawn(move || {
                info!(target: "tun", "Launching tun2socks runtime");
                match tun2socks::main_from_str(&yaml, fd) {
                    Ok(_) => info!(target: "tun", "tun2socks terminated"),
                    Err(code) => error!(target: "tun", code, "tun2socks exited with error"),
                }
            })
            .map_err(|e| TunError::OperationFailed(format!("failed to spawn tun2socks: {e}")))?;

        // Give tun2socks a brief head-start to attach the fd
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Touch the TUN device once to ensure the fd stays open in the async side.
        let mut buf = [0u8; 4];
        let _ = tun_async.read(&mut buf).await;

        Ok(Self {
            tun: tun_arc,
            _tun_async: tun_async,
            socks_addr,
            socks_task,
            tun2socks_thread: Some(tun2socks_thread),
            stop_tx: Some(stop_tx),
        })
    }

    pub fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }

        // tun2socks quit is global
        tun2socks::quit();

        if let Some(handle) = self.tun2socks_thread.take() {
            let _ = handle.join();
        }

        let _ = self.socks_task.await;
    }
}

struct SocksBridge {
    outbound: Arc<dyn OutboundConnector>,
    process_router: Option<Arc<ProcessRouter>>,
    process_matcher: Option<Arc<ProcessMatcher>>,
    stats: Arc<ProcessAwareTunStatistics>,
}

async fn run_socks_server(
    listener: TcpListener,
    mut stop_rx: oneshot::Receiver<()>,
    bridge: Arc<SocksBridge>,
) {
    loop {
        tokio::select! {
            _ = &mut stop_rx => {
                info!("tun(macos): stopping SOCKS bridge");
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((mut stream, peer)) => {
                        let bridge = bridge.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_socks_connection(&mut stream, peer, bridge).await {
                                debug!(peer=?peer, error=?err, "SOCKS session ended with error");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error=?err, "SOCKS accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
}

async fn handle_socks_connection(
    stream: &mut TcpStream,
    peer: SocketAddr,
    bridge: Arc<SocksBridge>,
) -> io::Result<()> {
    let reader = stream;

    let ver = read_u8(reader).await?;
    if ver != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS version",
        ));
    }

    let n_methods = read_u8(reader).await? as usize;
    let mut methods = vec![0u8; n_methods];
    reader.read_exact(&mut methods).await?;
    reader.write_all(&[0x05, 0x00]).await?; // NO AUTH

    let mut head = [0u8; 4];
    reader.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad request version",
        ));
    }

    let cmd = head[1];
    let atyp = head[3];

    let target = parse_target(reader, atyp).await?;

    match cmd {
        0x01 => handle_connect(reader, peer, target, bridge).await,
        0x03 => handle_udp_associate(reader, peer, bridge).await,
        _ => {
            reply(
                reader,
                0x07,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await?;
            Err(io::Error::other("command not supported"))
        }
    }
}

async fn handle_connect(
    stream: &mut TcpStream,
    peer: SocketAddr,
    target: Endpoint,
    bridge: Arc<SocksBridge>,
) -> io::Result<()> {
    let id = bridge.stats.next_tcp_id();
    let local_addr = stream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));

    let ctx = ConnCtx::new(id, Network::Tcp, local_addr, target.clone());

    let (chosen_ctx, decision_msg) = match bridge.process_router.as_ref() {
        Some(router) => {
            let host = target.host.clone();
            let (domain, ip) = match &host {
                Host::Name(name) => (Some(name.as_ref()), None),
                Host::Ip(addr) => (None, Some(*addr)),
            };
            let remote = target
                .to_socket_addr()
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), target.port));
            let decision = router
                .decide_with_process(domain, ip, false, Some(target.port), peer, remote)
                .await;
            (ctx, format!("{decision:?}"))
        }
        None => (ctx, "Direct".to_string()),
    };

    let maybe_process = if let Some(matcher) = bridge.process_matcher.as_ref() {
        let remote = target
            .to_socket_addr()
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), target.port));
        let info = ConnectionInfo {
            local_addr: peer,
            remote_addr: remote,
            protocol: ProcessProtocol::Tcp,
        };
        match matcher.match_connection(&info).await {
            Ok(proc_info) => Some(proc_info),
            Err(err) => {
                debug!(error=?err, "process match failed");
                None
            }
        }
    } else {
        None
    };

    bridge.stats.on_tcp_open(&target, maybe_process.as_ref());

    let mut ctx = chosen_ctx;
    if let Some(proc_info) = maybe_process {
        let core_proc =
            sb_core::types::ProcessInfo::new(proc_info.name, proc_info.path, proc_info.pid);
        ctx = ctx.with_process_info(core_proc);
    }

    let outbound = bridge
        .outbound
        .connect_tcp(&ctx)
        .await
        .map_err(|e| io::Error::other(format!("outbound connect failed: {e}")))?;

    reply(stream, 0x00, outbound.local_addr().unwrap_or(local_addr)).await?;

    info!(peer=?peer, dest=?target, decision=%decision_msg, "SOCKS CONNECT established");

    let (mut ri, mut wi) = tokio::io::split(stream);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    let client_to_remote = tokio::io::copy(&mut ri, &mut wo);
    let remote_to_client = tokio::io::copy(&mut ro, &mut wi);

    let res = tokio::try_join!(client_to_remote, remote_to_client);
    bridge.stats.on_tcp_close();

    res.map(|_| ())
        .map_err(|e| io::Error::other(format!("forward failed: {e}")))
}

async fn read_u8(stream: &mut TcpStream) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(buf[0])
}

async fn read_u16(stream: &mut TcpStream) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

async fn parse_target(stream: &mut TcpStream, atyp: u8) -> io::Result<Endpoint> {
    match atyp {
        0x01 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            let port = read_u16(stream).await?;
            Ok(Endpoint::new(
                Host::ip(IpAddr::V4(Ipv4Addr::from(buf))),
                port,
            ))
        }
        0x04 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            let port = read_u16(stream).await?;
            Ok(Endpoint::new(
                Host::ip(IpAddr::V6(Ipv6Addr::from(buf))),
                port,
            ))
        }
        0x03 => {
            let len = read_u8(stream).await? as usize;
            let mut host = vec![0u8; len];
            stream.read_exact(&mut host).await?;
            let port = read_u16(stream).await?;
            let host_str = String::from_utf8(host)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain"))?;
            Ok(Endpoint::new(Host::domain(host_str), port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported ATYP",
        )),
    }
}

async fn reply(stream: &mut TcpStream, rep: u8, bound: SocketAddr) -> io::Result<()> {
    let mut resp = vec![0x05, rep, 0x00];
    match bound.ip() {
        IpAddr::V4(addr) => {
            resp.push(0x01);
            resp.extend_from_slice(&addr.octets());
        }
        IpAddr::V6(addr) => {
            resp.push(0x04);
            resp.extend_from_slice(&addr.octets());
        }
    }
    resp.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&resp).await
}

fn build_tun2socks_config(config: &ProcessAwareTunConfig, socks: SocketAddr) -> String {
    let mut yaml = String::from("tunnel:\n");
    yaml.push_str(&format!("  name: {}\n", config.name));
    yaml.push_str(&format!("  mtu: {}\n", config.mtu));
    if let Some(ipv4) = config.ipv4 {
        yaml.push_str(&format!("  ipv4: {}\n", ipv4));
    }
    if let Some(ipv6) = config.ipv6 {
        yaml.push_str(&format!("  ipv6: {}\n", ipv6));
    }
    yaml.push_str("socks5:\n");
    yaml.push_str(&format!("  address: {}\n", socks.ip()));
    yaml.push_str(&format!("  port: {}\n", socks.port()));
    yaml.push_str("  udp: 'udp'\n");
    yaml
}

async fn handle_udp_associate(
    stream: &mut TcpStream,
    peer: SocketAddr,
    bridge: Arc<SocksBridge>,
) -> io::Result<()> {
    let udp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let bind_addr = udp_socket.local_addr()?;
    reply(stream, 0x00, bind_addr).await?;

    let socket = Arc::new(udp_socket);
    let manager = Arc::new(UdpSessionManager::new(
        socket.clone(),
        bridge.outbound.clone(),
        bridge.process_router.clone(),
        bridge.process_matcher.clone(),
        bridge.stats.clone(),
    ));

    tokio::spawn(manager.clone().inbound_loop());

    // Monitor the control TCP stream and teardown UDP sessions when it closes.
    // We duplicate the file descriptor to create an independent TcpStream for monitoring.
    let raw_fd = stream.as_raw_fd();
    unsafe {
        // Use libc::dup to duplicate the file descriptor
        let dup_fd = libc::dup(raw_fd);
        if dup_fd >= 0 {
            // Create a std::net::TcpStream from the duplicated fd
            let std_stream = std::net::TcpStream::from_raw_fd(dup_fd);
            // Set non-blocking mode for tokio compatibility
            if std_stream.set_nonblocking(true).is_ok() {
                // Convert to tokio TcpStream
                if let Ok(mut control) = TcpStream::from_std(std_stream) {
                    let manager = manager.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1];
                        loop {
                            match control.read(&mut buf).await {
                                Ok(0) | Err(_) => {
                                    manager.teardown().await;
                                    break;
                                }
                                Ok(_) => continue,
                            }
                        }
                    });
                }
            }
        }
    }

    info!(peer=?peer, bind=?bind_addr, "SOCKS UDP associate ready");
    Ok(())
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct UdpKey {
    client: SocketAddr,
    host: Host,
    port: u16,
}

struct UdpChannel {
    transport: Arc<dyn UdpTransport>,
    #[allow(dead_code)]
    endpoint: Endpoint,
}

struct UdpSessionManager {
    socket: Arc<UdpSocket>,
    outbound: Arc<dyn OutboundConnector>,
    process_router: Option<Arc<ProcessRouter>>,
    process_matcher: Option<Arc<ProcessMatcher>>,
    stats: Arc<ProcessAwareTunStatistics>,
    channels: RwLock<HashMap<UdpKey, Arc<UdpChannel>>>,
    #[allow(dead_code)]
    closed: Mutex<bool>,
}

impl UdpSessionManager {
    fn new(
        socket: Arc<UdpSocket>,
        outbound: Arc<dyn OutboundConnector>,
        process_router: Option<Arc<ProcessRouter>>,
        process_matcher: Option<Arc<ProcessMatcher>>,
        stats: Arc<ProcessAwareTunStatistics>,
    ) -> Self {
        Self {
            socket,
            outbound,
            process_router,
            process_matcher,
            stats,
            channels: RwLock::new(HashMap::new()),
            closed: Mutex::new(false),
        }
    }

    #[allow(dead_code)]
    async fn teardown(&self) {
        let mut closed = self.closed.lock().await;
        if !*closed {
            *closed = true;
        }
    }

    async fn inbound_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; 65535];
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    if let Err(err) = self.handle_datagram(&buf[..len], client_addr).await {
                        warn!(client=?client_addr, error=?err, "UDP datagram handling failed");
                    }
                }
                Err(err) => {
                    warn!(error=?err, "UDP socket receive failed");
                    break;
                }
            }
        }
    }

    async fn handle_datagram(&self, data: &[u8], client_addr: SocketAddr) -> io::Result<()> {
        if data.len() < 4 {
            return Ok(());
        }
        let frag = data[2];
        if frag != 0 {
            return Ok(());
        }

        let atyp = data[3];
        let mut idx = 4usize;
        let host = match atyp {
            0x01 => {
                if data.len() < idx + 4 {
                    return Ok(());
                }
                let ip = IpAddr::V4(Ipv4Addr::new(
                    data[idx],
                    data[idx + 1],
                    data[idx + 2],
                    data[idx + 3],
                ));
                idx += 4;
                Host::ip(ip)
            }
            0x04 => {
                if data.len() < idx + 16 {
                    return Ok(());
                }
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&data[idx..idx + 16]);
                idx += 16;
                Host::ip(IpAddr::V6(Ipv6Addr::from(bytes)))
            }
            0x03 => {
                if data.len() < idx + 1 {
                    return Ok(());
                }
                let len = data[idx] as usize;
                idx += 1;
                if data.len() < idx + len {
                    return Ok(());
                }
                let host_str = String::from_utf8(data[idx..idx + len].to_vec())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain"))?;
                idx += len;
                Host::domain(host_str)
            }
            _ => return Ok(()),
        };

        if data.len() < idx + 2 {
            return Ok(());
        }
        let port = u16::from_be_bytes([data[idx], data[idx + 1]]);
        idx += 2;
        let payload = &data[idx..];

        let endpoint = Endpoint::new(host.clone(), port);
        let key = UdpKey {
            client: client_addr,
            host,
            port,
        };

        let channel = {
            let guard = self.channels.read().await;
            guard.get(&key).cloned()
        };

        let channel = match channel {
            Some(ch) => ch,
            None => {
                drop(channel);
                let ch = self.establish_channel(&key, &endpoint, client_addr).await?;
                let mut guard = self.channels.write().await;
                guard.insert(key.clone(), ch.clone());
                ch
            }
        };

        channel
            .transport
            .send_to(payload, &endpoint)
            .await
            .map_err(|e| io::Error::other(format!("udp send failed: {e}")))?;
        self.stats.on_udp_packet();
        Ok(())
    }

    async fn establish_channel(
        &self,
        key: &UdpKey,
        endpoint: &Endpoint,
        client_addr: SocketAddr,
    ) -> io::Result<Arc<UdpChannel>> {
        let ctx = ConnCtx::new(
            self.stats.next_tcp_id(),
            Network::Udp,
            client_addr,
            endpoint.clone(),
        );
        let ctx = if let Some(matcher) = self.process_matcher.as_ref() {
            let remote = endpoint
                .to_socket_addr()
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), endpoint.port));
            let info = ConnectionInfo {
                local_addr: client_addr,
                remote_addr: remote,
                protocol: ProcessProtocol::Udp,
            };
            match matcher.match_connection(&info).await {
                Ok(proc_info) => {
                    let core_proc = sb_core::types::ProcessInfo::new(
                        proc_info.name,
                        proc_info.path,
                        proc_info.pid,
                    );
                    ctx.with_process_info(core_proc)
                }
                Err(_) => ctx,
            }
        } else {
            ctx
        };

        let transport = self
            .outbound
            .connect_udp(&ctx)
            .await
            .map_err(|e| io::Error::other(format!("udp connect failed: {e}")))?;
        let transport: Arc<dyn UdpTransport> = transport.into();

        if let Some(router) = self.process_router.as_ref() {
            let _ = router
                .decide_with_process(
                    match &endpoint.host {
                        Host::Name(name) => Some(name.as_ref()),
                        Host::Ip(_) => None,
                    },
                    endpoint.host.as_ip(),
                    true,
                    Some(endpoint.port),
                    client_addr,
                    endpoint.to_socket_addr().unwrap_or_else(|| {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), endpoint.port)
                    }),
                )
                .await;
        }

        let socket = self.socket.clone();
        let endpoint_clone = endpoint.clone();
        let transport_clone = transport.clone();
        let key_clone = key.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match transport_clone.recv_from(&mut buf).await {
                    Ok((size, addr)) => {
                        let packet = build_udp_response(&endpoint_clone, addr, &buf[..size]);
                        if socket.send_to(&packet, key_clone.client).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        warn!(error=?err, "UDP transport receive failed");
                        break;
                    }
                }
            }
        });

        Ok(Arc::new(UdpChannel {
            transport,
            endpoint: endpoint.clone(),
        }))
    }
}

fn build_udp_response(_ep: &Endpoint, addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(payload.len() + 32);
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);
    match addr.ip() {
        IpAddr::V4(ip) => {
            packet.push(0x01);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(0x04);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&addr.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}
