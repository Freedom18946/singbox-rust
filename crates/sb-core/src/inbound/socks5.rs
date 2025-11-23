//! Async SOCKS5 server: no auth, CONNECT (TCP) and UDP ASSOCIATE (minimal).
//! feature = "scaffold"
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::adapter::{Bridge, InboundService};
use crate::log::{self, Level};

#[cfg(feature = "router")]
use crate::routing::engine::{Engine as RouterEngine, Input as RouterInput};

#[cfg(feature = "router")]
type EngineX<'a> = RouterEngine<'a>;
#[cfg(not(feature = "router"))]
type EngineX<'a> = Engine;

#[cfg(not(feature = "router"))]
#[derive(Debug)]
pub(crate) struct Engine {
    cfg: sb_config::ir::ConfigIR,
}

#[cfg(not(feature = "router"))]
struct Decision {
    outbound: String,
}

#[cfg(not(feature = "router"))]
impl Engine {
    fn new(cfg: sb_config::ir::ConfigIR) -> Self {
        Self { cfg }
    }

    fn decide(&self, _input: &Input, _fake_ip: bool) -> Decision {
        Decision {
            outbound: "direct".to_string(),
        }
    }
}

#[cfg(not(feature = "router"))]
impl Clone for Engine {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
        }
    }
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)]
struct Input {
    host: String,
    port: u16,
    network: String,
    protocol: String,
}

#[cfg(not(feature = "router"))]
impl Input {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            host: String::new(),
            port: 0,
            network: String::new(),
            protocol: String::new(),
        }
    }
}

pub(crate) async fn handle_conn(
    mut cli: TcpStream,
    eng: &EngineX<'static>,
    bridge: &Bridge,
    sniff_enabled: bool,
) -> std::io::Result<()> {
    // greeting
    let mut head = [0u8; 2];
    cli.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    cli.read_exact(&mut methods).await?;
    // only no-auth
    cli.write_all(&[0x05, 0x00]).await?;

    // request
    let mut reqh = [0u8; 4];
    cli.read_exact(&mut reqh).await?;
    if reqh[1] == 0x03 {
        // UDP ASSOCIATE
        #[cfg(feature = "metrics")]
        sb_metrics::inc_socks_udp_assoc();

        // Allocate a UDP relay socket bound on the same listen interface
        // Note: minimal implementation; NAT and multi-client isolation kept per-association
        let bind_ip = "0.0.0.0".to_string();
        let relay_sock = UdpSocket::bind((bind_ip.as_str(), 0)).await?;
        let relay_addr = relay_sock.local_addr()?;
        let relay = std::sync::Arc::new(relay_sock);

        // Reply success with bound address
        let mut resp = Vec::with_capacity(16);
        resp.extend_from_slice(&[0x05, 0x00, 0x00]); // VER, REP, RSV
        match relay_addr.ip() {
            std::net::IpAddr::V4(v4) => {
                resp.push(0x01); // ATYP IPv4
                resp.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                resp.push(0x04); // ATYP IPv6
                resp.extend_from_slice(&v6.octets());
            }
        }
        resp.extend_from_slice(&relay_addr.port().to_be_bytes());
        cli.write_all(&resp).await?;

        // NAT map for direct UDP fallback (TTL 60s, capacity 1024)
        let nat_ttl = std::time::Duration::from_secs(
            std::env::var("SOCKS_UDP_NAT_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        );
        let nat_cap = std::env::var("SOCKS_UDP_NAT_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);
        let nat = crate::net::udp_nat::NatMap::new(nat_ttl, nat_cap);
        // Evictor task
        let nat_ev = nat.clone();
        tokio::spawn(async move { nat_ev.run_evictor(std::time::Duration::from_secs(5)).await });
        // Best-effort gauge updater for UDP sessions (does not include TCP)
        let nat_metric = nat.clone();
        tokio::spawn(async move {
            loop {
                let len = nat_metric.len() as u64;
                crate::metrics::inbound::set_active_connections("socks", len);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        // Spawn UDP relay loop
        let eng = eng.clone();
        let br = bridge.clone();
        tokio::spawn(async move {
            // Track client endpoint (learned from first client datagram)
            let mut client_ep: Option<std::net::SocketAddr> = None;
            // A simple buffer reused for I/O
            let mut buf = vec![0u8; 64 * 1024];
            // Outbound UDP session created lazily on demand
            let mut udp_sess: Option<Arc<dyn crate::adapter::UdpOutboundSession>> = None;
            loop {
                let Ok((n, src)) = relay.recv_from(&mut buf).await else {
                    break;
                };

                let from_client = match client_ep {
                    None => {
                        // First packet source becomes client endpoint
                        client_ep = Some(src);
                        true
                    }
                    Some(ep) => ep == src,
                };

                if from_client {
                    // Parse SOCKS5 UDP request: RSV(2)=0, FRAG(1)=0, ATYP, DST.ADDR, DST.PORT, DATA
                    if n < 4 {
                        continue;
                    }
                    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
                        continue;
                    }
                    let mut p = 3usize;
                    let atyp = buf[p];
                    p += 1;
                    let dst_host = match atyp {
                        0x01 => {
                            // IPv4
                            if p + 4 > n {
                                continue;
                            }
                            let ip =
                                std::net::Ipv4Addr::new(buf[p], buf[p + 1], buf[p + 2], buf[p + 3]);
                            p += 4;
                            ip.to_string()
                        }
                        0x03 => {
                            // Domain
                            if p >= n {
                                continue;
                            }
                            let ln = buf[p] as usize;
                            p += 1;
                            if p + ln > n {
                                continue;
                            }
                            let s = std::str::from_utf8(&buf[p..p + ln])
                                .unwrap_or("")
                                .to_string();
                            p += ln;
                            s
                        }
                        0x04 => {
                            // IPv6
                            if p + 16 > n {
                                continue;
                            }
                            let mut o = [0u8; 16];
                            o.copy_from_slice(&buf[p..p + 16]);
                            p += 16;
                            std::net::Ipv6Addr::from(o).to_string()
                        }
                        _ => continue,
                    };
                    if p + 2 > n {
                        continue;
                    }
                    let dst_port = u16::from_be_bytes([buf[p], buf[p + 1]]);
                    p += 2;
                    if p > n {
                        continue;
                    }
                    let payload = &buf[p..n];

                    #[cfg(feature = "metrics")]
                    sb_metrics::inc_socks_udp_packet("out");

                    // Router decision for UDP (bind outbound at first packet)
                    #[cfg(feature = "router")]
                    let d = {
                        let input = RouterInput {
                            host: &dst_host,
                            port: dst_port,
                            network: "udp",
                            protocol: "socks",
                            sniff_host: None,
                            sniff_alpn: None,
                        };
                        eng.decide(&input, false)
                    };
                    #[cfg(not(feature = "router"))]
                    let d = {
                        let input = Input {
                            host: dst_host.clone(),
                            port: dst_port,
                            network: "udp".to_string(),
                            protocol: "socks".to_string(),
                        };
                        eng.decide(&input, false)
                    };
                    let out_name = d.outbound;

                    // Open UDP session once, if available for outbound
                    if udp_sess.is_none() {
                        if let Some(factory) = br.find_udp_factory(&out_name) {
                            match factory.open_session().await {
                                Ok(sess) => {
                                    // Spawn a receive loop for this session → client endpoint
                                    if let Some(ep) = client_ep {
                                        let relay_c = relay.clone();
                                        let sess_c = sess.clone();
                                        tokio::spawn(async move {
                                            loop {
                                                match sess_c.recv_from().await {
                                                    Ok((data, src_addr)) => {
                                                        // Wrap and forward to client
                                                        let mut pkt =
                                                            Vec::with_capacity(data.len() + 10);
                                                        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
                                                        match src_addr.ip() {
                                                            std::net::IpAddr::V4(v4) => {
                                                                pkt.push(0x01);
                                                                pkt.extend_from_slice(&v4.octets());
                                                            }
                                                            std::net::IpAddr::V6(v6) => {
                                                                pkt.push(0x04);
                                                                pkt.extend_from_slice(&v6.octets());
                                                            }
                                                        }
                                                        pkt.extend_from_slice(
                                                            &src_addr.port().to_be_bytes(),
                                                        );
                                                        pkt.extend_from_slice(&data);
                                                        let _ = relay_c.send_to(&pkt, ep).await;
                                                    }
                                                    Err(_) => break,
                                                }
                                            }
                                        });
                                    }
                                    udp_sess = Some(sess);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "open udp session failed for outbound '{}': {}",
                                        out_name,
                                        e
                                    );
                                }
                            }
                        }
                    }

                    if let Some(ref sess) = udp_sess {
                        let _ = sess.send_to(payload, &dst_host, dst_port).await;
                    } else {
                        // Direct UDP via NAT entry per (client, dst)
                        use crate::net::udp_nat::{NatKey, TargetAddr as Tgt};
                        let dst = if let Ok(ip) = dst_host.parse::<std::net::IpAddr>() {
                            Tgt::Ip(std::net::SocketAddr::from((ip, dst_port)))
                        } else {
                            Tgt::Domain(dst_host.clone(), dst_port)
                        };
                        let c = client_ep.unwrap_or(src);
                        let key = NatKey { client: c, dst };

                        let (upstream, newly) = nat
                            .get_or_insert_with_async(key.clone(), || {
                                let host = dst_host.clone();
                                async move {
                                    let sock = UdpSocket::bind("0.0.0.0:0")
                                        .await
                                        .map_err(std::io::Error::other)
                                        .unwrap();
                                    // Resolve
                                    let mut it = tokio::net::lookup_host((host.as_str(), dst_port))
                                        .await
                                        .ok()
                                        .into_iter()
                                        .flatten();
                                    let addr = it.next().unwrap_or_else(|| {
                                        std::net::SocketAddr::from(([0, 0, 0, 0], dst_port))
                                    });
                                    sock.connect(addr).await.ok();
                                    Arc::new(sock)
                                }
                            })
                            .await;

                        if newly {
                            // Spawn read-back loop
                            let relay_c = relay.clone();
                            let client_c = c;
                            let upstream_c = upstream.clone();
                            tokio::spawn(async move {
                                let mut rbuf = vec![0u8; 64 * 1024];
                                loop {
                                    match upstream_c.recv(&mut rbuf).await {
                                        Ok(m) => {
                                            // Use connected peer as source
                                            if let Ok(peer) = upstream_c.peer_addr() {
                                                let mut pkt = Vec::with_capacity(m + 10);
                                                pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
                                                match peer.ip() {
                                                    std::net::IpAddr::V4(v4) => {
                                                        pkt.push(0x01);
                                                        pkt.extend_from_slice(&v4.octets());
                                                    }
                                                    std::net::IpAddr::V6(v6) => {
                                                        pkt.push(0x04);
                                                        pkt.extend_from_slice(&v6.octets());
                                                    }
                                                }
                                                pkt.extend_from_slice(&peer.port().to_be_bytes());
                                                pkt.extend_from_slice(&rbuf[..m]);
                                                let _ = relay_c.send_to(&pkt, client_c).await;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });

                            // Update NAT size metric (best-effort)
                            #[cfg(feature = "metrics")]
                            sb_metrics::socks::set_udp_nat_size(nat.len());
                        }

                        let _ = upstream.send(payload).await;
                    }
                } else {
                    // From remote to client: wrap with SOCKS5 UDP header and forward
                    #[cfg(feature = "metrics")]
                    sb_metrics::inc_socks_udp_packet("in");

                    let mut pkt = Vec::with_capacity(n + 10);
                    pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
                    match src.ip() {
                        std::net::IpAddr::V4(v4) => {
                            pkt.push(0x01);
                            pkt.extend_from_slice(&v4.octets());
                        }
                        std::net::IpAddr::V6(v6) => {
                            pkt.push(0x04);
                            pkt.extend_from_slice(&v6.octets());
                        }
                    }
                    pkt.extend_from_slice(&src.port().to_be_bytes());
                    pkt.extend_from_slice(&buf[..n]);
                    if let Some(ep) = client_ep {
                        let _ = relay.send_to(&pkt, ep).await;
                    }
                }
            }
        });

        return Ok(());
    }
    if reqh[1] != 0x01 {
        // Only CONNECT and UDP ASSOCIATE supported minimally
        cli.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(std::io::Error::other("unsupported SOCKS5 command"));
    }

    let host = match reqh[3] {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            cli.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            // domain
            let mut ln = [0u8; 1];
            cli.read_exact(&mut ln).await?;
            let mut name = vec![0u8; ln[0] as usize];
            cli.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            cli.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad atyp",
            ))
        }
    };

    let mut p = [0u8; 2];
    cli.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    // SOCKS5 规范通常在成功连接目标后再回包；为嗅探 ALPN/SNI，这里采用“乐观回包→快速读取首包→建立上游→回放首包”的策略。
    // 1) 立即回包成功（bound addr 使用 0.0.0.0:0）
    cli.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // 2) 可选嗅探：快速读取客户端首包（不阻塞）
    let mut sniff_host_opt: Option<String> = None;
    let mut sniff_alpn_opt: Option<String> = None;
    let mut first_payload = Vec::new();
    if sniff_enabled {
        let mut buf = [0u8; 1024];
        if let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_millis(150), cli.read(&mut buf)).await
        {
            if n > 0 {
                first_payload.extend_from_slice(&buf[..n]);
                if let Some(info) = crate::routing::sniff::sniff_tls_client_hello(&first_payload) {
                    sniff_host_opt = info.sni;
                    sniff_alpn_opt = info.alpn;
                }
            }
        }
    }

    // 3) 路由决策（允许使用嗅探字段）
    #[cfg(feature = "router")]
    let d = {
        let sniff_host_ref = sniff_host_opt.as_deref();
        let sniff_alpn_ref = sniff_alpn_opt.as_deref();
        let input = RouterInput {
            host: &host,
            port,
            network: "tcp",
            protocol: "socks",
            sniff_host: sniff_host_ref,
            sniff_alpn: sniff_alpn_ref,
        };
        eng.decide(&input, false)
    };
    #[cfg(not(feature = "router"))]
    let d = {
        let input = Input {
            host: host.clone(),
            port,
            network: "tcp".to_string(),
            protocol: "socks".to_string(),
        };
        eng.decide(&input, false)
    };
    let out_name = d.outbound;
    let ob = bridge
        .find_outbound(&out_name)
        .or_else(|| bridge.find_direct_fallback());

    // 4) 连接上游并回放首包
    let mut upstream = match ob {
        Some(connector) => match connector.connect(&host, port).await {
            Ok(mut stream) => {
                if !first_payload.is_empty() {
                    let _ = stream.write_all(&first_payload).await;
                }
                stream
            }
            Err(e) => {
                return Err(std::io::Error::other(e));
            }
        },
        None => {
            return Err(std::io::Error::other("no outbound connector available"));
        }
    };

    // 5) 透传双向数据
    let _ = tokio::io::copy_bidirectional(&mut cli, &mut upstream).await;

    Ok(())
}

#[derive(Debug)]
pub struct Socks5 {
    listen: String,
    port: u16,
    #[cfg(feature = "router")]
    engine: Option<EngineX<'static>>,
    #[cfg(not(feature = "router"))]
    engine: Option<Engine>,
    bridge: Option<Arc<Bridge>>,
    sniff_enabled: bool,
    shutdown: Arc<AtomicBool>,
    active: Arc<AtomicU64>,
    udp_count: Arc<AtomicU64>,
}

impl Socks5 {
    pub fn new(listen: String, port: u16) -> Self {
        Self {
            listen,
            port,
            engine: None,
            bridge: None,
            sniff_enabled: false,
            shutdown: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicU64::new(0)),
            udp_count: Arc::new(AtomicU64::new(0)),
        }
    }

    #[cfg(feature = "router")]
    pub fn with_engine(mut self, eng: EngineX<'static>) -> Self {
        self.engine = Some(eng);
        self
    }

    #[cfg(not(feature = "router"))]
    #[allow(dead_code)]
    pub(crate) fn with_engine(mut self, eng: Engine) -> Self {
        self.engine = Some(eng);
        self
    }

    pub fn with_bridge(mut self, br: Arc<Bridge>) -> Self {
        self.bridge = Some(br);
        self
    }

    /// Enable/disable inbound sniff features (TLS SNI/ALPN)
    pub fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    async fn do_serve_async(&self, eng: EngineX<'static>, br: Arc<Bridge>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.listen, self.port);
        let listener = TcpListener::bind(&addr).await?;
        log::log(Level::Info, "socks5 listening (async)", &[("addr", &addr)]);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(1000), listener.accept()).await {
                Err(_) => continue,
                Ok(Err(e)) => {
                    log::log(Level::Warn, "accept failed", &[("err", &format!("{}", e))]);
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    continue;
                }
                Ok(Ok((socket, _))) => {
                    let active = self.active.clone();
                    active.fetch_add(1, Ordering::Relaxed);
                    // metrics: report updated active count
                    crate::metrics::inbound::set_active_connections(
                        "socks",
                        active.load(Ordering::Relaxed),
                    );
                    let eng_clone = eng.clone();
                    let br_clone = br.clone();
                    let sniff = self.sniff_enabled;
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(socket, &eng_clone, &br_clone, sniff).await {
                            tracing::debug!(target: "sb_core::inbound::socks5", error = %e, "connection handler failed");
                        }
                        active.fetch_sub(1, Ordering::Relaxed);
                        crate::metrics::inbound::set_active_connections(
                            "socks",
                            active.load(Ordering::Relaxed),
                        );
                    });
                }
            }
        }
        Ok(())
    }
}

impl InboundService for Socks5 {
    fn serve(&self) -> std::io::Result<()> {
        // 阻塞式入口，内部启动 tokio runtime
        #[cfg(not(feature = "router"))]
        let eng = {
            let cfg = sb_config::ir::ConfigIR::default();
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };

        #[cfg(feature = "router")]
        let eng = {
            // For router feature, use Box::leak for static lifetime
            let cfg = Box::leak(Box::new(sb_config::ir::ConfigIR::default()));
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };
        let br = self
            .bridge
            .clone()
            .unwrap_or_else(|| Arc::new(crate::adapter::Bridge::new()));

        // 使用当前 tokio runtime 或创建新的
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Already in a tokio runtime
                handle.block_on(self.do_serve_async(eng, br))
            }
            Err(_) => {
                // No tokio runtime, create one
                let runtime = tokio::runtime::Runtime::new().map_err(std::io::Error::other)?;
                runtime.block_on(self.do_serve_async(eng, br))
            }
        }
    }

    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    fn active_connections(&self) -> Option<u64> {
        Some(self.active.load(Ordering::Relaxed))
    }

    fn udp_sessions_estimate(&self) -> Option<u64> {
        Some(self.udp_count.load(Ordering::Relaxed))
    }
}

// UDP SOCKS5 utility functions (keep as-is, already async)

use std::net::SocketAddr;
use tokio::net::TcpStream as AsyncTcpStream;

/// Perform SOCKS5 greeting without authentication
pub async fn greet_noauth(stream: &mut AsyncTcpStream) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    // Send greeting response: no auth required
    stream.write_all(&[0x05, 0x00]).await?;
    Ok(())
}

/// Establish UDP association for SOCKS5
pub async fn udp_associate(
    stream: &mut AsyncTcpStream,
    bind_hint: Option<SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read UDP ASSOCIATE request
    let mut req = [0u8; 10];
    stream.read_exact(&mut req).await?;

    // For simplicity, return a dummy relay address
    let relay_addr = bind_hint.unwrap_or_else(|| {
        "127.0.0.1:8080"
            .parse()
            .expect("Default relay address should always be valid")
    });

    // Send successful response
    let mut response = vec![0x05, 0x00, 0x00, 0x01]; // Success, IPv4
    match relay_addr {
        SocketAddr::V4(addr) => {
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            response[3] = 0x04; // IPv6
            response.extend_from_slice(&addr.ip().octets());
            response.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    stream.write_all(&response).await?;
    Ok(relay_addr)
}

/// Encode UDP request packet for SOCKS5
pub fn encode_udp_request(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x00, 0x00, 0x00]; // Reserved, Fragment

    match dst {
        SocketAddr::V4(addr) => {
            packet.push(0x01); // IPv4
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            packet.push(0x04); // IPv6
            packet.extend_from_slice(&addr.ip().octets());
            packet.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    packet.extend_from_slice(payload);
    packet
}

/// Decode UDP reply packet from SOCKS5
pub fn decode_udp_reply(packet: &[u8]) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
    if packet.len() < 7 {
        return Err(anyhow::anyhow!("packet too short"));
    }

    // Skip reserved bytes (3 bytes)
    let atyp = packet[3];
    let mut offset = 4;

    let addr = match atyp {
        0x01 => {
            // IPv4
            if packet.len() < offset + 6 {
                return Err(anyhow::anyhow!("invalid IPv4 packet"));
            }
            let ip = std::net::Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            );
            offset += 4;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
            SocketAddr::from((ip, port))
        }
        0x04 => {
            // IPv6
            if packet.len() < offset + 18 {
                return Err(anyhow::anyhow!("invalid IPv6 packet"));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&packet[offset..offset + 16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            offset += 16;
            let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
            offset += 2;
            SocketAddr::from((ip, port))
        }
        _ => {
            return Err(anyhow::anyhow!("unsupported address type"));
        }
    };

    let payload = packet[offset..].to_vec();
    Ok((addr, payload))
}
