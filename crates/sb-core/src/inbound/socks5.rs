//! Async SOCKS5 server: no auth, CONNECT only, TCP only.
//! feature = "scaffold"
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

async fn handle_conn(
    mut cli: TcpStream,
    eng: &EngineX<'_>,
    bridge: &Bridge,
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
    if reqh[1] != 0x01 {
        // CONNECT only
        cli.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(std::io::Error::other("only CONNECT supported"));
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

    // 路由决策（默认 direct） → 解析命名出站
    #[cfg(feature = "router")]
    let d = {
        let input = RouterInput {
            host: &host,
            port,
            network: "tcp",
            protocol: "socks",
            sniff_host: None,
            sniff_alpn: None,
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

    // 连接上游（异步）
    let mut upstream = match ob {
        Some(connector) => match connector.connect(&host, port).await {
            Ok(stream) => stream,
            Err(e) => {
                let _ = cli
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(e);
            }
        },
        None => {
            let _ = cli
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(std::io::Error::other("no outbound connector available"));
        }
    };

    // 成功回包（bound addr 使用 0.0.0.0:0）
    cli.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // 使用 tokio 的高性能双向复制
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
}

impl Socks5 {
    pub fn new(listen: String, port: u16) -> Self {
        Self {
            listen,
            port,
            engine: None,
            bridge: None,
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

    async fn do_serve_async(&self, eng: EngineX<'static>, br: Arc<Bridge>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.listen, self.port);
        let listener = TcpListener::bind(&addr).await?;
        log::log(Level::Info, "socks5 listening (async)", &[("addr", &addr)]);

        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    let eng_clone = eng.clone();
                    let br_clone = br.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(socket, &eng_clone, &br_clone).await {
                            tracing::debug!(target: "sb_core::inbound::socks5", error = %e, "connection handler failed");
                        }
                    });
                }
                Err(e) => {
                    log::log(Level::Warn, "accept failed", &[("err", &format!("{}", e))]);
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                }
            }
        }
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
                let runtime = tokio::runtime::Runtime::new()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                runtime.block_on(self.do_serve_async(eng, br))
            }
        }
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
