//! Minimal blocking SOCKS5 server: no auth, CONNECT only, TCP only.
//! feature = "scaffold"
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use crate::adapter::{Bridge, InboundService};
use crate::log::{self, Level};
use crate::routing::engine::{Engine, Input};

fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = s.read(&mut buf[off..])?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        off += n;
    }
    Ok(())
}

fn copy_bidi(a: TcpStream, b: TcpStream) {
    let (mut ra, mut wa) = (a.try_clone().unwrap(), a);
    let (mut rb, mut wb) = (b.try_clone().unwrap(), b);
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut ra, &mut wb);
        let _ = wb.shutdown(Shutdown::Write);
    });
    let t2 = thread::spawn(move || {
        let _ = std::io::copy(&mut rb, &mut wa);
        let _ = wa.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
}

fn handle_conn(mut cli: TcpStream, eng: &Engine, bridge: &Bridge) -> std::io::Result<()> {
    // greeting
    let mut head = [0u8; 2];
    read_exact(&mut cli, &mut head)?;
    if head[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not socks5",
        ));
    }
    let n_methods = head[1] as usize;
    let mut methods = vec![0u8; n_methods];
    read_exact(&mut cli, &mut methods)?;
    // only no-auth
    cli.write_all(&[0x05, 0x00])?;
    // request
    let mut reqh = [0u8; 4];
    read_exact(&mut cli, &mut reqh)?;
    if reqh[1] != 0x01 {
        // CONNECT only
        cli.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "only CONNECT supported",
        ));
    }
    let host = match reqh[3] {
        0x01 => {
            // IPv4
            let mut ip = [0u8; 4];
            read_exact(&mut cli, &mut ip)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            // domain
            let mut ln = [0u8; 1];
            read_exact(&mut cli, &mut ln)?;
            let mut name = vec![0u8; ln[0] as usize];
            read_exact(&mut cli, &mut name)?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => {
            // IPv6
            let mut ip = [0u8; 16];
            read_exact(&mut cli, &mut ip)?;
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
    read_exact(&mut cli, &mut p)?;
    let port = u16::from_be_bytes(p);

    // 路由决策（默认 direct） → 解析命名出站
    let d = eng.decide(
        &Input {
            host: &host,
            port,
            network: "tcp",
            protocol: "socks",
        },
        false,
    );
    let out_name = d.outbound;
    let ob = bridge
        .find_outbound(&out_name)
        .or_else(|| bridge.find_direct_fallback());

    // 连接上游（按命名出站；仍保留兜底报错）
    match ob.as_ref().map(|x| x.connect(&host, port)).transpose() {
        Ok(up) => {
            // 成功回包（bound addr 使用 0.0.0.0:0）
            let rep = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            cli.write_all(&rep)?;
            copy_bidi(cli, up.unwrap());
            Ok(())
        }
        Err(e) => {
            let _ = cli.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]); // general failure
            Err(e)
        }
    }
}

#[derive(Debug)]
pub struct Socks5 {
    listen: String,
    port: u16,
    engine: Option<Engine<'static>>,
    bridge: Option<std::sync::Arc<Bridge>>,
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
    pub fn with_engine(mut self, eng: Engine<'static>) -> Self {
        self.engine = Some(eng);
        self
    }
    pub fn with_bridge(mut self, br: std::sync::Arc<Bridge>) -> Self {
        self.bridge = Some(br);
        self
    }

    fn do_serve(&self, eng: Engine, br: std::sync::Arc<Bridge>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.listen, self.port);
        let l = TcpListener::bind(&addr)?;
        log::log(Level::Info, "socks5 listening", &[("addr", &addr)]);
        for c in l.incoming() {
            match c {
                Ok(s) => {
                    let eng_owned = Engine::new(Box::leak(Box::new(eng.cfg.clone())));
                    let brc = br.clone();
                    std::thread::spawn(move || {
                        let _ = handle_conn(s, &eng_owned, &brc);
                    });
                }
                Err(e) => {
                    log::log(Level::Warn, "accept failed", &[("err", &format!("{}", e))]);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
        Ok(())
    }
}

impl InboundService for Socks5 {
    fn serve(&self) -> std::io::Result<()> {
        // 安全起见，这里若 self.engine/bridge 缺失，构造兜底实例
        let cfg = sb_config::ir::ConfigIR::default();
        let eng = self.engine.clone().unwrap_or_else(|| Engine::new(&cfg));
        let br = self
            .bridge
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(crate::adapter::Bridge::new()));
        self.do_serve(eng, br)
    }
}

// UDP SOCKS5 utility functions

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
    let relay_addr = bind_hint.unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap());

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
