//! Minimal SOCKS5 helpers (RFC1928) for greeting, UDP ASSOC, and UDP datagram encode.
//! No auth; good enough for controlled env. Keep it *boringly correct*.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Client greeting: version=5, methods=[no-auth]
pub async fn greet_noauth(stream: &mut TcpStream) -> anyhow::Result<()> {
    // VER=5, NMETHODS=1, METHODS=0x00(no-auth)
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp != [0x05, 0x00] {
        return Err(anyhow::anyhow!("socks5: server rejected no-auth"));
    }
    Ok(())
}

/// UDP ASSOCIATE, returns the UDP relay endpoint (BND.ADDR/BND.PORT).
pub async fn udp_associate(stream: &mut TcpStream, bind: SocketAddr) -> anyhow::Result<SocketAddr> {
    // VER=5, CMD=3(UDP ASSOC), RSV=0, ATYP/ADDR/PORT = client bind (hint; many servers ignore and return their addr)
    let mut req = vec![0x05, 0x03, 0x00];
    match bind.ip() {
        IpAddr::V4(ip) => {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            req.push(0x04);
            req.extend_from_slice(&ip.octets());
        }
    }
    req.extend_from_slice(&bind.port().to_be_bytes());
    stream.write_all(&req).await?;

    // Response: VER=5, REP=0x00 success, RSV, ATYP, BND.ADDR, BND.PORT
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(anyhow::anyhow!("socks5: bad VER"));
    }
    if head[1] != 0x00 {
        return Err(anyhow::anyhow!("socks5: UDP ASSOC fail REP={}", head[1]));
    }
    let atyp = head[3];
    let bnd = match atyp {
        0x01 => {
            // IPv4
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), u16::from_be_bytes(p))
        }
        0x04 => {
            // IPv6
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), u16::from_be_bytes(p))
        }
        0x03 => {
            // Domain in reply is rare; optionally resolve via system resolver.
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            stream.read_exact(&mut d).await?;
            let mut p = [0u8; 2];
            stream.read_exact(&mut p).await?;
            let dom = String::from_utf8_lossy(&d).to_string();
            let port = u16::from_be_bytes(p);
            let enable = std::env::var("SB_SOCKS_UDP_RESOLVE_BND")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if enable {
                if let Ok(mut it) = tokio::net::lookup_host(format!("{dom}:{port}")).await {
                    if let Some(sa) = it.next() {
                        sa
                    } else {
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                    }
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
                }
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            }
        }
        _ => return Err(anyhow::anyhow!("socks5: bad ATYP in reply")),
    };
    Ok(bnd)
}

/// Encode a UDP REQUEST datagram header + payload as per RFC1928 section 7.
pub fn encode_udp_request(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    // RSV(2)=0x0000, FRAG=0x00, ATYP, DST.ADDR, DST.PORT, DATA
    let mut out = Vec::with_capacity(3 + 1 + 18 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]);
    match dst.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&dst.port().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decode a UDP REPLY datagram (RFC1928 §7). Returns (dst, payload).
/// FRAG must be 0 (we don't support fragmentation).
pub fn decode_udp_reply<'a>(buf: &'a [u8]) -> anyhow::Result<(SocketAddr, &'a [u8])> {
    if buf.len() < 3 {
        return Err(anyhow::anyhow!("socks5: short reply header"));
    }
    // RSV(2), FRAG(1)
    if buf[0] != 0 || buf[1] != 0 {
        return Err(anyhow::anyhow!("socks5: bad RSV"));
    }
    if buf[2] != 0 {
        return Err(anyhow::anyhow!("socks5: FRAG unsupported"));
    }
    let mut i = 3usize;
    if i >= buf.len() {
        return Err(anyhow::anyhow!("socks5: truncated"));
    }
    let atyp = buf[i];
    i += 1;
    let dst = match atyp {
        0x01 => {
            // IPv4
            if i + 4 + 2 > buf.len() {
                return Err(anyhow::anyhow!("socks5: v4 overrun"));
            }
            let mut a = [0u8; 4];
            a.copy_from_slice(&buf[i..i + 4]);
            i += 4;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(a)), port)
        }
        0x04 => {
            // IPv6
            if i + 16 + 2 > buf.len() {
                return Err(anyhow::anyhow!("socks5: v6 overrun"));
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&buf[i..i + 16]);
            i += 16;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port)
        }
        0x03 => {
            // DOMAIN (rare in replies, treat as error)
            if i >= buf.len() {
                return Err(anyhow::anyhow!("socks5: dom len overrun"));
            }
            let l = buf[i] as usize;
            i += 1;
            if i + l + 2 > buf.len() {
                return Err(anyhow::anyhow!("socks5: dom overrun"));
            }
            // We ignore domain in reply and just skip it.
            i += l;
            let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
            i += 2;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        }
        _ => return Err(anyhow::anyhow!("socks5: bad ATYP")),
    };
    if i > buf.len() {
        return Err(anyhow::anyhow!("socks5: payload underflow"));
    }
    Ok((dst, &buf[i..]))
}
