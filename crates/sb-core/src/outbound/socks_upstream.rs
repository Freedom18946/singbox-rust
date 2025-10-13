//! Async SOCKS5 upstream connector (scaffold). Supports optional username/password.
//! Warning: this is a minimal implementation intended for CI paths.
//! Production should come from sb-adapter.
use crate::adapter::OutboundConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
pub struct SocksUp {
    server: String,
    port: u16,
    user: Option<String>,
    pass: Option<String>,
}

impl SocksUp {
    pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {
        Self {
            server,
            port,
            user,
            pass,
        }
    }

    async fn handshake(
        &self,
        mut stream: TcpStream,
        host: &str,
        port: u16,
    ) -> std::io::Result<TcpStream> {
        // Greeting
        if self.user.is_some() {
            stream.write_all(&[0x05, 0x01, 0x02]).await?;
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
        }

        let mut rep = [0u8; 2];
        stream.read_exact(&mut rep).await?;
        if rep != [0x05, if self.user.is_some() { 0x02 } else { 0x00 }] {
            return Err(std::io::Error::other("socks method negotiation failed"));
        }

        // Authentication (username/password)
        if let (Some(u), Some(p)) = (self.user.as_ref(), self.pass.as_ref()) {
            if u.len() > 255 || p.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "credentials too long",
                ));
            }
            let mut pkt = vec![0x01, u.len() as u8];
            pkt.extend_from_slice(u.as_bytes());
            pkt.push(p.len() as u8);
            pkt.extend_from_slice(p.as_bytes());
            stream.write_all(&pkt).await?;

            let mut ar = [0u8; 2];
            stream.read_exact(&mut ar).await?;
            if ar != [0x01, 0x00] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "socks auth failed",
                ));
            }
        }

        // CONNECT request
        let mut req = vec![0x05, 0x01, 0x00];
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        } else if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ip6.octets());
        } else {
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await?;

        // Read response header
        let mut h = [0u8; 4];
        stream.read_exact(&mut h).await?;
        if h[1] != 0x00 {
            return Err(std::io::Error::other(format!(
                "socks connect failed: code={}",
                h[1]
            )));
        }

        // Skip bind address
        match h[3] {
            0x01 => {
                // IPv4
                let mut b = [0u8; 6];
                stream.read_exact(&mut b).await?;
            }
            0x03 => {
                // Domain
                let mut ln = [0u8; 1];
                stream.read_exact(&mut ln).await?;
                let mut dom = vec![0u8; ln[0] as usize + 2];
                stream.read_exact(&mut dom).await?;
            }
            0x04 => {
                // IPv6
                let mut b = [0u8; 18];
                stream.read_exact(&mut b).await?;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad atyp",
                ))
            }
        }

        Ok(stream)
    }
}

#[async_trait::async_trait]
impl OutboundConnector for SocksUp {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let stream = TcpStream::connect(&addr).await?;
        self.handshake(stream, host, port).await
    }
}
