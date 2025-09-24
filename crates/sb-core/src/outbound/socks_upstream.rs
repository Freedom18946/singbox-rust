//! SOCKS5 upstream connector (scaffold). Supports optional username/password.
//! Warning: this is a blocking, minimal implementation intended for CI paths.
//! Production should come from sb-adapter.
#![allow(clippy::manual_split_once)]
use crate::adapter::OutboundConnector;
use crate::transport::tcp::TcpDialer;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub struct SocksUp {
    server: String,
    port: u16,
    user: Option<String>,
    pass: Option<String>,
    dial: TcpDialer,
}

impl SocksUp {
    pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {
        Self {
            server,
            port,
            user,
            pass,
            dial: TcpDialer::default(),
        }
    }
    fn read_exact(s: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
        let mut o = 0usize;
        while o < buf.len() {
            let n = s.read(&mut buf[o..])?;
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            o += n;
        }
        Ok(())
    }
    fn handshake(&self, mut s: TcpStream, host: &str, port: u16) -> std::io::Result<TcpStream> {
        // greeting
        if self.user.is_some() {
            s.write_all(&[0x05, 0x01, 0x02])?;
        } else {
            s.write_all(&[0x05, 0x01, 0x00])?;
        }
        let mut rep = [0u8; 2];
        Self::read_exact(&mut s, &mut rep)?;
        if rep != [0x05, if self.user.is_some() { 0x02 } else { 0x00 }] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "socks method negot fail",
            ));
        }
        // auth (username/password)
        if let (Some(u), Some(p)) = (self.user.as_ref(), self.pass.as_ref()) {
            if u.len() > 255 || p.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "cred too long",
                ));
            }
            let mut pkt = vec![0x01, u.len() as u8];
            pkt.extend_from_slice(u.as_bytes());
            pkt.push(p.len() as u8);
            pkt.extend_from_slice(p.as_bytes());
            s.write_all(&pkt)?;
            let mut ar = [0u8; 2];
            Self::read_exact(&mut s, &mut ar)?;
            if ar != [0x01, 0x00] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "socks auth fail",
                ));
            }
        }
        // connect
        let mut req = vec![0x05, 0x01, 0x00];
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            req.push(0x01);
            req.extend_from_slice(&ip.octets());
        } else if let Ok(ip6) = host.parse::<std::net::Ipv6Addr>() {
            req.push(0x04);
            req.extend_from_slice(&ip6.octets());
        } else {
            req.push(0x03);
            req.push(host.as_bytes().len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req)?;
        let mut h = [0u8; 4];
        Self::read_exact(&mut s, &mut h)?;
        if h[1] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("socks connect fail code={}", h[1]),
            ));
        }
        // skip bind addr
        match h[3] {
            0x01 => {
                let mut b = [0u8; 6];
                Self::read_exact(&mut s, &mut b)?;
            }
            0x03 => {
                let mut ln = [0u8; 1];
                Self::read_exact(&mut s, &mut ln)?;
                let mut dom = vec![0u8; ln[0] as usize + 2];
                Self::read_exact(&mut s, &mut dom)?;
            }
            0x04 => {
                let mut b = [0u8; 18];
                Self::read_exact(&mut s, &mut b)?;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad atyp",
                ))
            }
        }
        Ok(s)
    }
}

impl OutboundConnector for SocksUp {
    fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let s = self.dial.dial(&addr).stream.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "dial socks upstream fail")
        })?;
        self.handshake(s, host, port)
    }
}
