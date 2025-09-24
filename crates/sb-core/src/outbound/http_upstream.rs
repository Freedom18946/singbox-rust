//! HTTP CONNECT upstream connector (scaffold). Optional Basic auth.
//! Warning: this is a blocking, minimal implementation intended for CI paths.
//! Production should come from sb-adapter.
#![allow(clippy::manual_split_once)]
use crate::adapter::OutboundConnector;
use crate::transport::tcp::TcpDialer;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub struct HttpUp {
    server: String,
    port: u16,
    user: Option<String>,
    pass: Option<String>,
    dial: TcpDialer,
}

impl HttpUp {
    pub fn new(server: String, port: u16, user: Option<String>, pass: Option<String>) -> Self {
        Self {
            server,
            port,
            user,
            pass,
            dial: TcpDialer::default(),
        }
    }
    fn read_line(s: &mut TcpStream) -> std::io::Result<String> {
        let mut buf = Vec::with_capacity(128);
        let mut b = [0u8; 1];
        let mut last_cr = false;
        loop {
            let n = s.read(&mut b)?;
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            buf.push(b[0]);
            if last_cr && b[0] == b'\n' {
                break;
            }
            last_cr = b[0] == b'\r';
            if buf.len() > 8192 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "line too long",
                ));
            }
        }
        Ok(String::from_utf8_lossy(&buf).trim().to_string())
    }
}

impl OutboundConnector for HttpUp {
    fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let addr = format!("{}:{}", self.server, self.port);
        let mut s = self.dial.dial(&addr).stream.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "dial http upstream fail")
        })?;
        // CONNECT
        let mut req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
            host, port, host, port
        );
        if let (Some(u), Some(p)) = (self.user.as_ref(), self.pass.as_ref()) {
            use base64::Engine as _;
            let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", u, p));
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", token));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes())?;
        // 读取状态行与头（忽略头体）
        let line = Self::read_line(&mut s)?;
        let ok = line.starts_with("HTTP/1.1 200") || line.starts_with("HTTP/1.0 200");
        // 丢弃剩余头
        loop {
            let l = Self::read_line(&mut s)?;
            if l.is_empty() {
                break;
            }
        }
        if !ok {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("http upstream not 200: {}", line),
            ));
        }
        Ok(s)
    }
}
