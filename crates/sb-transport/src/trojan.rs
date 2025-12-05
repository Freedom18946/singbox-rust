//! Trojan Transport Implementation
//!
//! Provides the Trojan protocol transport layer for proxying traffic.
//! Trojan disguises proxy traffic as HTTPS traffic.
//!
//! ## Protocol Format
//!
//! ```text
//! +-----------------------+
//! | hex(SHA224(password)) |  56 bytes
//! +-----------------------+
//! | CRLF                  |  2 bytes
//! +-----------------------+
//! | Command               |  1 byte (0x01=CONNECT, 0x03=UDP)
//! +-----------------------+
//! | Address Type          |  1 byte
//! +-----------------------+
//! | Address               |  Variable
//! +-----------------------+
//! | Port                  |  2 bytes
//! +-----------------------+
//! | CRLF                  |  2 bytes
//! +-----------------------+
//! | Payload               |  Variable
//! +-----------------------+
//! ```
//!
//! ## References
//! - https://trojan-gfw.github.io/trojan/protocol

use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha224};
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Trojan command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrojanCommand {
    /// TCP connect
    Connect = 0x01,
    /// UDP associate
    UdpAssociate = 0x03,
}

/// Address types for Trojan protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrojanAddrType {
    /// IPv4 address
    IPv4 = 0x01,
    /// Domain name
    Domain = 0x03,
    /// IPv6 address
    IPv6 = 0x04,
}

/// Trojan address representation
#[derive(Debug, Clone)]
pub enum TrojanAddr {
    /// IPv4 socket address
    V4(std::net::SocketAddrV4),
    /// IPv6 socket address
    V6(std::net::SocketAddrV6),
    /// Domain name with port
    Domain(String, u16),
}

impl TrojanAddr {
    /// Create from socket address
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4(v4),
            SocketAddr::V6(v6) => Self::V6(v6),
        }
    }

    /// Create from domain and port
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self::Domain(domain.into(), port)
    }

    /// Get port
    pub fn port(&self) -> u16 {
        match self {
            Self::V4(addr) => addr.port(),
            Self::V6(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    /// Encode address to bytes
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(64);
        match self {
            Self::V4(addr) => {
                buf.put_u8(TrojanAddrType::IPv4 as u8);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::V6(addr) => {
                buf.put_u8(TrojanAddrType::IPv6 as u8);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::Domain(domain, port) => {
                let domain_bytes = domain.as_bytes();
                buf.put_u8(TrojanAddrType::Domain as u8);
                buf.put_u8(domain_bytes.len() as u8);
                buf.put_slice(domain_bytes);
                buf.put_u16(*port);
            }
        }
        buf.freeze()
    }
}

/// Trojan protocol configuration
#[derive(Debug, Clone)]
pub struct TrojanConfig {
    /// Password (will be hashed with SHA224)
    pub password: String,
    /// Target address
    pub target: TrojanAddr,
    /// Command type (default: Connect)
    pub command: TrojanCommand,
}

impl TrojanConfig {
    /// Create new Trojan config for TCP connect
    pub fn new(password: impl Into<String>, target: TrojanAddr) -> Self {
        Self {
            password: password.into(),
            target,
            command: TrojanCommand::Connect,
        }
    }

    /// Set command type
    pub fn with_command(mut self, cmd: TrojanCommand) -> Self {
        self.command = cmd;
        self
    }

    /// Hash password using SHA224 and return hex string
    pub fn hash_password(&self) -> String {
        let mut hasher = Sha224::new();
        hasher.update(self.password.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Build the Trojan request header
    pub fn build_header(&self) -> Bytes {
        let hash = self.hash_password();
        let addr_bytes = self.target.encode();

        let mut buf = BytesMut::with_capacity(64 + addr_bytes.len());
        
        // Password hash (56 bytes hex)
        buf.put_slice(hash.as_bytes());
        
        // CRLF
        buf.put_slice(b"\r\n");
        
        // Command
        buf.put_u8(self.command as u8);
        
        // Address
        buf.put_slice(&addr_bytes);
        
        // CRLF
        buf.put_slice(b"\r\n");

        buf.freeze()
    }
}

/// Trojan stream wrapper
pub struct TrojanStream<S> {
    inner: S,
    config: TrojanConfig,
    header_sent: bool,
    read_buffer: BytesMut,
}

impl<S> TrojanStream<S> {
    /// Create a new Trojan stream wrapper
    pub fn new(inner: S, config: TrojanConfig) -> Self {
        Self {
            inner,
            config,
            header_sent: false,
            read_buffer: BytesMut::with_capacity(4096),
        }
    }

    /// Get reference to inner stream
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Get mutable reference to inner stream
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume and return inner stream
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Get the target address
    pub fn target(&self) -> &TrojanAddr {
        &self.config.target
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrojanStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Simple pass-through after handshake
        // Trojan has no response header to parse
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrojanStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        
        if !this.header_sent {
            // Build and send header with first payload
            let header = this.config.build_header();
            let mut full_buf = BytesMut::with_capacity(header.len() + buf.len());
            full_buf.put_slice(&header);
            full_buf.put_slice(buf);
            
            match Pin::new(&mut this.inner).poll_write(cx, &full_buf) {
                Poll::Ready(Ok(n)) => {
                    if n >= header.len() {
                        this.header_sent = true;
                        // Return payload bytes written
                        Poll::Ready(Ok(n - header.len()))
                    } else {
                        // Partial header write, need to retry
                        Poll::Ready(Err(io::Error::new(
                            ErrorKind::WriteZero,
                            "failed to write complete Trojan header",
                        )))
                    }
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            // Direct pass-through after header
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Trojan UDP packet format
#[derive(Debug, Clone)]
pub struct TrojanUdpPacket {
    /// Target address
    pub addr: TrojanAddr,
    /// Payload data
    pub data: Bytes,
}

impl TrojanUdpPacket {
    /// Create a new UDP packet
    pub fn new(addr: TrojanAddr, data: impl Into<Bytes>) -> Self {
        Self {
            addr,
            data: data.into(),
        }
    }

    /// Encode packet for transmission
    pub fn encode(&self) -> Bytes {
        let addr_bytes = self.addr.encode();
        let mut buf = BytesMut::with_capacity(addr_bytes.len() + 2 + 2 + self.data.len());
        
        // Address
        buf.put_slice(&addr_bytes);
        
        // Length + CRLF
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(b"\r\n");
        
        // Payload
        buf.put_slice(&self.data);
        
        buf.freeze()
    }

    /// Decode packet from buffer
    pub fn decode(buf: &mut BytesMut) -> io::Result<Option<Self>> {
        if buf.is_empty() {
            return Ok(None);
        }

        let addr_type = buf[0];
        let addr_len = match addr_type {
            0x01 => 1 + 4 + 2,  // type + ipv4 + port
            0x04 => 1 + 16 + 2, // type + ipv6 + port
            0x03 => {
                if buf.len() < 2 {
                    return Ok(None);
                }
                1 + 1 + (buf[1] as usize) + 2 // type + len + domain + port
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("unknown address type: {}", addr_type),
                ));
            }
        };

        if buf.len() < addr_len + 4 {
            // Need address + length(2) + crlf(2)
            return Ok(None);
        }

        // Parse address
        let addr = match addr_type {
            0x01 => {
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                let port = ((buf[5] as u16) << 8) | (buf[6] as u16);
                TrojanAddr::V4(std::net::SocketAddrV4::new(ip, port))
            }
            0x04 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = ((buf[17] as u16) << 8) | (buf[18] as u16);
                TrojanAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0))
            }
            0x03 => {
                let domain_len = buf[1] as usize;
                let domain = String::from_utf8_lossy(&buf[2..2 + domain_len]).to_string();
                let port_offset = 2 + domain_len;
                let port = ((buf[port_offset] as u16) << 8) | (buf[port_offset + 1] as u16);
                TrojanAddr::Domain(domain, port)
            }
            _ => unreachable!(),
        };

        // Get payload length
        let len_offset = addr_len;
        let payload_len = ((buf[len_offset] as usize) << 8) | (buf[len_offset + 1] as usize);
        
        // Check for CRLF
        if buf.len() < len_offset + 2 + 2 + payload_len {
            return Ok(None);
        }
        
        // Skip to payload
        let payload_offset = len_offset + 4; // length(2) + crlf(2)
        let _ = buf.split_to(payload_offset);
        let data = buf.split_to(payload_len).freeze();

        Ok(Some(Self { addr, data }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash() {
        let config = TrojanConfig::new(
            "test_password",
            TrojanAddr::from_domain("example.com", 443),
        );
        
        let hash = config.hash_password();
        assert_eq!(hash.len(), 56); // SHA224 produces 28 bytes = 56 hex chars
    }

    #[test]
    fn test_header_build() {
        let config = TrojanConfig::new(
            "test",
            TrojanAddr::V4("192.168.1.1:443".parse().unwrap()),
        );
        
        let header = config.build_header();
        
        // 56 (hash) + 2 (crlf) + 1 (cmd) + 7 (addr) + 2 (crlf) = 68
        assert_eq!(header.len(), 68);
        
        // Check CRLF positions
        assert_eq!(&header[56..58], b"\r\n");
        assert_eq!(&header[66..68], b"\r\n");
        
        // Check command
        assert_eq!(header[58], TrojanCommand::Connect as u8);
    }

    #[test]
    fn test_addr_encode_ipv4() {
        let addr = TrojanAddr::V4("192.168.1.1:443".parse().unwrap());
        let encoded = addr.encode();
        
        assert_eq!(encoded[0], TrojanAddrType::IPv4 as u8);
        assert_eq!(&encoded[1..5], &[192, 168, 1, 1]);
        assert_eq!(&encoded[5..7], &[0x01, 0xbb]); // 443 in big-endian
    }

    #[test]
    fn test_addr_encode_domain() {
        let addr = TrojanAddr::from_domain("example.com", 80);
        let encoded = addr.encode();
        
        assert_eq!(encoded[0], TrojanAddrType::Domain as u8);
        assert_eq!(encoded[1], 11); // "example.com".len()
        assert_eq!(&encoded[2..13], b"example.com");
    }

    #[test]
    fn test_udp_packet_encode_decode() {
        let packet = TrojanUdpPacket::new(
            TrojanAddr::V4("1.2.3.4:8080".parse().unwrap()),
            Bytes::from("hello"),
        );
        
        let encoded = packet.encode();
        let mut buf = BytesMut::from(&encoded[..]);
        
        let decoded = TrojanUdpPacket::decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.data, Bytes::from("hello"));
    }
}
