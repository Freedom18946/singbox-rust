//! UDP over TCP (UoT) protocol implementation
//!
//! Provides a mechanism to tunnel UDP packets over a TCP connection.
//! Compatible with sing-box's UDP over TCP protocol.
//!
//! ## Protocol Format
//!
//! Each UDP packet is prefixed with a length header:
//! ```text
//! +--------+--------+----------------+
//! | Length (2 bytes, big-endian)    |
//! +--------+--------+----------------+
//! | UDP Payload (Length bytes)      |
//! +----------------------------------+
//! ```
//!
//! ## Version Support
//! - v1: Simple length prefix (2 bytes)
//! - v2: Extended header with address info (sing-box compatible)

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum UDP packet size (64KB - header overhead)
pub const MAX_UDP_PACKET_SIZE: usize = 65507;

/// UoT protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UotVersion {
    /// Version 1: Simple 2-byte length prefix
    #[default]
    V1,
    /// Version 2: Extended with address header (sing-box compatible)
    V2,
}

/// Address type for UoT v2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    /// IPv4 address (4 bytes)
    IPv4 = 0x01,
    /// Domain name (1-byte length + domain)
    Domain = 0x03,
    /// IPv6 address (16 bytes)
    IPv6 = 0x04,
}

/// UDP packet with destination address (for UoT v2)
#[derive(Debug, Clone)]
pub struct UdpPacket {
    /// Target address
    pub addr: SocketAddr,
    /// Payload data
    pub data: Bytes,
}

impl UdpPacket {
    /// Create a new UDP packet
    pub fn new(addr: SocketAddr, data: impl Into<Bytes>) -> Self {
        Self {
            addr,
            data: data.into(),
        }
    }
}

/// UDP over TCP stream wrapper
pub struct UotStream<S> {
    inner: S,
    version: UotVersion,
    read_buffer: BytesMut,
    pending_packet: Option<Bytes>,
}

impl<S> UotStream<S> {
    /// Create a new UoT stream with specified version
    pub fn new(inner: S, version: UotVersion) -> Self {
        Self {
            inner,
            version,
            read_buffer: BytesMut::with_capacity(MAX_UDP_PACKET_SIZE + 2),
            pending_packet: None,
        }
    }

    /// Create a new UoT v1 stream
    pub fn v1(inner: S) -> Self {
        Self::new(inner, UotVersion::V1)
    }

    /// Create a new UoT v2 stream
    pub fn v2(inner: S) -> Self {
        Self::new(inner, UotVersion::V2)
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

    /// Get the protocol version
    pub fn version(&self) -> UotVersion {
        self.version
    }
}

/// Encode a UDP packet with length prefix (v1)
pub fn encode_packet_v1(data: &[u8]) -> io::Result<Bytes> {
    if data.len() > MAX_UDP_PACKET_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "UDP packet too large",
        ));
    }

    let mut buf = BytesMut::with_capacity(2 + data.len());
    buf.put_u16(data.len() as u16);
    buf.put_slice(data);
    Ok(buf.freeze())
}

/// Encode a UDP packet with address header (v2)
pub fn encode_packet_v2(packet: &UdpPacket) -> io::Result<Bytes> {
    if packet.data.len() > MAX_UDP_PACKET_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "UDP packet too large",
        ));
    }

    let mut buf = BytesMut::with_capacity(32 + packet.data.len());

    // Address encoding
    match packet.addr {
        SocketAddr::V4(addr) => {
            buf.put_u8(AddressType::IPv4 as u8);
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
        SocketAddr::V6(addr) => {
            buf.put_u8(AddressType::IPv6 as u8);
            buf.put_slice(&addr.ip().octets());
            buf.put_u16(addr.port());
        }
    }

    // Length + data
    buf.put_u16(packet.data.len() as u16);
    buf.put_slice(&packet.data);

    Ok(buf.freeze())
}

/// Decode a UDP packet from length-prefixed data (v1)
pub fn decode_packet_v1(buf: &mut BytesMut) -> io::Result<Option<Bytes>> {
    if buf.len() < 2 {
        return Ok(None);
    }

    let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
    if len > MAX_UDP_PACKET_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "UDP packet length exceeds maximum",
        ));
    }

    if buf.len() < 2 + len {
        return Ok(None);
    }

    buf.advance(2);
    Ok(Some(buf.split_to(len).freeze()))
}

/// Decode a UDP packet with address header (v2)
pub fn decode_packet_v2(buf: &mut BytesMut) -> io::Result<Option<UdpPacket>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let addr_type = buf[0];
    let header_len = match addr_type {
        0x01 => 1 + 4 + 2,  // type + IPv4 + port
        0x04 => 1 + 16 + 2, // type + IPv6 + port
        0x03 => {
            // Domain: type + len + domain + port
            if buf.len() < 2 {
                return Ok(None);
            }
            1 + 1 + (buf[1] as usize) + 2
        }
        _ => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unknown address type: {}", addr_type),
            ));
        }
    };

    if buf.len() < header_len + 2 {
        return Ok(None);
    }

    let addr = match addr_type {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = ((buf[5] as u16) << 8) | (buf[6] as u16);
            SocketAddr::from((ip, port))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = ((buf[17] as u16) << 8) | (buf[18] as u16);
            SocketAddr::from((ip, port))
        }
        0x03 => {
            // Domain not supported for decoded address, return placeholder
            let domain_len = buf[1] as usize;
            let port_offset = 2 + domain_len;
            let port = ((buf[port_offset] as u16) << 8) | (buf[port_offset + 1] as u16);
            // Use unspecified address with port for domain
            SocketAddr::from(([0, 0, 0, 0], port))
        }
        _ => unreachable!(),
    };

    buf.advance(header_len);

    // Read length + data
    if buf.len() < 2 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "incomplete packet length",
        ));
    }

    let len = ((buf[0] as usize) << 8) | (buf[1] as usize);
    if len > MAX_UDP_PACKET_SIZE {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "UDP packet length exceeds maximum",
        ));
    }

    if buf.len() < 2 + len {
        return Ok(None);
    }

    buf.advance(2);
    let data = buf.split_to(len).freeze();

    Ok(Some(UdpPacket { addr, data }))
}

impl<S: AsyncRead + Unpin> AsyncRead for UotStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Return pending packet first
        if let Some(packet) = self.pending_packet.take() {
            let len = std::cmp::min(buf.remaining(), packet.len());
            buf.put_slice(&packet[..len]);
            if len < packet.len() {
                self.pending_packet = Some(packet.slice(len..));
            }
            return Poll::Ready(Ok(()));
        }

        let this = self.get_mut();

        // Read more data from inner stream
        let mut tmp = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut tmp);
        
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.read_buffer.extend_from_slice(read_buf.filled());
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                if this.read_buffer.is_empty() {
                    return Poll::Pending;
                }
            }
        }

        // Try to decode a packet
        match this.version {
            UotVersion::V1 => match decode_packet_v1(&mut this.read_buffer)? {
                Some(packet) => {
                    let len = std::cmp::min(buf.remaining(), packet.len());
                    buf.put_slice(&packet[..len]);
                    if len < packet.len() {
                        this.pending_packet = Some(packet.slice(len..));
                    }
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            },
            UotVersion::V2 => match decode_packet_v2(&mut this.read_buffer)? {
                Some(udp_packet) => {
                    let len = std::cmp::min(buf.remaining(), udp_packet.data.len());
                    buf.put_slice(&udp_packet.data[..len]);
                    if len < udp_packet.data.len() {
                        this.pending_packet = Some(udp_packet.data.slice(len..));
                    }
                    Poll::Ready(Ok(()))
                }
                None => Poll::Pending,
            },
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for UotStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let version = self.version;
        let packet = match version {
            UotVersion::V1 => encode_packet_v1(buf)?,
            UotVersion::V2 => {
                // For v2 without explicit address, use unspecified
                // Copy buf data to owned Bytes
                let data = Bytes::copy_from_slice(buf);
                let pkt = UdpPacket::new(([0, 0, 0, 0], 0).into(), data);
                encode_packet_v2(&pkt)?
            }
        };

        let buf_len = buf.len();
        match Pin::new(&mut self.inner).poll_write(cx, &packet) {
            Poll::Ready(Ok(n)) if n >= packet.len() => Poll::Ready(Ok(buf_len)),
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                ErrorKind::WriteZero,
                "failed to write complete packet",
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Helper trait for sending UDP packets over TCP
pub trait UotSend {
    /// Send a UDP packet
    fn send_packet(&mut self, data: &[u8]) -> impl std::future::Future<Output = io::Result<()>>;
    
    /// Send a UDP packet with address (v2)
    fn send_packet_to(&mut self, packet: &UdpPacket) -> impl std::future::Future<Output = io::Result<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_v1() {
        let data = b"Hello, UDP over TCP!";
        let encoded = encode_packet_v1(data).unwrap();
        
        assert_eq!(encoded.len(), 2 + data.len());
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], data.len() as u8);
        
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_packet_v1(&mut buf).unwrap().unwrap();
        
        assert_eq!(&decoded[..], &data[..]);
    }

    #[test]
    fn test_encode_decode_v2_ipv4() {
        let packet = UdpPacket::new(
            "192.168.1.1:8080".parse().unwrap(),
            Bytes::from("test data"),
        );
        
        let encoded = encode_packet_v2(&packet).unwrap();
        
        // type(1) + ipv4(4) + port(2) + len(2) + data(9)
        assert_eq!(encoded.len(), 1 + 4 + 2 + 2 + 9);
        assert_eq!(encoded[0], AddressType::IPv4 as u8);
        
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_packet_v2(&mut buf).unwrap().unwrap();
        
        assert_eq!(decoded.addr, packet.addr);
        assert_eq!(decoded.data, packet.data);
    }

    #[test]
    fn test_encode_decode_v2_ipv6() {
        let packet = UdpPacket::new(
            "[::1]:9000".parse().unwrap(),
            Bytes::from("ipv6 test"),
        );
        
        let encoded = encode_packet_v2(&packet).unwrap();
        
        // type(1) + ipv6(16) + port(2) + len(2) + data(9)
        assert_eq!(encoded.len(), 1 + 16 + 2 + 2 + 9);
        assert_eq!(encoded[0], AddressType::IPv6 as u8);
        
        let mut buf = BytesMut::from(&encoded[..]);
        let decoded = decode_packet_v2(&mut buf).unwrap().unwrap();
        
        assert_eq!(decoded.addr, packet.addr);
        assert_eq!(decoded.data, packet.data);
    }

    #[test]
    fn test_packet_too_large() {
        let large_data = vec![0u8; MAX_UDP_PACKET_SIZE + 1];
        assert!(encode_packet_v1(&large_data).is_err());
    }
}
