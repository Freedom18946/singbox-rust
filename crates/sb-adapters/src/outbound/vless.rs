//! VLESS protocol outbound connector implementation
//!
//! VLESS is a stateless, lightweight protocol that reduces overhead compared to VMess.
//! It supports multiple flow control modes and encryption options.

use async_trait::async_trait;
use bytes::BufMut;
use sb_core::{
    error::{ErrorClass, IssueCode, SbError, SbResult},
    outbound::traits::{OutboundConnector, UdpTransport},
    types::{ConnCtx, Endpoint, Host},
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

/// VLESS configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessConfig {
    pub server: String,
    pub uuid: String,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default)]
    pub packet_encoding: Option<String>,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
}

fn default_network() -> String {
    "tcp".to_string()
}

/// VLESS flow control modes
#[derive(Debug, Clone, PartialEq)]
pub enum VlessFlow {
    None,
    XtlsRprxVision,
}

impl VlessFlow {
    pub fn from_str(s: &str) -> Self {
        match s {
            "xtls-rprx-vision" => Self::XtlsRprxVision,
            _ => Self::None,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::None => "",
            Self::XtlsRprxVision => "xtls-rprx-vision",
        }
    }
}

/// VLESS command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessCommand {
    Tcp = 0x01,
    Udp = 0x02,
    Mux = 0x03,
}

impl VlessCommand {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(VlessCommand::Tcp),
            0x02 => Some(VlessCommand::Udp),
            0x03 => Some(VlessCommand::Mux),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// VLESS address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

impl VlessAddressType {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(VlessAddressType::Ipv4),
            0x02 => Some(VlessAddressType::Domain),
            0x03 => Some(VlessAddressType::Ipv6),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// VLESS packet encoding types
#[derive(Debug, Clone, PartialEq)]
pub enum VlessPacketEncoding {
    None,
    PacketAddr,
    Xudp,
}

impl VlessPacketEncoding {
    pub fn from_str(s: &str) -> Self {
        match s {
            "packetaddr" => Self::PacketAddr,
            "xudp" => Self::Xudp,
            _ => Self::None,
        }
    }
}

/// VLESS request header structure
#[derive(Debug, Clone)]
pub struct VlessRequestHeader {
    pub version: u8,
    pub uuid: Uuid,
    pub addons_length: u8,
    pub addons: Vec<u8>,
    pub command: VlessCommand,
    pub port: u16,
    pub address_type: VlessAddressType,
    pub address: Vec<u8>,
}

impl VlessRequestHeader {
    /// Create a new VLESS request header
    pub fn new(uuid: Uuid, command: VlessCommand, destination: &Endpoint) -> Self {
        let (address_type, address, port) = match &destination.host {
            Host::Ip(IpAddr::V4(ipv4)) => (
                VlessAddressType::Ipv4,
                ipv4.octets().to_vec(),
                destination.port,
            ),
            Host::Ip(IpAddr::V6(ipv6)) => (
                VlessAddressType::Ipv6,
                ipv6.octets().to_vec(),
                destination.port,
            ),
            Host::Name(domain) => {
                let mut addr = Vec::with_capacity(domain.len() + 1);
                addr.push(domain.len() as u8);
                addr.extend_from_slice(domain.as_bytes());
                (VlessAddressType::Domain, addr, destination.port)
            }
        };

        Self {
            version: 0x00,
            uuid,
            addons_length: 0x00,
            addons: Vec::new(),
            command,
            port,
            address_type,
            address,
        }
    }

    /// Encode the header to bytes
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Version (1 byte)
        buf.push(self.version);

        // UUID (16 bytes)
        buf.extend_from_slice(self.uuid.as_bytes());

        // Addons length (1 byte)
        buf.push(self.addons_length);

        // Addons (variable length)
        buf.extend_from_slice(&self.addons);

        // Command (1 byte)
        buf.push(self.command.to_byte());

        // Port (2 bytes, big-endian)
        buf.put_u16(self.port);

        // Address type (1 byte)
        buf.push(self.address_type.to_byte());

        // Address (variable length)
        buf.extend_from_slice(&self.address);

        buf
    }

    /// Decode header from bytes
    pub fn decode(data: &[u8]) -> SbResult<(Self, usize)> {
        if data.len() < 17 {
            return Err(SbError::network(
                ErrorClass::Protocol,
                "Data too short for VLESS header".to_string(),
            ));
        }

        let mut offset = 0;

        // Version
        let version = data[offset];
        offset += 1;

        if version != 0x00 {
            return Err(SbError::network(
                ErrorClass::Protocol,
                format!("Unsupported VLESS version: {}", version),
            ));
        }

        // UUID
        let uuid_bytes = &data[offset..offset + 16];
        let uuid = Uuid::from_bytes(uuid_bytes.try_into().map_err(|_| {
            SbError::network(
                ErrorClass::Protocol,
                "Invalid UUID in VLESS header".to_string(),
            )
        })?);
        offset += 16;

        // Addons length
        let addons_length = data[offset];
        offset += 1;

        // Addons
        if data.len() < offset + addons_length as usize {
            return Err(SbError::network(
                ErrorClass::Protocol,
                "Data too short for VLESS addons".to_string(),
            ));
        }
        let addons = data[offset..offset + addons_length as usize].to_vec();
        offset += addons_length as usize;

        // Command
        if data.len() < offset + 1 {
            return Err(SbError::network(
                ErrorClass::Protocol,
                "Data too short for VLESS command".to_string(),
            ));
        }
        let command = VlessCommand::from_byte(data[offset]).ok_or_else(|| {
            SbError::network(ErrorClass::Protocol, "Invalid VLESS command".to_string())
        })?;
        offset += 1;

        // Port
        if data.len() < offset + 2 {
            return Err(SbError::network(
                ErrorClass::Protocol,
                "Data too short for VLESS port".to_string(),
            ));
        }
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Address type
        if data.len() < offset + 1 {
            return Err(SbError::network(
                ErrorClass::Protocol,
                "Data too short for VLESS address type".to_string(),
            ));
        }
        let address_type = VlessAddressType::from_byte(data[offset]).ok_or_else(|| {
            SbError::network(
                ErrorClass::Protocol,
                "Invalid VLESS address type".to_string(),
            )
        })?;
        offset += 1;

        // Address
        let address = match address_type {
            VlessAddressType::Ipv4 => {
                if data.len() < offset + 4 {
                    return Err(SbError::network(
                        ErrorClass::Protocol,
                        "Data too short for IPv4 address".to_string(),
                    ));
                }
                let addr = data[offset..offset + 4].to_vec();
                offset += 4;
                addr
            }
            VlessAddressType::Ipv6 => {
                if data.len() < offset + 16 {
                    return Err(SbError::network(
                        ErrorClass::Protocol,
                        "Data too short for IPv6 address".to_string(),
                    ));
                }
                let addr = data[offset..offset + 16].to_vec();
                offset += 16;
                addr
            }
            VlessAddressType::Domain => {
                if data.len() < offset + 1 {
                    return Err(SbError::network(
                        ErrorClass::Protocol,
                        "Data too short for domain length".to_string(),
                    ));
                }
                let domain_len = data[offset] as usize;
                offset += 1;

                if data.len() < offset + domain_len {
                    return Err(SbError::network(
                        ErrorClass::Protocol,
                        "Data too short for domain".to_string(),
                    ));
                }
                let mut addr = Vec::with_capacity(domain_len + 1);
                addr.push(domain_len as u8);
                addr.extend_from_slice(&data[offset..offset + domain_len]);
                offset += domain_len;
                addr
            }
        };

        let header = VlessRequestHeader {
            version,
            uuid,
            addons_length,
            addons,
            command,
            port,
            address_type,
            address,
        };

        Ok((header, offset))
    }
}

/// VLESS outbound connector
#[derive(Debug, Clone)]
pub struct VlessConnector {
    config: VlessConfig,
    user_id: Uuid,
    flow: VlessFlow,
    packet_encoding: VlessPacketEncoding,
    connect_timeout: Duration,
}

impl VlessConnector {
    /// Create a new VLESS connector
    pub fn new(config: VlessConfig) -> SbResult<Self> {
        let user_id = Uuid::parse_str(&config.uuid).map_err(|e| {
            SbError::config(
                IssueCode::InvalidType,
                "vless.uuid",
                format!("Invalid UUID format: {}", e),
            )
        })?;

        let flow = config
            .flow
            .as_ref()
            .map(|f| VlessFlow::from_str(f))
            .unwrap_or(VlessFlow::None);

        let packet_encoding = config
            .packet_encoding
            .as_ref()
            .map(|e| VlessPacketEncoding::from_str(e))
            .unwrap_or(VlessPacketEncoding::Xudp);

        let connect_timeout = Duration::from_secs(config.connect_timeout_sec.unwrap_or(10));

        Ok(Self {
            config,
            user_id,
            flow,
            packet_encoding,
            connect_timeout,
        })
    }

    /// Resolve server address
    async fn resolve_server(&self) -> SbResult<SocketAddr> {
        let mut addrs = lookup_host(&self.config.server).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to resolve VLESS server: {}", e),
            )
        })?;

        addrs.next().ok_or_else(|| {
            SbError::network(
                ErrorClass::Connection,
                "No addresses resolved for VLESS server".to_string(),
            )
        })
    }

    /// Perform VLESS handshake
    async fn handshake<S>(&self, stream: &mut S, dst: &Endpoint, cmd: VlessCommand) -> SbResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Create and send request header
        let header = VlessRequestHeader::new(self.user_id, cmd, dst);
        let header_bytes = header.encode();

        stream.write_all(&header_bytes).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to send VLESS handshake: {}", e),
            )
        })?;

        // Read response header (VLESS response is minimal - just 1 byte)
        let mut response = [0u8; 1];
        stream.read_exact(&mut response).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to read VLESS response: {}", e),
            )
        })?;

        // VLESS response should be 0x00 for success
        if response[0] != 0x00 {
            return Err(SbError::network(
                ErrorClass::Protocol,
                format!("VLESS handshake failed with response: {}", response[0]),
            ));
        }

        Ok(())
    }

    /// Get the connect timeout duration
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Get the flow control mode
    pub fn flow(&self) -> &VlessFlow {
        &self.flow
    }

    /// Get the packet encoding mode
    pub fn packet_encoding(&self) -> &VlessPacketEncoding {
        &self.packet_encoding
    }
}

#[async_trait]
impl OutboundConnector for VlessConnector {
    async fn connect_tcp(&self, ctx: &ConnCtx) -> SbResult<TcpStream> {
        // Connect to VLESS server
        let server_addr = self.resolve_server().await?;
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(server_addr))
            .await
            .map_err(|_| {
                SbError::timeout("vless_tcp_connect", self.connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("VLESS TCP connection failed: {}", e),
                )
            })?;

        // Perform VLESS handshake
        self.handshake(&mut stream, &ctx.dst, VlessCommand::Tcp)
            .await?;

        Ok(stream)
    }

    async fn connect_udp(&self, ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>> {
        // For VLESS UDP, we establish a TCP connection and use it for UDP relay
        let server_addr = self.resolve_server().await?;
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(server_addr))
            .await
            .map_err(|_| {
                SbError::timeout("vless_udp_connect", self.connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("VLESS UDP connection failed: {}", e),
                )
            })?;

        // Perform VLESS handshake for UDP
        self.handshake(&mut stream, &ctx.dst, VlessCommand::Udp)
            .await?;

        Ok(Box::new(VlessUdpTransport::new(
            stream,
            self.packet_encoding.clone(),
        )))
    }
}

/// VLESS UDP transport over TCP connection
pub struct VlessUdpTransport {
    stream: std::sync::Arc<tokio::sync::Mutex<TcpStream>>,
    packet_encoding: VlessPacketEncoding,
}

impl VlessUdpTransport {
    fn new(stream: TcpStream, packet_encoding: VlessPacketEncoding) -> Self {
        Self {
            stream: std::sync::Arc::new(tokio::sync::Mutex::new(stream)),
            packet_encoding,
        }
    }

    /// Encode UDP packet according to the packet encoding scheme
    fn encode_udp_packet(&self, buf: &[u8], dst: &Endpoint) -> SbResult<Vec<u8>> {
        match self.packet_encoding {
            VlessPacketEncoding::None => {
                // No encoding, just pass through
                Ok(buf.to_vec())
            }
            VlessPacketEncoding::PacketAddr => {
                // PacketAddr encoding: [addr_type][addr][port][data]
                let mut packet = Vec::new();

                match &dst.host {
                    Host::Ip(IpAddr::V4(ipv4)) => {
                        packet.push(VlessAddressType::Ipv4.to_byte());
                        packet.extend_from_slice(&ipv4.octets());
                    }
                    Host::Ip(IpAddr::V6(ipv6)) => {
                        packet.push(VlessAddressType::Ipv6.to_byte());
                        packet.extend_from_slice(&ipv6.octets());
                    }
                    Host::Name(domain) => {
                        packet.push(VlessAddressType::Domain.to_byte());
                        packet.push(domain.len() as u8);
                        packet.extend_from_slice(domain.as_bytes());
                    }
                }

                packet.extend_from_slice(&dst.port.to_be_bytes());
                packet.extend_from_slice(buf);
                Ok(packet)
            }
            VlessPacketEncoding::Xudp => {
                // XUDP encoding: [length][addr_type][addr][port][data]
                let mut packet = Vec::new();

                // Calculate address length
                let addr_len = match &dst.host {
                    Host::Ip(IpAddr::V4(_)) => 4,
                    Host::Ip(IpAddr::V6(_)) => 16,
                    Host::Name(domain) => 1 + domain.len(),
                };

                // Total length: addr_type(1) + addr + port(2) + data
                let total_len = 1 + addr_len + 2 + buf.len();
                packet.extend_from_slice(&(total_len as u16).to_be_bytes());

                // Address type and address
                match &dst.host {
                    Host::Ip(IpAddr::V4(ipv4)) => {
                        packet.push(VlessAddressType::Ipv4.to_byte());
                        packet.extend_from_slice(&ipv4.octets());
                    }
                    Host::Ip(IpAddr::V6(ipv6)) => {
                        packet.push(VlessAddressType::Ipv6.to_byte());
                        packet.extend_from_slice(&ipv6.octets());
                    }
                    Host::Name(domain) => {
                        packet.push(VlessAddressType::Domain.to_byte());
                        packet.push(domain.len() as u8);
                        packet.extend_from_slice(domain.as_bytes());
                    }
                }

                packet.extend_from_slice(&dst.port.to_be_bytes());
                packet.extend_from_slice(buf);
                Ok(packet)
            }
        }
    }
}

#[async_trait]
impl UdpTransport for VlessUdpTransport {
    async fn send_to(&self, buf: &[u8], dst: &Endpoint) -> SbResult<usize> {
        let encoded_packet = self.encode_udp_packet(buf, dst)?;
        let mut stream = self.stream.lock().await;

        stream.write_all(&encoded_packet).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("VLESS UDP send failed: {}", e),
            )
        })?;

        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> SbResult<(usize, SocketAddr)> {
        let mut stream = self.stream.lock().await;

        match self.packet_encoding {
            VlessPacketEncoding::None => {
                let n = stream.read(buf).await.map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("VLESS UDP recv failed: {}", e),
                    )
                })?;

                // Return dummy address for now
                let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);
                Ok((n, addr))
            }
            VlessPacketEncoding::PacketAddr | VlessPacketEncoding::Xudp => {
                // For encoded packets, we need to decode the address and data
                // This is a simplified implementation
                let n = stream.read(buf).await.map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("VLESS UDP recv failed: {}", e),
                    )
                })?;

                // TODO: Implement proper packet decoding
                // For now, return dummy address
                let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);
                Ok((n, addr))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_command_conversion() {
        assert_eq!(VlessCommand::Tcp.to_byte(), 0x01);
        assert_eq!(VlessCommand::from_byte(0x01), Some(VlessCommand::Tcp));

        assert_eq!(VlessCommand::Udp.to_byte(), 0x02);
        assert_eq!(VlessCommand::from_byte(0x02), Some(VlessCommand::Udp));

        assert_eq!(VlessCommand::Mux.to_byte(), 0x03);
        assert_eq!(VlessCommand::from_byte(0x03), Some(VlessCommand::Mux));

        assert_eq!(VlessCommand::from_byte(0xFF), None);
    }

    #[test]
    fn test_vless_address_type_conversion() {
        assert_eq!(VlessAddressType::Ipv4.to_byte(), 0x01);
        assert_eq!(
            VlessAddressType::from_byte(0x01),
            Some(VlessAddressType::Ipv4)
        );

        assert_eq!(VlessAddressType::Domain.to_byte(), 0x02);
        assert_eq!(
            VlessAddressType::from_byte(0x02),
            Some(VlessAddressType::Domain)
        );

        assert_eq!(VlessAddressType::Ipv6.to_byte(), 0x03);
        assert_eq!(
            VlessAddressType::from_byte(0x03),
            Some(VlessAddressType::Ipv6)
        );

        assert_eq!(VlessAddressType::from_byte(0xFF), None);
    }

    #[test]
    fn test_vless_flow_conversion() {
        assert_eq!(
            VlessFlow::from_str("xtls-rprx-vision"),
            VlessFlow::XtlsRprxVision
        );
        assert_eq!(VlessFlow::from_str("unknown"), VlessFlow::None);

        assert_eq!(VlessFlow::XtlsRprxVision.to_str(), "xtls-rprx-vision");
        assert_eq!(VlessFlow::None.to_str(), "");
    }

    #[test]
    fn test_vless_packet_encoding() {
        assert_eq!(
            VlessPacketEncoding::from_str("packetaddr"),
            VlessPacketEncoding::PacketAddr
        );
        assert_eq!(
            VlessPacketEncoding::from_str("xudp"),
            VlessPacketEncoding::Xudp
        );
        assert_eq!(
            VlessPacketEncoding::from_str("unknown"),
            VlessPacketEncoding::None
        );
    }

    #[test]
    fn test_vless_header_encode_decode() {
        let uuid = Uuid::new_v4();
        let endpoint = Endpoint::new("example.com", 80);
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

        let encoded = header.encode();
        let (decoded_header, _) = VlessRequestHeader::decode(&encoded).unwrap();

        assert_eq!(decoded_header.version, header.version);
        assert_eq!(decoded_header.uuid, header.uuid);
        assert_eq!(decoded_header.command, header.command);
        assert_eq!(decoded_header.port, header.port);
        assert_eq!(decoded_header.address_type, header.address_type);
        assert_eq!(decoded_header.address, header.address);
    }

    #[test]
    fn test_vless_connector_creation() {
        let config = VlessConfig {
            server: "example.com:443".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            network: "tcp".to_string(),
            packet_encoding: Some("xudp".to_string()),
            connect_timeout_sec: Some(5),
        };

        let connector = VlessConnector::new(config);
        assert!(connector.is_ok());

        let connector = connector.unwrap();
        assert_eq!(connector.connect_timeout, Duration::from_secs(5));
        assert_eq!(connector.flow, VlessFlow::XtlsRprxVision);
        assert_eq!(connector.packet_encoding, VlessPacketEncoding::Xudp);
    }

    #[test]
    fn test_vless_connector_invalid_uuid() {
        let config = VlessConfig {
            server: "example.com:443".to_string(),
            uuid: "invalid-uuid".to_string(),
            flow: None,
            network: "tcp".to_string(),
            packet_encoding: None,
            connect_timeout_sec: None,
        };

        let connector = VlessConnector::new(config);
        assert!(connector.is_err());
    }

    #[test]
    fn test_vless_header_ipv4() {
        let uuid = Uuid::new_v4();
        let endpoint = Endpoint::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

        assert_eq!(header.address_type, VlessAddressType::Ipv4);
        assert_eq!(header.address, vec![127, 0, 0, 1]);
        assert_eq!(header.port, 8080);
    }

    #[test]
    fn test_vless_header_ipv6() {
        let uuid = Uuid::new_v4();
        let ipv6 = std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let endpoint = Endpoint::new(IpAddr::V6(ipv6), 8080);
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

        assert_eq!(header.address_type, VlessAddressType::Ipv6);
        assert_eq!(header.address, ipv6.octets().to_vec());
        assert_eq!(header.port, 8080);
    }

    #[test]
    fn test_vless_header_domain() {
        let uuid = Uuid::new_v4();
        let endpoint = Endpoint::new("example.com", 443);
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, &endpoint);

        assert_eq!(header.address_type, VlessAddressType::Domain);
        assert_eq!(header.address[0], 11); // "example.com".len()
        assert_eq!(&header.address[1..], b"example.com");
        assert_eq!(header.port, 443);
    }
}
