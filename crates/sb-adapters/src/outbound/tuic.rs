//! TUIC protocol outbound connector implementation
//!
//! TUIC (The Ultimate Internet Connector) is a QUIC-based proxy protocol
//! that provides UDP relay and multiplexing features with authentication
//! and session management.

use async_trait::async_trait;
use sb_core::{
    error::{ErrorClass, IssueCode, SbError, SbResult},
    outbound::traits::{OutboundConnector, UdpTransport},
    types::{ConnCtx, Endpoint, Host},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::lookup_host;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

#[cfg(feature = "tuic")]
use quinn::{ClientConfig, Connection, Endpoint as QuicEndpoint};

/// TUIC configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicConfig {
    pub server: String,
    pub uuid: String,
    pub password: String,
    #[serde(default = "default_congestion_control")]
    pub congestion_control: String,
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    #[serde(default)]
    pub udp_over_stream: bool,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default = "default_heartbeat")]
    pub heartbeat: u64,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    #[serde(default)]
    pub auth_timeout_sec: Option<u64>,
}

fn default_congestion_control() -> String {
    "bbr".to_string()
}

fn default_heartbeat() -> u64 {
    10000 // 10 seconds in milliseconds
}

/// TUIC congestion control algorithms
#[derive(Debug, Clone, PartialEq)]
pub enum TuicCongestionControl {
    Bbr,
    Cubic,
    NewReno,
}

impl TuicCongestionControl {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "bbr" => Self::Bbr,
            "cubic" => Self::Cubic,
            "new_reno" | "newreno" => Self::NewReno,
            _ => Self::Bbr,
        }
    }
}

/// TUIC UDP relay modes
#[derive(Debug, Clone, PartialEq)]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}

impl TuicUdpRelayMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "native" => Self::Native,
            "quic" => Self::Quic,
            _ => Self::Native,
        }
    }
}

/// TUIC command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicCommand {
    Connect = 0x01,
    Packet = 0x02,
    Dissociate = 0x03,
    Heartbeat = 0x04,
    Authenticate = 0x05,
}

impl TuicCommand {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(TuicCommand::Connect),
            0x02 => Some(TuicCommand::Packet),
            0x03 => Some(TuicCommand::Dissociate),
            0x04 => Some(TuicCommand::Heartbeat),
            0x05 => Some(TuicCommand::Authenticate),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// TUIC address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuicAddressType {
    None = 0x00,
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

impl TuicAddressType {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(TuicAddressType::None),
            0x01 => Some(TuicAddressType::Ipv4),
            0x02 => Some(TuicAddressType::Domain),
            0x03 => Some(TuicAddressType::Ipv6),
            _ => None,
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// TUIC authentication packet
#[derive(Debug, Clone)]
pub struct TuicAuthPacket {
    pub uuid: Uuid,
    pub password: String,
    pub timestamp: u64,
}

impl TuicAuthPacket {
    pub fn new(uuid: Uuid, password: String) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            uuid,
            password,
            timestamp,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Command
        buf.push(TuicCommand::Authenticate.to_byte());

        // UUID (16 bytes)
        buf.extend_from_slice(self.uuid.as_bytes());

        // Password length and password
        let password_bytes = self.password.as_bytes();
        buf.push(password_bytes.len() as u8);
        buf.extend_from_slice(password_bytes);

        // Timestamp (8 bytes)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        buf
    }
}

/// TUIC connect packet
#[derive(Debug, Clone)]
pub struct TuicConnectPacket {
    pub address_type: TuicAddressType,
    pub address: Vec<u8>,
    pub port: u16,
}

impl TuicConnectPacket {
    pub fn new(endpoint: &Endpoint) -> Self {
        let (address_type, address) = match &endpoint.host {
            Host::Ip(IpAddr::V4(ipv4)) => (TuicAddressType::Ipv4, ipv4.octets().to_vec()),
            Host::Ip(IpAddr::V6(ipv6)) => (TuicAddressType::Ipv6, ipv6.octets().to_vec()),
            Host::Name(domain) => {
                let mut addr = Vec::with_capacity(domain.len() + 1);
                addr.push(domain.len() as u8);
                addr.extend_from_slice(domain.as_bytes());
                (TuicAddressType::Domain, addr)
            }
        };

        Self {
            address_type,
            address,
            port: endpoint.port,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Command
        buf.push(TuicCommand::Connect.to_byte());

        // Address type
        buf.push(self.address_type.to_byte());

        // Address
        buf.extend_from_slice(&self.address);

        // Port (2 bytes, big-endian)
        buf.extend_from_slice(&self.port.to_be_bytes());

        buf
    }
}

/// TUIC packet for UDP relay
#[derive(Debug, Clone)]
pub struct TuicPacket {
    pub session_id: u16,
    pub packet_id: u16,
    pub fragment_total: u8,
    pub fragment_id: u8,
    pub address_type: TuicAddressType,
    pub address: Vec<u8>,
    pub port: u16,
    pub data: Vec<u8>,
}

impl TuicPacket {
    pub fn new(session_id: u16, packet_id: u16, endpoint: &Endpoint, data: Vec<u8>) -> Self {
        let (address_type, address) = match &endpoint.host {
            Host::Ip(IpAddr::V4(ipv4)) => (TuicAddressType::Ipv4, ipv4.octets().to_vec()),
            Host::Ip(IpAddr::V6(ipv6)) => (TuicAddressType::Ipv6, ipv6.octets().to_vec()),
            Host::Name(domain) => {
                let mut addr = Vec::with_capacity(domain.len() + 1);
                addr.push(domain.len() as u8);
                addr.extend_from_slice(domain.as_bytes());
                (TuicAddressType::Domain, addr)
            }
        };

        Self {
            session_id,
            packet_id,
            fragment_total: 1,
            fragment_id: 0,
            address_type,
            address,
            port: endpoint.port,
            data,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Command
        buf.push(TuicCommand::Packet.to_byte());

        // Session ID (2 bytes)
        buf.extend_from_slice(&self.session_id.to_be_bytes());

        // Packet ID (2 bytes)
        buf.extend_from_slice(&self.packet_id.to_be_bytes());

        // Fragment total (1 byte)
        buf.push(self.fragment_total);

        // Fragment ID (1 byte)
        buf.push(self.fragment_id);

        // Address type
        buf.push(self.address_type.to_byte());

        // Address
        buf.extend_from_slice(&self.address);

        // Port (2 bytes, big-endian)
        buf.extend_from_slice(&self.port.to_be_bytes());

        // Data length (2 bytes)
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());

        // Data
        buf.extend_from_slice(&self.data);

        buf
    }
}

/// TUIC session for multiplexing
#[derive(Debug)]
pub struct TuicSession {
    pub id: u16,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

impl TuicSession {
    pub fn new(id: u16) -> Self {
        let now = Instant::now();
        Self {
            id,
            created_at: now,
            last_activity: now,
            tx_packets: 0,
            rx_packets: 0,
        }
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// TUIC multiplexer for managing sessions
#[derive(Debug)]
pub struct TuicMultiplexer {
    pub sessions: HashMap<u16, TuicSession>,
    next_session_id: u16,
    next_packet_id: u16,
}

impl TuicMultiplexer {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_id: 1,
            next_packet_id: 1,
        }
    }

    pub fn create_session(&mut self) -> u16 {
        let session_id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        let session = TuicSession::new(session_id);
        self.sessions.insert(session_id, session);

        session_id
    }

    pub fn get_session_mut(&mut self, id: u16) -> Option<&mut TuicSession> {
        self.sessions.get_mut(&id)
    }

    pub fn next_packet_id(&mut self) -> u16 {
        let packet_id = self.next_packet_id;
        self.next_packet_id = self.next_packet_id.wrapping_add(1);
        packet_id
    }

    pub fn cleanup_expired_sessions(&mut self, timeout: Duration) {
        let now = Instant::now();
        self.sessions
            .retain(|_, session| now.duration_since(session.last_activity) < timeout);
    }
}

/// TUIC outbound connector
#[derive(Debug)]
pub struct TuicConnector {
    config: TuicConfig,
    user_id: Uuid,
    congestion_control: TuicCongestionControl,
    udp_relay_mode: TuicUdpRelayMode,
    connect_timeout: Duration,
    auth_timeout: Duration,
    heartbeat_interval: Duration,
}

impl TuicConnector {
    /// Create a new TUIC connector
    pub fn new(config: TuicConfig) -> SbResult<Self> {
        let user_id = Uuid::parse_str(&config.uuid).map_err(|e| {
            SbError::config(
                IssueCode::InvalidType,
                "tuic.uuid",
                format!("Invalid UUID format: {}", e),
            )
        })?;

        let congestion_control = TuicCongestionControl::from_str(&config.congestion_control);

        let udp_relay_mode = config
            .udp_relay_mode
            .as_ref()
            .map(|m| TuicUdpRelayMode::from_str(m))
            .unwrap_or(TuicUdpRelayMode::Native);

        let connect_timeout = Duration::from_secs(config.connect_timeout_sec.unwrap_or(10));

        let auth_timeout = Duration::from_secs(config.auth_timeout_sec.unwrap_or(3));

        let heartbeat_interval = Duration::from_millis(config.heartbeat);

        Ok(Self {
            config,
            user_id,
            congestion_control,
            udp_relay_mode,
            connect_timeout,
            auth_timeout,
            heartbeat_interval,
        })
    }

    /// Resolve server address
    async fn resolve_server(&self) -> SbResult<SocketAddr> {
        let mut addrs = lookup_host(&self.config.server).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to resolve TUIC server: {}", e),
            )
        })?;

        addrs.next().ok_or_else(|| {
            SbError::network(
                ErrorClass::Connection,
                "No addresses resolved for TUIC server".to_string(),
            )
        })
    }

    #[cfg(feature = "tuic")]
    /// Create QUIC client configuration
    fn create_quic_config(&self) -> SbResult<ClientConfig> {
        // Use Quinn's convenient method to create a client config with platform verifier
        let quic_config = ClientConfig::try_with_platform_verifier().map_err(|e| {
            SbError::config(
                IssueCode::TlsCertInvalid,
                "/tls/platform_verifier".to_string(),
                format!("Failed to create QUIC config with platform verifier: {}", e),
            )
        })?;

        Ok(quic_config)
    }

    #[cfg(feature = "tuic")]
    /// Establish QUIC connection
    async fn connect_quic(&self) -> SbResult<Connection> {
        use tokio::time::timeout;

        let server_addr = self.resolve_server().await?;
        let quic_config = self.create_quic_config()?;

        let mut endpoint = QuicEndpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to create QUIC endpoint: {}", e),
            )
        })?;

        endpoint.set_default_client_config(quic_config);

        let server_name = self
            .config
            .server
            .split(':')
            .next()
            .unwrap_or(&self.config.server);

        let connecting = endpoint.connect(server_addr, server_name).map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("TUIC QUIC connect failed: {}", e),
            )
        })?;

        let connection = timeout(self.connect_timeout, connecting)
            .await
            .map_err(|_| {
                SbError::timeout("tuic_quic_connect", self.connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("TUIC QUIC connection failed: {}", e),
                )
            })?;

        Ok(connection)
    }

    #[cfg(feature = "tuic")]
    /// Perform TUIC authentication
    async fn authenticate(&self, connection: &Connection) -> SbResult<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::time::timeout;

        let auth_packet = TuicAuthPacket::new(self.user_id, self.config.password.clone());
        let auth_data = auth_packet.encode();

        let mut send_stream = connection.open_uni().await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to open TUIC auth stream: {}", e),
            )
        })?;

        timeout(self.auth_timeout, send_stream.write_all(&auth_data))
            .await
            .map_err(|_| SbError::timeout("tuic_auth", self.auth_timeout.as_millis() as u64))?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Authentication,
                    format!("TUIC authentication failed: {}", e),
                )
            })?;

        send_stream.finish().map_err(|e| {
            SbError::network(
                ErrorClass::Authentication,
                format!("Failed to finish TUIC auth stream: {}", e),
            )
        })?;

        Ok(())
    }

    #[cfg(not(feature = "tuic"))]
    async fn connect_quic(&self) -> SbResult<()> {
        // Use the fields to avoid dead code warnings
        let _ = (
            &self.config,
            &self.user_id,
            &self.auth_timeout,
            &self.heartbeat_interval,
        );
        Err(SbError::network(
            ErrorClass::Configuration,
            "TUIC support not enabled. Rebuild with --features tuic".to_string(),
        ))
    }

    #[cfg(not(feature = "tuic"))]
    async fn authenticate(&self, _connection: &()) -> SbResult<()> {
        let _ = (
            &self.config,
            &self.user_id,
            &self.auth_timeout,
            &self.heartbeat_interval,
        );
        Err(SbError::network(
            ErrorClass::Configuration,
            "TUIC support not enabled. Rebuild with --features tuic".to_string(),
        ))
    }

    /// Get the connect timeout duration
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Get the congestion control mode
    pub fn congestion_control(&self) -> &TuicCongestionControl {
        &self.congestion_control
    }

    /// Get the UDP relay mode
    pub fn udp_relay_mode(&self) -> &TuicUdpRelayMode {
        &self.udp_relay_mode
    }
}

#[cfg(feature = "tuic")]
#[async_trait]
impl OutboundConnector for TuicConnector {
    async fn connect_tcp(&self, _ctx: &ConnCtx) -> SbResult<tokio::net::TcpStream> {
        // TUIC uses QUIC streams for TCP connections
        // This is a simplified implementation that would need proper stream handling
        Err(SbError::network(
            ErrorClass::Protocol,
            "TUIC TCP connections require QUIC stream implementation".to_string(),
        ))
    }

    async fn connect_udp(&self, _ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>> {
        let connection = self.connect_quic().await?;
        self.authenticate(&connection).await?;

        Ok(Box::new(TuicUdpTransport::new(
            connection,
            self.udp_relay_mode.clone(),
            self.config.udp_over_stream,
        )))
    }
}

#[cfg(not(feature = "tuic"))]
#[async_trait]
impl OutboundConnector for TuicConnector {
    async fn connect_tcp(&self, _ctx: &ConnCtx) -> SbResult<tokio::net::TcpStream> {
        Err(SbError::network(
            ErrorClass::Configuration,
            "TUIC support not enabled. Rebuild with --features tuic".to_string(),
        ))
    }

    async fn connect_udp(&self, _ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>> {
        Err(SbError::network(
            ErrorClass::Configuration,
            "TUIC support not enabled. Rebuild with --features tuic".to_string(),
        ))
    }
}

/// TUIC UDP transport over QUIC connection
#[cfg(feature = "tuic")]
pub struct TuicUdpTransport {
    connection: Connection,
    udp_relay_mode: TuicUdpRelayMode,
    udp_over_stream: bool,
    multiplexer: Arc<Mutex<TuicMultiplexer>>,
}

#[cfg(feature = "tuic")]
impl TuicUdpTransport {
    fn new(
        connection: Connection,
        udp_relay_mode: TuicUdpRelayMode,
        udp_over_stream: bool,
    ) -> Self {
        Self {
            connection,
            udp_relay_mode,
            udp_over_stream,
            multiplexer: Arc::new(Mutex::new(TuicMultiplexer::new())),
        }
    }
}

#[cfg(feature = "tuic")]
#[async_trait]
impl UdpTransport for TuicUdpTransport {
    async fn send_to(&self, buf: &[u8], dst: &Endpoint) -> SbResult<usize> {
        if self.udp_over_stream {
            // Use QUIC stream for UDP over stream mode
            let mut send_stream = self.connection.open_uni().await.map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to open TUIC UDP stream: {}", e),
                )
            })?;

            let connect_packet = TuicConnectPacket::new(dst);
            let connect_data = connect_packet.encode();

            use tokio::io::AsyncWriteExt;

            send_stream.write_all(&connect_data).await.map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to send TUIC connect: {}", e),
                )
            })?;

            send_stream.write_all(buf).await.map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to send TUIC UDP data: {}", e),
                )
            })?;

            send_stream.finish().map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to finish TUIC UDP stream: {}", e),
                )
            })?;

            Ok(buf.len())
        } else {
            // Use QUIC datagrams for native UDP relay
            let mut multiplexer = self.multiplexer.lock().await;
            let session_id = multiplexer.create_session();
            let packet_id = multiplexer.next_packet_id();

            let packet = TuicPacket::new(session_id, packet_id, dst, buf.to_vec());
            let packet_data = packet.encode();

            self.connection
                .send_datagram(packet_data.into())
                .map_err(|e| {
                    SbError::network(
                        ErrorClass::Connection,
                        format!("Failed to send TUIC UDP packet: {}", e),
                    )
                })?;

            if let Some(session) = multiplexer.get_session_mut(session_id) {
                session.tx_packets += 1;
                session.update_activity();
            }

            Ok(buf.len())
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> SbResult<(usize, SocketAddr)> {
        if self.udp_over_stream {
            // For UDP over stream, we would need to handle incoming streams
            // This is a simplified implementation
            Err(SbError::network(
                ErrorClass::Protocol,
                "TUIC UDP over stream recv not fully implemented".to_string(),
            ))
        } else {
            // Receive QUIC datagrams
            let datagram = self.connection.read_datagram().await.map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("Failed to receive TUIC UDP packet: {}", e),
                )
            })?;

            // Parse TUIC packet (simplified)
            let data = datagram.as_ref();
            if data.len() > buf.len() {
                return Err(SbError::network(
                    ErrorClass::Protocol,
                    "TUIC UDP packet too large for buffer".to_string(),
                ));
            }

            buf[..data.len()].copy_from_slice(data);

            // Return dummy address for now - would need proper packet parsing
            let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);
            Ok((data.len(), addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_command_conversion() {
        assert_eq!(TuicCommand::Connect.to_byte(), 0x01);
        assert_eq!(TuicCommand::from_byte(0x01), Some(TuicCommand::Connect));

        assert_eq!(TuicCommand::Packet.to_byte(), 0x02);
        assert_eq!(TuicCommand::from_byte(0x02), Some(TuicCommand::Packet));

        assert_eq!(TuicCommand::Authenticate.to_byte(), 0x05);
        assert_eq!(
            TuicCommand::from_byte(0x05),
            Some(TuicCommand::Authenticate)
        );

        assert_eq!(TuicCommand::from_byte(0xFF), None);
    }

    #[test]
    fn test_tuic_address_type_conversion() {
        assert_eq!(TuicAddressType::Ipv4.to_byte(), 0x01);
        assert_eq!(
            TuicAddressType::from_byte(0x01),
            Some(TuicAddressType::Ipv4)
        );

        assert_eq!(TuicAddressType::Domain.to_byte(), 0x02);
        assert_eq!(
            TuicAddressType::from_byte(0x02),
            Some(TuicAddressType::Domain)
        );

        assert_eq!(TuicAddressType::Ipv6.to_byte(), 0x03);
        assert_eq!(
            TuicAddressType::from_byte(0x03),
            Some(TuicAddressType::Ipv6)
        );

        assert_eq!(TuicAddressType::from_byte(0xFF), None);
    }

    #[test]
    fn test_tuic_congestion_control() {
        assert_eq!(
            TuicCongestionControl::from_str("bbr"),
            TuicCongestionControl::Bbr
        );
        assert_eq!(
            TuicCongestionControl::from_str("cubic"),
            TuicCongestionControl::Cubic
        );
        assert_eq!(
            TuicCongestionControl::from_str("new_reno"),
            TuicCongestionControl::NewReno
        );
        assert_eq!(
            TuicCongestionControl::from_str("unknown"),
            TuicCongestionControl::Bbr
        );
    }

    #[test]
    fn test_tuic_udp_relay_mode() {
        assert_eq!(
            TuicUdpRelayMode::from_str("native"),
            TuicUdpRelayMode::Native
        );
        assert_eq!(TuicUdpRelayMode::from_str("quic"), TuicUdpRelayMode::Quic);
        assert_eq!(
            TuicUdpRelayMode::from_str("unknown"),
            TuicUdpRelayMode::Native
        );
    }

    #[test]
    fn test_tuic_connector_creation() {
        let config = TuicConfig {
            server: "example.com:443".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            password: "test_password".to_string(),
            congestion_control: "bbr".to_string(),
            udp_relay_mode: Some("native".to_string()),
            udp_over_stream: false,
            zero_rtt_handshake: false,
            heartbeat: 10000,
            connect_timeout_sec: Some(5),
            auth_timeout_sec: Some(3),
        };

        let connector = TuicConnector::new(config);
        assert!(connector.is_ok());

        let connector = connector.unwrap();
        assert_eq!(connector.connect_timeout, Duration::from_secs(5));
        assert_eq!(connector.congestion_control, TuicCongestionControl::Bbr);
        assert_eq!(connector.udp_relay_mode, TuicUdpRelayMode::Native);
    }

    #[test]
    fn test_tuic_connector_invalid_uuid() {
        let config = TuicConfig {
            server: "example.com:443".to_string(),
            uuid: "invalid-uuid".to_string(),
            password: "test_password".to_string(),
            congestion_control: "bbr".to_string(),
            udp_relay_mode: None,
            udp_over_stream: false,
            zero_rtt_handshake: false,
            heartbeat: 10000,
            connect_timeout_sec: None,
            auth_timeout_sec: None,
        };

        let connector = TuicConnector::new(config);
        assert!(connector.is_err());
    }

    #[test]
    fn test_tuic_auth_packet() {
        let uuid = Uuid::new_v4();
        let password = "test_password".to_string();
        let auth_packet = TuicAuthPacket::new(uuid, password.clone());

        let encoded = auth_packet.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], TuicCommand::Authenticate.to_byte());

        // Check UUID is present
        let uuid_bytes = &encoded[1..17];
        assert_eq!(uuid_bytes, uuid.as_bytes());

        // Check password length and password
        let password_len = encoded[17] as usize;
        assert_eq!(password_len, password.len());
        let password_bytes = &encoded[18..18 + password_len];
        assert_eq!(password_bytes, password.as_bytes());
    }

    #[test]
    fn test_tuic_connect_packet() {
        let endpoint = Endpoint::new("example.com", 443);
        let connect_packet = TuicConnectPacket::new(&endpoint);

        let encoded = connect_packet.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], TuicCommand::Connect.to_byte());
        assert_eq!(encoded[1], TuicAddressType::Domain.to_byte());

        // Check domain length and domain
        let domain_len = encoded[2] as usize;
        assert_eq!(domain_len, 11); // "example.com".len()
        let domain_bytes = &encoded[3..3 + domain_len];
        assert_eq!(domain_bytes, b"example.com");

        // Check port
        let port_bytes = &encoded[3 + domain_len..3 + domain_len + 2];
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        assert_eq!(port, 443);
    }

    #[test]
    fn test_tuic_packet() {
        let endpoint = Endpoint::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let data = b"test data".to_vec();
        let packet = TuicPacket::new(1, 2, &endpoint, data.clone());

        let encoded = packet.encode();
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], TuicCommand::Packet.to_byte());

        // Check session ID
        let session_id = u16::from_be_bytes([encoded[1], encoded[2]]);
        assert_eq!(session_id, 1);

        // Check packet ID
        let packet_id = u16::from_be_bytes([encoded[3], encoded[4]]);
        assert_eq!(packet_id, 2);

        // Check address type
        assert_eq!(encoded[7], TuicAddressType::Ipv4.to_byte());

        // Check IP address
        let ip_bytes = &encoded[8..12];
        assert_eq!(ip_bytes, &[127, 0, 0, 1]);

        // Check port
        let port_bytes = &encoded[12..14];
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_tuic_multiplexer() {
        let mut multiplexer = TuicMultiplexer::new();

        let session_id1 = multiplexer.create_session();
        let session_id2 = multiplexer.create_session();

        assert_ne!(session_id1, session_id2);
        assert!(multiplexer.get_session_mut(session_id1).is_some());
        assert!(multiplexer.get_session_mut(session_id2).is_some());

        let packet_id1 = multiplexer.next_packet_id();
        let packet_id2 = multiplexer.next_packet_id();

        assert_ne!(packet_id1, packet_id2);
    }
}
