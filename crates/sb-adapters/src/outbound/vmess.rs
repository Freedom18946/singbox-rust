//! VMess protocol outbound connector implementation

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Key, Nonce,
};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use rand::Rng;
use sb_core::{
    error::{ErrorClass, IssueCode, SbError, SbResult},
    outbound::traits::{OutboundConnector, UdpTransport},
    types::{ConnCtx, Endpoint, Host},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

/// VMess configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessConfig {
    pub server: String,
    pub uuid: String,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub alter_id: u16,
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
}

fn default_security() -> String {
    "auto".to_string()
}

/// VMess security methods
#[derive(Debug, Clone, PartialEq)]
pub enum VmessSecurity {
    Auto,
    Aes128Gcm,
    None,
}

impl VmessSecurity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "auto" => Self::Auto,
            "aes-128-gcm" => Self::Aes128Gcm,
            "none" => Self::None,
            _ => Self::Auto,
        }
    }
}

/// VMess command types
#[derive(Debug, Clone, Copy)]
pub enum VmessCommand {
    Tcp = 1,
    Udp = 2,
}

/// VMess address types
#[derive(Debug, Clone, Copy)]
pub enum VmessAddressType {
    Ipv4 = 1,
    Domain = 2,
    Ipv6 = 3,
}

/// VMess outbound connector
#[derive(Debug, Clone)]
pub struct VmessConnector {
    config: VmessConfig,
    user_id: Uuid,
    connect_timeout: Duration,
}

impl VmessConnector {
    /// Create a new VMess connector
    pub fn new(config: VmessConfig) -> SbResult<Self> {
        let user_id = Uuid::parse_str(&config.uuid).map_err(|e| {
            SbError::config(
                IssueCode::InvalidType,
                "vmess.uuid",
                format!("Invalid UUID format: {}", e),
            )
        })?;

        let connect_timeout = Duration::from_secs(config.connect_timeout_sec.unwrap_or(10));

        Ok(Self {
            config,
            user_id,
            connect_timeout,
        })
    }

    /// Resolve server address
    async fn resolve_server(&self) -> SbResult<SocketAddr> {
        let mut addrs = lookup_host(&self.config.server).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to resolve VMess server: {}", e),
            )
        })?;

        addrs.next().ok_or_else(|| {
            SbError::network(
                ErrorClass::Connection,
                "No addresses resolved for VMess server".to_string(),
            )
        })
    }

    /// Generate VMess request header
    pub fn generate_request_header(&self, cmd: VmessCommand, dst: &Endpoint) -> SbResult<Vec<u8>> {
        let mut header = Vec::new();

        // Version (1 byte)
        header.push(1);

        // Data IV (16 bytes)
        let mut data_iv = [0u8; 16];
        rand::thread_rng().fill(&mut data_iv);
        header.extend_from_slice(&data_iv);

        // Data Key (16 bytes)
        let mut data_key = [0u8; 16];
        rand::thread_rng().fill(&mut data_key);
        header.extend_from_slice(&data_key);

        // Response header (1 byte)
        header.push(rand::thread_rng().gen::<u8>());

        // Option (1 byte)
        header.push(0x01);

        // Command (1 byte)
        header.push(cmd as u8);

        // Port (2 bytes, big endian)
        header.extend_from_slice(&dst.port.to_be_bytes());

        // Address type and address
        match &dst.host {
            Host::Ip(IpAddr::V4(ipv4)) => {
                header.push(VmessAddressType::Ipv4 as u8);
                header.extend_from_slice(&ipv4.octets());
            }
            Host::Ip(IpAddr::V6(ipv6)) => {
                header.push(VmessAddressType::Ipv6 as u8);
                header.extend_from_slice(&ipv6.octets());
            }
            Host::Name(domain) => {
                header.push(VmessAddressType::Domain as u8);
                header.push(domain.len() as u8);
                header.extend_from_slice(domain.as_bytes());
            }
        }

        Ok(header)
    }

    /// Encrypt VMess request header using AEAD
    fn encrypt_request_header(&self, header: &[u8], timestamp: u64) -> SbResult<Vec<u8>> {
        // Generate authentication info
        let mut auth_info = Vec::new();
        auth_info.extend_from_slice(&timestamp.to_be_bytes());
        auth_info.extend_from_slice(&rand::thread_rng().gen::<[u8; 4]>());
        auth_info.extend_from_slice(&rand::thread_rng().gen::<[u8; 4]>());
        auth_info.push(rand::thread_rng().gen::<u8>());

        // Calculate HMAC
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.user_id.as_bytes()).map_err(|e| {
                SbError::network(
                    ErrorClass::Protocol,
                    format!("HMAC initialization failed: {}", e),
                )
            })?;
        mac.update(&auth_info);
        let auth_hash = mac.finalize().into_bytes();

        // Use first 16 bytes as AES key
        let key = Key::<Aes128Gcm>::from_slice(&auth_hash[..16]);
        let cipher = Aes128Gcm::new(key);

        // Generate nonce (12 bytes for AES-GCM)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&timestamp.to_be_bytes());
        nonce_bytes[8..].copy_from_slice(&rand::thread_rng().gen::<[u8; 4]>());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt header
        let encrypted = cipher.encrypt(nonce, header).map_err(|e| {
            SbError::network(
                ErrorClass::Protocol,
                format!("VMess header encryption failed: {}", e),
            )
        })?;

        // Construct final packet
        let mut packet = Vec::new();
        packet.extend_from_slice(&auth_info);
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&encrypted);

        Ok(packet)
    }

    /// Perform VMess handshake
    async fn handshake<S>(&self, stream: &mut S, dst: &Endpoint, cmd: VmessCommand) -> SbResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Generate request header
        let header = self.generate_request_header(cmd, dst)?;

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Encrypt and send header
        let encrypted_header = self.encrypt_request_header(&header, timestamp)?;
        stream.write_all(&encrypted_header).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to send VMess handshake: {}", e),
            )
        })?;

        // Read response header (4 bytes)
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("Failed to read VMess response: {}", e),
            )
        })?;

        Ok(())
    }
}

#[async_trait]
impl OutboundConnector for VmessConnector {
    async fn connect_tcp(&self, ctx: &ConnCtx) -> SbResult<TcpStream> {
        // Connect to VMess server
        let server_addr = self.resolve_server().await?;
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(server_addr))
            .await
            .map_err(|_| {
                SbError::timeout("vmess_tcp_connect", self.connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("VMess TCP connection failed: {}", e),
                )
            })?;

        // Perform VMess handshake
        self.handshake(&mut stream, &ctx.dst, VmessCommand::Tcp)
            .await?;

        Ok(stream)
    }

    async fn connect_udp(&self, ctx: &ConnCtx) -> SbResult<Box<dyn UdpTransport>> {
        // For VMess UDP, we establish a TCP connection and use it for UDP relay
        let server_addr = self.resolve_server().await?;
        let mut stream = timeout(self.connect_timeout, TcpStream::connect(server_addr))
            .await
            .map_err(|_| {
                SbError::timeout("vmess_udp_connect", self.connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| {
                SbError::network(
                    ErrorClass::Connection,
                    format!("VMess UDP connection failed: {}", e),
                )
            })?;

        // Perform VMess handshake for UDP
        self.handshake(&mut stream, &ctx.dst, VmessCommand::Udp)
            .await?;

        Ok(Box::new(VmessUdpTransport::new(stream)))
    }
}

/// VMess UDP transport over TCP connection
pub struct VmessUdpTransport {
    stream: std::sync::Arc<tokio::sync::Mutex<TcpStream>>,
}

impl VmessUdpTransport {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: std::sync::Arc::new(tokio::sync::Mutex::new(stream)),
        }
    }
}

#[async_trait]
impl UdpTransport for VmessUdpTransport {
    async fn send_to(&self, buf: &[u8], _dst: &Endpoint) -> SbResult<usize> {
        let mut stream = self.stream.lock().await;
        stream.write_all(buf).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("VMess UDP send failed: {}", e),
            )
        })?;

        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> SbResult<(usize, SocketAddr)> {
        let mut stream = self.stream.lock().await;
        let n = stream.read(buf).await.map_err(|e| {
            SbError::network(
                ErrorClass::Connection,
                format!("VMess UDP recv failed: {}", e),
            )
        })?;

        // Return dummy address for now
        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);
        Ok((n, addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_security_from_str() {
        assert_eq!(VmessSecurity::from_str("auto"), VmessSecurity::Auto);
        assert_eq!(
            VmessSecurity::from_str("aes-128-gcm"),
            VmessSecurity::Aes128Gcm
        );
        assert_eq!(VmessSecurity::from_str("none"), VmessSecurity::None);
        assert_eq!(VmessSecurity::from_str("unknown"), VmessSecurity::Auto);
    }

    #[test]
    fn test_vmess_connector_creation() {
        let config = VmessConfig {
            server: "example.com:443".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            security: "auto".to_string(),
            alter_id: 0,
            connect_timeout_sec: Some(5),
        };

        let connector = VmessConnector::new(config);
        assert!(connector.is_ok());

        let connector = connector.unwrap();
        assert_eq!(connector.connect_timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_vmess_connector_invalid_uuid() {
        let config = VmessConfig {
            server: "example.com:443".to_string(),
            uuid: "invalid-uuid".to_string(),
            security: "auto".to_string(),
            alter_id: 0,
            connect_timeout_sec: None,
        };

        let connector = VmessConnector::new(config);
        assert!(connector.is_err());
    }

    #[test]
    fn test_generate_request_header() {
        let config = VmessConfig {
            server: "example.com:443".to_string(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            security: "auto".to_string(),
            alter_id: 0,
            connect_timeout_sec: None,
        };

        let connector = VmessConnector::new(config).unwrap();
        let endpoint = Endpoint::new(Host::domain("example.com"), 80);

        let header = connector.generate_request_header(VmessCommand::Tcp, &endpoint);
        assert!(header.is_ok());

        let header = header.unwrap();
        assert!(!header.is_empty());
        assert_eq!(header[0], 1); // Version should be 1
    }
}
