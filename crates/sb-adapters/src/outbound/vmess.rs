//! VMess outbound connector implementation
//!
//! This module provides VMess protocol support for outbound connections.
//! VMess is a stateful protocol used by V2Ray with strong encryption and obfuscation.

use crate::outbound::prelude::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;
use rand::Rng;

/// VMess security levels
#[derive(Debug, Clone, PartialEq)]
pub enum Security {
    /// No encryption (not recommended for production)
    None,
    /// AES-128-GCM
    Aes128Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// Auto selection based on client capabilities
    Auto,
    /// Zero encryption (legacy)
    Zero,
}

impl Security {
    fn as_str(&self) -> &str {
        match self {
            Security::None => "none",
            Security::Aes128Gcm => "aes-128-gcm",
            Security::ChaCha20Poly1305 => "chacha20-poly1305",
            Security::Auto => "auto",
            Security::Zero => "zero",
        }
    }

    fn cipher_id(&self) -> u8 {
        match self {
            Security::None => 0,
            Security::Aes128Gcm => 3,
            Security::ChaCha20Poly1305 => 4,
            Security::Auto => 0, // Will be negotiated
            Security::Zero => 0,
        }
    }
}

/// VMess authentication settings
#[derive(Debug, Clone)]
pub struct VmessAuth {
    /// User UUID
    pub uuid: Uuid,
    /// Alter ID for additional security (0-65535)
    pub alter_id: u16,
    /// Security level
    pub security: Security,
    /// Additional authentication data
    pub additional_data: Option<Vec<u8>>,
}

/// VMess transport settings
#[derive(Debug, Clone)]
pub struct VmessTransport {
    /// Enable TCP fast open
    pub tcp_fast_open: bool,
    /// Enable TCP no delay
    pub tcp_no_delay: bool,
    /// Connection keep alive interval
    pub keep_alive: Option<std::time::Duration>,
    /// Socket mark (Linux only)
    pub socket_mark: Option<u32>,
}

impl Default for VmessTransport {
    fn default() -> Self {
        Self {
            tcp_fast_open: false,
            tcp_no_delay: true,
            keep_alive: Some(std::time::Duration::from_secs(30)),
            socket_mark: None,
        }
    }
}

/// VMess configuration
#[derive(Debug, Clone)]
pub struct VmessConfig {
    /// Server address and port
    pub server_addr: SocketAddr,
    /// Authentication settings
    pub auth: VmessAuth,
    /// Transport settings
    pub transport: VmessTransport,
    /// Connection timeout
    pub timeout: Option<std::time::Duration>,
    /// Enable packet encoding
    pub packet_encoding: bool,
    /// Custom headers for obfuscation
    pub headers: HashMap<String, String>,
}

impl Default for VmessConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:443".parse().unwrap(),
            auth: VmessAuth {
                uuid: Uuid::new_v4(),
                alter_id: 0,
                security: Security::Auto,
                additional_data: None,
            },
            transport: VmessTransport::default(),
            timeout: Some(std::time::Duration::from_secs(30)),
            packet_encoding: false,
            headers: HashMap::new(),
        }
    }
}

/// VMess request header structure
#[derive(Debug)]
struct VmessRequestHeader {
    version: u8,
    iv: [u8; 16],
    key: [u8; 16],
    response_auth: [u8; 4],
    command: u8,
    port: u16,
    address_type: u8,
    address: Vec<u8>,
    random: [u8; 16],
}

/// VMess outbound connector
#[derive(Debug, Clone)]
pub struct VmessConnector {
    config: VmessConfig,
    /// Cached authentication data
    auth_cache: Option<Vec<u8>>,
}

impl VmessConnector {
    /// Create a new VMess connector with the given configuration
    pub fn new(config: VmessConfig) -> Self {
        Self {
            config,
            auth_cache: None,
        }
    }

    /// Generate VMess authentication data
    fn generate_auth_data(&self) -> Vec<u8> {
        let mut auth_data = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add timestamp (8 bytes)
        auth_data.extend_from_slice(&timestamp.to_be_bytes());

        // Add UUID (16 bytes)
        auth_data.extend_from_slice(self.config.auth.uuid.as_bytes());

        // Add alter ID (2 bytes)
        auth_data.extend_from_slice(&self.config.auth.alter_id.to_be_bytes());

        // Add security method (1 byte)
        auth_data.push(self.config.auth.security.cipher_id());

        // Add random padding (4 bytes)
        let mut rng = rand::thread_rng();
        for _ in 0..4 {
            auth_data.push(rng.gen());
        }

        auth_data
    }

    /// Build VMess request header
    fn build_request_header(&self, target: &Target) -> VmessRequestHeader {
        let mut rng = rand::thread_rng();

        // Generate random IV and key
        let mut iv = [0u8; 16];
        let mut key = [0u8; 16];
        let mut response_auth = [0u8; 4];
        let mut random_data = [0u8; 16];

        rng.fill(&mut iv);
        rng.fill(&mut key);
        rng.fill(&mut response_auth);
        rng.fill(&mut random_data);

        // Determine address type and encode address
        let (address_type, address) = match target.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ipv4)) => (1u8, ipv4.octets().to_vec()),
            Ok(std::net::IpAddr::V6(ipv6)) => (3u8, ipv6.octets().to_vec()),
            Err(_) => {
                let mut addr_bytes = Vec::new();
                addr_bytes.push(target.host.len() as u8);
                addr_bytes.extend_from_slice(target.host.as_bytes());
                (2u8, addr_bytes)
            }
        };

        VmessRequestHeader {
            version: 1,
            iv,
            key,
            response_auth,
            command: 1, // TCP
            port: target.port,
            address_type,
            address,
            random: random_data,
        }
    }

    /// Serialize VMess request header
    fn serialize_request_header(&self, header: &VmessRequestHeader) -> Vec<u8> {
        let mut data = Vec::new();

        // Version
        data.push(header.version);

        // IV
        data.extend_from_slice(&header.iv);

        // Key
        data.extend_from_slice(&header.key);

        // Response auth
        data.extend_from_slice(&header.response_auth);

        // Command
        data.push(header.command);

        // Port (big endian)
        data.extend_from_slice(&header.port.to_be_bytes());

        // Address type
        data.push(header.address_type);

        // Address
        data.extend_from_slice(&header.address);

        // Random data
        data.extend_from_slice(&header.random);

        data
    }

    /// Perform VMess handshake
    async fn handshake(&self, stream: &mut BoxedStream, target: &Target) -> Result<()> {
        // Generate authentication data
        let auth_data = self.generate_auth_data();

        // Send authentication data
        stream
            .write_all(&auth_data)
            .await
            .map_err(AdapterError::Io)?;

        // Build and send request header
        let request_header = self.build_request_header(target);
        let header_data = self.serialize_request_header(&request_header);

        stream.write_all(&header_data).await.map_err(AdapterError::Io)?;

        // Read response
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.map_err(AdapterError::Io)?;

        // Verify response authentication
        if response != request_header.response_auth {
            return Err(AdapterError::Other("VMess authentication failed".to_string()));
        }

        Ok(())
    }

    /// Create connection to VMess server
    async fn create_connection(&self) -> Result<BoxedStream> {
        let timeout = self.config.timeout.unwrap_or(std::time::Duration::from_secs(30));

        // Connect with timeout
        let tcp_stream = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(self.config.server_addr)
        ).await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(AdapterError::Io)?;

        // Configure transport options
        if self.config.transport.tcp_no_delay {
            if let Err(e) = tcp_stream.set_nodelay(true) {
                tracing::warn!("Failed to set TCP_NODELAY: {}", e);
            }
        }

        let boxed_stream: BoxedStream = Box::new(tcp_stream);
        Ok(boxed_stream)
    }

    /// Validate configuration
    fn validate_config(&self) -> Result<()> {
        if self.config.auth.uuid.is_nil() {
            return Err(AdapterError::InvalidConfig("VMess UUID cannot be nil"));
        }

        if self.config.auth.alter_id > 65535 {
            return Err(AdapterError::InvalidConfig(
                "VMess alter_id must be between 0 and 65535",
            ));
        }

        Ok(())
    }
}

impl Default for VmessConnector {
    fn default() -> Self {
        Self::new(VmessConfig::default())
    }
}

#[async_trait]
impl OutboundConnector for VmessConnector {
    fn name(&self) -> &'static str {
        "vmess"
    }

    async fn start(&self) -> Result<()> {
        // Validate configuration
        self.validate_config()?;

        // Test connectivity (optional)
        if let Err(e) = tokio::net::TcpStream::connect(self.config.server_addr).await {
            tracing::warn!("VMess server connectivity test failed: {}", e);
        }

        tracing::info!(
            "VMess connector started - server: {}, security: {:?}, alter_id: {}",
            self.config.server_addr,
            self.config.auth.security,
            self.config.auth.alter_id
        );

        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        tracing::debug!("VMess dialing target: {:?}", target);

        // Create connection to VMess server
        let mut stream = self.create_connection().await?;

        // Perform VMess handshake
        self.handshake(&mut stream, &target).await?;

        tracing::debug!("VMess connection established to: {:?}", target);

        Ok(stream)
    }
}
