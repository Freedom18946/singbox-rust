//! VMess outbound connector implementation
//! VMess 出站连接器实现
//!
//! This module provides VMess protocol support for outbound connections.
//! 本模块提供 VMess 协议的出站连接支持。
//! VMess is a stateful protocol used by V2Ray with strong encryption and obfuscation.
//! VMess 是 V2Ray 使用的一种有状态协议，具有强大的加密和混淆功能。

use crate::outbound::prelude::*;
use crate::transport_config::TransportConfig;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// VMess security levels
/// VMess 安全级别
#[derive(Debug, Clone, PartialEq)]
pub enum Security {
    /// No encryption (not recommended for production)
    /// 无加密 (不建议用于生产环境)
    None,
    /// AES-128-GCM
    Aes128Gcm,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// Auto selection based on client capabilities
    /// 根据客户端能力自动选择
    Auto,
    /// Zero encryption (legacy)
    /// 零加密 (旧版)
    Zero,
}

impl Security {
    #[allow(dead_code)]
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
/// VMess 认证设置
#[derive(Debug, Clone)]
pub struct VmessAuth {
    /// User UUID
    /// 用户 UUID
    pub uuid: Uuid,
    /// Alter ID for additional security (0-65535)
    /// Alter ID 用于额外的安全性 (0-65535)
    pub alter_id: u16,
    /// Security level
    /// 安全级别
    pub security: Security,
    /// Additional authentication data
    /// 额外的认证数据
    pub additional_data: Option<Vec<u8>>,
}

/// VMess transport settings
/// VMess 传输设置
#[derive(Debug, Clone)]
pub struct VmessTransport {
    /// Enable TCP fast open
    /// 启用 TCP 快速打开
    pub tcp_fast_open: bool,
    /// Enable TCP no delay
    /// 启用 TCP 无延迟
    pub tcp_no_delay: bool,
    /// Connection keep alive interval
    /// 连接保持活跃间隔
    pub keep_alive: Option<std::time::Duration>,
    /// Socket mark (Linux only)
    /// Socket 标记 (仅限 Linux)
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
/// VMess 配置
#[derive(Debug, Clone)]
pub struct VmessConfig {
    /// Server address and port
    /// 服务端地址和端口
    pub server_addr: SocketAddr,
    /// Authentication settings
    /// 认证设置
    pub auth: VmessAuth,
    /// Transport settings (TCP-level options)
    /// 传输设置 (TCP 级选项)
    pub transport: VmessTransport,
    /// Transport layer (TCP/WebSocket/gRPC/HTTPUpgrade)
    /// 传输层 (TCP/WebSocket/gRPC/HTTPUpgrade)
    pub transport_layer: TransportConfig,
    /// Connection timeout
    /// 连接超时
    pub timeout: Option<std::time::Duration>,
    /// Enable packet encoding
    /// 启用数据包编码
    pub packet_encoding: bool,
    /// Custom headers for obfuscation
    /// 用于混淆的自定义头
    pub headers: HashMap<String, String>,
    /// Multiplex configuration
    /// 多路复用配置
    #[cfg(feature = "transport_mux")]
    pub multiplex: Option<sb_transport::multiplex::MultiplexConfig>,
    /// TLS configuration (experimental, requires working TLS transport layer)
    /// TLS 配置 (实验性，需要工作的 TLS 传输层)
    #[cfg(feature = "transport_tls")]
    pub tls: Option<sb_transport::TlsConfig>,
}

impl Default for VmessConfig {
    fn default() -> Self {
        Self {
            server_addr: SocketAddr::from(([127, 0, 0, 1], 443)),
            auth: VmessAuth {
                uuid: Uuid::new_v4(),
                alter_id: 0,
                security: Security::Auto,
                additional_data: None,
            },
            transport: VmessTransport::default(),
            transport_layer: TransportConfig::default(),
            timeout: Some(std::time::Duration::from_secs(30)),
            packet_encoding: false,
            headers: HashMap::new(),
            #[cfg(feature = "transport_mux")]
            multiplex: None,
            #[cfg(feature = "transport_tls")]
            tls: None,
        }
    }
}

/// VMess request header structure
/// VMess 请求头结构
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
/// VMess 出站连接器
#[derive(Clone)]
pub struct VmessConnector {
    config: VmessConfig,
    /// Cached authentication data
    /// 缓存的认证数据
    #[allow(dead_code)]
    auth_cache: Option<Vec<u8>>,
    /// Transport dialer with optional TLS and Multiplex layers
    /// 带有可选 TLS 和多路复用层的传输拨号器
    #[cfg(feature = "sb-transport")]
    dialer: Option<std::sync::Arc<dyn sb_transport::Dialer>>,
}

impl std::fmt::Debug for VmessConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessConnector")
            .field("config", &self.config)
            .field("auth_cache", &self.auth_cache)
            .field("dialer", &"<dialer>")
            .finish()
    }
}

impl VmessConnector {
    /// Create a new VMess connector with the given configuration
    /// 使用给定的配置创建一个新的 VMess 连接器
    pub fn new(config: VmessConfig) -> Self {
        // Create dialer with transport layer, TLS, and multiplex layers
        // 创建带有传输层、TLS 和多路复用层的拨号器
        #[cfg(feature = "sb-transport")]
        let dialer = {
            #[cfg(feature = "transport_tls")]
            let tls_config = config.tls.as_ref();
            #[cfg(not(feature = "transport_tls"))]
            let tls_config = None;

            #[cfg(feature = "transport_mux")]
            let multiplex_config = config.multiplex.as_ref();
            #[cfg(not(feature = "transport_mux"))]
            let multiplex_config = None;

            Some(
                config
                    .transport_layer
                    .create_dialer_with_layers(tls_config, multiplex_config),
            )
        };

        Self {
            config,
            auth_cache: None,
            #[cfg(feature = "sb-transport")]
            dialer,
        }
    }

    /// Generate VMess authentication data
    /// 生成 VMess 认证数据
    fn generate_auth_data(&self) -> Vec<u8> {
        let mut auth_data = Vec::new();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
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
    /// 构建 VMess 请求头
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
    /// 序列化 VMess 请求头
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
    /// 执行 VMess 握手
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

        stream
            .write_all(&header_data)
            .await
            .map_err(AdapterError::Io)?;

        // Read response
        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .await
            .map_err(AdapterError::Io)?;

        // Verify response authentication
        if response != request_header.response_auth {
            return Err(AdapterError::Other(
                "VMess authentication failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Create connection to VMess server
    /// 创建到 VMess 服务端的连接
    async fn create_connection(&self) -> Result<BoxedStream> {
        let timeout = self
            .config
            .timeout
            .unwrap_or(std::time::Duration::from_secs(30));

        #[cfg(feature = "sb-transport")]
        {
            // Use the configured dialer (which already has Transport → TLS → Multiplex layers)
            // 使用配置的拨号器 (已经包含 传输 → TLS → 多路复用 层)
            if let Some(ref dialer) = self.dialer {
                tracing::debug!(
                    "Using transport dialer for VMess connection (transport: {:?})",
                    self.config.transport_layer.transport_type()
                );

                let stream = tokio::time::timeout(
                    timeout,
                    dialer.connect(
                        &self.config.server_addr.ip().to_string(),
                        self.config.server_addr.port(),
                    ),
                )
                .await
                .map_err(|_| AdapterError::Timeout(timeout))?
                .map_err(|e| AdapterError::Other(format!("Transport dial failed: {}", e)))?;

                return Ok(crate::traits::from_transport_stream(stream));
            }
        }

        // Fallback to direct TCP connection (for backward compatibility or when sb-transport feature is disabled)
        // 回退到直接 TCP 连接 (为了向后兼容或当 sb-transport 特性被禁用时)
        tracing::debug!("Using direct TCP connection for VMess");
        let tcp_stream = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(self.config.server_addr),
        )
        .await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(AdapterError::Io)?;

        // Configure transport options
        if self.config.transport.tcp_no_delay {
            if let Err(e) = tcp_stream.set_nodelay(true) {
                tracing::warn!("Failed to set TCP_NODELAY: {}", e);
            }
        }

        Ok(Box::new(tcp_stream))
    }

    /// Validate configuration
    /// 验证配置
    fn validate_config(&self) -> Result<()> {
        if self.config.auth.uuid.is_nil() {
            return Err(AdapterError::InvalidConfig("VMess UUID cannot be nil"));
        }

        // alter_id is u16, so it's always <= 65535
        // Validation passes automatically

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
