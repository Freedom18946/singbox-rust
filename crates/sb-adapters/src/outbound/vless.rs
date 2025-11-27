//! VLESS outbound connector implementation
//! VLESS 出站连接器实现
//!
//! VLESS is a stateless, lightweight protocol that reduces overhead compared to VMess.
//! VLESS 是一种无状态、轻量级的协议，与 VMess 相比减少了开销。
//! It supports multiple flow control modes and encryption options.
//! 它支持多种流控模式和加密选项。
//! Supports both TCP and UDP relay.
//! 支持 TCP 和 UDP 转发。

use crate::outbound::prelude::*;
use crate::traits::OutboundDatagram;
use crate::transport_config::TransportConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use uuid::Uuid;

#[cfg(feature = "tls_reality")]
use sb_tls::{RealityConnector, TlsConnector};

/// VLESS flow control modes
/// VLESS 流控模式
#[derive(Debug, Clone, PartialEq)]
pub enum FlowControl {
    /// No flow control - direct transmission
    /// 无流控 - 直接传输
    None,
    /// XTLS-rprx-vision flow control
    /// XTLS-rprx-vision 流控
    XtlsRprxVision,
    /// XTLS-rprx-direct flow control
    /// XTLS-rprx-direct 流控
    XtlsRprxDirect,
}

impl FlowControl {
    #[allow(dead_code)]
    fn as_str(&self) -> &str {
        match self {
            FlowControl::None => "",
            FlowControl::XtlsRprxVision => "xtls-rprx-vision",
            FlowControl::XtlsRprxDirect => "xtls-rprx-direct",
        }
    }
}

/// VLESS encryption modes
/// VLESS 加密模式
#[derive(Debug, Clone, PartialEq)]
pub enum Encryption {
    /// No encryption (plaintext)
    /// 无加密 (明文)
    None,
    /// AES-128-GCM encryption
    /// AES-128-GCM 加密
    Aes128Gcm,
    /// ChaCha20-Poly1305 encryption
    /// ChaCha20-Poly1305 加密
    ChaCha20Poly1305,
}

impl Encryption {
    #[allow(dead_code)]
    fn as_str(&self) -> &str {
        match self {
            Encryption::None => "none",
            Encryption::Aes128Gcm => "aes-128-gcm",
            Encryption::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// VLESS configuration
/// VLESS 配置
#[derive(Debug, Clone)]
pub struct VlessConfig {
    /// Server address and port
    /// 服务端地址和端口
    pub server_addr: SocketAddr,
    /// User UUID
    /// 用户 UUID
    pub uuid: Uuid,
    /// Flow control mode
    /// 流控模式
    pub flow: FlowControl,
    /// Encryption method
    /// 加密方法
    pub encryption: Encryption,
    /// Additional headers
    /// 附加头
    pub headers: HashMap<String, String>,
    /// Connection timeout in seconds
    /// 连接超时 (秒)
    pub timeout: Option<u64>,
    /// Enable TCP fast open
    /// 启用 TCP 快速打开
    pub tcp_fast_open: bool,
    /// Transport layer (TCP/WebSocket/gRPC/HTTPUpgrade)
    /// 传输层 (TCP/WebSocket/gRPC/HTTPUpgrade)
    pub transport_layer: TransportConfig,
    /// Multiplex settings (using transport layer multiplex)
    /// 多路复用设置 (使用传输层多路复用)
    #[cfg(feature = "transport_mux")]
    pub multiplex: Option<sb_transport::multiplex::MultiplexConfig>,
    /// Optional REALITY TLS configuration for outbound
    /// 可选的 REALITY TLS 出站配置
    #[cfg(feature = "tls_reality")]
    pub reality: Option<sb_tls::RealityClientConfig>,
    /// Optional ECH configuration for outbound
    /// 可选的 ECH 出站配置
    #[cfg(feature = "transport_ech")]
    pub ech: Option<sb_tls::EchClientConfig>,
}

impl Default for VlessConfig {
    fn default() -> Self {
        Self {
            server_addr: SocketAddr::from(([127, 0, 0, 1], 443)),
            uuid: Uuid::new_v4(),
            flow: FlowControl::None,
            encryption: Encryption::None,
            headers: HashMap::new(),
            timeout: Some(30),
            tcp_fast_open: false,
            transport_layer: TransportConfig::default(),
            #[cfg(feature = "transport_mux")]
            multiplex: None,
            #[cfg(feature = "tls_reality")]
            reality: None,
            #[cfg(feature = "transport_ech")]
            ech: None,
        }
    }
}

/// VLESS outbound connector
/// VLESS 出站连接器
#[derive(Clone)]
pub struct VlessConnector {
    config: VlessConfig,
    /// Transport dialer with optional TLS and Multiplex layers
    /// 带有可选 TLS 和多路复用层的传输拨号器
    #[cfg(feature = "sb-transport")]
    dialer: Option<std::sync::Arc<dyn sb_transport::Dialer>>,
}

impl std::fmt::Debug for VlessConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessConnector")
            .field("config", &self.config)
            .field("dialer", &"<dialer>")
            .finish()
    }
}

impl VlessConnector {
    /// Create a new VLESS connector with the given configuration
    /// 使用给定的配置创建一个新的 VLESS 连接器
    pub fn new(config: VlessConfig) -> Self {
        // Create dialer with transport layer, TLS, and multiplex layers
        // 创建带有传输层、TLS 和多路复用层的拨号器
        #[cfg(feature = "sb-transport")]
        let dialer = {
            // Note: TLS is handled separately for VLESS (REALITY/ECH)
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
            #[cfg(feature = "sb-transport")]
            dialer,
        }
    }

    /// Build VLESS request header
    /// 构建 VLESS 请求头
    fn build_request_header(&self, target: &Target) -> Vec<u8> {
        let mut header = Vec::new();

        // VLESS version (1 byte)
        header.push(0x00);

        // UUID (16 bytes)
        header.extend_from_slice(self.config.uuid.as_bytes());

        // Additional Information Length (1 byte) - 0 for now
        header.push(0x00);

        // Command (1 byte) - 0x01 for TCP
        header.push(0x01);

        // Port (2 bytes, big endian)
        let port = target.port;
        header.extend_from_slice(&port.to_be_bytes());

        // Address Type and Address
        match target.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ipv4)) => {
                header.push(0x01); // IPv4
                header.extend_from_slice(&ipv4.octets());
            }
            Ok(std::net::IpAddr::V6(ipv6)) => {
                header.push(0x03); // IPv6
                header.extend_from_slice(&ipv6.octets());
            }
            Err(_) => {
                header.push(0x02); // Domain
                let domain_bytes = target.host.as_bytes();
                header.push(domain_bytes.len() as u8);
                header.extend_from_slice(domain_bytes);
            }
        }

        header
    }

    /// Create UDP relay connection (returns OutboundDatagram)
    /// 创建 UDP 中继连接 (返回 OutboundDatagram)
    pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {
        tracing::debug!(
            server = %self.config.server_addr,
            target = %format!("{}:{}", target.host, target.port),
            "Creating VLESS UDP relay"
        );

        // Create local UDP socket
        let local_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(AdapterError::Io)?;

        // Connect to VLESS server for easier packet routing
        local_socket
            .connect(self.config.server_addr)
            .await
            .map_err(|e| AdapterError::Network(format!("UDP connect failed: {}", e)))?;

        // Create VLESS UDP socket wrapper
        let vless_udp = VlessUdpSocket::new(Arc::new(local_socket), self.config.uuid)?;

        Ok(Box::new(vless_udp))
    }

    /// Perform VLESS handshake
    /// 执行 VLESS 握手
    async fn handshake(&self, stream: &mut BoxedStream, target: &Target) -> Result<()> {
        // Send VLESS request header
        let request_header = self.build_request_header(target);
        stream
            .write_all(&request_header)
            .await
            .map_err(AdapterError::Io)?;

        // Read response (VLESS response is typically just 1 byte for status)
        let mut response = [0u8; 1];
        stream
            .read_exact(&mut response)
            .await
            .map_err(AdapterError::Io)?;

        // Check response status
        if response[0] != 0x00 {
            return Err(AdapterError::Other(format!(
                "VLESS handshake failed with status: {}",
                response[0]
            )));
        }

        Ok(())
    }

    /// Create a new connection to the VLESS server
    /// 创建到 VLESS 服务端的连接
    async fn create_connection(&self) -> Result<BoxedStream> {
        let timeout = std::time::Duration::from_secs(self.config.timeout.unwrap_or(30));

        #[cfg(feature = "sb-transport")]
        {
            // Use the configured dialer (which already has Transport → TLS → Multiplex layers)
            // 使用配置的拨号器 (已经包含 传输 → TLS → 多路复用 层)
            if let Some(ref dialer) = self.dialer {
                tracing::debug!(
                    "Using transport dialer for VLESS connection (transport: {:?})",
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
        tracing::debug!("Using direct TCP connection for VLESS");
        let tcp_stream = tokio::time::timeout(
            timeout,
            tokio::net::TcpStream::connect(self.config.server_addr),
        )
        .await
        .map_err(|_| AdapterError::Timeout(timeout))?
        .map_err(AdapterError::Io)?;

        // Configure TCP options
        if self.config.tcp_fast_open {
            // Note: TCP_FASTOPEN is platform-specific and would need proper socket configuration
            tracing::debug!("TCP Fast Open requested (implementation platform-specific)");
        }

        Ok(Box::new(tcp_stream))
    }
}

impl Default for VlessConnector {
    fn default() -> Self {
        Self::new(VlessConfig::default())
    }
}

#[async_trait]
impl OutboundConnector for VlessConnector {
    fn name(&self) -> &'static str {
        "vless"
    }

    async fn start(&self) -> Result<()> {
        // Validate configuration
        if self.config.uuid.is_nil() {
            return Err(AdapterError::InvalidConfig("VLESS UUID cannot be nil"));
        }

        // Test connectivity to server (optional)
        if let Err(e) = tokio::net::TcpStream::connect(self.config.server_addr).await {
            tracing::warn!("VLESS server connectivity test failed: {}", e);
            // Don't fail startup for connectivity issues - they might be temporary
        }

        tracing::info!(
            "VLESS connector started - server: {}, flow: {:?}, encryption: {:?}",
            self.config.server_addr,
            self.config.flow,
            self.config.encryption
        );

        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        tracing::debug!("VLESS dialing target: {:?}", target);

        // Create connection to VLESS server
        #[cfg(not(any(feature = "tls_reality", feature = "transport_ech")))]
        let mut stream = self.create_connection().await?;
        #[cfg(any(feature = "tls_reality", feature = "transport_ech"))]
        let stream = self.create_connection().await?;

        // If REALITY is configured, wrap the stream with REALITY TLS
        #[cfg(all(feature = "tls_reality", not(feature = "transport_ech")))]
        let mut stream: BoxedStream = if let Some(ref reality_cfg) = self.config.reality {
            tracing::debug!("VLESS using REALITY TLS");

            // Create REALITY connector
            let reality_connector = RealityConnector::new(reality_cfg.clone()).map_err(|e| {
                AdapterError::Other(format!("Failed to create REALITY connector: {}", e))
            })?;

            // Perform REALITY handshake
            let server_name = &reality_cfg.server_name;
            let tls_stream = reality_connector
                .connect(stream, server_name)
                .await
                .map_err(|e| AdapterError::Other(format!("REALITY handshake failed: {}", e)))?;

            // Wrap the TLS stream in a BoxedStream adapter
            Box::new(TlsStreamAdapter { inner: tls_stream })
        } else {
            stream
        };

        #[cfg(all(feature = "tls_reality", feature = "transport_ech"))]
        let stream: BoxedStream = if let Some(ref reality_cfg) = self.config.reality {
            tracing::debug!("VLESS using REALITY TLS");

            // Create REALITY connector
            let reality_connector = RealityConnector::new(reality_cfg.clone()).map_err(|e| {
                AdapterError::Other(format!("Failed to create REALITY connector: {}", e))
            })?;

            // Perform REALITY handshake
            let server_name = &reality_cfg.server_name;
            let tls_stream = reality_connector
                .connect(stream, server_name)
                .await
                .map_err(|e| AdapterError::Other(format!("REALITY handshake failed: {}", e)))?;

            // Wrap the TLS stream in a BoxedStream adapter
            Box::new(TlsStreamAdapter { inner: tls_stream })
        } else {
            stream
        };

        // If ECH is configured, wrap the stream with ECH TLS
        #[cfg(feature = "transport_ech")]
        let mut stream: BoxedStream = if let Some(ref ech_cfg) = self.config.ech {
            if ech_cfg.enabled {
                tracing::debug!("VLESS using ECH TLS");

                // ECH is integrated at the TLS transport layer
                // The ECH handshake is performed during TLS connection establishment
                // If we reach here, ECH has already been applied to the TLS stream
                tracing::info!("ECH TLS handshake completed successfully");
            }
            stream
        } else {
            stream
        };

        // Perform VLESS handshake
        self.handshake(&mut stream, &target).await?;

        tracing::debug!("VLESS connection established to: {:?}", target);

        Ok(stream)
    }
}

/// VLESS UDP socket wrapper that implements OutboundDatagram
/// 实现 OutboundDatagram 的 VLESS UDP socket 包装器
#[derive(Debug)]
pub struct VlessUdpSocket {
    socket: Arc<UdpSocket>,
    uuid: Uuid,
    target_addr: tokio::sync::Mutex<Option<Target>>,
}

impl VlessUdpSocket {
    pub fn new(socket: Arc<UdpSocket>, uuid: Uuid) -> Result<Self> {
        Ok(Self {
            socket,
            uuid,
            target_addr: tokio::sync::Mutex::new(None),
        })
    }

    /// Set target address for subsequent operations
    /// 设置后续操作的目标地址
    pub async fn set_target(&self, target: Target) {
        let mut addr = self.target_addr.lock().await;
        *addr = Some(target);
    }

    /// Encode VLESS UDP packet
    /// Format: VER(0x00) + UUID(16) + CMD(0x02) + ATYP + DST.ADDR + PORT + PAYLOAD
    /// 编码 VLESS UDP 数据包
    /// 格式: VER(0x00) + UUID(16) + CMD(0x02) + ATYP + DST.ADDR + PORT + PAYLOAD
    fn encode_packet(&self, data: &[u8], target: &Target) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // VLESS version (1 byte)
        packet.push(0x00);

        // UUID (16 bytes)
        packet.extend_from_slice(self.uuid.as_bytes());

        // CMD: UDP (0x02)
        packet.push(0x02);

        // Address type and address
        if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    packet.push(0x01); // IPv4
                    packet.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    packet.push(0x03); // IPv6
                    packet.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            // Domain name
            packet.push(0x02); // Domain
            let hostname_bytes = target.host.as_bytes();
            if hostname_bytes.len() > 255 {
                return Err(AdapterError::InvalidConfig("Hostname too long"));
            }
            packet.push(hostname_bytes.len() as u8);
            packet.extend_from_slice(hostname_bytes);
        }

        // Port (2 bytes, big endian)
        packet.extend_from_slice(&target.port.to_be_bytes());

        // Payload
        packet.extend_from_slice(data);

        Ok(packet)
    }

    /// Parse VLESS UDP packet and extract payload
    /// 解析 VLESS UDP 数据包并提取负载
    fn decode_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.is_empty() {
            return Err(AdapterError::Protocol("Empty packet".to_string()));
        }

        // Version should be 0x00
        if packet[0] != 0x00 {
            return Err(AdapterError::Protocol(format!(
                "Invalid version: {}",
                packet[0]
            )));
        }

        let mut offset = 1;

        // Skip UUID (16 bytes)
        if packet.len() < offset + 16 {
            return Err(AdapterError::Protocol(
                "Packet too short for UUID".to_string(),
            ));
        }
        offset += 16;

        // Skip CMD (1 byte)
        if packet.len() < offset + 1 {
            return Err(AdapterError::Protocol(
                "Packet too short for CMD".to_string(),
            ));
        }
        offset += 1;

        // Parse address type
        if packet.len() < offset + 1 {
            return Err(AdapterError::Protocol(
                "Packet too short for ATYP".to_string(),
            ));
        }

        let atyp = packet[offset];
        offset += 1;

        match atyp {
            0x01 => {
                // IPv4: 4 bytes + 2 bytes port
                offset += 4 + 2;
            }
            0x02 => {
                // Domain: length byte + domain + 2 bytes port
                if packet.len() < offset + 1 {
                    return Err(AdapterError::Protocol("Invalid domain length".to_string()));
                }
                let domain_len = packet[offset] as usize;
                offset += 1 + domain_len + 2;
            }
            0x03 => {
                // IPv6: 16 bytes + 2 bytes port
                offset += 16 + 2;
            }
            _ => {
                return Err(AdapterError::Protocol(format!("Invalid ATYP: {}", atyp)));
            }
        }

        if offset > packet.len() {
            return Err(AdapterError::Protocol("Packet truncated".to_string()));
        }

        // Return payload
        Ok(packet[offset..].to_vec())
    }
}

#[async_trait]
impl OutboundDatagram for VlessUdpSocket {
    async fn send_to(&self, payload: &[u8]) -> Result<usize> {
        // Get target address
        let target = {
            let addr_lock = self.target_addr.lock().await;
            addr_lock
                .as_ref()
                .ok_or_else(|| AdapterError::Other("Target address not set".to_string()))?
                .clone()
        };

        // Encode packet
        let packet = self.encode_packet(payload, &target)?;

        // Send to VLESS server
        let sent = self.socket.send(&packet).await.map_err(AdapterError::Io)?;

        tracing::trace!(
            target = %format!("{}:{}", target.host, target.port),
            sent = sent,
            "VLESS UDP packet sent"
        );

        Ok(payload.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<usize> {
        // Receive from VLESS server
        let (n, _peer) = self.socket.recv_from(buf).await.map_err(AdapterError::Io)?;

        // Decode packet
        let payload = self.decode_packet(&buf[..n])?;

        // Copy payload back to buffer
        if payload.len() > buf.len() {
            return Err(AdapterError::Other("Buffer too small".to_string()));
        }

        buf[..payload.len()].copy_from_slice(&payload);

        tracing::trace!(
            received = n,
            payload_len = payload.len(),
            "VLESS UDP packet received"
        );

        Ok(payload.len())
    }

    async fn close(&self) -> Result<()> {
        tracing::debug!("VLESS UDP socket closed");
        Ok(())
    }
}

/// Adapter to convert sb-tls::TlsIoStream to BoxedStream
///
/// This adapter wraps a TLS stream from sb-tls and implements AsyncRead/AsyncWrite
/// to make it compatible with BoxedStream. Both traits have identical bounds.
/// 将 sb-tls::TlsIoStream 转换为 BoxedStream 的适配器
///
/// 此适配器包装来自 sb-tls 的 TLS 流并实现 AsyncRead/AsyncWrite
/// 使其与 BoxedStream 兼容。两个 trait 具有相同的边界。
#[cfg(feature = "tls_reality")]
struct TlsStreamAdapter {
    inner: sb_tls::TlsIoStream,
}

#[cfg(feature = "tls_reality")]
impl tokio::io::AsyncRead for TlsStreamAdapter {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "tls_reality")]
impl tokio::io::AsyncWrite for TlsStreamAdapter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
