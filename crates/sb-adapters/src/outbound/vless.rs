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
use crate::transport_config::{TransportConfig, TransportType};
use parking_lot::Mutex;
use rand::{Rng, RngCore};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::UdpSocket;
use uuid::Uuid;

#[cfg(feature = "tls_reality")]
use sb_tls::reality::RealityClientTlsStream;
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
    /// Server host
    /// 服务端主机
    pub server: String,
    /// Server port
    /// 服务端端口
    pub port: u16,
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
            server: "127.0.0.1".to_string(),
            port: 443,
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
    fn flow_addons(&self) -> Vec<u8> {
        let flow = self.config.flow.as_str();
        if flow.is_empty() {
            return Vec::new();
        }

        let flow_bytes = flow.as_bytes();
        let mut addons =
            Vec::with_capacity(1 + uvarint_len(flow_bytes.len() as u64) + flow_bytes.len());
        addons.push(0x0a);
        push_uvarint(&mut addons, flow_bytes.len() as u64);
        addons.extend_from_slice(flow_bytes);
        addons
    }

    fn server_endpoint(&self) -> String {
        format!("{}:{}", self.config.server, self.config.port)
    }

    fn vision_enabled(&self) -> bool {
        self.config.flow == FlowControl::XtlsRprxVision
    }

    #[cfg(feature = "transport_ech")]
    fn ech_enabled(&self) -> bool {
        self.config
            .ech
            .as_ref()
            .is_some_and(|ech_cfg| ech_cfg.enabled)
    }

    /// Report the configured transport type for diagnostics.
    pub fn transport_type(&self) -> TransportType {
        self.config.transport_layer.transport_type()
    }

    /// Report whether this connector will use the transport dialer path.
    pub fn uses_transport_dialer(&self) -> bool {
        #[cfg(feature = "sb-transport")]
        {
            self.dialer.is_some()
        }
        #[cfg(not(feature = "sb-transport"))]
        {
            false
        }
    }

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
        let addons = self.flow_addons();

        // VLESS version (1 byte)
        header.push(0x00);

        // UUID (16 bytes)
        header.extend_from_slice(self.config.uuid.as_bytes());

        // Additional Information Length (1 byte)
        header.push(addons.len() as u8);
        header.extend_from_slice(&addons);

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
            server = %self.server_endpoint(),
            target = %format!("{}:{}", target.host, target.port),
            "Creating VLESS UDP relay"
        );

        // Create local UDP socket
        let local_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(AdapterError::Io)?;

        // Connect to VLESS server for easier packet routing
        local_socket
            .connect((self.config.server.as_str(), self.config.port))
            .await
            .map_err(|e| AdapterError::Network(format!("UDP connect failed: {}", e)))?;

        // Create VLESS UDP socket wrapper
        let vless_udp = VlessUdpSocket::new(Arc::new(local_socket), self.config.uuid)?;

        Ok(Box::new(vless_udp))
    }

    async fn write_request<S>(&self, stream: &mut S, target: &Target) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + ?Sized,
    {
        let request_header = self.build_request_header(target);
        stream
            .write_all(&request_header)
            .await
            .map_err(AdapterError::Io)
    }

    async fn read_response<S>(&self, stream: &mut S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + ?Sized,
    {
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(AdapterError::Io)?;

        if response[0] != 0x00 {
            return Err(AdapterError::Other(format!(
                "VLESS handshake failed with version: {}",
                response[0]
            )));
        }

        let additional_len = response[1] as usize;
        if additional_len > 0 {
            let mut additional = vec![0u8; additional_len];
            stream
                .read_exact(&mut additional)
                .await
                .map_err(AdapterError::Io)?;
        }

        Ok(())
    }

    /// Perform VLESS handshake
    /// 执行 VLESS 握手
    async fn handshake<S>(&self, stream: &mut S, target: &Target) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + ?Sized,
    {
        self.write_request(stream, target).await?;
        self.read_response(stream).await
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
                    dialer.connect(&self.config.server, self.config.port),
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
            tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port)),
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
        if let Err(e) =
            tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port)).await
        {
            tracing::warn!("VLESS server connectivity test failed: {}", e);
            // Don't fail startup for connectivity issues - they might be temporary
        }

        tracing::info!(
            "VLESS connector started - server: {}, flow: {:?}, encryption: {:?}",
            self.server_endpoint(),
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

        #[cfg(feature = "tls_reality")]
        if self.vision_enabled() && self.config.reality.is_some() {
            #[cfg(feature = "transport_ech")]
            if self.ech_enabled() {
                tracing::debug!("Vision REALITY raw-bypass path skipped because ECH is enabled");
            } else {
                let reality_cfg = self.config.reality.as_ref().expect("checked is_some");
                tracing::debug!("VLESS using REALITY TLS concrete vision path");

                let reality_connector =
                    RealityConnector::new(reality_cfg.clone()).map_err(|e| {
                        AdapterError::Other(format!("Failed to create REALITY connector: {}", e))
                    })?;
                let server_name = &reality_cfg.server_name;
                let mut tls_stream = reality_connector
                    .connect_stream(stream, server_name)
                    .await
                    .map_err(|e| AdapterError::Other(format!("REALITY handshake failed: {}", e)))?;

                self.write_request(&mut tls_stream, &target).await?;

                let stream: BoxedStream = Box::new(VisionRealityClientStream::new(
                    tls_stream,
                    *self.config.uuid.as_bytes(),
                    true,
                ));
                tracing::debug!("VLESS connection established to: {:?}", target);
                return Ok(stream);
            }

            #[cfg(not(feature = "transport_ech"))]
            {
                let reality_cfg = self.config.reality.as_ref().expect("checked is_some");
                tracing::debug!("VLESS using REALITY TLS concrete vision path");

                let reality_connector =
                    RealityConnector::new(reality_cfg.clone()).map_err(|e| {
                        AdapterError::Other(format!("Failed to create REALITY connector: {}", e))
                    })?;
                let server_name = &reality_cfg.server_name;
                let mut tls_stream = reality_connector
                    .connect_stream(stream, server_name)
                    .await
                    .map_err(|e| AdapterError::Other(format!("REALITY handshake failed: {}", e)))?;

                self.write_request(&mut tls_stream, &target).await?;

                let stream: BoxedStream = Box::new(VisionRealityClientStream::new(
                    tls_stream,
                    *self.config.uuid.as_bytes(),
                    true,
                ));
                tracing::debug!("VLESS connection established to: {:?}", target);
                return Ok(stream);
            }
        }

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

        if self.vision_enabled() {
            self.write_request(&mut stream, &target).await?;
        } else {
            self.handshake(&mut stream, &target).await?;
        }

        if self.vision_enabled() {
            stream = Box::new(VisionClientStream::new(
                stream,
                *self.config.uuid.as_bytes(),
                true,
            ));
        }

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

const VISION_UUID_LEN: usize = 16;
const VISION_FRAME_HEADER_LEN: usize = 5;
const VISION_CHUNK_SIZE: usize = 8192;
const VISION_BUFFER_LIMIT: usize = VISION_CHUNK_SIZE - (VISION_UUID_LEN + VISION_FRAME_HEADER_LEN);
const VISION_PADDING_BUDGET: usize = 8;
const COMMAND_PADDING_CONTINUE: u8 = 0;
const COMMAND_PADDING_END: u8 = 1;
const COMMAND_PADDING_DIRECT: u8 = 2;
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS13_AES_128_CCM_8_SHA256: u16 = 0x1305;
const VISION_DIRECT_SPLIT_DELAY: std::time::Duration = std::time::Duration::from_millis(5);
const VISION_DIRECT_COALESCE_DELAY: std::time::Duration = std::time::Duration::from_millis(2);

#[cfg(feature = "tls_reality")]
#[derive(Debug, Default)]
struct VisionDeferredRawWrites {
    ready_at: Option<tokio::time::Instant>,
    chunks: VecDeque<Vec<u8>>,
}

#[cfg(feature = "tls_reality")]
impl VisionDeferredRawWrites {
    fn new() -> Self {
        Self::default()
    }

    fn is_waiting(&self) -> bool {
        self.ready_at.is_some()
    }

    fn ready_at(&self) -> Option<tokio::time::Instant> {
        self.ready_at
    }

    fn schedule_after_direct<I>(&mut self, chunks: I, now: tokio::time::Instant)
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        self.ready_at = Some(now + VISION_DIRECT_SPLIT_DELAY);
        self.chunks.extend(chunks);
    }

    fn take_ready_chunks(&mut self) -> Vec<Vec<u8>> {
        self.ready_at = None;
        self.chunks.drain(..).collect()
    }
}

#[cfg(feature = "tls_reality")]
async fn wait_for_deferred_raw_write(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[derive(Debug, Default)]
struct VisionTlsState {
    is_tls: bool,
    packets_to_filter: usize,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: Option<u16>,
    enable_xtls: bool,
}

impl VisionTlsState {
    fn new() -> Self {
        Self {
            packets_to_filter: VISION_PADDING_BUDGET,
            remaining_server_hello: -1,
            ..Self::default()
        }
    }

    fn observe_buffer(&mut self, buffer: &[u8]) {
        if self.packets_to_filter == 0 || buffer.is_empty() {
            return;
        }

        self.packets_to_filter = self.packets_to_filter.saturating_sub(1);

        if buffer.len() > 6 {
            if buffer.starts_with(&TLS_SERVER_HANDSHAKE_START) {
                self.is_tls = true;
                if buffer[5] == 2 {
                    self.is_tls12_or_above = true;
                    self.remaining_server_hello = ((buffer[3] as i32) << 8 | buffer[4] as i32) + 5;

                    if buffer.len() >= 79 && self.remaining_server_hello >= 79 {
                        let session_id_len = buffer[43] as usize;
                        let cipher_index = 44 + session_id_len;
                        if let Some(cipher) = buffer
                            .get(cipher_index..cipher_index + 2)
                            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                        {
                            self.cipher = Some(cipher);
                        }
                    }
                }
            } else if buffer.starts_with(&TLS_CLIENT_HANDSHAKE_START) && buffer[5] == 1 {
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let end = self.remaining_server_hello.min(buffer.len() as i32) as usize;
            self.remaining_server_hello -= end as i32;
            if buffer[..end]
                .windows(TLS13_SUPPORTED_VERSIONS.len())
                .any(|window| window == TLS13_SUPPORTED_VERSIONS)
            {
                if self
                    .cipher
                    .is_some_and(|cipher| cipher != TLS13_AES_128_CCM_8_SHA256)
                {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello == 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

struct VisionEncoder {
    user_uuid: [u8; VISION_UUID_LEN],
    tls_state: Arc<Mutex<VisionTlsState>>,
    is_padding: bool,
    write_uuid: bool,
    allow_direct: bool,
}

struct VisionWritePlan {
    chunks: Vec<Vec<u8>>,
    pause_after_first_chunk: bool,
    enter_direct_after_first_chunk: bool,
}

impl VisionEncoder {
    #[allow(dead_code)]
    fn new(user_uuid: [u8; VISION_UUID_LEN], tls_state: Arc<Mutex<VisionTlsState>>) -> Self {
        Self::new_with_direct(user_uuid, tls_state, true)
    }

    fn new_with_direct(
        user_uuid: [u8; VISION_UUID_LEN],
        tls_state: Arc<Mutex<VisionTlsState>>,
        allow_direct: bool,
    ) -> Self {
        Self {
            user_uuid,
            tls_state,
            is_padding: true,
            write_uuid: true,
            allow_direct,
        }
    }

    fn encode(&mut self, input: &[u8]) -> VisionWritePlan {
        if input.is_empty() {
            return VisionWritePlan {
                chunks: Vec::new(),
                pause_after_first_chunk: false,
                enter_direct_after_first_chunk: false,
            };
        }

        self.tls_state.lock().observe_buffer(input);
        if !self.is_padding {
            return VisionWritePlan {
                chunks: vec![input.to_vec()],
                pause_after_first_chunk: false,
                enter_direct_after_first_chunk: false,
            };
        }

        let buffers = reshape_buffer(input);
        let mut output = Vec::new();
        for (index, chunk) in buffers.iter().enumerate() {
            let (is_tls, is_tls12_or_above, packets_to_filter, enable_xtls) = {
                let tls_state = self.tls_state.lock();
                (
                    tls_state.is_tls,
                    tls_state.is_tls12_or_above,
                    tls_state.packets_to_filter,
                    tls_state.enable_xtls,
                )
            };

            if is_tls && chunk.len() > 6 && chunk.starts_with(&TLS_APPLICATION_DATA_START) {
                self.is_padding = false;
                if enable_xtls && self.allow_direct {
                    let mut chunks = vec![self.padding(chunk, COMMAND_PADDING_DIRECT, is_tls)];
                    chunks.extend(buffers.iter().skip(index + 1).cloned());
                    return VisionWritePlan {
                        pause_after_first_chunk: chunks.len() > 1,
                        enter_direct_after_first_chunk: true,
                        chunks,
                    };
                }

                output.extend_from_slice(&self.padding(chunk, COMMAND_PADDING_END, is_tls));
                for remainder in buffers.iter().skip(index + 1) {
                    output.extend_from_slice(remainder);
                }
                return VisionWritePlan {
                    chunks: vec![output],
                    pause_after_first_chunk: false,
                    enter_direct_after_first_chunk: false,
                };
            }

            if !is_tls12_or_above && packets_to_filter <= 1 {
                self.is_padding = false;
                output.extend_from_slice(&self.padding(chunk, COMMAND_PADDING_END, is_tls));
                for remainder in buffers.iter().skip(index + 1) {
                    output.extend_from_slice(remainder);
                }
                return VisionWritePlan {
                    chunks: vec![output],
                    pause_after_first_chunk: false,
                    enter_direct_after_first_chunk: false,
                };
            }

            output.extend_from_slice(&self.padding(chunk, COMMAND_PADDING_CONTINUE, is_tls));
        }

        VisionWritePlan {
            chunks: vec![output],
            pause_after_first_chunk: false,
            enter_direct_after_first_chunk: false,
        }
    }

    fn direct_input_tls_record_len(&self, input: &[u8]) -> Option<usize> {
        if !self.is_padding
            || !self.allow_direct
            || input.len() <= 6
            || !input.starts_with(&TLS_APPLICATION_DATA_START)
        {
            return None;
        }

        let tls_state = self.tls_state.lock();
        if tls_state.is_tls && tls_state.enable_xtls {
            tls_record_len(input)
        } else {
            None
        }
    }

    fn padding(&mut self, content: &[u8], command: u8, is_tls: bool) -> Vec<u8> {
        let padding_len = if content.len() < 900 && is_tls {
            rand::thread_rng().gen_range(0..500) + 900 - content.len()
        } else {
            rand::thread_rng().gen_range(0..256)
        };

        let mut frame = Vec::with_capacity(
            usize::from(self.write_uuid) * VISION_UUID_LEN
                + VISION_FRAME_HEADER_LEN
                + content.len()
                + padding_len,
        );
        if self.write_uuid {
            frame.extend_from_slice(&self.user_uuid);
            self.write_uuid = false;
        }
        frame.push(command);
        frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(padding_len as u16).to_be_bytes());
        frame.extend_from_slice(content);
        let padding_start = frame.len();
        frame.resize(padding_start + padding_len, 0);
        rand::thread_rng().fill_bytes(&mut frame[padding_start..]);
        frame
    }
}

fn tls_record_len(input: &[u8]) -> Option<usize> {
    if input.len() < 5 || !input.starts_with(&TLS_APPLICATION_DATA_START) {
        return None;
    }

    Some(5 + u16::from_be_bytes([input[3], input[4]]) as usize)
}

fn split_direct_tls_record(input: &mut Vec<u8>, record_len: usize) -> Vec<u8> {
    if input.len() <= record_len {
        return Vec::new();
    }

    input.split_off(record_len)
}

struct VisionDecoder {
    user_uuid: [u8; VISION_UUID_LEN],
    tls_state: Arc<Mutex<VisionTlsState>>,
    pending: Vec<u8>,
    remaining_content: isize,
    remaining_padding: isize,
    current_command: u8,
    passthrough: bool,
    raw_reads_enabled: bool,
}

impl VisionDecoder {
    fn new(user_uuid: [u8; VISION_UUID_LEN], tls_state: Arc<Mutex<VisionTlsState>>) -> Self {
        Self {
            user_uuid,
            tls_state,
            pending: Vec::new(),
            remaining_content: -1,
            remaining_padding: -1,
            current_command: COMMAND_PADDING_CONTINUE,
            passthrough: false,
            raw_reads_enabled: false,
        }
    }

    fn decode(&mut self, chunk: &[u8]) -> std::io::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        if self.passthrough {
            let output = self.pending.clone();
            self.pending.clear();
            return Ok(output);
        }

        let mut output = Vec::new();
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            if self.pending.len() < VISION_UUID_LEN + VISION_FRAME_HEADER_LEN {
                return Ok(output);
            }
            if !self.pending.starts_with(&self.user_uuid) {
                output.extend_from_slice(&self.pending);
                self.pending.clear();
                self.passthrough = true;
                return Ok(output);
            }
            self.pending.drain(..VISION_UUID_LEN);
            self.remaining_content = 0;
            self.remaining_padding = 0;
        }

        loop {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.current_command == COMMAND_PADDING_END
                    || self.current_command == COMMAND_PADDING_DIRECT
                {
                    if self.current_command == COMMAND_PADDING_DIRECT {
                        self.raw_reads_enabled = true;
                    }
                    self.passthrough = true;
                    output.extend_from_slice(&self.pending);
                    self.pending.clear();
                    break;
                }
                if self.pending.len() < VISION_FRAME_HEADER_LEN {
                    break;
                }

                let header: Vec<u8> = self.pending.drain(..VISION_FRAME_HEADER_LEN).collect();
                self.current_command = header[0];
                self.remaining_content = u16::from_be_bytes([header[1], header[2]]) as isize;
                self.remaining_padding = u16::from_be_bytes([header[3], header[4]]) as isize;
                continue;
            }

            if self.remaining_content > 0 {
                if self.pending.is_empty() {
                    break;
                }
                let take = self.pending.len().min(self.remaining_content as usize);
                output.extend(self.pending.drain(..take));
                self.remaining_content -= take as isize;
                continue;
            }

            if self.remaining_padding > 0 {
                if self.pending.is_empty() {
                    break;
                }
                let skip = self.pending.len().min(self.remaining_padding as usize);
                self.pending.drain(..skip);
                self.remaining_padding -= skip as isize;
                continue;
            }
        }

        if !output.is_empty() {
            self.tls_state.lock().observe_buffer(&output);
        }

        Ok(output)
    }

    #[allow(dead_code)]
    fn raw_reads_enabled(&self) -> bool {
        self.raw_reads_enabled
    }
}

#[allow(dead_code)]
fn drain_vision_direct_read_buffers(
    decoder: &mut VisionDecoder,
    pending_plaintext: &[u8],
    buffered_raw_tls: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut drained = Vec::with_capacity(pending_plaintext.len() + buffered_raw_tls.len());
    if !pending_plaintext.is_empty() {
        drained.extend_from_slice(&decoder.decode(pending_plaintext)?);
    }
    drained.extend_from_slice(buffered_raw_tls);
    Ok(drained)
}

async fn consume_vless_response<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin + Send + ?Sized,
{
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("VLESS handshake failed with version: {}", response[0]),
        ));
    }

    let additional_len = response[1] as usize;
    if additional_len > 0 {
        let mut additional = vec![0u8; additional_len];
        stream.read_exact(&mut additional).await?;
    }

    Ok(())
}

#[derive(Debug, Default)]
struct VlessResponsePeeler {
    header: Vec<u8>,
    additional: Vec<u8>,
    additional_len: Option<usize>,
    complete: bool,
}

impl VlessResponsePeeler {
    fn new() -> Self {
        Self::default()
    }

    fn consume<'a>(&mut self, chunk: &'a [u8]) -> std::io::Result<Option<&'a [u8]>> {
        if self.complete {
            return Ok(Some(chunk));
        }

        let mut offset = 0;
        if self.additional_len.is_none() {
            let needed = 2usize.saturating_sub(self.header.len());
            let take = needed.min(chunk.len());
            self.header.extend_from_slice(&chunk[..take]);
            offset += take;

            if self.header.len() < 2 {
                return Ok(None);
            }

            if self.header[0] != 0x00 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("VLESS handshake failed with version: {}", self.header[0]),
                ));
            }
            self.additional_len = Some(self.header[1] as usize);
            self.header.clear();
        }

        let additional_len = self.additional_len.expect("set above");
        let needed = additional_len.saturating_sub(self.additional.len());
        let take = needed.min(chunk.len().saturating_sub(offset));
        self.additional
            .extend_from_slice(&chunk[offset..offset + take]);
        offset += take;

        if self.additional.len() < additional_len {
            return Ok(None);
        }

        self.complete = true;
        self.additional.clear();
        Ok(Some(&chunk[offset..]))
    }
}

#[cfg(feature = "tls_reality")]
#[allow(dead_code)]
async fn consume_vless_response_tls(
    stream: &mut RealityClientTlsStream<BoxedStream>,
) -> std::io::Result<()> {
    let mut response = [0u8; 2];
    let read = stream.read_tls(&mut response).await?;
    if read != response.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "early eof while reading vless response header",
        ));
    }
    if response[0] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("VLESS handshake failed with version: {}", response[0]),
        ));
    }

    let additional_len = response[1] as usize;
    if additional_len > 0 {
        let mut additional = vec![0u8; additional_len];
        let read = stream.read_tls(&mut additional).await?;
        if read != additional.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "early eof while reading vless response addons",
            ));
        }
    }

    Ok(())
}

struct VisionClientStream {
    reader: DuplexStream,
    writer: DuplexStream,
    read_task: tokio::task::JoinHandle<()>,
    write_task: tokio::task::JoinHandle<()>,
}

impl VisionClientStream {
    fn new(stream: BoxedStream, user_uuid: [u8; VISION_UUID_LEN], response_pending: bool) -> Self {
        Self::new_with_direct(stream, user_uuid, response_pending, true)
    }

    fn new_with_direct(
        stream: BoxedStream,
        user_uuid: [u8; VISION_UUID_LEN],
        response_pending: bool,
        allow_direct: bool,
    ) -> Self {
        let (reader, mut reader_bridge) = tokio::io::duplex(64 * 1024);
        let (mut writer_bridge, writer) = tokio::io::duplex(64 * 1024);
        let (mut inner_reader, mut inner_writer) = tokio::io::split(stream);
        let tls_state = Arc::new(Mutex::new(VisionTlsState::new()));
        let read_tls_state = tls_state.clone();
        let write_tls_state = tls_state;

        let read_task = tokio::spawn(async move {
            let mut decoder = VisionDecoder::new(user_uuid, read_tls_state);
            let mut buffer = vec![0u8; VISION_CHUNK_SIZE];
            if response_pending && consume_vless_response(&mut inner_reader).await.is_err() {
                let _ = reader_bridge.shutdown().await;
                return;
            }
            loop {
                let read = match inner_reader.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(_) => break,
                };

                let decoded = match decoder.decode(&buffer[..read]) {
                    Ok(decoded) => decoded,
                    Err(_) => break,
                };
                if !decoded.is_empty() && reader_bridge.write_all(&decoded).await.is_err() {
                    break;
                }
            }
            let _ = reader_bridge.shutdown().await;
        });

        let write_task = tokio::spawn(async move {
            let mut encoder =
                VisionEncoder::new_with_direct(user_uuid, write_tls_state, allow_direct);
            let mut buffer = vec![0u8; VISION_CHUNK_SIZE];
            loop {
                let read = match writer_bridge.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => read,
                    Err(_) => break,
                };

                let plan = encoder.encode(&buffer[..read]);
                if plan.chunks.is_empty() {
                    continue;
                }
                for (index, chunk) in plan.chunks.iter().enumerate() {
                    if inner_writer.write_all(chunk).await.is_err() {
                        return;
                    }
                    if index == 0 && plan.pause_after_first_chunk {
                        tokio::time::sleep(VISION_DIRECT_SPLIT_DELAY).await;
                    }
                }
            }
            let _ = inner_writer.shutdown().await;
        });

        Self {
            reader,
            writer,
            read_task,
            write_task,
        }
    }
}

#[cfg(feature = "tls_reality")]
struct VisionRealityClientStream {
    reader: DuplexStream,
    writer: DuplexStream,
    io_task: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "tls_reality")]
impl VisionRealityClientStream {
    fn new(
        stream: RealityClientTlsStream<BoxedStream>,
        user_uuid: [u8; VISION_UUID_LEN],
        response_pending: bool,
    ) -> Self {
        let (reader, mut reader_bridge) = tokio::io::duplex(64 * 1024);
        let (mut writer_bridge, writer) = tokio::io::duplex(64 * 1024);
        let tls_state = Arc::new(Mutex::new(VisionTlsState::new()));
        let io_task = tokio::spawn(async move {
            let mut stream = stream;
            let mut decoder = VisionDecoder::new(user_uuid, tls_state.clone());
            let mut encoder = VisionEncoder::new(user_uuid, tls_state);
            let mut read_buffer = vec![0u8; VISION_CHUNK_SIZE];
            let mut write_buffer = vec![0u8; VISION_CHUNK_SIZE];
            let mut response_peeler = response_pending.then(VlessResponsePeeler::new);
            let mut use_raw_reads = false;
            let mut use_raw_writes = false;
            let mut writer_closed = false;
            let mut deferred_raw_writes = VisionDeferredRawWrites::new();

            loop {
                tokio::select! {
                    read = async {
                        if use_raw_reads {
                            stream.read_raw(&mut read_buffer).await
                        } else {
                            stream.read_tls(&mut read_buffer).await
                        }
                    } => {
                        let read = match read {
                            Ok(0) => break,
                            Ok(read) => read,
                            Err(_) => break,
                        };

                        let payload = if let Some(peeler) = response_peeler.as_mut() {
                            match peeler.consume(&read_buffer[..read]) {
                                Ok(Some(payload)) => payload,
                                Ok(None) => continue,
                                Err(_) => break,
                            }
                        } else {
                            &read_buffer[..read]
                        };

                        if payload.is_empty() {
                            continue;
                        }

                        let decoded = match decoder.decode(payload) {
                            Ok(decoded) => decoded,
                            Err(_) => break,
                        };
                        if !decoded.is_empty() && reader_bridge.write_all(&decoded).await.is_err() {
                            break;
                        }
                        if !use_raw_reads && decoder.raw_reads_enabled() {
                            let pending_plaintext = stream.take_pending_tls_plaintext();
                            let buffered_raw_tls = stream.take_buffered_raw_tls();
                            tracing::debug!(
                                pending_plaintext_len = pending_plaintext.len(),
                                buffered_raw_tls_len = buffered_raw_tls.len(),
                                "Vision REALITY enabling raw reads"
                            );
                            let drained = match drain_vision_direct_read_buffers(
                                &mut decoder,
                                &pending_plaintext,
                                &buffered_raw_tls,
                            ) {
                                Ok(drained) => drained,
                                Err(_) => break,
                            };
                            if !drained.is_empty() && reader_bridge.write_all(&drained).await.is_err() {
                                break;
                            }
                            use_raw_reads = true;
                        }
                    }
                    _ = wait_for_deferred_raw_write(deferred_raw_writes.ready_at()), if deferred_raw_writes.is_waiting() => {
                        let chunks = deferred_raw_writes.take_ready_chunks();
                        let mut wrote = false;
                        for chunk in chunks {
                            if stream.write_raw_all(&chunk).await.is_err() {
                                return;
                            }
                            wrote = true;
                        }
                        if wrote && stream.flush_raw().await.is_err() {
                            return;
                        }
                    }
                    write = writer_bridge.read(&mut write_buffer), if !writer_closed && !deferred_raw_writes.is_waiting() => {
                        let read = match write {
                            Ok(0) => {
                                writer_closed = true;
                                let _ = if use_raw_writes {
                                    stream.shutdown_raw().await
                                } else {
                                    stream.shutdown_tls().await
                                };
                                continue;
                            }
                            Ok(read) => read,
                            Err(_) => break,
                        };

                        let mut input = write_buffer[..read].to_vec();
                        let mut direct_raw_remainder = Vec::new();
                        if let Some(record_len) = encoder.direct_input_tls_record_len(&input) {
                            while input.len() < record_len {
                                let mut extra = vec![0u8; VISION_CHUNK_SIZE];
                                match tokio::time::timeout(
                                    VISION_DIRECT_COALESCE_DELAY,
                                    writer_bridge.read(&mut extra),
                                )
                                .await
                                {
                                    Ok(Ok(0)) => {
                                        writer_closed = true;
                                        break;
                                    }
                                    Ok(Ok(extra_read)) => {
                                        let needed = record_len.saturating_sub(input.len());
                                        let take = needed.min(extra_read);
                                        input.extend_from_slice(&extra[..take]);
                                        if take < extra_read {
                                            direct_raw_remainder
                                                .extend_from_slice(&extra[take..extra_read]);
                                            break;
                                        }
                                    }
                                    Ok(Err(_)) => break,
                                    Err(_) => break,
                                }
                            }
                            direct_raw_remainder
                                .extend(split_direct_tls_record(&mut input, record_len));
                        }

                        let plan = encoder.encode(&input);
                        if plan.chunks.is_empty() {
                            continue;
                        }

                        let mut flush_after_plan = true;
                        for (index, chunk) in plan.chunks.iter().enumerate() {
                            if plan.enter_direct_after_first_chunk && index > 0 {
                                let mut deferred_chunks: Vec<Vec<u8>> =
                                    plan.chunks.iter().skip(index).cloned().collect();
                                let raw_remainder = std::mem::take(&mut direct_raw_remainder);
                                if !raw_remainder.is_empty() {
                                    deferred_chunks.push(raw_remainder);
                                }
                                deferred_raw_writes.schedule_after_direct(
                                    deferred_chunks,
                                    tokio::time::Instant::now(),
                                );
                                flush_after_plan = false;
                                break;
                            }

                            let write_raw =
                                use_raw_writes || (plan.enter_direct_after_first_chunk && index > 0);
                            if write_raw {
                                tracing::debug!(
                                    raw_write_len = chunk.len(),
                                    "Vision REALITY raw write"
                                );
                            }
                            let result = if write_raw {
                                stream.write_raw_all(chunk).await
                            } else {
                                stream.write_tls_all(chunk).await
                            };
                            if result.is_err() {
                                return;
                            }
                            if index == 0 && plan.enter_direct_after_first_chunk {
                                let header_offset = if chunk.len()
                                    >= VISION_UUID_LEN + VISION_FRAME_HEADER_LEN
                                    && chunk[..VISION_UUID_LEN] == encoder.user_uuid
                                {
                                    VISION_UUID_LEN
                                } else {
                                    0
                                };
                                let direct_content_len = chunk
                                    .get(header_offset + 1..header_offset + 3)
                                    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                                    .unwrap_or_default();
                                let direct_padding_len = chunk
                                    .get(header_offset + 3..header_offset + 5)
                                    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                                    .unwrap_or_default();
                                tracing::debug!(
                                    direct_frame_len = chunk.len(),
                                    direct_content_len,
                                    direct_padding_len,
                                    raw_remainder_chunks = plan.chunks.len().saturating_sub(1),
                                    "Vision REALITY enabling raw writes"
                                );
                                if stream.flush_tls().await.is_err() {
                                    return;
                                }
                                let raw_remainder = std::mem::take(&mut direct_raw_remainder);
                                let deferred_chunks = if raw_remainder.is_empty() {
                                    Vec::new()
                                } else {
                                    vec![raw_remainder]
                                };
                                deferred_raw_writes.schedule_after_direct(
                                    deferred_chunks,
                                    tokio::time::Instant::now(),
                                );
                                use_raw_writes = true;
                                flush_after_plan = false;
                            }
                        }

                        if flush_after_plan {
                            let flush_result = if use_raw_writes {
                                stream.flush_raw().await
                            } else {
                                stream.flush_tls().await
                            };
                            if flush_result.is_err() {
                                return;
                            }
                        }
                    }
                }
            }

            let _ = reader_bridge.shutdown().await;
        });

        Self {
            reader,
            writer,
            io_task,
        }
    }
}

#[cfg(feature = "tls_reality")]
impl Drop for VisionRealityClientStream {
    fn drop(&mut self) {
        self.io_task.abort();
    }
}

#[cfg(feature = "tls_reality")]
impl tokio::io::AsyncRead for VisionRealityClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

#[cfg(feature = "tls_reality")]
impl tokio::io::AsyncWrite for VisionRealityClientStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

impl Drop for VisionClientStream {
    fn drop(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }
}

impl tokio::io::AsyncRead for VisionClientStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for VisionClientStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

fn push_uvarint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buffer.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

fn uvarint_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        len += 1;
        value >>= 7;
    }
    len
}

fn reshape_buffer(input: &[u8]) -> Vec<Vec<u8>> {
    if input.len() < VISION_BUFFER_LIMIT {
        return vec![input.to_vec()];
    }

    let split_index = input
        .windows(TLS_APPLICATION_DATA_START.len())
        .rposition(|window| window == TLS_APPLICATION_DATA_START)
        .filter(|index| *index > 0)
        .unwrap_or(VISION_CHUNK_SIZE / 2);

    vec![input[..split_index].to_vec(), input[split_index..].to_vec()]
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn vision_tls_state() -> Arc<Mutex<VisionTlsState>> {
        Arc::new(Mutex::new(VisionTlsState::new()))
    }

    fn vision_frame(uuid: [u8; VISION_UUID_LEN], command: u8, content: &[u8]) -> Vec<u8> {
        let mut frame =
            Vec::with_capacity(VISION_UUID_LEN + VISION_FRAME_HEADER_LEN + content.len());
        frame.extend_from_slice(&uuid);
        frame.push(command);
        frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(content);
        frame
    }

    fn tls13_server_hello(cipher: u16) -> Vec<u8> {
        let mut record = vec![0u8; 96];
        record[0] = 0x16;
        record[1] = 0x03;
        record[2] = 0x03;
        record[3] = 0x00;
        record[4] = 0x5b;
        record[5] = 0x02;
        record[43] = 0x00;
        record[44] = (cipher >> 8) as u8;
        record[45] = cipher as u8;
        record[70..76].copy_from_slice(&TLS13_SUPPORTED_VERSIONS);
        record
    }

    #[test]
    fn test_build_request_header_omits_addons_without_flow() {
        let connector = VlessConnector::default();
        let target = Target::tcp("example.com", 80);
        let header = connector.build_request_header(&target);

        assert_eq!(header[0], 0x00);
        assert_eq!(header[17], 0x00);
        assert_eq!(header[18], 0x01);
    }

    #[test]
    fn test_build_request_header_encodes_vision_flow_addon() {
        let connector = VlessConnector::new(VlessConfig {
            flow: FlowControl::XtlsRprxVision,
            ..VlessConfig::default()
        });
        let target = Target::tcp("example.com", 80);
        let header = connector.build_request_header(&target);

        let flow = b"xtls-rprx-vision";
        let mut expected_addons = vec![0x0a, flow.len() as u8];
        expected_addons.extend_from_slice(flow);

        assert_eq!(header[17] as usize, expected_addons.len());
        assert_eq!(
            &header[18..18 + expected_addons.len()],
            expected_addons.as_slice()
        );
        assert_eq!(header[18 + expected_addons.len()], 0x01);
    }

    #[tokio::test]
    async fn test_handshake_consumes_vless_response_addons() {
        let connector = VlessConnector::new(VlessConfig {
            flow: FlowControl::XtlsRprxVision,
            ..VlessConfig::default()
        });
        let target = Target::tcp("example.com", 80);
        let request = connector.build_request_header(&target);
        let (client, mut server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut request_buf = vec![0u8; request.len()];
            server.read_exact(&mut request_buf).await.unwrap();
            assert_eq!(request_buf, request);

            server
                .write_all(&[0x00, 0x03, 0x01, 0x02, 0x03])
                .await
                .unwrap();
            server.write_all(b"ok").await.unwrap();
        });

        let mut client: BoxedStream = Box::new(client);
        connector.handshake(&mut client, &target).await.unwrap();

        let mut payload = [0u8; 2];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ok");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_write_request_does_not_wait_for_response() {
        let connector = VlessConnector::new(VlessConfig {
            flow: FlowControl::XtlsRprxVision,
            ..VlessConfig::default()
        });
        let target = Target::tcp("example.com", 80);
        let request = connector.build_request_header(&target);
        let (mut client, mut server) = tokio::io::duplex(4096);

        let server_task = tokio::spawn(async move {
            let mut request_buf = vec![0u8; request.len()];
            server.read_exact(&mut request_buf).await.unwrap();
            assert_eq!(request_buf, request);
        });

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            connector.write_request(&mut client, &target),
        )
        .await
        .unwrap()
        .unwrap();

        server_task.await.unwrap();
    }

    #[test]
    fn test_vision_encoder_roundtrips_continue_frame() {
        let uuid = [7u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new(uuid, tls_state.clone());
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        let plan = encoder.encode(b"ping");
        assert_eq!(plan.chunks.len(), 1);
        let encoded = &plan.chunks[0];

        assert_eq!(&encoded[..VISION_UUID_LEN], &uuid);
        assert_eq!(encoded[VISION_UUID_LEN], COMMAND_PADDING_CONTINUE);
        assert_eq!(decoder.decode(encoded).unwrap(), b"ping");
    }

    #[test]
    fn test_vision_padding_uses_random_padding_bytes() {
        let uuid = [8u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new(uuid, tls_state);
        let content = b"x";
        let frame = encoder.padding(content, COMMAND_PADDING_CONTINUE, true);
        let padding_start = VISION_UUID_LEN + VISION_FRAME_HEADER_LEN + content.len();

        assert!(frame.len() > padding_start);
        assert!(frame[padding_start..].iter().any(|byte| *byte != 0));
    }

    #[test]
    fn test_vision_encoder_coalesces_only_first_direct_appdata() {
        let uuid = [8u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        {
            let mut state = tls_state.lock();
            state.is_tls = true;
            state.enable_xtls = true;
        }
        let mut encoder = VisionEncoder::new(uuid, tls_state);
        let mut appdata = TLS_APPLICATION_DATA_START.to_vec();
        appdata.extend_from_slice(b"\x00\x02xy");

        assert_eq!(encoder.direct_input_tls_record_len(&appdata), Some(7));
        assert_eq!(
            encoder.direct_input_tls_record_len(b"\x16\x03\x03\x00\x01x"),
            None
        );
        let _ = encoder.encode(&appdata);
        assert_eq!(encoder.direct_input_tls_record_len(&appdata), None);
    }

    #[test]
    fn test_split_direct_tls_record_keeps_overflow_for_raw_write() {
        let mut appdata = TLS_APPLICATION_DATA_START.to_vec();
        appdata.extend_from_slice(b"\x00\x02xy");
        appdata.extend_from_slice(b"next-record");

        let overflow = split_direct_tls_record(&mut appdata, 7);

        assert_eq!(appdata, b"\x17\x03\x03\x00\x02xy");
        assert_eq!(overflow, b"next-record");
    }

    #[test]
    fn test_vision_encoder_emits_end_when_padding_budget_is_exhausted() {
        let uuid = [9u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        tls_state.lock().packets_to_filter = 1;
        let mut encoder = VisionEncoder::new(uuid, tls_state);

        let plan = encoder.encode(b"final");
        let encoded = &plan.chunks[0];

        assert_eq!(encoded[VISION_UUID_LEN], COMMAND_PADDING_END);
        assert!(!encoder.is_padding);
    }

    #[test]
    fn test_vision_encoder_emits_direct_after_tls13_server_hello() {
        let uuid = [3u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new(uuid, tls_state.clone());
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        let server_hello = tls13_server_hello(0x1301);
        let decoded = decoder
            .decode(&vision_frame(uuid, COMMAND_PADDING_CONTINUE, &server_hello))
            .unwrap();
        assert_eq!(decoded, server_hello);

        let plan = encoder.encode(&[0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]);
        assert_eq!(plan.chunks[0][VISION_UUID_LEN], COMMAND_PADDING_DIRECT);
        assert!(plan.enter_direct_after_first_chunk);
    }

    #[test]
    fn test_vision_encoder_does_not_direct_without_known_tls13_cipher() {
        let uuid = [12u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new(uuid, tls_state.clone());
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        let mut server_hello = tls13_server_hello(0x1301);
        server_hello.truncate(76);
        decoder
            .decode(&vision_frame(uuid, COMMAND_PADDING_CONTINUE, &server_hello))
            .unwrap();

        let plan = encoder.encode(&[0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]);
        assert!(!plan.enter_direct_after_first_chunk);
        assert_eq!(plan.chunks[0][VISION_UUID_LEN], COMMAND_PADDING_END);
    }

    #[test]
    fn test_vision_encoder_does_not_direct_for_tls13_ccm8_cipher() {
        let uuid = [13u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new(uuid, tls_state.clone());
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        decoder
            .decode(&vision_frame(
                uuid,
                COMMAND_PADDING_CONTINUE,
                &tls13_server_hello(TLS13_AES_128_CCM_8_SHA256),
            ))
            .unwrap();

        let plan = encoder.encode(&[0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]);
        assert!(!plan.enter_direct_after_first_chunk);
        assert_eq!(plan.chunks[0][VISION_UUID_LEN], COMMAND_PADDING_END);
    }

    #[test]
    fn test_vision_encoder_can_disable_direct_after_tls13_server_hello() {
        let uuid = [10u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new_with_direct(uuid, tls_state.clone(), false);
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        let server_hello = tls13_server_hello(0x1301);
        decoder
            .decode(&vision_frame(uuid, COMMAND_PADDING_CONTINUE, &server_hello))
            .unwrap();

        let plan = encoder.encode(&[0x17, 0x03, 0x03, 0x00, 0x02, 0x01, 0x02]);
        assert!(!plan.pause_after_first_chunk);
        assert!(!plan.enter_direct_after_first_chunk);
        assert_eq!(plan.chunks[0][VISION_UUID_LEN], COMMAND_PADDING_END);
        assert!(!encoder.is_padding);
    }

    #[test]
    fn test_vision_encoder_splits_direct_write_plan() {
        let uuid = [4u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new(uuid, tls_state.clone());
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        let server_hello = tls13_server_hello(0x1301);
        decoder
            .decode(&vision_frame(uuid, COMMAND_PADDING_CONTINUE, &server_hello))
            .unwrap();

        let mut payload = vec![0u8; VISION_BUFFER_LIMIT + 32];
        payload[..3].copy_from_slice(&TLS_APPLICATION_DATA_START);
        let plan = encoder.encode(&payload);

        assert!(plan.pause_after_first_chunk);
        assert!(plan.enter_direct_after_first_chunk);
        assert_eq!(plan.chunks.len(), 2);
        assert_eq!(plan.chunks[0][VISION_UUID_LEN], COMMAND_PADDING_DIRECT);
        assert_eq!(plan.chunks[1], payload[VISION_CHUNK_SIZE / 2..].to_vec());
    }

    #[test]
    fn test_vision_encoder_marks_single_chunk_direct_for_later_raw_writes() {
        let uuid = [11u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut encoder = VisionEncoder::new(uuid, tls_state.clone());
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        decoder
            .decode(&vision_frame(
                uuid,
                COMMAND_PADDING_CONTINUE,
                &tls13_server_hello(0x1301),
            ))
            .unwrap();

        let plan = encoder.encode(&[0x17, 0x03, 0x03, 0x00, 0x02, 0x2a, 0x2b]);
        assert_eq!(plan.chunks.len(), 1);
        assert!(!plan.pause_after_first_chunk);
        assert!(plan.enter_direct_after_first_chunk);
        assert_eq!(plan.chunks[0][VISION_UUID_LEN], COMMAND_PADDING_DIRECT);
    }

    #[cfg(feature = "tls_reality")]
    #[test]
    fn test_deferred_raw_writes_hold_direct_remainder_until_deadline() {
        let now = tokio::time::Instant::now();
        let mut deferred = VisionDeferredRawWrites::new();

        assert!(!deferred.is_waiting());
        deferred.schedule_after_direct(vec![b"raw-a".to_vec(), b"raw-b".to_vec()], now);

        assert!(deferred.is_waiting());
        assert_eq!(deferred.ready_at(), Some(now + VISION_DIRECT_SPLIT_DELAY));
        assert_eq!(
            deferred.take_ready_chunks(),
            vec![b"raw-a".to_vec(), b"raw-b".to_vec()]
        );
        assert!(!deferred.is_waiting());
    }

    #[test]
    fn test_vision_decoder_enables_raw_reads_after_direct_frame() {
        let uuid = [6u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        let payload = b"direct-payload";
        let decoded = decoder
            .decode(&vision_frame(uuid, COMMAND_PADDING_DIRECT, payload))
            .unwrap();

        assert_eq!(decoded, payload);
        assert!(decoder.raw_reads_enabled());
    }

    #[test]
    fn test_drain_vision_direct_read_buffers_keeps_plaintext_before_raw_tls() {
        let uuid = [8u8; VISION_UUID_LEN];
        let tls_state = vision_tls_state();
        let mut decoder = VisionDecoder::new(uuid, tls_state);

        let direct_payload = decoder
            .decode(&vision_frame(uuid, COMMAND_PADDING_DIRECT, b"direct"))
            .unwrap();
        assert_eq!(direct_payload, b"direct");
        assert!(decoder.raw_reads_enabled());

        let drained =
            drain_vision_direct_read_buffers(&mut decoder, b"tls-plaintext", b"raw-tls-bytes")
                .unwrap();
        assert_eq!(drained, b"tls-plaintextraw-tls-bytes");
    }

    #[test]
    fn test_vless_response_peeler_allows_coalesced_vision_payload() {
        let mut peeler = VlessResponsePeeler::new();
        assert_eq!(peeler.consume(&[0x00]).unwrap(), None);

        let payload = peeler
            .consume(&[0x02, 0xaa, 0xbb, 0xcc, 0xdd])
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"\xcc\xdd");

        let next = peeler.consume(b"vision").unwrap().unwrap();
        assert_eq!(next, b"vision");
    }

    #[tokio::test]
    async fn test_vision_stream_consumes_deferred_vless_response_before_payloads() {
        let uuid = [1u8; VISION_UUID_LEN];
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let mut stream = VisionClientStream::new(Box::new(client_side), uuid, true);

        let server_task = tokio::spawn(async move {
            let tls_state = vision_tls_state();
            let mut encoder = VisionEncoder::new(uuid, tls_state);

            server_side
                .write_all(&[0x00, 0x02, 0xAA, 0xBB])
                .await
                .unwrap();

            let plan = encoder.encode(b"pong");
            for chunk in plan.chunks {
                server_side.write_all(&chunk).await.unwrap();
            }
        });

        let mut response = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"pong");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_vision_stream_roundtrips_bidirectional_payloads() {
        let uuid = [5u8; VISION_UUID_LEN];
        let (client_side, mut server_side) = tokio::io::duplex(64 * 1024);
        let mut stream = VisionClientStream::new(Box::new(client_side), uuid, false);

        let server_task = tokio::spawn(async move {
            let tls_state = vision_tls_state();
            let mut decoder = VisionDecoder::new(uuid, tls_state.clone());
            let mut encoder = VisionEncoder::new(uuid, tls_state);
            let mut buffer = vec![0u8; VISION_CHUNK_SIZE];

            let read = server_side.read(&mut buffer).await.unwrap();
            let decoded = decoder.decode(&buffer[..read]).unwrap();
            assert_eq!(decoded, b"ping");

            let plan = encoder.encode(b"pong");
            for chunk in plan.chunks {
                server_side.write_all(&chunk).await.unwrap();
            }
        });

        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();

        let mut response = [0u8; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"pong");

        server_task.await.unwrap();
    }
}
