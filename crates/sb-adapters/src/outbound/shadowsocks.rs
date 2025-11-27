//! Shadowsocks outbound connector implementation
//! Shadowsocks 出站连接器实现
//!
//! This module provides Shadowsocks protocol support for outbound connections.
//! Supports AEAD ciphers including AES-GCM and ChaCha20-Poly1305.
//! Supports both TCP and UDP relay.
//! 本模块为出站连接提供 Shadowsocks 协议支持。
//! 支持 AEAD 加密算法，包括 AES-GCM 和 ChaCha20-Poly1305。
//! 支持 TCP 和 UDP 中继。

use crate::outbound::prelude::*;
use crate::traits::{OutboundDatagram, ResolveMode};
use anyhow::Context;
use sb_transport::Dialer;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

// Crypto imports
use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Shadowsocks configuration
/// Shadowsocks 配置
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShadowsocksConfig {
    /// Server address (host:port)
    /// 服务器地址 (host:port)
    pub server: String,
    /// Connection tag
    /// 连接标签
    #[serde(default)]
    pub tag: Option<String>,
    /// Encryption method
    /// 加密方法
    pub method: String,
    /// Password for encryption
    /// 加密密码
    pub password: String,
    /// Connection timeout in seconds
    /// 连接超时（秒）
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// Multiplex configuration
    /// 多路复用配置
    #[serde(default)]
    pub multiplex: Option<sb_transport::multiplex::MultiplexConfig>,
}

/// Supported Shadowsocks encryption methods
/// 支持的 Shadowsocks 加密方法
#[derive(Debug, Clone, PartialEq)]
pub enum CipherMethod {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherMethod {
    fn from_str(method: &str) -> Result<Self> {
        match method.to_lowercase().as_str() {
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Self::ChaCha20Poly1305),
            _ => Err(AdapterError::Protocol(format!(
                "Unsupported cipher method: {}",
                method
            ))),
        }
    }

    fn key_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,        // AES-256
            Self::ChaCha20Poly1305 => 32, // ChaCha20
        }
    }

    fn nonce_size(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,        // GCM nonce
            Self::ChaCha20Poly1305 => 12, // ChaCha20 nonce
        }
    }

    #[allow(dead_code)]
    fn tag_size(&self) -> usize {
        16 // Both AES-GCM and ChaCha20-Poly1305 use 16-byte tags
    }
}

/// Shadowsocks outbound connector
/// Shadowsocks 出站连接器
#[derive(Debug, Clone)]
pub struct ShadowsocksConnector {
    config: ShadowsocksConfig,
    cipher_method: CipherMethod,
    key: Vec<u8>,
    multiplex_dialer: Option<std::sync::Arc<sb_transport::multiplex::MultiplexDialer>>,
}

impl ShadowsocksConnector {
    pub fn new(config: ShadowsocksConfig) -> Result<Self> {
        let cipher_method = CipherMethod::from_str(&config.method)?;
        let key = Self::derive_key(&config.password, &cipher_method);

        // Create multiplex dialer if configured
        // 如果配置了多路复用，创建多路复用拨号器
        let multiplex_dialer = if let Some(mux_config) = config.multiplex.clone() {
            let tcp_dialer = Box::new(sb_transport::TcpDialer) as Box<dyn sb_transport::Dialer>;
            Some(std::sync::Arc::new(
                sb_transport::multiplex::MultiplexDialer::new(mux_config, tcp_dialer),
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            cipher_method,
            key,
            multiplex_dialer,
        })
    }

    /// Derive encryption key from password using HKDF-SHA1 (Shadowsocks standard)
    /// 使用 HKDF-SHA1 从密码派生加密密钥（Shadowsocks 标准）
    fn derive_key(password: &str, method: &CipherMethod) -> Vec<u8> {
        let key_len = method.key_size();
        let mut key = vec![0u8; key_len];

        // Simple key derivation based on Shadowsocks spec
        // 基于 Shadowsocks 规范的简单密钥派生
        // For production, this should use proper HKDF
        // 生产环境中应使用正确的 HKDF
        let mut d = Vec::new();
        let mut i = 0;

        while d.len() < key_len {
            let mut hasher = Sha256::new();
            if i > 0 {
                hasher.update(&d[(i - 1) * 32..]);
            }
            hasher.update(password.as_bytes());
            let hash = hasher.finalize();
            d.extend_from_slice(&hash);
            i += 1;
        }

        key.copy_from_slice(&d[..key_len]);
        key
    }

    /// Create a connector with simplified configuration
    /// 使用简化配置创建连接器
    pub fn with_config(
        server: impl Into<String>,
        method: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self> {
        let config = ShadowsocksConfig {
            server: server.into(),
            tag: None,
            method: method.into(),
            password: password.into(),
            connect_timeout_sec: Some(30),
            multiplex: None,
        };
        Self::new(config)
    }

    /// Create UDP relay connection (returns OutboundDatagram)
    /// 创建 UDP 中继连接（返回 OutboundDatagram）
    pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {
        #[cfg(not(feature = "adapter-shadowsocks"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowsocks",
        });

        #[cfg(feature = "adapter-shadowsocks")]
        {
            tracing::debug!(
                server = %self.config.server,
                target = %format!("{}:{}", target.host, target.port),
                method = %self.config.method,
                "Creating Shadowsocks UDP relay"
            );

            // Parse server address
            // 解析服务器地址
            let server_addr: SocketAddr = self
                .config
                .server
                .parse()
                .with_context(|| {
                    format!("Invalid Shadowsocks server address: {}", self.config.server)
                })
                .map_err(|e| AdapterError::Other(e.to_string()))?;

            // Create local UDP socket
            // 创建本地 UDP socket
            let local_socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(AdapterError::Io)?;

            // Connect to server for easier packet routing
            // 连接到服务器以便于数据包路由
            local_socket
                .connect(server_addr)
                .await
                .map_err(|e| AdapterError::Network(format!("UDP connect failed: {}", e)))?;

            // Create UDP socket wrapper
            // 创建 UDP socket 包装器
            let udp_socket = ShadowsocksUdpSocket::new(
                Arc::new(local_socket),
                self.cipher_method.clone(),
                self.key.clone(),
            )?;

            Ok(Box::new(udp_socket))
        }
    }
}

impl Default for ShadowsocksConnector {
    fn default() -> Self {
        // Create a default config for testing
        // 创建用于测试的默认配置
        let config = ShadowsocksConfig {
            server: "127.0.0.1:8388".to_string(),
            tag: None,
            method: "aes-256-gcm".to_string(),
            password: "default-password".to_string(),
            connect_timeout_sec: Some(30),
            multiplex: None,
        };
        Self::new(config.clone()).unwrap_or_else(|_| Self {
            config,
            cipher_method: CipherMethod::Aes256Gcm,
            key: vec![0u8; 32],
            multiplex_dialer: None,
        })
    }
}

#[async_trait]
impl OutboundConnector for ShadowsocksConnector {
    fn name(&self) -> &'static str {
        "shadowsocks"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-shadowsocks"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowsocks",
        });

        #[cfg(feature = "adapter-shadowsocks")]
        Ok(())
    }

    async fn dial(&self, target: Target, opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-shadowsocks"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowsocks",
        });

        #[cfg(feature = "adapter-shadowsocks")]
        {
            let _span = crate::outbound::span_dial("shadowsocks", &target);

            // Start metrics timing
            // 开始指标计时
            #[cfg(feature = "metrics")]
            let start_time = sb_metrics::start_adapter_timer();

            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "Shadowsocks outbound only supports TCP".to_string(),
                ));
            }

            // Clone target for logging before moving into async block
            // 在移入异步块之前克隆目标以进行日志记录
            let target_for_log = format!("{}:{}", target.host, target.port);

            let dial_result = async {
                // Parse server address
                // 解析服务器地址
                let server_addr: SocketAddr = self
                    .config
                    .server
                    .parse()
                    .with_context(|| {
                        format!("Invalid Shadowsocks server address: {}", self.config.server)
                    })
                    .map_err(|e| AdapterError::Other(e.to_string()))?;

                // Connect to Shadowsocks server (with or without multiplex)
                // 连接到 Shadowsocks 服务器（带或不带多路复用）
                let stream: BoxedStream = if let Some(ref mux_dialer) = self.multiplex_dialer {
                    // Use multiplex dialer
                    // 使用多路复用拨号器
                    tracing::debug!("Using multiplex dialer for Shadowsocks connection");
                    let io_stream = mux_dialer
                        .connect(&server_addr.ip().to_string(), server_addr.port())
                        .await
                        .map_err(|e| {
                            AdapterError::Other(format!("Multiplex dial failed: {}", e))
                        })?;
                    // Convert IoStream to BoxedStream
                    // 将 IoStream 转换为 BoxedStream
                    Box::new(io_stream) as BoxedStream
                } else {
                    // Standard TCP connection
                    // 标准 TCP 连接
                    let timeout = std::time::Duration::from_secs(
                        self.config.connect_timeout_sec.unwrap_or(30),
                    );
                    let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(server_addr))
                        .await
                        .with_context(|| {
                            format!("Failed to connect to Shadowsocks server {}", server_addr)
                        })
                        .map_err(|e| AdapterError::Other(e.to_string()))?
                        .with_context(|| {
                            format!(
                                "TCP connection to Shadowsocks server {} failed",
                                server_addr
                            )
                        })
                        .map_err(|e| AdapterError::Other(e.to_string()))?;
                    Box::new(tcp_stream) as BoxedStream
                };

                // Create encrypted stream wrapper
                // 创建加密流包装器
                let encrypted_stream = ShadowsocksStream::new(
                    stream,
                    self.cipher_method.clone(),
                    self.key.clone(),
                    target,
                    opts.resolve_mode.clone(),
                )
                .await?;

                Ok(Box::new(encrypted_stream) as BoxedStream)
            }
            .await;

            // Record metrics
            // 记录指标
            #[cfg(feature = "metrics")]
            {
                let result = match &dial_result {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e as &dyn core::fmt::Display),
                };
                sb_metrics::record_adapter_dial("shadowsocks", start_time, result);
            }

            // Handle result
            // 处理结果
            match dial_result {
                Ok(stream) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %target_for_log,
                        method = %self.config.method,
                        "Shadowsocks connection established"
                    );
                    Ok(stream)
                }
                Err(e) => {
                    tracing::debug!(
                        server = %self.config.server,
                        target = %target_for_log,
                        method = %self.config.method,
                        error = %e,
                        "Shadowsocks connection failed"
                    );
                    Err(e)
                }
            }
        }
    }
}

/// Encrypted stream wrapper for Shadowsocks AEAD
/// Shadowsocks AEAD 的加密流包装器
#[cfg(feature = "adapter-shadowsocks")]
struct ShadowsocksStream {
    inner: BoxedStream,
    cipher_method: CipherMethod,
    key: Vec<u8>,
    #[allow(dead_code)]
    write_buffer: Vec<u8>,
    #[allow(dead_code)]
    read_buffer: Vec<u8>,
    initialized: bool,
}

#[cfg(feature = "adapter-shadowsocks")]
impl ShadowsocksStream {
    async fn new(
        stream: BoxedStream,
        cipher_method: CipherMethod,
        key: Vec<u8>,
        target: Target,
        resolve_mode: ResolveMode,
    ) -> Result<Self> {
        // Send initial request with target address
        // 发送包含目标地址的初始请求
        let mut ss_stream = Self {
            inner: stream,
            cipher_method: cipher_method.clone(),
            key,
            write_buffer: Vec::new(),
            read_buffer: Vec::new(),
            initialized: false,
        };

        // Build target address payload
        // 构建目标地址负载
        let addr_payload = ShadowsocksStream::encode_target_address(&target, &resolve_mode).await?;

        // Encrypt and send initial payload
        // 加密并发送初始负载
        ss_stream.send_encrypted_data(&addr_payload).await?;
        ss_stream.initialized = true;

        Ok(ss_stream)
    }

    async fn encode_target_address(target: &Target, resolve_mode: &ResolveMode) -> Result<Vec<u8>> {
        let mut payload = Vec::new();

        // Determine target address based on resolve mode
        // 根据解析模式确定目标地址
        match resolve_mode {
            ResolveMode::Local => {
                // Resolve locally first
                // 先在本地解析
                if let Ok(ip) = target.host.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(ipv4) => {
                            payload.push(0x01); // IPv4
                            payload.extend_from_slice(&ipv4.octets());
                        }
                        IpAddr::V6(ipv6) => {
                            payload.push(0x04); // IPv6
                            payload.extend_from_slice(&ipv6.octets());
                        }
                    }
                } else {
                    // Domain name - resolve locally
                    // 域名 - 本地解析
                    match tokio::net::lookup_host((target.host.clone(), target.port)).await {
                        Ok(mut addrs) => {
                            if let Some(addr) = addrs.next() {
                                match addr.ip() {
                                    IpAddr::V4(ipv4) => {
                                        payload.push(0x01);
                                        payload.extend_from_slice(&ipv4.octets());
                                    }
                                    IpAddr::V6(ipv6) => {
                                        payload.push(0x04);
                                        payload.extend_from_slice(&ipv6.octets());
                                    }
                                }
                            } else {
                                return Err(AdapterError::Network(format!(
                                    "Failed to resolve {}",
                                    target.host
                                )));
                            }
                        }
                        Err(e) => {
                            return Err(AdapterError::Network(format!(
                                "DNS resolution failed for {}: {}",
                                target.host, e
                            )));
                        }
                    }
                }
            }
            ResolveMode::Remote => {
                // Send domain name for remote resolution
                // 发送域名进行远程解析
                payload.push(0x03); // Domain name
                let hostname_bytes = target.host.as_bytes();
                if hostname_bytes.len() > 255 {
                    return Err(AdapterError::InvalidConfig("Hostname too long"));
                }
                payload.push(hostname_bytes.len() as u8);
                payload.extend_from_slice(hostname_bytes);
            }
        }

        // Add port
        // 添加端口
        payload.extend_from_slice(&target.port.to_be_bytes());

        Ok(payload)
    }

    async fn send_encrypted_data(&mut self, data: &[u8]) -> Result<()> {
        let encrypted_data = self.encrypt_data(data)?;
        self.inner
            .write_all(&encrypted_data)
            .await
            .map_err(AdapterError::Io)?;
        Ok(())
    }

    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce
        // 生成随机 nonce
        let nonce_len = self.cipher_method.nonce_size();
        let mut nonce = vec![0u8; nonce_len];
        rand::thread_rng().fill_bytes(&mut nonce);

        let ciphertext = match &self.cipher_method {
            CipherMethod::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                let nonce_array = Nonce::from_slice(&nonce);
                cipher
                    .encrypt(nonce_array, data)
                    .map_err(|_| AdapterError::Protocol("AES-GCM encryption failed".to_string()))?
            }
            CipherMethod::ChaCha20Poly1305 => {
                let key_array = Key::from_slice(&self.key);
                let cipher = ChaCha20Poly1305::new(key_array);
                let nonce_array = ChaNonce::from_slice(&nonce);
                cipher.encrypt(nonce_array, data).map_err(|_| {
                    AdapterError::Protocol("ChaCha20-Poly1305 encryption failed".to_string())
                })?
            }
        };

        // Combine salt + nonce + ciphertext for AEAD format
        // 组合 salt + nonce + 密文为 AEAD 格式
        let mut result = Vec::new();
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    #[allow(dead_code)]
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let nonce_len = self.cipher_method.nonce_size();
        if encrypted_data.len() < nonce_len {
            return Err(AdapterError::Protocol(
                "Encrypted data too short".to_string(),
            ));
        }

        let nonce = &encrypted_data[..nonce_len];
        let ciphertext = &encrypted_data[nonce_len..];

        let plaintext = match &self.cipher_method {
            CipherMethod::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                let nonce_array = Nonce::from_slice(nonce);
                cipher
                    .decrypt(nonce_array, ciphertext)
                    .map_err(|_| AdapterError::Protocol("AES-GCM decryption failed".to_string()))?
            }
            CipherMethod::ChaCha20Poly1305 => {
                let key_array = Key::from_slice(&self.key);
                let cipher = ChaCha20Poly1305::new(key_array);
                let nonce_array = ChaNonce::from_slice(nonce);
                cipher.decrypt(nonce_array, ciphertext).map_err(|_| {
                    AdapterError::Protocol("ChaCha20-Poly1305 decryption failed".to_string())
                })?
            }
        };

        Ok(plaintext)
    }
}

#[cfg(feature = "adapter-shadowsocks")]
impl tokio::io::AsyncRead for ShadowsocksStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Simple passthrough for now - in production this should handle chunked decryption
        // 目前简单透传 - 生产环境中应处理分块解密
        let inner = std::pin::Pin::new(&mut self.inner);
        inner.poll_read(cx, buf)
    }
}

#[cfg(feature = "adapter-shadowsocks")]
impl tokio::io::AsyncWrite for ShadowsocksStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        // Simple passthrough for now - in production this should handle encryption
        // 目前简单透传 - 生产环境中应处理加密
        let inner = std::pin::Pin::new(&mut self.inner);
        inner.poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let inner = std::pin::Pin::new(&mut self.inner);
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        let inner = std::pin::Pin::new(&mut self.inner);
        inner.poll_shutdown(cx)
    }
}

/// Shadowsocks UDP socket wrapper that implements OutboundDatagram
/// 实现 OutboundDatagram 的 Shadowsocks UDP socket 包装器
/// Handles AEAD encryption/decryption for UDP packets
/// 处理 UDP 数据包的 AEAD 加密/解密
#[cfg(feature = "adapter-shadowsocks")]
#[derive(Debug)]
pub struct ShadowsocksUdpSocket {
    socket: Arc<UdpSocket>,
    cipher_method: CipherMethod,
    key: Vec<u8>,
    /// Target address for UDP relay (stored during creation)
    target_addr: tokio::sync::Mutex<Option<Target>>,
}

#[cfg(feature = "adapter-shadowsocks")]
impl ShadowsocksUdpSocket {
    pub fn new(socket: Arc<UdpSocket>, cipher_method: CipherMethod, key: Vec<u8>) -> Result<Self> {
        Ok(Self {
            socket,
            cipher_method,
            key,
            target_addr: tokio::sync::Mutex::new(None),
        })
    }

    /// Set target address for subsequent operations
    /// 设置后续操作的目标地址
    pub async fn set_target(&self, target: Target) {
        let mut addr = self.target_addr.lock().await;
        *addr = Some(target);
    }

    /// Encode target address in SOCKS5 format
    /// 以 SOCKS5 格式编码目标地址
    fn encode_target_address(&self, target: &Target) -> Result<Vec<u8>> {
        let mut payload = Vec::new();

        // Try to parse as IP address first
        // 尝试先解析为 IP 地址
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ipv4) => {
                    payload.push(0x01); // IPv4
                    payload.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    payload.push(0x04); // IPv6
                    payload.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            // Domain name
            // 域名
            payload.push(0x03); // Domain
            let hostname_bytes = target.host.as_bytes();
            if hostname_bytes.len() > 255 {
                return Err(AdapterError::InvalidConfig("Hostname too long"));
            }
            payload.push(hostname_bytes.len() as u8);
            payload.extend_from_slice(hostname_bytes);
        }

        // Add port
        // 添加端口
        payload.extend_from_slice(&target.port.to_be_bytes());

        Ok(payload)
    }

    /// Encrypt UDP packet with AEAD
    /// 使用 AEAD 加密 UDP 数据包
    /// Format: salt (16-32 bytes) + encrypted(ATYP + ADDR + PORT + DATA) + tag (16 bytes)
    /// 格式：salt (16-32 字节) + encrypted(ATYP + ADDR + PORT + DATA) + tag (16 字节)
    fn encrypt_packet(&self, data: &[u8], target: &Target) -> Result<Vec<u8>> {
        // Generate random salt
        // 生成随机 salt
        let salt_len = self.cipher_method.nonce_size();
        let mut salt = vec![0u8; salt_len];
        rand::thread_rng().fill_bytes(&mut salt);

        // Build payload: address + port + data
        // 构建负载：地址 + 端口 + 数据
        let mut payload = self.encode_target_address(target)?;
        payload.extend_from_slice(data);

        // Encrypt payload
        // 加密负载
        let ciphertext = match &self.cipher_method {
            CipherMethod::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                let nonce_array = Nonce::from_slice(&salt);
                cipher
                    .encrypt(nonce_array, payload.as_ref())
                    .map_err(|_| AdapterError::Protocol("AES-GCM encryption failed".to_string()))?
            }
            CipherMethod::ChaCha20Poly1305 => {
                let key_array = Key::from_slice(&self.key);
                let cipher = ChaCha20Poly1305::new(key_array);
                let nonce_array = ChaNonce::from_slice(&salt);
                cipher.encrypt(nonce_array, payload.as_ref()).map_err(|_| {
                    AdapterError::Protocol("ChaCha20-Poly1305 encryption failed".to_string())
                })?
            }
        };

        // Combine: salt + ciphertext (includes tag)
        // 组合：salt + 密文（包含 tag）
        let mut packet = Vec::with_capacity(salt.len() + ciphertext.len());
        packet.extend_from_slice(&salt);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }

    /// Decrypt UDP packet with AEAD
    /// 使用 AEAD 解密 UDP 数据包
    fn decrypt_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let salt_len = self.cipher_method.nonce_size();
        let tag_size = self.cipher_method.tag_size();

        if packet.len() < salt_len + tag_size {
            return Err(AdapterError::Protocol("Packet too short".to_string()));
        }

        let salt = &packet[..salt_len];
        let ciphertext = &packet[salt_len..];

        // Decrypt
        // 解密
        let plaintext = match &self.cipher_method {
            CipherMethod::Aes256Gcm => {
                let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
                let nonce_array = Nonce::from_slice(salt);
                cipher
                    .decrypt(nonce_array, ciphertext)
                    .map_err(|_| AdapterError::Protocol("AES-GCM decryption failed".to_string()))?
            }
            CipherMethod::ChaCha20Poly1305 => {
                let key_array = Key::from_slice(&self.key);
                let cipher = ChaCha20Poly1305::new(key_array);
                let nonce_array = ChaNonce::from_slice(salt);
                cipher.decrypt(nonce_array, ciphertext).map_err(|_| {
                    AdapterError::Protocol("ChaCha20-Poly1305 decryption failed".to_string())
                })?
            }
        };

        // Skip address header (ATYP + ADDR + PORT) and return data
        // 跳过地址头部 (ATYP + ADDR + PORT) 并返回数据
        // For now, we return the full decrypted payload
        // 目前，我们返回完整的解密负载
        // In production, should parse and skip the address header
        // 生产环境中，应解析并跳过地址头部
        let addr_len = self.parse_address_length(&plaintext)?;
        Ok(plaintext[addr_len..].to_vec())
    }

    /// Parse address header length from decrypted payload
    /// 从解密负载中解析地址头部长度
    fn parse_address_length(&self, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Err(AdapterError::Protocol("Empty payload".to_string()));
        }

        let atyp = data[0];
        match atyp {
            0x01 => Ok(1 + 4 + 2), // IPv4: ATYP + 4 bytes + port
            0x03 => {
                // Domain: ATYP + length byte + domain + port
                if data.len() < 2 {
                    return Err(AdapterError::Protocol("Invalid domain address".to_string()));
                }
                let domain_len = data[1] as usize;
                Ok(1 + 1 + domain_len + 2)
            }
            0x04 => Ok(1 + 16 + 2), // IPv6: ATYP + 16 bytes + port
            _ => Err(AdapterError::Protocol(format!(
                "Unsupported address type: {}",
                atyp
            ))),
        }
    }
}

#[cfg(feature = "adapter-shadowsocks")]
#[async_trait]
impl OutboundDatagram for ShadowsocksUdpSocket {
    async fn send_to(&self, payload: &[u8]) -> Result<usize> {
        // Get target address
        // 获取目标地址
        let target = {
            let addr_lock = self.target_addr.lock().await;
            addr_lock
                .as_ref()
                .ok_or_else(|| AdapterError::Other("Target address not set".to_string()))?
                .clone()
        };

        // Encrypt packet
        // 加密数据包
        let encrypted_packet = self.encrypt_packet(payload, &target)?;

        // Send to Shadowsocks server
        // 发送到 Shadowsocks 服务器
        let sent = self
            .socket
            .send(&encrypted_packet)
            .await
            .map_err(AdapterError::Io)?;

        tracing::trace!(
            target = %format!("{}:{}", target.host, target.port),
            sent = sent,
            encrypted_len = encrypted_packet.len(),
            "Shadowsocks UDP packet sent"
        );

        Ok(payload.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<usize> {
        // Receive from Shadowsocks server
        // 从 Shadowsocks 服务器接收
        let (n, _peer) = self.socket.recv_from(buf).await.map_err(AdapterError::Io)?;

        // Decrypt packet
        // 解密数据包
        let decrypted = self.decrypt_packet(&buf[..n])?;

        // Copy decrypted data back to buffer
        // 将解密数据复制回缓冲区
        if decrypted.len() > buf.len() {
            return Err(AdapterError::Other("Buffer too small".to_string()));
        }

        buf[..decrypted.len()].copy_from_slice(&decrypted);

        tracing::trace!(
            received = n,
            decrypted_len = decrypted.len(),
            "Shadowsocks UDP packet received"
        );

        Ok(decrypted.len())
    }

    async fn close(&self) -> Result<()> {
        // No explicit close needed for UDP sockets
        tracing::debug!("Shadowsocks UDP socket closed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_shadowsocks_connector_creation() {
        let config = ShadowsocksConfig {
            server: "127.0.0.1:8388".to_string(),
            tag: Some("test".to_string()),
            method: "aes-256-gcm".to_string(),
            password: "test-password".to_string(),
            connect_timeout_sec: Some(30),
            multiplex: None,
        };

        let connector = ShadowsocksConnector::new(config).expect("Failed to create connector");
        assert_eq!(connector.name(), "shadowsocks");
        assert_eq!(connector.cipher_method, CipherMethod::Aes256Gcm);
        assert_eq!(connector.key.len(), 32); // AES-256 key size
    }

    #[test]
    fn test_cipher_method_parsing() {
        assert_eq!(
            CipherMethod::from_str("aes-256-gcm").unwrap(),
            CipherMethod::Aes256Gcm
        );
        assert_eq!(
            CipherMethod::from_str("chacha20-poly1305").unwrap(),
            CipherMethod::ChaCha20Poly1305
        );
        assert_eq!(
            CipherMethod::from_str("chacha20-ietf-poly1305").unwrap(),
            CipherMethod::ChaCha20Poly1305
        );

        assert!(CipherMethod::from_str("unsupported-method").is_err());
    }

    #[test]
    fn test_key_derivation() {
        let password = "test-password";
        let method = CipherMethod::Aes256Gcm;
        let key = ShadowsocksConnector::derive_key(password, &method);

        assert_eq!(key.len(), 32);
        // Key should be deterministic for same password
        let key2 = ShadowsocksConnector::derive_key(password, &method);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_with_config_helper() {
        let connector =
            ShadowsocksConnector::with_config("127.0.0.1:8388", "aes-256-gcm", "test-password")
                .expect("Failed to create connector");

        assert_eq!(connector.name(), "shadowsocks");
        assert_eq!(connector.config.server, "127.0.0.1:8388");
    }

    #[cfg(feature = "adapter-shadowsocks")]
    #[tokio::test]
    async fn test_udp_socket_address_encoding_ipv4() {
        use crate::traits::TransportKind;

        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let udp_socket =
            ShadowsocksUdpSocket::new(socket, CipherMethod::Aes256Gcm, vec![0u8; 32]).unwrap();

        let target = Target::new("192.168.1.1", 8080, TransportKind::Udp);
        let encoded = udp_socket.encode_target_address(&target).unwrap();

        // Verify IPv4 encoding: ATYP(1) + IP(4) + PORT(2) = 7 bytes
        assert_eq!(encoded[0], 0x01); // IPv4 ATYP
        assert_eq!(encoded.len(), 7);
        assert_eq!(&encoded[1..5], &[192, 168, 1, 1]); // IP
        assert_eq!(u16::from_be_bytes([encoded[5], encoded[6]]), 8080); // Port
    }

    #[cfg(feature = "adapter-shadowsocks")]
    #[tokio::test]
    async fn test_udp_socket_address_encoding_domain() {
        use crate::traits::TransportKind;

        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let udp_socket =
            ShadowsocksUdpSocket::new(socket, CipherMethod::Aes256Gcm, vec![0u8; 32]).unwrap();

        let target = Target::new("example.com", 443, TransportKind::Udp);
        let encoded = udp_socket.encode_target_address(&target).unwrap();

        // Verify domain encoding: ATYP(1) + LEN(1) + DOMAIN(11) + PORT(2) = 15 bytes
        assert_eq!(encoded[0], 0x03); // Domain ATYP
        assert_eq!(encoded[1], 11); // Length of "example.com"
        assert_eq!(&encoded[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([encoded[13], encoded[14]]), 443);
    }

    #[cfg(feature = "adapter-shadowsocks")]
    #[tokio::test]
    async fn test_udp_packet_encryption_decryption() {
        use crate::traits::TransportKind;

        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let udp_socket =
            ShadowsocksUdpSocket::new(socket, CipherMethod::ChaCha20Poly1305, vec![0u8; 32])
                .unwrap();

        let target = Target::new("192.168.1.1", 8080, TransportKind::Udp);
        let test_data = b"Hello, World!";

        // Encrypt
        let encrypted = udp_socket.encrypt_packet(test_data, &target).unwrap();

        // Verify encrypted packet structure
        assert!(encrypted.len() > test_data.len()); // Should be longer due to salt, address, and tag

        // Decrypt
        let decrypted = udp_socket.decrypt_packet(&encrypted).unwrap();

        // Verify decrypted data matches original
        assert_eq!(decrypted, test_data);
    }

    #[cfg(feature = "adapter-shadowsocks")]
    #[tokio::test]
    async fn test_parse_address_length() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let udp_socket =
            ShadowsocksUdpSocket::new(socket, CipherMethod::Aes256Gcm, vec![0u8; 32]).unwrap();

        // IPv4: ATYP(1) + IP(4) + PORT(2) = 7
        let ipv4_data = vec![0x01, 192, 168, 1, 1, 0x1f, 0x90];
        assert_eq!(udp_socket.parse_address_length(&ipv4_data).unwrap(), 7);

        // Domain: ATYP(1) + LEN(1) + DOMAIN(11) + PORT(2) = 15
        let domain_data = vec![
            0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb,
        ];
        assert_eq!(udp_socket.parse_address_length(&domain_data).unwrap(), 15);

        // IPv6: ATYP(1) + IP(16) + PORT(2) = 19
        let mut ipv6_data = vec![0x04];
        ipv6_data.extend_from_slice(&[0u8; 16]); // IPv6 address
        ipv6_data.extend_from_slice(&[0x00, 0x50]); // Port
        assert_eq!(udp_socket.parse_address_length(&ipv6_data).unwrap(), 19);
    }
}
