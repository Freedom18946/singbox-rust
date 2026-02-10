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
use hkdf::Hkdf;
use sb_transport::Dialer;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// Crypto imports
use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaNonce};
use rand::RngCore;
use sha1::Sha1;

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
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherMethod {
    fn from_str(method: &str) -> Result<Self> {
        match method.to_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
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
            Self::Aes128Gcm => 16,        // AES-128
            Self::Aes256Gcm => 32,        // AES-256
            Self::ChaCha20Poly1305 => 32, // ChaCha20
        }
    }

    fn salt_len(&self) -> usize {
        // SIP004: salt length equals key length.
        self.key_size()
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
    master_key: Vec<u8>,
    multiplex_dialer: Option<std::sync::Arc<sb_transport::multiplex::MultiplexDialer>>,
}

impl ShadowsocksConnector {
    pub fn new(config: ShadowsocksConfig) -> Result<Self> {
        let cipher_method = CipherMethod::from_str(&config.method)?;
        let master_key = Self::derive_master_key(&config.password, cipher_method.key_size());

        // Create multiplex dialer if configured
        // 如果配置了多路复用，创建多路复用拨号器
        let multiplex_dialer = if let Some(mux_config) = config.multiplex.clone() {
            let timeout = std::time::Duration::from_secs(config.connect_timeout_sec.unwrap_or(30));
            let ss_dialer = Box::new(ShadowsocksTunnelDialer::new(
                cipher_method.clone(),
                master_key.clone(),
                timeout,
            )) as Box<dyn sb_transport::Dialer>;
            Some(std::sync::Arc::new(
                sb_transport::multiplex::MultiplexDialer::new(mux_config, ss_dialer),
            ))
        } else {
            None
        };

        Ok(Self {
            config,
            cipher_method,
            master_key,
            multiplex_dialer,
        })
    }

    /// Derive master key from password.
    ///
    /// Note: this mirrors the inbound's current derivation logic (SHA1-based, deterministic).
    /// It is intentionally kept compatible with our inbound implementation.
    fn derive_master_key(password: &str, key_len: usize) -> Vec<u8> {
        use sha1::Digest;
        let mut hasher = sha1::Sha1::new();
        hasher.update(password.as_bytes());
        let mut out = hasher.finalize().to_vec();
        while out.len() < key_len {
            let mut h = sha1::Sha1::new();
            h.update(&out);
            out.extend_from_slice(&h.finalize());
        }
        out.truncate(key_len);
        out
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
                self.master_key.clone(),
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
            master_key: vec![0u8; 32],
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

                let addr_payload = encode_target_address(&target, &opts.resolve_mode).await?;

                if let Some(ref mux_dialer) = self.multiplex_dialer {
                    // Multiplex is layered over the encrypted Shadowsocks tunnel:
                    // SS(auth + AEAD chunks) transports yamux; each yamux stream starts with
                    // a Shadowsocks address header (cleartext inside the tunnel).
                    let io_stream: sb_transport::dialer::IoStream = mux_dialer
                        .connect(&server_addr.ip().to_string(), server_addr.port())
                        .await
                        .map_err(|e| {
                            AdapterError::Other(format!("Multiplex dial failed: {}", e))
                        })?;
                    let mut stream: BoxedStream = Box::new(io_stream) as BoxedStream;
                    stream
                        .write_all(&addr_payload)
                        .await
                        .map_err(AdapterError::Io)?;
                    Ok(stream)
                } else {
                    // Standard TCP connection (no multiplex): create a single encrypted tunnel
                    // and send one address header for this connection.
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

                    let mut tunnel: BoxedStream = Box::new(
                        ShadowsocksTunnelStream::connect(
                            tcp_stream,
                            self.cipher_method.clone(),
                            self.master_key.clone(),
                        )
                        .await?,
                    );

                    tunnel
                        .write_all(&addr_payload)
                        .await
                        .map_err(AdapterError::Io)?;
                    Ok(tunnel)
                }
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

#[cfg(feature = "adapter-shadowsocks")]
async fn encode_target_address(target: &Target, resolve_mode: &ResolveMode) -> Result<Vec<u8>> {
    let mut payload = Vec::new();

    match resolve_mode {
        ResolveMode::Local => {
            if let Ok(ip) = target.host.parse::<IpAddr>() {
                match ip {
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
            payload.push(0x03);
            let hostname_bytes = target.host.as_bytes();
            if hostname_bytes.len() > 255 {
                return Err(AdapterError::InvalidConfig("Hostname too long"));
            }
            payload.push(hostname_bytes.len() as u8);
            payload.extend_from_slice(hostname_bytes);
        }
    }

    payload.extend_from_slice(&target.port.to_be_bytes());
    Ok(payload)
}

#[cfg(feature = "adapter-shadowsocks")]
fn ss_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(feature = "adapter-shadowsocks")]
fn hkdf_subkey(master_key: &[u8], salt: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    let mut okm = vec![0u8; out_len];
    hk.expand(b"ss-subkey", &mut okm)
        .map_err(|_| AdapterError::Protocol("HKDF expand failed".to_string()))?;
    Ok(okm)
}

#[cfg(feature = "adapter-shadowsocks")]
fn aead_encrypt(cipher: &CipherMethod, key: &[u8], nonce_ctr: u64, data: &[u8]) -> Result<Vec<u8>> {
    let nonce = ss_nonce(nonce_ctr);
    match cipher {
        CipherMethod::Aes128Gcm => {
            let aead = Aes128Gcm::new(GenericArray::from_slice(key));
            aead.encrypt(Nonce::from_slice(&nonce), data)
                .map_err(|_| AdapterError::Protocol("AES-GCM encrypt failed".to_string()))
        }
        CipherMethod::Aes256Gcm => {
            let aead = Aes256Gcm::new(GenericArray::from_slice(key));
            aead.encrypt(Nonce::from_slice(&nonce), data)
                .map_err(|_| AdapterError::Protocol("AES-GCM encrypt failed".to_string()))
        }
        CipherMethod::ChaCha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(Key::from_slice(key));
            aead.encrypt(ChaNonce::from_slice(&nonce), data)
                .map_err(|_| AdapterError::Protocol("ChaCha20 encrypt failed".to_string()))
        }
    }
}

#[cfg(feature = "adapter-shadowsocks")]
fn aead_decrypt(cipher: &CipherMethod, key: &[u8], nonce_ctr: u64, data: &[u8]) -> Result<Vec<u8>> {
    let nonce = ss_nonce(nonce_ctr);
    match cipher {
        CipherMethod::Aes128Gcm => {
            let aead = Aes128Gcm::new(GenericArray::from_slice(key));
            aead.decrypt(Nonce::from_slice(&nonce), data)
                .map_err(|_| AdapterError::Protocol("AES-GCM decrypt failed".to_string()))
        }
        CipherMethod::Aes256Gcm => {
            let aead = Aes256Gcm::new(GenericArray::from_slice(key));
            aead.decrypt(Nonce::from_slice(&nonce), data)
                .map_err(|_| AdapterError::Protocol("AES-GCM decrypt failed".to_string()))
        }
        CipherMethod::ChaCha20Poly1305 => {
            let aead = ChaCha20Poly1305::new(Key::from_slice(key));
            aead.decrypt(ChaNonce::from_slice(&nonce), data)
                .map_err(|_| AdapterError::Protocol("ChaCha20 decrypt failed".to_string()))
        }
    }
}

#[cfg(feature = "adapter-shadowsocks")]
async fn read_exact_n(r: &mut (impl tokio::io::AsyncRead + Unpin), n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await.map_err(AdapterError::Io)?;
    Ok(buf)
}

#[cfg(feature = "adapter-shadowsocks")]
async fn read_aead_chunk(
    cipher: &CipherMethod,
    key: &[u8],
    nonce_ctr: &mut u64,
    r: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Vec<u8>> {
    let tag = 16usize;
    let enc_len = read_exact_n(r, 2 + tag).await?;
    let len_plain = aead_decrypt(cipher, key, *nonce_ctr, &enc_len)?;
    *nonce_ctr += 1;
    if len_plain.len() != 2 {
        return Err(AdapterError::Protocol("bad len".to_string()));
    }
    let plen = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    let enc_payload = read_exact_n(r, plen + tag).await?;
    let payload = aead_decrypt(cipher, key, *nonce_ctr, &enc_payload)?;
    *nonce_ctr += 1;
    Ok(payload)
}

#[cfg(feature = "adapter-shadowsocks")]
async fn write_aead_chunk(
    cipher: &CipherMethod,
    key: &[u8],
    nonce_ctr: &mut u64,
    w: &mut (impl tokio::io::AsyncWrite + Unpin),
    data: &[u8],
) -> Result<()> {
    if data.is_empty() {
        let len_be = 0u16.to_be_bytes();
        let enc_len = aead_encrypt(cipher, key, *nonce_ctr, &len_be)?;
        *nonce_ctr += 1;
        let enc_payload = aead_encrypt(cipher, key, *nonce_ctr, &[])?;
        *nonce_ctr += 1;
        w.write_all(&enc_len).await.map_err(AdapterError::Io)?;
        w.write_all(&enc_payload).await.map_err(AdapterError::Io)?;
        return Ok(());
    }

    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + u16::MAX as usize).min(data.len());
        let chunk = &data[offset..end];
        let len_be = (chunk.len() as u16).to_be_bytes();
        let enc_len = aead_encrypt(cipher, key, *nonce_ctr, &len_be)?;
        *nonce_ctr += 1;
        let enc_payload = aead_encrypt(cipher, key, *nonce_ctr, chunk)?;
        *nonce_ctr += 1;
        w.write_all(&enc_len).await.map_err(AdapterError::Io)?;
        w.write_all(&enc_payload).await.map_err(AdapterError::Io)?;
        offset = end;
    }
    Ok(())
}

/// A client-side Shadowsocks AEAD tunnel that exposes a cleartext stream to upper layers.
/// It performs salt exchange and chunked AEAD framing compatible with our inbound implementation.
#[cfg(feature = "adapter-shadowsocks")]
struct ShadowsocksTunnelStream {
    inner: tokio::io::DuplexStream,
    task_encrypt: tokio::task::JoinHandle<()>,
    task_decrypt: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "adapter-shadowsocks")]
impl ShadowsocksTunnelStream {
    async fn connect(
        mut tcp_stream: TcpStream,
        cipher: CipherMethod,
        master_key: Vec<u8>,
    ) -> Result<Self> {
        let salt_len = cipher.salt_len();

        // Client salt + subkey (client -> server)
        let mut csalt = vec![0u8; salt_len];
        rand::thread_rng().fill_bytes(&mut csalt);
        tcp_stream
            .write_all(&csalt)
            .await
            .map_err(AdapterError::Io)?;
        let c_subkey = hkdf_subkey(&master_key, &csalt, cipher.key_size())?;

        // Write one empty chunk to ensure the server proceeds and sends back server salt.
        let mut wnonce = 0u64;
        write_aead_chunk(&cipher, &c_subkey, &mut wnonce, &mut tcp_stream, &[]).await?;
        debug_assert_eq!(wnonce, 2);

        // Server salt + subkey (server -> client)
        let mut ssalt = vec![0u8; salt_len];
        tcp_stream
            .read_exact(&mut ssalt)
            .await
            .map_err(AdapterError::Io)?;
        let s_subkey = hkdf_subkey(&master_key, &ssalt, cipher.key_size())?;

        let (clear_local, clear_remote) = tokio::io::duplex(65536);
        let (mut clear_r, mut clear_w) = tokio::io::split(clear_remote);
        let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp_stream);

        let cipher_read = cipher.clone();
        let key_read = s_subkey.clone();
        let task_decrypt = tokio::spawn(async move {
            let mut rnonce = 0u64;
            while let Ok(payload) =
                read_aead_chunk(&cipher_read, &key_read, &mut rnonce, &mut tcp_r).await
            {
                if clear_w.write_all(&payload).await.is_err() {
                    break;
                }
            }
        });

        let cipher_write = cipher.clone();
        let key_write = c_subkey.clone();
        let task_encrypt = tokio::spawn(async move {
            let mut wnonce = 2u64;
            let mut buf = vec![0u8; 65536];
            loop {
                match clear_r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if write_aead_chunk(
                            &cipher_write,
                            &key_write,
                            &mut wnonce,
                            &mut tcp_w,
                            &buf[..n],
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            inner: clear_local,
            task_encrypt,
            task_decrypt,
        })
    }
}

#[cfg(feature = "adapter-shadowsocks")]
impl Drop for ShadowsocksTunnelStream {
    fn drop(&mut self) {
        self.task_encrypt.abort();
        self.task_decrypt.abort();
    }
}

#[cfg(feature = "adapter-shadowsocks")]
impl tokio::io::AsyncRead for ShadowsocksTunnelStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "adapter-shadowsocks")]
impl tokio::io::AsyncWrite for ShadowsocksTunnelStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
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

/// sb-transport Dialer that returns a cleartext Shadowsocks AEAD tunnel (for layering yamux over it).
#[cfg(feature = "adapter-shadowsocks")]
struct ShadowsocksTunnelDialer {
    cipher: CipherMethod,
    master_key: Vec<u8>,
    timeout: std::time::Duration,
}

#[cfg(feature = "adapter-shadowsocks")]
impl ShadowsocksTunnelDialer {
    fn new(cipher: CipherMethod, master_key: Vec<u8>, timeout: std::time::Duration) -> Self {
        Self {
            cipher,
            master_key,
            timeout,
        }
    }
}

#[cfg(feature = "adapter-shadowsocks")]
#[async_trait::async_trait]
impl sb_transport::dialer::Dialer for ShadowsocksTunnelDialer {
    async fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> std::result::Result<sb_transport::dialer::IoStream, sb_transport::dialer::DialError> {
        let ip: std::net::IpAddr = host
            .parse()
            .map_err(|_| sb_transport::dialer::DialError::Other(format!("invalid host: {host}")))?;
        let addr = std::net::SocketAddr::new(ip, port);
        let tcp_stream = tokio::time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| sb_transport::dialer::DialError::Other("timeout".to_string()))?
            .map_err(sb_transport::dialer::DialError::Io)?;

        let tunnel = ShadowsocksTunnelStream::connect(
            tcp_stream,
            self.cipher.clone(),
            self.master_key.clone(),
        )
        .await
        .map_err(|e| sb_transport::dialer::DialError::Other(e.to_string()))?;

        Ok(Box::new(tunnel))
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

// Stub implementation for builds without `adapter-shadowsocks`.
// The outbound connector will return NotImplemented in that case, but we still
// need the type to exist for `ShadowsocksConnector::new()` to compile.
#[cfg(not(feature = "adapter-shadowsocks"))]
struct ShadowsocksTunnelDialer;

#[cfg(not(feature = "adapter-shadowsocks"))]
impl ShadowsocksTunnelDialer {
    #[allow(dead_code)]
    fn new(_cipher: CipherMethod, _master_key: Vec<u8>, _timeout: std::time::Duration) -> Self {
        Self
    }
}

#[cfg(not(feature = "adapter-shadowsocks"))]
#[async_trait::async_trait]
impl sb_transport::dialer::Dialer for ShadowsocksTunnelDialer {
    async fn connect(
        &self,
        _host: &str,
        _port: u16,
    ) -> std::result::Result<sb_transport::dialer::IoStream, sb_transport::dialer::DialError> {
        Err(sb_transport::dialer::DialError::NotSupported)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
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
    master_key: Vec<u8>,
    /// Target address for UDP relay (stored during creation)
    target_addr: tokio::sync::Mutex<Option<Target>>,
}

#[cfg(feature = "adapter-shadowsocks")]
impl ShadowsocksUdpSocket {
    pub fn new(
        socket: Arc<UdpSocket>,
        cipher_method: CipherMethod,
        master_key: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self {
            socket,
            cipher_method,
            master_key,
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
        // Generate random salt (salt length equals key length).
        let salt_len = self.cipher_method.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::thread_rng().fill_bytes(&mut salt);

        // Build payload: address + port + data
        // 构建负载：地址 + 端口 + 数据
        let mut payload = self.encode_target_address(target)?;
        payload.extend_from_slice(data);

        // Derive subkey for this packet and encrypt with nonce=0.
        let subkey = hkdf_subkey(&self.master_key, &salt, self.cipher_method.key_size())?;
        let ciphertext = aead_encrypt(&self.cipher_method, &subkey, 0, &payload)?;

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
        let salt_len = self.cipher_method.salt_len();
        let tag_size = self.cipher_method.tag_size();

        if packet.len() < salt_len + tag_size {
            return Err(AdapterError::Protocol("Packet too short".to_string()));
        }

        let salt = &packet[..salt_len];
        let ciphertext = &packet[salt_len..];

        let subkey = hkdf_subkey(&self.master_key, salt, self.cipher_method.key_size())?;
        let plaintext = aead_decrypt(&self.cipher_method, &subkey, 0, ciphertext)?;

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
        assert_eq!(connector.master_key.len(), 32); // AES-256 master key size
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
        let key = ShadowsocksConnector::derive_master_key(password, method.key_size());

        assert_eq!(key.len(), 32);
        // Key should be deterministic for same password
        let key2 = ShadowsocksConnector::derive_master_key(password, method.key_size());
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
        let Some(socket) = bind_udp_socket().await else {
            return;
        };

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
        let Some(socket) = bind_udp_socket().await else {
            return;
        };

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
        let Some(socket) = bind_udp_socket().await else {
            return;
        };

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
        let Some(socket) = bind_udp_socket().await else {
            return;
        };

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

    #[cfg(feature = "adapter-shadowsocks")]
    async fn bind_udp_socket() -> Option<Arc<UdpSocket>> {
        match tokio::net::UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => Some(Arc::new(socket)),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping shadowsocks udp test: permission denied");
                None
            }
            Err(e) => panic!("udp bind failed: {e}"),
        }
    }
}
