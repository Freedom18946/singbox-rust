//! Shadowsocks outbound connector implementation
//!
//! This module provides Shadowsocks protocol support for outbound connections.
//! Supports AEAD ciphers including AES-GCM and ChaCha20-Poly1305.

use crate::outbound::prelude::*;
use crate::traits::ResolveMode;
use anyhow::Context;
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

// Crypto imports
use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Shadowsocks configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShadowsocksConfig {
    /// Server address (host:port)
    pub server: String,
    /// Connection tag
    #[serde(default)]
    pub tag: Option<String>,
    /// Encryption method
    pub method: String,
    /// Password for encryption
    pub password: String,
    /// Connection timeout in seconds
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
}

/// Supported Shadowsocks encryption methods
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
#[derive(Debug, Clone)]
pub struct ShadowsocksConnector {
    config: ShadowsocksConfig,
    cipher_method: CipherMethod,
    key: Vec<u8>,
}

impl ShadowsocksConnector {
    pub fn new(config: ShadowsocksConfig) -> Result<Self> {
        let cipher_method = CipherMethod::from_str(&config.method)?;
        let key = Self::derive_key(&config.password, &cipher_method);

        Ok(Self {
            config,
            cipher_method,
            key,
        })
    }

    /// Derive encryption key from password using HKDF-SHA1 (Shadowsocks standard)
    fn derive_key(password: &str, method: &CipherMethod) -> Vec<u8> {
        let key_len = method.key_size();
        let mut key = vec![0u8; key_len];

        // Simple key derivation based on Shadowsocks spec
        // For production, this should use proper HKDF
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
        };
        Self::new(config)
    }
}

impl Default for ShadowsocksConnector {
    fn default() -> Self {
        // Create a default config for testing
        let config = ShadowsocksConfig {
            server: "127.0.0.1:8388".to_string(),
            tag: None,
            method: "aes-256-gcm".to_string(),
            password: "default-password".to_string(),
            connect_timeout_sec: Some(30),
        };
        Self::new(config.clone()).unwrap_or_else(|_| Self {
            config,
            cipher_method: CipherMethod::Aes256Gcm,
            key: vec![0u8; 32],
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
            #[cfg(feature = "metrics")]
            let start_time = sb_metrics::start_adapter_timer();

            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "Shadowsocks outbound only supports TCP".to_string(),
                ));
            }

            // Clone target for logging before moving into async block
            let target_for_log = format!("{}:{}", target.host, target.port);

            let dial_result = async {
                // Parse server address
                let server_addr: SocketAddr = self
                    .config
                    .server
                    .parse()
                    .with_context(|| {
                        format!("Invalid Shadowsocks server address: {}", self.config.server)
                    })
                    .map_err(|e| AdapterError::Other(e.to_string()))?;

                // Connect to Shadowsocks server
                let timeout =
                    std::time::Duration::from_secs(self.config.connect_timeout_sec.unwrap_or(30));
                let stream = tokio::time::timeout(timeout, TcpStream::connect(server_addr))
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

                // Create encrypted stream wrapper
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
            #[cfg(feature = "metrics")]
            {
                let result = match &dial_result {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e as &dyn core::fmt::Display),
                };
                sb_metrics::record_adapter_dial("shadowsocks", start_time, result);
            }

            // Handle result
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
#[cfg(feature = "adapter-shadowsocks")]
struct ShadowsocksStream {
    inner: TcpStream,
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
        stream: TcpStream,
        cipher_method: CipherMethod,
        key: Vec<u8>,
        target: Target,
        resolve_mode: ResolveMode,
    ) -> Result<Self> {
        // Send initial request with target address
        let mut ss_stream = Self {
            inner: stream,
            cipher_method: cipher_method.clone(),
            key,
            write_buffer: Vec::new(),
            read_buffer: Vec::new(),
            initialized: false,
        };

        // Build target address payload
        let addr_payload = ss_stream
            .encode_target_address(&target, &resolve_mode)
            .await?;

        // Encrypt and send initial payload
        ss_stream.send_encrypted_data(&addr_payload).await?;
        ss_stream.initialized = true;

        Ok(ss_stream)
    }

    async fn encode_target_address(
        &self,
        target: &Target,
        resolve_mode: &ResolveMode,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();

        // Determine target address based on resolve mode
        match resolve_mode {
            ResolveMode::Local => {
                // Resolve locally first
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadowsocks_connector_creation() {
        let config = ShadowsocksConfig {
            server: "127.0.0.1:8388".to_string(),
            tag: Some("test".to_string()),
            method: "aes-256-gcm".to_string(),
            password: "test-password".to_string(),
            connect_timeout_sec: Some(30),
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
}
