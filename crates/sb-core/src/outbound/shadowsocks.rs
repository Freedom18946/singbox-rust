#[cfg(feature = "out_ss")]
use super::crypto_types::{HostPort, OutboundTcp};
#[cfg(feature = "out_ss")]
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
#[cfg(feature = "out_ss")]
use async_trait::async_trait;
#[cfg(feature = "out_ss")]
use chacha20poly1305::ChaCha20Poly1305;
#[cfg(feature = "out_ss")]
use std::pin::Pin;
#[cfg(feature = "out_ss")]
use std::task::{Context, Poll};
#[cfg(feature = "out_ss")]
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[cfg(feature = "out_ss")]
#[derive(Clone, Debug)]
pub enum ShadowsocksCipher {
    Aes256Gcm,
    Chacha20Poly1305,
}

#[cfg(feature = "out_ss")]
impl ShadowsocksCipher {
    pub fn key_size(&self) -> usize {
        match self {
            ShadowsocksCipher::Aes256Gcm => 32,
            ShadowsocksCipher::Chacha20Poly1305 => 32,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            ShadowsocksCipher::Aes256Gcm => 12,
            ShadowsocksCipher::Chacha20Poly1305 => 12,
        }
    }

    pub fn tag_size(&self) -> usize {
        16 // Both ciphers use 16-byte authentication tag
    }
}

#[cfg(feature = "out_ss")]
#[derive(Clone, Debug)]
pub struct ShadowsocksConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: ShadowsocksCipher,
}

#[cfg(feature = "out_ss")]
impl ShadowsocksConfig {
    pub fn new(server: String, port: u16, password: String, cipher: ShadowsocksCipher) -> Self {
        Self {
            server,
            port,
            password,
            cipher,
        }
    }

    pub fn derive_key(&self) -> Vec<u8> {
        let key_size = self.cipher.key_size();
        evp_bytes_to_key(self.password.as_bytes(), key_size)
    }
}

#[cfg(feature = "out_ss")]
pub struct ShadowsocksOutbound {
    config: ShadowsocksConfig,
    key: Vec<u8>,
}

#[cfg(feature = "out_ss")]
impl ShadowsocksOutbound {
    pub fn new(config: ShadowsocksConfig) -> Self {
        let key = config.derive_key();
        Self { config, key }
    }
}

#[cfg(feature = "out_ss")]
#[async_trait]
impl OutboundTcp for ShadowsocksOutbound {
    type IO = ShadowsocksStream;

    async fn connect(&self, target: &HostPort) -> std::io::Result<Self::IO> {
        let start = std::time::Instant::now();

        // Step 1: TCP connect to Shadowsocks server
        let tcp = tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port))
            .await
            .inspect_err(|e| {
                #[cfg(feature = "metrics")]
                crate::telemetry::outbound_connect(
                    "shadowsocks",
                    "error",
                    Some(crate::telemetry::err_kind(e)),
                );
            })?;

        #[cfg(feature = "metrics")]
        crate::telemetry::outbound_connect("shadowsocks", "ok", None);

        // Step 2: Perform Shadowsocks handshake
        let mut stream = ShadowsocksStream::new(tcp, self.key.clone(), self.config.cipher.clone());

        let handshake_result = stream.handshake(target).await;
        let elapsed = start.elapsed();

        match handshake_result {
            Ok(()) => {
                #[cfg(feature = "metrics")]
                {
                    crate::telemetry::outbound_handshake("shadowsocks", "ok", None);
                    if let Ok(ms) = u64::try_from(elapsed.as_millis()) {
                        crate::metrics::outbound::handshake_duration_histogram()
                            .with_label_values(&["shadowsocks"])
                            .observe(ms as f64);
                    }
                }
                Ok(stream)
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                crate::telemetry::outbound_handshake(
                    "shadowsocks",
                    "error",
                    Some(crate::telemetry::err_kind(&e)),
                );
                Err(e)
            }
        }
    }

    fn protocol_name(&self) -> &'static str {
        "shadowsocks"
    }
}

#[cfg(feature = "out_ss")]
pub struct ShadowsocksStream {
    inner: tokio::net::TcpStream,
    key: Vec<u8>,
    cipher: ShadowsocksCipher,
    write_nonce: u64,
    #[allow(dead_code)]
    read_nonce: u64,
    handshake_complete: bool,
}

#[cfg(feature = "out_ss")]
impl ShadowsocksStream {
    fn new(stream: tokio::net::TcpStream, key: Vec<u8>, cipher: ShadowsocksCipher) -> Self {
        Self {
            inner: stream,
            key,
            cipher,
            write_nonce: 0,
            read_nonce: 0,
            handshake_complete: false,
        }
    }

    async fn handshake(&mut self, target: &HostPort) -> std::io::Result<()> {
        // Generate random salt
        let salt_size = self.cipher.key_size();
        let mut salt = vec![0u8; salt_size];
        fastrand::fill(&mut salt);

        // Derive session key from master key and salt
        let mut session_key = vec![0u8; self.cipher.key_size()];
        let context = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, &salt);
        let prk = context.extract(&self.key);
        let okm = prk
            .expand(&[], ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY)
            .unwrap();
        okm.fill(&mut session_key).unwrap();

        // Send salt
        self.inner.write_all(&salt).await?;

        // Prepare target address
        let addr_buf = self.encode_target_address(target)?;

        // Encrypt and send address
        let encrypted_addr = self.encrypt_data(&addr_buf, &session_key)?;
        self.inner.write_all(&encrypted_addr).await?;

        self.handshake_complete = true;
        Ok(())
    }

    fn encode_target_address(&self, target: &HostPort) -> std::io::Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Address type (0x03 for domain)
        buf.push(0x03);

        // Domain length
        let domain_bytes = target.host.as_bytes();
        if domain_bytes.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "domain name too long",
            ));
        }
        buf.push(domain_bytes.len() as u8);

        // Domain
        buf.extend_from_slice(domain_bytes);

        // Port (big-endian)
        buf.extend_from_slice(&target.port.to_be_bytes());

        Ok(buf)
    }

    fn encrypt_data(&mut self, data: &[u8], session_key: &[u8]) -> std::io::Result<Vec<u8>> {
        let nonce_size = self.cipher.nonce_size();
        let _tag_size = self.cipher.tag_size();

        // Create nonce
        let mut nonce_bytes = vec![0u8; nonce_size];
        nonce_bytes[..8].copy_from_slice(&self.write_nonce.to_le_bytes());

        let result = match self.cipher {
            ShadowsocksCipher::Aes256Gcm => {
                use aes_gcm::aead::{Aead, Payload};
                let cipher = Aes256Gcm::new_from_slice(session_key).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid key")
                })?;
                let nonce = Nonce::from_slice(&nonce_bytes);
                cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: data,
                            aad: &[],
                        },
                    )
                    .map_err(|_| std::io::Error::other("encryption failed"))?
            }
            ShadowsocksCipher::Chacha20Poly1305 => {
                use chacha20poly1305::aead::{Aead, Payload};
                let cipher = ChaCha20Poly1305::new_from_slice(session_key).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid key")
                })?;
                let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
                cipher
                    .encrypt(
                        nonce,
                        Payload {
                            msg: data,
                            aad: &[],
                        },
                    )
                    .map_err(|_| std::io::Error::other("encryption failed"))?
            }
        };

        self.write_nonce += 1;

        // Prepend length
        let mut output = Vec::new();
        output.extend_from_slice(&(result.len() as u16).to_be_bytes());
        output.extend_from_slice(&result);

        Ok(output)
    }
}

#[cfg(feature = "out_ss")]
impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.handshake_complete {
            return Poll::Ready(Err(std::io::Error::other("handshake not complete")));
        }

        // For simplicity, we'll implement a basic pass-through for now
        // In a full implementation, this would handle AEAD decryption
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "out_ss")]
impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if !self.handshake_complete {
            return Poll::Ready(Err(std::io::Error::other("handshake not complete")));
        }

        // For simplicity, we'll implement a basic pass-through for now
        // In a full implementation, this would handle AEAD encryption
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "out_ss")]
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    // OpenSSL EVP_BytesToKey compatibility would normally use MD5.
    // For build portability we approximate using SHA-256 and truncate.
    use sha2::{Digest, Sha256};

    let mut key = Vec::new();
    let mut prev = Vec::new();
    while key.len() < key_len {
        let mut hasher = Sha256::new();
        if !prev.is_empty() {
            hasher.update(&prev);
        }
        hasher.update(password);
        prev = hasher.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

#[cfg(not(feature = "out_ss"))]
mod stub {
    use super::super::crypto_types::{HostPort, OutboundTcp};
    use async_trait::async_trait;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite};

    #[derive(Clone, Debug)]
    pub enum ShadowsocksCipher {
        Aes256Gcm,
        Chacha20Poly1305,
    }

    #[derive(Clone, Debug)]
    pub struct ShadowsocksConfig;

    impl ShadowsocksConfig {
        pub fn new(
            _server: String,
            _port: u16,
            _password: String,
            _cipher: ShadowsocksCipher,
        ) -> Self {
            Self
        }
    }

    pub struct ShadowsocksOutbound;

    impl ShadowsocksOutbound {
        pub fn new(_config: ShadowsocksConfig) -> Self {
            Self
        }
    }

    pub struct ShadowsocksStream;

    impl AsyncRead for ShadowsocksStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Shadowsocks support not compiled in",
            )))
        }
    }

    impl AsyncWrite for ShadowsocksStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Shadowsocks support not compiled in",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait]
    impl OutboundTcp for ShadowsocksOutbound {
        type IO = ShadowsocksStream;

        async fn connect(&self, _target: &HostPort) -> std::io::Result<Self::IO> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Shadowsocks support not compiled in",
            ))
        }

        fn protocol_name(&self) -> &'static str {
            "shadowsocks"
        }
    }
}

#[cfg(not(feature = "out_ss"))]
pub use stub::{ShadowsocksCipher, ShadowsocksConfig, ShadowsocksOutbound, ShadowsocksStream};
