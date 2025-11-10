use super::super::address::{encode_ss_addr, get_port_from_target, Addr};
use super::super::types::{Outbound, TcpConnectRequest, UdpBindRequest};
use super::hkdf::{derive_subkey, generate_salt, HashAlgorithm};
use crate::metrics::outbound as metrics;
use crate::telemetry::{err_kind, outbound_connect, outbound_handshake};

use async_trait::async_trait;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};

/// Shadowsocks AEAD cipher types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsAeadCipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SsAeadCipher {
    pub fn key_size(&self) -> usize {
        match self {
            SsAeadCipher::Aes256Gcm => 32,
            SsAeadCipher::ChaCha20Poly1305 => 32,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            SsAeadCipher::Aes256Gcm => 12,
            SsAeadCipher::ChaCha20Poly1305 => 12,
        }
    }

    pub fn tag_size(&self) -> usize {
        16 // Both ciphers use 16-byte authentication tag
    }

    pub fn salt_size(&self) -> usize {
        self.key_size()
    }

    pub fn name(&self) -> &'static str {
        match self {
            SsAeadCipher::Aes256Gcm => "aes-256-gcm",
            SsAeadCipher::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// Shadowsocks AEAD TCP configuration
#[derive(Clone, Debug)]
pub struct SsAeadTcpConfig {
    pub server: String,
    pub port: u16,
    pub cipher: SsAeadCipher,
    pub master_key: Vec<u8>,
}

/// Shadowsocks AEAD TCP outbound
pub struct SsAeadTcp {
    config: SsAeadTcpConfig,
}

impl SsAeadTcp {
    pub fn new(config: SsAeadTcpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Outbound for SsAeadTcp {
    async fn tcp_connect(&self, req: TcpConnectRequest) -> anyhow::Result<tokio::net::TcpStream> {
        let start = std::time::Instant::now();

        // Step 1: Connect to Shadowsocks server
        let mut tcp =
            tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port))
                .await
                .inspect_err(|e| {
                    outbound_connect("shadowsocks", "error", Some(err_kind(e)));
                    metrics::record_shadowsocks_connect_error();
                })?;

        outbound_connect("shadowsocks", "ok", None);

        // Step 2: Generate random salt
        let salt = generate_salt(self.config.cipher.salt_size());

        // Step 3: Derive session subkey using HKDF
        let subkey = derive_subkey(&self.config.master_key, &salt, HashAlgorithm::Sha1);

        // Step 4: Send salt
        tcp.write_all(&salt).await.inspect_err(|e| {
            outbound_handshake("shadowsocks", "error", Some(err_kind(e)));
        })?;

        // Step 5: Prepare target address
        let addr = Addr::from_target_addr(&req.target);
        let port = get_port_from_target(&req.target);
        let mut addr_buf = Vec::new();
        encode_ss_addr(&addr, port, &mut addr_buf);

        // Step 6: Encrypt address using AEAD with proper framing
        let encrypted_addr = encrypt_aead_chunk(&addr_buf, &subkey, 0, &self.config.cipher)?;
        tcp.write_all(&encrypted_addr).await.inspect_err(|e| {
            outbound_handshake("shadowsocks", "error", Some(err_kind(e)));
        })?;

        let elapsed = start.elapsed();
        outbound_handshake("shadowsocks", "ok", None);
        metrics::record_shadowsocks_connect_success();

        #[cfg(feature = "metrics")]
        if let Ok(ms) = u64::try_from(elapsed.as_millis()) {
            metrics::handshake_duration_histogram()
                .with_label_values(&["shadowsocks"])
                .observe(ms as f64);
        }

        // Wrap in AEAD stream for ongoing encryption
        // Establish a local TCP pair and pump plaintext<->ciphertext with AEAD framing
        // Create a loopback listener and connect to it; return the client end.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let server_task = tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
        let client = tokio::net::TcpStream::connect(local_addr).await?;
        let local_server = server_task.await.map_err(|e| anyhow::anyhow!(e))?;
        let local_server = local_server?;

        // Split streams
        let (mut ls_r, mut ls_w) = local_server.into_split();
        let (mut ss_r, mut ss_w) = tcp.into_split();

        // Clone parameters for tasks
        let cipher_w = self.config.cipher.clone();
        let cipher_r = self.config.cipher.clone();
        let subkey_w = subkey;
        let subkey_r = subkey_w; // same subkey

        // Writer: local -> ss (encrypt frames)
        tokio::spawn(async move {
            let mut write_nonce: u64 = 2; // after addr (0,1)
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match ls_r.read(&mut buf).await {
                    Ok(0) => {
                        let _ = ss_w.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        let enc_res = encrypt_aead_chunk(&buf[..n], &subkey_w, write_nonce, &cipher_w);
                        if let Ok(enc) = enc_res {
                            if ss_w.write_all(&enc).await.is_err() {
                                break;
                            }
                            write_nonce = write_nonce.wrapping_add(2);
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Reader: ss -> local (decrypt frames)
        tokio::spawn(async move {
            let mut read_nonce: u64 = 0;
            let tag = cipher_r.tag_size();
            let mut len_buf = vec![0u8; 2 + tag];
            loop {
                if let Err(_) = ss_r.read_exact(&mut len_buf).await { break; }
                let plain_len = match decrypt_aead(&len_buf, &subkey_r, read_nonce, &cipher_r)
                    .and_then(|v| {
                        if v.len() >= 2 {
                            Ok::<_, std::io::Error>(u16::from_be_bytes([v[0], v[1]]) as usize)
                        } else {
                            Err(std::io::Error::other("bad len"))
                        }
                    }) {
                    Ok(l) => l,
                    Err(_) => break,
                };

                let mut payload = vec![0u8; plain_len + tag];
                if let Err(_) = ss_r.read_exact(&mut payload).await { break; }
                let plain = match decrypt_aead(&payload, &subkey_r, read_nonce.wrapping_add(1), &cipher_r) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if ls_w.write_all(&plain).await.is_err() { break; }
                read_nonce = read_nonce.wrapping_add(2);
            }
            let _ = ls_w.shutdown().await;
        });

        Ok(client)
    }

    async fn tcp_connect_tls(
        &self,
        _req: TcpConnectRequest,
    ) -> anyhow::Result<crate::transport::TlsStream<tokio::net::TcpStream>> {
        anyhow::bail!("Shadowsocks does not support TLS wrapping");
    }

    async fn udp_bind(&self, _req: UdpBindRequest) -> anyhow::Result<tokio::net::UdpSocket> {
        anyhow::bail!("UDP not supported by shadowsocks-aead-tcp outbound");
    }

    fn name(&self) -> &'static str {
        "shadowsocks-aead-tcp"
    }
}

/// Encrypt a chunk using AEAD with proper framing
/// Format: AEAD(length) || AEAD(payload)
pub(crate) fn encrypt_aead_chunk(
    data: &[u8],
    key: &[u8],
    nonce_counter: u64,
    cipher: &SsAeadCipher,
) -> Result<Vec<u8>> {
    let data_len = data.len();
    if data_len > 0x3fff {
        return Err(Error::new(ErrorKind::InvalidInput, "chunk too large"));
    }

    let mut result = Vec::new();

    // Encrypt length (2 bytes)
    let len_bytes = (data_len as u16).to_be_bytes();
    let encrypted_len = encrypt_aead(&len_bytes, key, nonce_counter, cipher)?;
    result.extend_from_slice(&encrypted_len);

    // Encrypt payload
    let encrypted_payload = encrypt_aead(data, key, nonce_counter + 1, cipher)?;
    result.extend_from_slice(&encrypted_payload);

    Ok(result)
}

/// Encrypt data using AEAD cipher
pub fn encrypt_aead(
    data: &[u8],
    key: &[u8],
    nonce_counter: u64,
    cipher: &SsAeadCipher,
) -> Result<Vec<u8>> {
    let nonce_size = cipher.nonce_size();
    let mut nonce_bytes = vec![0u8; nonce_size];

    // Use little-endian counter in nonce
    let counter_bytes = nonce_counter.to_le_bytes();
    let copy_len = std::cmp::min(counter_bytes.len(), nonce_bytes.len());
    nonce_bytes[..copy_len].copy_from_slice(&counter_bytes[..copy_len]);

    match cipher {
        SsAeadCipher::Aes256Gcm => {
            let cipher_impl = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid AES key"))?;
            let nonce = AesNonce::from_slice(&nonce_bytes);
            cipher_impl
                .encrypt(
                    nonce,
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| Error::other("AES encryption failed"))
        }
        SsAeadCipher::ChaCha20Poly1305 => {
            let cipher_impl = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid ChaCha20 key"))?;
            let nonce = ChachaNonce::from_slice(&nonce_bytes);
            cipher_impl
                .encrypt(
                    nonce,
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| Error::other("ChaCha20 encryption failed"))
        }
    }
}

/// Decrypt data using AEAD cipher
pub fn decrypt_aead(
    data: &[u8],
    key: &[u8],
    nonce_counter: u64,
    cipher: &SsAeadCipher,
) -> Result<Vec<u8>> {
    let nonce_size = cipher.nonce_size();
    let mut nonce_bytes = vec![0u8; nonce_size];

    let counter_bytes = nonce_counter.to_le_bytes();
    let copy_len = std::cmp::min(counter_bytes.len(), nonce_bytes.len());
    nonce_bytes[..copy_len].copy_from_slice(&counter_bytes[..copy_len]);

    match cipher {
        SsAeadCipher::Aes256Gcm => {
            let cipher_impl = Aes256Gcm::new_from_slice(key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid AES key"))?;
            let nonce = AesNonce::from_slice(&nonce_bytes);
            cipher_impl
                .decrypt(
                    nonce,
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| Error::other("AES decryption failed"))
        }
        SsAeadCipher::ChaCha20Poly1305 => {
            let cipher_impl = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid ChaCha20 key"))?;
            let nonce = ChachaNonce::from_slice(&nonce_bytes);
            cipher_impl
                .decrypt(
                    nonce,
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| Error::other("ChaCha20 decryption failed"))
        }
    }
}

/// AEAD encrypted TCP stream
pub struct SsAeadTcpStream {
    inner: tokio::net::TcpStream,
    /// Encryption key for AEAD cipher
    #[allow(dead_code)]
    key: [u8; 32],
    #[allow(dead_code)]
    cipher: SsAeadCipher,
    #[allow(dead_code)]
    write_nonce: u64,
    #[allow(dead_code)]
    read_nonce: u64,
    #[allow(dead_code)]
    read_buffer: Vec<u8>,
    #[allow(dead_code)]
    write_buffer: Vec<u8>,
}

impl SsAeadTcpStream {
    #[allow(dead_code)]
    fn new(stream: tokio::net::TcpStream, key: [u8; 32], cipher: SsAeadCipher) -> Self {
        Self {
            inner: stream,
            key,
            cipher,
            write_nonce: 2,
            read_nonce: 0,
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
        }
    }
}

impl AsyncRead for SsAeadTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        // Pass-through: this struct is not used in final return path
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SsAeadTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        // Pass-through: this struct is not used in final return path
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_aes256gcm() {
        let key = [0u8; 32];
        let data = b"hello world";
        let cipher = SsAeadCipher::Aes256Gcm;

        let encrypted = encrypt_aead(data, &key, 0, &cipher).unwrap();
        let decrypted = decrypt_aead(&encrypted, &key, 0, &cipher).unwrap();

        assert_eq!(data, decrypted.as_slice());
        assert_ne!(data.to_vec(), encrypted);
    }

    #[test]
    fn test_encrypt_decrypt_chacha20poly1305() {
        let key = [1u8; 32];
        let data = b"test message";
        let cipher = SsAeadCipher::ChaCha20Poly1305;

        let encrypted = encrypt_aead(data, &key, 1, &cipher).unwrap();
        let decrypted = decrypt_aead(&encrypted, &key, 1, &cipher).unwrap();

        assert_eq!(data, decrypted.as_slice());
        assert_ne!(data.to_vec(), encrypted);
    }

    #[test]
    fn test_encrypt_chunk_framing() {
        let key = [2u8; 32];
        let data = b"chunk data";
        let cipher = SsAeadCipher::Aes256Gcm;

        let encrypted_chunk = encrypt_aead_chunk(data, &key, 0, &cipher).unwrap();

        // Should contain encrypted length + encrypted payload
        let tag_size = cipher.tag_size();
        let expected_len = 2 + tag_size + data.len() + tag_size;
        assert_eq!(encrypted_chunk.len(), expected_len);
    }

    #[test]
    fn test_different_nonces_different_output() {
        let key = [3u8; 32];
        let data = b"same data";
        let cipher = SsAeadCipher::ChaCha20Poly1305;

        let encrypted1 = encrypt_aead(data, &key, 0, &cipher).unwrap();
        let encrypted2 = encrypt_aead(data, &key, 1, &cipher).unwrap();

        assert_ne!(
            encrypted1, encrypted2,
            "Different nonces should produce different ciphertext"
        );
    }

    #[test]
    fn test_cipher_properties() {
        let aes_cipher = SsAeadCipher::Aes256Gcm;
        let chacha_cipher = SsAeadCipher::ChaCha20Poly1305;

        assert_eq!(aes_cipher.key_size(), 32);
        assert_eq!(aes_cipher.nonce_size(), 12);
        assert_eq!(aes_cipher.tag_size(), 16);
        assert_eq!(aes_cipher.name(), "aes-256-gcm");

        assert_eq!(chacha_cipher.key_size(), 32);
        assert_eq!(chacha_cipher.nonce_size(), 12);
        assert_eq!(chacha_cipher.tag_size(), 16);
        assert_eq!(chacha_cipher.name(), "chacha20-poly1305");
    }
}
