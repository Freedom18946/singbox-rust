//! VMess TCP AEAD outbound implementation
//!
//! Provides minimal VMess protocol support with AEAD encryption
//! for secure TCP tunneling with UUID-based authentication.

#[cfg(feature = "out_vmess")]
pub mod aead;

#[cfg(feature = "out_vmess")]
use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
#[cfg(feature = "out_vmess")]
use async_trait::async_trait;
#[cfg(feature = "out_vmess")]
use chacha20poly1305::{ChaCha20Poly1305, Key};
#[cfg(feature = "out_vmess")]
use digest::Digest;
#[cfg(feature = "out_vmess")]
use hmac::{Hmac, Mac};
#[cfg(feature = "out_vmess")]
use sha2::Sha256;
#[cfg(feature = "out_vmess")]
use std::io;
#[cfg(feature = "out_vmess")]
use sb_tls::{UtlsConfig, UtlsFingerprint};
#[cfg(feature = "out_vmess")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(feature = "out_vmess")]
use tokio::net::TcpStream;

#[cfg(feature = "out_vmess")]
use super::crypto_types::{HostPort, OutboundTcp};
#[cfg(feature = "out_vmess")]
use super::types::{encode_ss_addr, Addr};

#[cfg(feature = "out_vmess")]
#[derive(Clone, Debug)]
pub struct VmessConfig {
    pub server: String,
    pub port: u16,
    pub id: uuid::Uuid,
    pub security: String, // "aes-128-gcm" or "chacha20-poly1305"
    pub alter_id: u8,     // Legacy compatibility, should be 0 for AEAD
    // Transport layering from IR (optional)
    pub transport: Option<Vec<String>>, // e.g., ["tls","ws"], ["tls","h2"]
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub h2_path: Option<String>,
    pub h2_host: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_alpn: Option<Vec<String>>,
    /// Optional uTLS fingerprint name for outbound TLS layer.
    pub utls_fingerprint: Option<String>,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub grpc_authority: Option<String>,
    pub grpc_metadata: Vec<(String, String)>,
    pub http_upgrade_path: Option<String>,
    pub http_upgrade_headers: Vec<(String, String)>,
    pub multiplex: Option<sb_config::ir::MultiplexOptionsIR>,
}

impl Default for VmessConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 0,
            id: uuid::Uuid::nil(),
            security: "aes-128-gcm".to_string(),
            alter_id: 0,
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            tls_sni: None,
            tls_alpn: None,
            utls_fingerprint: None,
            grpc_service: None,
            grpc_method: None,
            grpc_authority: None,
            grpc_metadata: Vec::new(),
            http_upgrade_path: None,
            http_upgrade_headers: Vec::new(),
            multiplex: None,
        }
    }
}

#[cfg(feature = "out_vmess")]
#[derive(Debug)]
pub struct VmessOutbound {
    config: VmessConfig,
}

#[cfg(feature = "out_vmess")]
impl VmessOutbound {
    pub fn new(config: VmessConfig) -> anyhow::Result<Self> {
        if let Some(fp) = config.utls_fingerprint.as_deref() {
            fp.parse::<UtlsFingerprint>()
                .map_err(|e| anyhow::anyhow!("invalid uTLS fingerprint: {e}"))?;
        }
        // Validate security cipher
        match config.security.as_str() {
            "aes-128-gcm" | "chacha20-poly1305" => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported VMess security: {}",
                    config.security
                ))
            }
        }

        // Validate alter_id for AEAD
        if config.alter_id != 0 {
            return Err(anyhow::anyhow!(
                "VMess AEAD implementation requires alter_id=0, got: {}",
                config.alter_id
            ));
        }

        Ok(Self { config })
    }

    #[cfg(feature = "out_vmess")]
    pub(crate) async fn do_handshake_on<S: AsyncRead + AsyncWrite + Unpin + Send + ?Sized>(
        &self,
        target: &HostPort,
        stream: &mut S,
    ) -> io::Result<[u8; 16]> {
        // Generate timestamp for authentication
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Derive KDF keys and generate nonce for request
        let (req_key_vec, resp_key_vec) = aead::kdf(&self.config.id, &self.config.security)
            .map_err(|e| io::Error::other(format!("VMess KDF error: {}", e)))?;
        let mut request_key = [0u8; 16];
        request_key.copy_from_slice(&req_key_vec[..16]);
        let mut response_key = [0u8; 16];
        response_key.copy_from_slice(&resp_key_vec[..16]);
        let nonce = aead::generate_nonce(&self.config.security);

        // Prepare authentication header: timestamp + legacy HMAC + nonce + req_tag
        let mut auth_header = Vec::new();
        auth_header.extend_from_slice(&timestamp.to_be_bytes());
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.config.id.as_bytes()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("HMAC error: {}", e))
            })?;
        mac.update(&timestamp.to_be_bytes());
        let legacy = mac.finalize().into_bytes();
        auth_header.extend_from_slice(&legacy[..16]);
        // Append nonce and AEAD request tag
        auth_header.extend_from_slice(&nonce);
        let req_tag = aead::req_tag(timestamp, &self.config.id, &nonce)
            .map_err(|e| io::Error::other(format!("req_tag error: {}", e)))?;
        auth_header.extend_from_slice(&req_tag);
        // Write auth header with timeout
        let write_timeout = std::time::Duration::from_millis(
            std::env::var("SB_VMESS_WRITE_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
        );
        tokio::time::timeout(write_timeout, stream.write_all(&auth_header))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VMess auth write timeout"))??;

        // Generate and send request
        let request = self.encode_vmess_request(target)?;

        // Encrypt request with request key and explicit nonce
        let encrypted_request = self.encrypt_request(&request, &request_key, &nonce)?;
        tracing::debug!(
            "VMess request encrypted with {} byte key",
            request_key.len()
        );

        tokio::time::timeout(write_timeout, stream.write_all(&encrypted_request))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "VMess request write timeout")
            })??;

        // Read and validate response tag
        let mut response_tag = [0u8; 16];
        let resp_timeout = std::time::Duration::from_millis(
            std::env::var("SB_VMESS_RESP_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(500),
        );
        match tokio::time::timeout(resp_timeout, stream.read_exact(&mut response_tag)).await {
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "VMess response timeout",
                ));
            }
            Ok(Err(e)) => {
                return Err(e);
            }
            Ok(Ok(_)) => {
                // Validate response tag using AEAD module
                match aead::resp_tag(&req_tag, &response_key) {
                    Ok(expected_tag) => {
                        if response_tag != expected_tag {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "VMess response tag validation failed",
                            ));
                        }
                        #[cfg(feature = "metrics")]
                        {
                            use metrics::counter;
                            counter!("vmess_handshake_total", "result"=>"ok").increment(1);
                        }
                    }
                    Err(_) => {
                        return Err(io::Error::other("VMess tag calculation error"));
                    }
                }
            }
        }

        Ok(request_key)
    }

    #[allow(dead_code)]
    fn generate_request_key(&self) -> [u8; 16] {
        let (req_key, _resp_key) = aead::kdf(&self.config.id, &self.config.security)
            .expect("vmess cipher already validated");
        let mut key = [0u8; 16];
        key.copy_from_slice(&req_key[..16]);
        key
    }

    #[allow(dead_code)]
    fn generate_response_key(&self) -> [u8; 16] {
        let (_req_key, resp_key) = aead::kdf(&self.config.id, &self.config.security)
            .expect("vmess cipher already validated");
        let mut key = [0u8; 16];
        key.copy_from_slice(&resp_key[..16]);
        key
    }

    fn encrypt_request(
        &self,
        plaintext: &[u8],
        key: &[u8; 16],
        nonce_bytes: &[u8],
    ) -> io::Result<Vec<u8>> {
        match self.config.security.as_str() {
            "aes-128-gcm" => {
                let cipher = Aes128Gcm::new_from_slice(key)
                    .map_err(|e| io::Error::other(format!("AES key error: {}", e)))?;
                let nonce = Nonce::from_slice(nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| io::Error::other(format!("AES encryption error: {}", e)))?;

                // Prepend nonce to ciphertext
                let mut result = nonce.to_vec();
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            "chacha20-poly1305" => {
                let cipher_key = Key::from_slice(key);
                let cipher = ChaCha20Poly1305::new(cipher_key);
                let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| io::Error::other(format!("ChaCha20 encryption error: {}", e)))?;

                // Prepend nonce to ciphertext
                let mut result = nonce.to_vec();
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unsupported cipher: {}", self.config.security),
            )),
        }
    }

    fn encode_vmess_request(&self, target: &HostPort) -> io::Result<Vec<u8>> {
        let mut request = Vec::new();

        // Version (1 byte) - VMess version 1
        request.push(0x01);

        // IV (16 bytes)
        let iv: [u8; 16] = rand::random();
        request.extend_from_slice(&iv);

        // Encryption key (16 bytes)
        let key: [u8; 16] = rand::random();
        request.extend_from_slice(&key);

        // Response authentication (1 byte)
        request.push(0x01);

        // Options (1 byte)
        // Controlled via env SB_VMESS_OPTIONS, comma separated: pad,chunk
        let opts_env = std::env::var("SB_VMESS_OPTIONS").unwrap_or_default();
        let mut options: u8 = 0;
        for part in opts_env.split(',').map(|s| s.trim().to_ascii_lowercase()) {
            match part.as_str() {
                "pad" | "padding" => options |= 0x04,     // example bit
                "chunk" | "chunkmask" => options |= 0x01, // example bit
                _ => {}
            }
        }
        request.push(options);

        // Padding and Security (4 bits each)
        let padding_security = match self.config.security.as_str() {
            "aes-128-gcm" => 0x03,
            "chacha20-poly1305" => 0x04,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unknown security method",
                ))
            }
        };
        request.push(padding_security);

        // Reserved (1 byte)
        request.push(0x00);

        // Command (1 byte) - TCP
        request.push(0x01);

        // Target address
        let addr = if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => Addr::V4(v4),
                std::net::IpAddr::V6(v6) => Addr::V6(v6),
            }
        } else {
            Addr::Domain(target.host.clone())
        };

        encode_ss_addr(&addr, target.port, &mut request);

        // Padding length and data (controlled by SB_VMESS_PADDING_MAX, default 15)
        let max_pad = std::env::var("SB_VMESS_PADDING_MAX")
            .ok()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(15)
            .min(15);
        let padding_len = if max_pad == 0 {
            0
        } else {
            fastrand::u8(0..=max_pad)
        };
        request.push(padding_len);
        if padding_len > 0 {
            let padding: Vec<u8> = (0..padding_len).map(|_| fastrand::u8(..)).collect();
            request.extend_from_slice(&padding);
        }

        // Calculate checksum
        let mut hasher = Sha256::new();
        hasher.update(&request[1..]); // Skip version byte
        let hash = hasher.finalize();
        request.extend_from_slice(&hash[..4]); // Use first 4 bytes as checksum

        Ok(request)
    }
}

#[cfg(feature = "out_vmess")]
fn vmess_encrypt_aead(
    cipher_name: &str,
    key: &[u8; 16],
    nonce_counter: u64,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&nonce_counter.to_le_bytes());
    match cipher_name {
        "aes-128-gcm" => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| io::Error::other(format!("AES key error: {}", e)))?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher
                .encrypt(nonce, data)
                .map_err(|e| io::Error::other(format!("AES encryption error: {}", e)))
        }
        "chacha20-poly1305" => {
            // sing-box uses "chacha20-poly1305" in VMess security; our KDF currently yields 16 bytes.
            // Expand to 32 bytes for the IETF construction.
            let mut key32 = [0u8; 32];
            key32[..16].copy_from_slice(key);
            key32[16..].copy_from_slice(key);
            let k = chacha20poly1305::Key::from_slice(&key32);
            let cipher = ChaCha20Poly1305::new(k);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            cipher
                .encrypt(nonce, data)
                .map_err(|e| io::Error::other(format!("ChaCha20 encryption error: {}", e)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported cipher: {}", other),
        )),
    }
}

#[cfg(feature = "out_vmess")]
fn vmess_decrypt_aead(
    cipher_name: &str,
    key: &[u8; 16],
    nonce_counter: u64,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(&nonce_counter.to_le_bytes());
    match cipher_name {
        "aes-128-gcm" => {
            let cipher = Aes128Gcm::new_from_slice(key)
                .map_err(|e| io::Error::other(format!("AES key error: {}", e)))?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher
                .decrypt(nonce, data)
                .map_err(|e| io::Error::other(format!("AES decryption error: {}", e)))
        }
        "chacha20-poly1305" => {
            let mut key32 = [0u8; 32];
            key32[..16].copy_from_slice(key);
            key32[16..].copy_from_slice(key);
            let k = chacha20poly1305::Key::from_slice(&key32);
            let cipher = ChaCha20Poly1305::new(k);
            let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
            cipher
                .decrypt(nonce, data)
                .map_err(|e| io::Error::other(format!("ChaCha20 decryption error: {}", e)))
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported cipher: {}", other),
        )),
    }
}

#[cfg(feature = "out_vmess")]
#[async_trait]
impl OutboundTcp for VmessOutbound {
    type IO = TcpStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{record_connect_attempt, record_connect_success};
        use crate::metrics::record_outbound_error;

        record_connect_attempt(crate::outbound::OutboundKind::Vmess);

        let _start = std::time::Instant::now();

        // Connect to VMess server
        let mut stream =
            match TcpStream::connect((self.config.server.as_str(), self.config.port)).await {
                Ok(stream) => stream,
                Err(e) => {
                    record_outbound_error(crate::outbound::OutboundKind::Direct, &e);

                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("vmess_connect_total", "result" => "connect_fail").increment(1);
                    }

                    return Err(e);
                }
            };

        // Perform handshake and receive data key
        let data_key = match self.do_handshake_on(target, &mut stream).await {
            Ok(k) => k,
            Err(e) => {
                record_outbound_error(crate::outbound::OutboundKind::Direct, &e);

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("vmess_connect_total", "result" => "handshake_fail").increment(1);
                }

                return Err(e);
            }
        };

        record_connect_success(crate::outbound::OutboundKind::Direct);

        // After handshake, wrap the connection with a local loopback bridge that
        // encrypts all subsequent payloads using AEAD frames with the derived key.
        let (mut ss_r, mut ss_w) = stream.into_split();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let accept_task = tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });
        let client = tokio::net::TcpStream::connect(local_addr).await?;
        let local_server = accept_task
            .await
            .map_err(|e| io::Error::other(e.to_string()))??;
        let (mut ls_r, mut ls_w) = local_server.into_split();

        // Select cipher
        let cipher = self.config.security.clone();
        // Writer: local -> server
        let key_w = data_key;
        let cipher_w = cipher.clone();
        tokio::spawn(async move {
            let mut write_nonce: u64 = 0;
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match ls_r.read(&mut buf).await {
                    Ok(0) => {
                        let _ = ss_w.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        // frame length
                        if let Ok(enc_len) = vmess_encrypt_aead(
                            &cipher_w,
                            &key_w,
                            write_nonce,
                            &(n as u16).to_be_bytes(),
                        ) {
                            if ss_w.write_all(&enc_len).await.is_err() {
                                break;
                            }
                        } else {
                            break;
                        }
                        // frame payload
                        if let Ok(enc_payload) = vmess_encrypt_aead(
                            &cipher_w,
                            &key_w,
                            write_nonce.wrapping_add(1),
                            &buf[..n],
                        ) {
                            if ss_w.write_all(&enc_payload).await.is_err() {
                                break;
                            }
                        } else {
                            break;
                        }
                        write_nonce = write_nonce.wrapping_add(2);
                    }
                    Err(_) => break,
                }
            }
        });

        // Reader: server -> local
        let key_r = data_key;
        let cipher_r = cipher;
        tokio::spawn(async move {
            let mut read_nonce: u64 = 0;
            let tag = 16usize; // AEAD tag size for both ciphers here
            let mut len_buf = vec![0u8; 2 + tag];
            loop {
                if (ss_r.read_exact(&mut len_buf).await).is_err() {
                    break;
                }
                let len_plain = match vmess_decrypt_aead(&cipher_r, &key_r, read_nonce, &len_buf) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if len_plain.len() < 2 {
                    break;
                }
                let plain_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;

                let mut payload = vec![0u8; plain_len + tag];
                if (ss_r.read_exact(&mut payload).await).is_err() {
                    break;
                }
                let plain = match vmess_decrypt_aead(
                    &cipher_r,
                    &key_r,
                    read_nonce.wrapping_add(1),
                    &payload,
                ) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if ls_w.write_all(&plain).await.is_err() {
                    break;
                }
                read_nonce = read_nonce.wrapping_add(2);
            }
            let _ = ls_w.shutdown().await;
        });

        // Record VMess-specific metrics
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::labels::{
                record_connect_total, record_handshake_duration, CipherType, Proto, ResultTag,
            };

            let cipher_type = match self.config.security.as_str() {
                "aes-128-gcm" => CipherType::Aes128Gcm,
                "chacha20-poly1305" => CipherType::ChaCha20Poly1305,
                _ => CipherType::None,
            };

            record_connect_total(Proto::Vmess, ResultTag::Ok);
            record_handshake_duration(Proto::Vmess, _start.elapsed().as_millis() as f64);

            use metrics::counter;
            counter!("vmess_connect_total", "result" => "ok", "cipher" => cipher_type.as_str())
                .increment(1);
        }

        Ok(client)
    }

    fn protocol_name(&self) -> &'static str {
        "vmess"
    }
}

#[cfg(feature = "out_vmess")]
#[async_trait::async_trait]
impl crate::adapter::OutboundConnector for VmessOutbound {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        // Create target host:port
        let target = HostPort {
            host: host.to_string(),
            port,
        };

        // Use async connect implementation
        OutboundTcp::connect(self, &target).await
    }
}

// V2Ray transport integration (feature-gated)
#[cfg(all(feature = "out_vmess", feature = "v2ray_transport"))]
#[async_trait::async_trait]
impl crate::outbound::traits::OutboundConnectorIo for VmessOutbound {
    async fn connect_tcp_io(
        &self,
        ctx: &crate::types::ConnCtx,
    ) -> crate::error::SbResult<sb_transport::IoStream> {
        use sb_transport::Dialer as _;
        use sb_transport::TransportBuilder;

        // Build target for VMess handshake
        let target = HostPort {
            host: match &ctx.dst.host {
                crate::types::Host::Name(d) => d.to_string(),
                crate::types::Host::Ip(ip) => ip.to_string(),
            },
            port: ctx.dst.port,
        };

        let alpn_csv = self.config.tls_alpn.as_ref().map(|v| v.join(","));
        let chain_opt = self.config.transport.as_deref();
        let tls_override = if let Some(fp_name) = self.config.utls_fingerprint.as_deref() {
            let fp = fp_name
                .parse::<UtlsFingerprint>()
                .map_err(|e| crate::error::SbError::other(format!("invalid uTLS fingerprint: {e}")))?;
            let sni = self
                .config
                .tls_sni
                .as_deref()
                .unwrap_or(self.config.server.as_str());
            let utls_cfg = UtlsConfig::new(sni.to_string()).with_fingerprint(fp);
            let roots = crate::tls::global::base_root_store();
            Some(utls_cfg.build_client_config_with_roots(roots))
        } else {
            None
        };
        let builder = crate::runtime::transport::map::apply_layers(
            TransportBuilder::tcp(),
            chain_opt,
            self.config.tls_sni.as_deref(),
            alpn_csv.as_deref(),
            self.config.ws_path.as_deref(),
            self.config.ws_host.as_deref(),
            self.config.h2_path.as_deref(),
            self.config.h2_host.as_deref(),
            self.config.http_upgrade_path.as_deref(),
            &self.config.http_upgrade_headers,
            self.config.grpc_service.as_deref(),
            self.config.grpc_method.as_deref(),
            self.config.grpc_authority.as_deref(),
            &self.config.grpc_metadata,
            tls_override,
            self.config.multiplex.as_ref(),
        );

        let mut stream = builder
            .build()
            .connect(self.config.server.as_str(), self.config.port)
            .await
            .map_err(|e| crate::error::SbError::other(format!("transport dial failed: {}", e)))?;

        // Perform VMess handshake over the established stream
        self.do_handshake_on(&target, &mut *stream)
            .await
            .map_err(crate::error::SbError::from)?;

        Ok(stream)
    }
}

#[cfg(test)]
#[cfg(feature = "out_vmess")]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_aead_roundtrip_aes() {
        let key = [1u8; 16];
        let nonce0 = 0u64;
        let plain = b"hello vmess";
        let ct_len = vmess_encrypt_aead(
            "aes-128-gcm",
            &key,
            nonce0,
            &(plain.len() as u16).to_be_bytes(),
        )
        .unwrap();
        let pt_len = vmess_decrypt_aead("aes-128-gcm", &key, nonce0, &ct_len).unwrap();
        assert_eq!(pt_len.as_slice(), &(plain.len() as u16).to_be_bytes());
        let ct = vmess_encrypt_aead("aes-128-gcm", &key, nonce0 + 1, plain).unwrap();
        let pt = vmess_decrypt_aead("aes-128-gcm", &key, nonce0 + 1, &ct).unwrap();
        assert_eq!(pt, plain);
    }

    #[test]
    fn test_vmess_aead_roundtrip_chacha() {
        let key = [2u8; 16];
        let nonce0 = 7u64;
        let plain = b"hello chacha";
        let ct_len = vmess_encrypt_aead(
            "chacha20-poly1305",
            &key,
            nonce0,
            &(plain.len() as u16).to_be_bytes(),
        )
        .unwrap();
        let pt_len = vmess_decrypt_aead("chacha20-poly1305", &key, nonce0, &ct_len).unwrap();
        assert_eq!(pt_len.as_slice(), &(plain.len() as u16).to_be_bytes());
        let ct = vmess_encrypt_aead("chacha20-poly1305", &key, nonce0 + 1, plain).unwrap();
        let pt = vmess_decrypt_aead("chacha20-poly1305", &key, nonce0 + 1, &ct).unwrap();
        assert_eq!(pt, plain);
    }

    #[test]
    fn test_vmess_rejects_unknown_utls_fingerprint() {
        let cfg = VmessConfig {
            utls_fingerprint: Some("invalid-fp".to_string()),
            ..Default::default()
        };
        assert!(VmessOutbound::new(cfg).is_err());
    }
}

#[cfg(not(feature = "out_vmess"))]
pub struct VmessConfig;

#[cfg(not(feature = "out_vmess"))]
impl VmessConfig {
    pub fn new() -> Self {
        Self
    }
}
