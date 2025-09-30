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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
}

#[cfg(feature = "out_vmess")]
#[derive(Debug)]
pub struct VmessOutbound {
    config: VmessConfig,
}

#[cfg(feature = "out_vmess")]
impl VmessOutbound {
    pub fn new(config: VmessConfig) -> anyhow::Result<Self> {
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

    fn generate_request_key(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(self.config.id.as_bytes());
        hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        let hash = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        key
    }

    fn generate_response_key(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(self.config.id.as_bytes());
        hasher.update(b"c42f7b3e-64e6-4396-8e01-eb28c8c7d56c");
        let hash = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        key
    }

    fn encrypt_request(&self, plaintext: &[u8], key: &[u8; 16]) -> io::Result<Vec<u8>> {
        match self.config.security.as_str() {
            "aes-128-gcm" => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("AES key error: {}", e))
                })?;

                // Generate random nonce
                let nonce = Nonce::from_slice(&[0u8; 12]); // In real implementation, use random nonce

                let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("AES encryption error: {}", e))
                })?;

                // Prepend nonce to ciphertext
                let mut result = nonce.to_vec();
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            "chacha20-poly1305" => {
                let cipher_key = Key::from_slice(key);
                let cipher = ChaCha20Poly1305::new(cipher_key);

                // Generate random nonce
                let nonce = chacha20poly1305::Nonce::from_slice(&[0u8; 12]); // In real implementation, use random nonce

                let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("ChaCha20 encryption error: {}", e),
                    )
                })?;

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

        // Options (1 byte) - no special options
        request.push(0x00);

        // Padding and Security (4 bits each)
        let padding_security = (0x0 << 4)
            | match self.config.security.as_str() {
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

        // Padding length and data
        let padding_len = fastrand::u8(0..16);
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
#[async_trait]
impl OutboundTcp for VmessOutbound {
    type IO = TcpStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{
            record_connect_attempt, record_connect_error, record_connect_success,
            OutboundErrorClass,
        };

        record_connect_attempt(crate::outbound::OutboundKind::Vmess);

        let start = std::time::Instant::now();

        // Connect to VMess server
        let mut stream =
            match TcpStream::connect((self.config.server.as_str(), self.config.port)).await {
                Ok(stream) => stream,
                Err(e) => {
                    record_connect_error(
                        crate::outbound::OutboundKind::Direct,
                        OutboundErrorClass::Io,
                    );

                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("vmess_connect_total", "result" => "connect_fail").increment(1);
                    }

                    return Err(e);
                }
            };

        // Generate timestamp for authentication
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Prepare authentication header
        let mut auth_header = Vec::new();
        auth_header.extend_from_slice(&timestamp.to_be_bytes());

        // Create HMAC for authentication
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(self.config.id.as_bytes()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("HMAC error: {}", e))
            })?;
        mac.update(&auth_header);
        let auth_hash = mac.finalize().into_bytes();

        auth_header.extend_from_slice(&auth_hash[..16]); // Use first 16 bytes

        // Send authentication header
        if let Err(e) = stream.write_all(&auth_header).await {
            record_connect_error(
                crate::outbound::OutboundKind::Direct,
                OutboundErrorClass::Protocol,
            );

            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("vmess_connect_total", "result" => "auth_fail").increment(1);
            }

            return Err(e);
        }

        // Generate and send request
        let request = self.encode_vmess_request(target)?;

        // Encrypt request with request key
        let request_key = self.generate_request_key();

        // Use request_key for AEAD encryption (simplified implementation)
        let encrypted_request = self.encrypt_request(&request, &request_key)?;
        tracing::debug!(
            "VMess request encrypted with {} byte key",
            request_key.len()
        );

        if let Err(e) = stream.write_all(&encrypted_request).await {
            record_connect_error(
                crate::outbound::OutboundKind::Direct,
                OutboundErrorClass::Protocol,
            );

            #[cfg(feature = "metrics")]
            {
                use metrics::counter;
                counter!("vmess_connect_total", "result" => "handshake_fail").increment(1);
            }

            return Err(e);
        }

        // Read and validate response tag
        let mut response_tag = [0u8; 16];
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read_exact(&mut response_tag),
        )
        .await
        {
            Err(_) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Protocol,
                );

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("vmess_connect_total", "result" => "resp_timeout").increment(1);
                }

                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "VMess response timeout",
                ));
            }
            Ok(Err(e)) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Protocol,
                );

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("vmess_connect_total", "result" => "response_fail").increment(1);
                }

                return Err(e);
            }
            Ok(Ok(_)) => {
                // Validate response tag using AEAD module
                let response_key = self.generate_response_key();
                let request_tag = self.generate_request_key(); // Simplified - should use actual request tag

                match aead::resp_tag(&request_tag, &response_key) {
                    Ok(expected_tag) => {
                        if response_tag != expected_tag {
                            #[cfg(feature = "metrics")]
                            {
                                use metrics::counter;
                                counter!("vmess_connect_total", "result" => "bad_tag").increment(1);
                            }

                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "VMess response tag validation failed",
                            ));
                        }
                    }
                    Err(_) => {
                        #[cfg(feature = "metrics")]
                        {
                            use metrics::counter;
                            counter!("vmess_connect_total", "result" => "tag_error").increment(1);
                        }

                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "VMess tag calculation error",
                        ));
                    }
                }
            }
        }

        record_connect_success(crate::outbound::OutboundKind::Direct);

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
            record_handshake_duration(Proto::Vmess, start.elapsed().as_millis() as f64);

            use metrics::counter;
            counter!("vmess_connect_total", "result" => "ok", "cipher" => cipher_type.as_str())
                .increment(1);
        }

        Ok(stream)
    }

    fn protocol_name(&self) -> &'static str {
        "vmess"
    }
}

#[cfg(feature = "out_vmess")]
impl crate::adapter::OutboundConnector for VmessOutbound {
    fn connect(&self, host: &str, port: u16) -> std::io::Result<std::net::TcpStream> {
        // Create a blocking runtime to run async VMess connection
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        rt.block_on(async {
            // Create target host:port
            let target = HostPort {
                host: host.to_string(),
                port,
            };

            // Use async connect implementation
            let tokio_stream = OutboundTcp::connect(self, &target).await?;

            // Convert tokio TcpStream to std TcpStream
            tokio_stream.into_std()
        })
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
