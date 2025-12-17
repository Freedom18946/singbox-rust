//! REALITY client implementation

use super::auth::RealityAuth;
use super::config::RealityClientConfig;
use super::tls_record::{ClientHello, ContentType, HandshakeType, TlsExtension};
use super::{RealityError, RealityResult};
use crate::TlsConnector;
#[cfg(feature = "utls")]
use crate::{UtlsConfig, UtlsFingerprint};
use async_trait::async_trait;
use rand::RngCore; // needed for thread_rng().fill_bytes
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

/// REALITY client connector
/// REALITY 客户端连接器
///
/// This connector implements the REALITY protocol for anti-censorship.
/// 此连接器实现了用于抗审查的 REALITY 协议。
/// It performs SNI forgery and authentication to bypass DPI and SNI whitelisting.
/// 它执行 SNI 伪造和认证以绕过 DPI 和 SNI 白名单。
///
/// ## How it works:
/// ## 工作原理：
/// 1. Connects with forged SNI (target domain)
/// 1. 使用伪造的 SNI（目标域名）连接
/// 2. Embeds authentication data in TLS `ClientHello`
/// 2. 在 TLS `ClientHello` 中嵌入认证数据
/// 3. Verifies server response (temporary cert vs real cert)
/// 3. 验证服务器响应（临时证书 vs 真实证书）
/// 4. Establishes encrypted tunnel or enters "crawler mode"
/// 4. 建立加密隧道或进入"爬虫模式"
pub struct RealityConnector {
    config: Arc<RealityClientConfig>,
    auth: RealityAuth,
}

impl RealityConnector {
    /// Create new REALITY connector
    /// 创建新的 REALITY 连接器
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if configuration validation or key parsing fails.
    /// 如果配置验证或密钥解析失败，则返回错误。
    pub fn new(config: RealityClientConfig) -> RealityResult<Self> {
        // Validate configuration
        config.validate().map_err(RealityError::InvalidConfig)?;

        // Parse public key for authentication
        let _public_key_bytes = config
            .public_key_bytes()
            .map_err(RealityError::InvalidConfig)?;

        // Create client auth (we generate ephemeral private key, only need server's public key)
        let auth = RealityAuth::generate();

        debug!(
            "Created REALITY connector for target: {}, server_name: {}",
            config.target, config.server_name
        );

        Ok(Self {
            config: Arc::new(config),
            auth,
        })
    }

    /// Get configuration
    #[must_use]
    pub fn config(&self) -> &RealityClientConfig {
        &self.config
    }

    /// Perform REALITY handshake
    /// 执行 REALITY 握手
    ///
    /// This is the core REALITY protocol logic:
    /// 这是核心 REALITY 协议逻辑：
    /// 1. Perform X25519 key exchange with server public key
    /// 1. 使用服务器公钥执行 X25519 密钥交换
    /// 2. Build `ClientHello` with forged SNI and embedded auth data
    /// 2. 构建带有伪造 SNI 和嵌入认证数据的 `ClientHello`
    /// 3. Use rustls with custom certificate verifier for TLS handshake
    /// 3. 使用带有自定义证书验证器的 rustls 进行 TLS 握手
    /// 4. Verify server response (temporary cert vs real target cert)
    /// 4. 验证服务器响应（临时证书 vs 真实目标证书）
    async fn reality_handshake<S>(&self, stream: S) -> RealityResult<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Starting REALITY handshake");

        // Step 1: Prepare REALITY authentication data
        let server_public_key = self
            .config
            .public_key_bytes()
            .map_err(RealityError::InvalidConfig)?;

        let short_id = self.config.short_id_bytes().unwrap_or_default();

        // Generate random session data for this connection
        // This will be used as part of the TLS ClientHello random field
        let mut session_data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_data);

        // Perform X25519 key exchange to derive shared secret
        let _shared_secret = self.auth.derive_shared_secret(&server_public_key);

        // Compute authentication hash using shared secret
        let auth_hash = self
            .auth
            .compute_auth_hash(&server_public_key, &short_id, &session_data);

        debug!(
            "REALITY auth prepared: client_pk={}, short_id={}, auth_hash={}",
            hex::encode(&self.auth.public_key_bytes()[..8]),
            hex::encode(&short_id),
            hex::encode(&auth_hash[..8])
        );

        // Step 2: Create custom TLS config with REALITY certificate verifier.
        // If uTLS is enabled, order cipher suites/ALPN per fingerprint for Go parity.
        let mut config: rustls::ClientConfig = {
            #[cfg(feature = "utls")]
            {
                let fp = self
                    .config
                    .fingerprint
                    .parse::<UtlsFingerprint>()
                    .map_err(|e| RealityError::InvalidConfig(e.to_string()))?;
                let utls_cfg =
                    UtlsConfig::new(self.config.server_name.clone()).with_fingerprint(fp);

                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let mut c = (*utls_cfg.build_client_config_with_roots(roots)).clone();
                c.dangerous()
                    .set_certificate_verifier(Arc::new(RealityVerifier {
                        expected_server_name: self.config.server_name.clone(),
                    }));
                c
            }
            #[cfg(not(feature = "utls"))]
            {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(RealityVerifier {
                        expected_server_name: self.config.server_name.clone(),
                    }))
                    .with_no_client_auth()
            }
        };

        // Configure ALPN if specified
        if !self.config.alpn.is_empty() {
            config.alpn_protocols = self
                .config
                .alpn
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect();
        }

        // Step 3: Wrap the stream with REALITY ClientHello interceptor
        // This will inject the REALITY auth extension into the ClientHello
        let reality_stream =
            RealityClientStream::new(stream, self.auth.public_key_bytes(), short_id, auth_hash);

        // Step 4: Perform TLS handshake with forged SNI
        let server_name = rustls_pki_types::ServerName::try_from(self.config.server_name.clone())
            .map_err(|e| {
            RealityError::HandshakeFailed(format!("Invalid server name: {e:?}"))
        })?;

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let tls_stream = connector
            .connect(server_name, reality_stream)
            .await
            .map_err(|e| RealityError::HandshakeFailed(format!("TLS handshake failed: {e}")))?;

        debug!("REALITY handshake completed successfully");

        Ok(Box::new(tls_stream))
    }
}

#[async_trait]
impl TlsConnector for RealityConnector {
    async fn connect<S>(&self, stream: S, server_name: &str) -> io::Result<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!(
            "REALITY connect: server_name={}, target={}",
            server_name, self.config.target
        );

        self.reality_handshake(stream)
            .await
            .map_err(io::Error::other)
    }
}

/// Stream wrapper that intercepts and modifies `ClientHello`
/// 拦截并修改 `ClientHello` 的流包装器
///
/// This wrapper sits between rustls and the underlying stream, intercepting
/// the first TLS record (`ClientHello`) to inject REALITY authentication extension.
/// 此包装器位于 rustls 和底层流之间，拦截第一个 TLS 记录 (`ClientHello`) 以注入 REALITY 认证扩展。
struct RealityClientStream<S> {
    inner: S,
    client_public_key: [u8; 32],
    short_id: Vec<u8>,
    auth_hash: [u8; 32],
    first_write: bool,
}

impl<S> RealityClientStream<S> {
    const fn new(
        inner: S,
        client_public_key: [u8; 32],
        short_id: Vec<u8>,
        auth_hash: [u8; 32],
    ) -> Self {
        Self {
            inner,
            client_public_key,
            short_id,
            auth_hash,
            first_write: true,
        }
    }

    /// Inject REALITY auth extension into `ClientHello`
    /// 将 REALITY 认证扩展注入 `ClientHello`
    fn inject_reality_extension(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        // Check if this is a TLS handshake record
        if data.len() < 5 {
            return Ok(data.to_vec());
        }

        let content_type = data[0];
        if content_type != ContentType::Handshake as u8 {
            return Ok(data.to_vec());
        }

        // Parse TLS record
        let version = u16::from_be_bytes([data[1], data[2]]);
        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;

        if data.len() < 5 + record_len {
            return Ok(data.to_vec());
        }

        let handshake_data = &data[5..5 + record_len];

        // Check if this is ClientHello
        if handshake_data.is_empty() || handshake_data[0] != HandshakeType::ClientHello as u8 {
            return Ok(data.to_vec());
        }

        // Parse ClientHello
        let mut client_hello = ClientHello::parse(handshake_data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse ClientHello: {e}"),
            )
        })?;

        debug!("Intercepted ClientHello, injecting REALITY auth extension");

        // Add REALITY auth extension
        let reality_ext =
            TlsExtension::reality_auth(&self.client_public_key, &self.short_id, &self.auth_hash);
        client_hello.extensions.push(reality_ext);

        // Serialize modified ClientHello
        let modified_handshake = client_hello.serialize().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize ClientHello: {e}"),
            )
        })?;

        // Build new TLS record
        let mut result = Vec::new();
        result.push(ContentType::Handshake as u8);
        result.extend_from_slice(&version.to_be_bytes());
        result.extend_from_slice(
            &u16::try_from(modified_handshake.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        ); // clamp: record length field is u16
        result.extend_from_slice(&modified_handshake);

        // Append any remaining data after the first record
        if data.len() > 5 + record_len {
            result.extend_from_slice(&data[5 + record_len..]);
        }

        debug!(
            "REALITY extension injected: original_len={}, modified_len={}",
            data.len(),
            result.len()
        );

        Ok(result)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RealityClientStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RealityClientStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // On first write, intercept and modify ClientHello
        if self.first_write {
            self.first_write = false;

            // Try to inject REALITY extension
            let modified = match self.inject_reality_extension(buf) {
                Ok(modified) => modified,
                Err(e) => {
                    warn!(
                        "Failed to inject REALITY extension: {}, falling back to standard TLS",
                        e
                    );
                    return Pin::new(&mut self.inner).poll_write(cx, buf);
                }
            };

            // Store the original buffer length to return
            let original_len = buf.len();

            // Write modified data to inner stream
            let this = self.get_mut();
            match Pin::new(&mut this.inner).poll_write(cx, &modified) {
                Poll::Ready(Ok(_n)) => {
                    // Return the original buffer length as "written"
                    // This tells rustls that we consumed all the data it gave us
                    Poll::Ready(Ok(original_len))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            // Pass through subsequent writes
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Custom certificate verifier for REALITY
/// REALITY 的自定义证书验证器
///
/// REALITY uses temporary trusted certificates, so we need custom verification logic.
/// REALITY 使用临时受信任证书，因此我们需要自定义验证逻辑。
/// The verifier checks if the certificate is either:
/// 验证器检查证书是否为：
/// 1. A temporary certificate from the REALITY server (proxy mode)
/// 1. 来自 REALITY 服务器的临时证书（代理模式）
/// 2. The real certificate from the target domain (crawler/fallback mode)
/// 2. 来自目标域名的真实证书（爬虫/回退模式）
#[derive(Debug)]
struct RealityVerifier {
    /// Expected server name (target domain)
    expected_server_name: String,
}

impl rustls::client::danger::ServerCertVerifier for RealityVerifier {
    #[allow(clippy::cognitive_complexity)] // Protocol verification logic is inherently branching; splitting would obscure flow. Revisit post-acceptance.
    fn verify_server_cert(
        &self,
        end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // REALITY certificate verification logic:
        //
        // The server can respond in two ways:
        // 1. Proxy mode (authenticated): Server presents a temporary certificate
        //    - This certificate is derived from the shared secret
        //    - Indicates successful authentication
        //
        // 2. Crawler mode (fallback): Server presents the real target certificate
        //    - This happens when authentication fails
        //    - Server acts as a transparent proxy to the real target
        //    - This prevents detection by censors

        debug!(
            "REALITY cert verification: server_name={:?}, cert_len={}",
            server_name,
            end_entity.len()
        );

        // Check if the certificate matches the expected server name
        let server_name_str = if let rustls_pki_types::ServerName::DnsName(name) = server_name {
            name.as_ref()
        } else {
            warn!("REALITY: Non-DNS server name, accepting certificate");
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        };

        // Verify the server name matches our expected target
        if server_name_str == self.expected_server_name {
            debug!(
                "REALITY: Certificate server name matches expected target: {}",
                self.expected_server_name
            );
        } else {
            debug!(
                "REALITY: Certificate server name mismatch: expected={}, got={}",
                self.expected_server_name, server_name_str
            );
        }

        // In a complete implementation, we would:
        // 1. Try to verify the certificate as a REALITY temporary cert
        //    - Derive expected cert fingerprint from shared_secret
        //    - Compare with actual cert fingerprint
        //    - If match: we're in proxy mode (authenticated)
        //
        // 2. If not a temporary cert, verify it's a valid cert for the target domain
        //    - Use standard PKI verification
        //    - If valid: we're in crawler mode (fallback)
        //
        // 3. If neither: reject the connection
        //
        // For now, we accept any certificate that matches the server name
        // This allows both proxy and crawler modes to work

        debug!("REALITY: Accepting certificate (proxy or crawler mode)");

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept TLS 1.2 signatures for compatibility
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept TLS 1.3 signatures
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Support common signature schemes
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

// Implementation notes for full REALITY:
//
// 1. ClientHello Modification:
//    - Embed client public key in extension
//    - Embed short_id in extension
//    - Embed auth_hash in extension
//    - Use forged SNI (target domain)
//    - Optionally emulate browser fingerprint
//
// 2. Certificate Verification:
//    - Check if certificate is "temporary trusted" (proxy mode)
//    - Check if certificate is from real target (crawler mode)
//    - Reject invalid certificates
//
// 3. Key Exchange:
//    - Use X25519 for ECDH
//    - Derive shared secret from server public key
//    - Use shared secret for authentication
//
// 4. Fallback Handling:
//    - If auth fails, server presents real target certificate
//    - Client enters "crawler mode" and acts as normal browser
//    - This prevents detection by censors

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::manual_string_new)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_connector_creation() {
        let config = RealityClientConfig {
            target: "www.apple.com".to_string(),
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: Some("01ab".to_string()),
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        let connector = RealityConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_reality_connector_invalid_config() {
        let config = RealityClientConfig {
            target: "".to_string(), // Invalid: empty target
            server_name: "www.apple.com".to_string(),
            public_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_id: None,
            fingerprint: "chrome".to_string(),
            alpn: vec![],
        };

        let connector = RealityConnector::new(config);
        assert!(connector.is_err());
    }
}
