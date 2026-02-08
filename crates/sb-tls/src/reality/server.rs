//! REALITY server implementation

use super::auth::{RealityAuth, compute_temp_cert_signature, derive_auth_key};
use super::config::RealityServerConfig;
use super::{RealityError, RealityResult};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::parse_x509_certificate;

/// Combined trait for stream types used in fallback
/// 用于回退的流类型的组合 trait
pub trait FallbackStream: AsyncRead + AsyncWrite + Unpin + Send {}

// Blanket implementation for all types that satisfy the bounds
impl<T> FallbackStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// REALITY server acceptor
/// REALITY 服务端接收器
///
/// This acceptor implements the REALITY protocol server side.
/// 此接收器实现了 REALITY 协议的服务端。
/// It verifies client authentication and either:
/// 它验证客户端认证，并执行以下操作之一：
/// - Establishes proxy connection (auth success)
/// - 建立代理连接（认证成功）
/// - Falls back to target website (auth failure)
/// - 回退到目标网站（认证失败）
///
/// ## How it works:
/// ## 工作原理：
/// 1. Receives TLS `ClientHello` with embedded auth data
/// 1. 接收带有嵌入认证数据的 TLS `ClientHello`
/// 2. Verifies authentication using shared secret
/// 2. 使用共享密钥验证认证
/// 3. If valid: issues temporary certificate and proxies traffic
/// 3. 如果有效：颁发临时证书并代理流量
/// 4. If invalid: proxies to real target website (disguise)
/// 4. 如果无效：代理到真实目标网站（伪装）
pub struct RealityAcceptor {
    config: Arc<RealityServerConfig>,
    auth: RealityAuth,
    target_chain: Arc<RwLock<Option<TargetChain>>>,
}

impl RealityAcceptor {
    /// Create new REALITY acceptor
    /// 创建新的 REALITY 接收器
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if configuration validation or key parsing fails.
    /// 如果配置验证或密钥解析失败，则返回错误。
    pub fn new(config: RealityServerConfig) -> RealityResult<Self> {
        // Validate configuration
        config.validate().map_err(RealityError::InvalidConfig)?;

        // Parse private key for authentication
        let private_key_bytes = config
            .private_key_bytes()
            .map_err(RealityError::InvalidConfig)?;

        let auth = RealityAuth::from_private_key(private_key_bytes);

        info!(
            "Created REALITY acceptor for target: {}, server_names: {:?}",
            config.target, config.server_names
        );

        Ok(Self {
            config: Arc::new(config),
            auth,
            target_chain: Arc::new(RwLock::new(None)),
        })
    }

    /// Get configuration
    #[must_use]
    pub fn config(&self) -> &RealityServerConfig {
        &self.config
    }

    /// Accept and handle REALITY connection
    /// 接受并处理 REALITY 连接
    ///
    /// This is the core server-side REALITY logic:
    /// 这是核心服务端 REALITY 逻辑：
    /// 1. Parse `ClientHello` and extract auth data
    /// 1. 解析 `ClientHello` 并提取认证数据
    /// 2. Verify authentication
    /// 2. 验证认证
    /// 3. Either proxy or fallback based on auth result
    /// 3. 根据认证结果进行代理或回退
    /// # Errors
    /// # 错误
    /// Returns an error if the handshake times out or validation fails.
    /// 如果握手超时或验证失败，则返回错误。
    pub async fn accept<S>(&self, stream: S) -> RealityResult<RealityConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let handshake_timeout = Duration::from_secs(self.config.handshake_timeout);

        timeout(handshake_timeout, self.handle_handshake(stream))
            .await
            .map_err(|_| RealityError::HandshakeFailed("handshake timeout".to_string()))?
    }

    /// Handle REALITY handshake
    #[allow(clippy::cognitive_complexity)] // Handshake flow has necessary branching; refactor would risk protocol regressions. Revisit post-acceptance.
    async fn handle_handshake<S>(&self, mut stream: S) -> RealityResult<RealityConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Handling REALITY handshake");

        // Step 1: Read and parse ClientHello to extract REALITY extensions
        // We need to buffer the data so we can replay it for the TLS handshake
        let (client_public_key, short_id, auth_hash, session_data, sni, client_hello_data) =
            self.parse_and_buffer_client_hello(&mut stream).await?;

        debug!(
            "Parsed ClientHello: SNI={}, short_id={}",
            sni,
            hex::encode(&short_id)
        );

        // Step 2: Verify SNI is in accepted list
        if !self.config.server_names.contains(&sni) {
            warn!("SNI not in accepted list: {}", sni);
            // Replay the ClientHello data and fallback
            let replay_stream = ReplayStream::new(stream, client_hello_data);
            return self.fallback_to_target(replay_stream).await;
        }

        // Step 3: Verify short ID
        if !self.config.accepts_short_id(&short_id) {
            warn!("Short ID not accepted: {}", hex::encode(&short_id));
            let replay_stream = ReplayStream::new(stream, client_hello_data);
            return self.fallback_to_target(replay_stream).await;
        }

        // Step 4: Verify authentication hash using ClientHello random as session data
        if !self
            .auth
            .verify_auth_hash(&client_public_key, &short_id, &session_data, &auth_hash)
        {
            warn!("Authentication failed: invalid auth hash");
            let replay_stream = ReplayStream::new(stream, client_hello_data);
            return self.fallback_to_target(replay_stream).await;
        }

        info!("REALITY authentication successful");

        let shared_secret = self.auth.derive_shared_secret(&client_public_key);
        let auth_key =
            derive_auth_key(shared_secret, &session_data).map_err(RealityError::HandshakeFailed)?;

        let target_chain = self.ensure_target_chain(&sni).await;

        // Step 5: Complete TLS handshake with temporary certificate
        // Replay the ClientHello data for rustls
        let replay_stream = ReplayStream::new(stream, client_hello_data);
        let tls_stream = self
            .complete_tls_handshake(replay_stream, &sni, &auth_key, target_chain.as_ref())
            .await?;

        Ok(RealityConnection::Proxy(tls_stream))
    }

    /// Parse `ClientHello` and buffer the data for replay
    /// 解析 `ClientHello` 并缓冲数据以供重放
    ///
    /// Returns: (`client_public_key`, `short_id`, `auth_hash`, `session_data`, sni, `buffered_data`)
    /// 返回：(`client_public_key`, `short_id`, `auth_hash`, `session_data`, sni, `buffered_data`)
    #[allow(clippy::cognitive_complexity)] // Parsing and validation sequence is linear but branching by spec; splitting reduces readability. Revisit later.
    async fn parse_and_buffer_client_hello<S>(
        &self,
        stream: &mut S,
    ) -> RealityResult<([u8; 32], Vec<u8>, [u8; 32], [u8; 32], String, Vec<u8>)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use super::tls_record::{ClientHello, ContentType, ExtensionType};
        use tokio::io::AsyncReadExt;

        // Read TLS record header (5 bytes)
        let mut header_buf = [0u8; 5];
        stream.read_exact(&mut header_buf).await.map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to read TLS record header: {e}"))
        })?;

        let content_type = ContentType::try_from(header_buf[0])
            .map_err(|e| RealityError::HandshakeFailed(format!("Invalid content type: {e}")))?;
        let version = u16::from_be_bytes([header_buf[1], header_buf[2]]);
        let length = u16::from_be_bytes([header_buf[3], header_buf[4]]);

        debug!(
            "TLS record: type={:?}, version=0x{:04x}, length={}",
            content_type, version, length
        );

        // Verify this is a handshake record
        if content_type != ContentType::Handshake {
            return Err(RealityError::HandshakeFailed(format!(
                "Expected Handshake record, got {content_type:?}"
            )));
        }

        // Read handshake data
        let mut handshake_data = vec![0u8; length as usize];
        stream
            .read_exact(&mut handshake_data)
            .await
            .map_err(|e| RealityError::HandshakeFailed(format!("Failed to read handshake: {e}")))?;

        // Parse ClientHello
        let client_hello = ClientHello::parse(&handshake_data).map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to parse ClientHello: {e}"))
        })?;

        debug!(
            "Parsed ClientHello: version=0x{:04x}, {} extensions",
            client_hello.version,
            client_hello.extensions.len()
        );

        let session_data = client_hello.random;

        // Extract SNI
        let sni = client_hello
            .get_sni()
            .ok_or_else(|| RealityError::HandshakeFailed("No SNI in ClientHello".to_string()))?;

        debug!("SNI: {}", sni);

        // Extract REALITY authentication extension
        let reality_ext = client_hello
            .find_extension(ExtensionType::RealityAuth as u16)
            .ok_or_else(|| RealityError::AuthFailed("No REALITY auth extension".to_string()))?;

        let (client_public_key, short_id, auth_hash) =
            reality_ext.parse_reality_auth().map_err(|e| {
                RealityError::HandshakeFailed(format!("Failed to parse REALITY extension: {e}"))
            })?;

        debug!(
            "REALITY auth: public_key={}, short_id={}, auth_hash={}",
            hex::encode(&client_public_key[..8]),
            hex::encode(&short_id),
            hex::encode(&auth_hash[..8])
        );

        // Combine header and handshake data for replay
        let mut buffered_data = Vec::with_capacity(5 + handshake_data.len());
        buffered_data.extend_from_slice(&header_buf);
        buffered_data.extend_from_slice(&handshake_data);

        Ok((
            client_public_key,
            short_id,
            auth_hash,
            session_data,
            sni,
            buffered_data,
        ))
    }

    /// Complete TLS handshake with temporary certificate
    /// 使用临时证书完成 TLS 握手
    async fn complete_tls_handshake<S>(
        &self,
        stream: S,
        server_name: &str,
        auth_key: &[u8; 32],
        target_chain: Option<&TargetChain>,
    ) -> RealityResult<crate::TlsIoStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("Completing TLS handshake for REALITY connection");

        let (cert_der, key_der) = self.generate_temporary_certificate(
            server_name,
            auth_key,
            target_chain.and_then(|c| c.template.as_ref()),
        )?;

        // Create TLS server config with the temporary certificate
        let mut chain = vec![cert_der];
        if let Some(chain_info) = target_chain {
            chain.extend(chain_info.intermediates.iter().cloned());
        }

        crate::ensure_crypto_provider();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)
            .map_err(|e| {
                RealityError::HandshakeFailed(format!("Failed to create TLS config: {e}"))
            })?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        // Perform TLS handshake
        let tls_stream = acceptor
            .accept(stream)
            .await
            .map_err(|e| RealityError::HandshakeFailed(format!("TLS handshake failed: {e}")))?;

        debug!("REALITY TLS handshake completed successfully");

        Ok(Box::new(tls_stream))
    }

    fn generate_temporary_certificate(
        &self,
        server_name: &str,
        auth_key: &[u8; 32],
        template: Option<&TargetCertTemplate>,
    ) -> RealityResult<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to generate temp keypair: {e}"))
        })?;

        let params = build_certificate_params(server_name, template).map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to build cert params: {e}"))
        })?;
        let cert = params.self_signed(&key_pair).map_err(|e| {
            RealityError::HandshakeFailed(format!("Failed to generate certificate: {e}"))
        })?;

        let mut cert_der = cert.der().to_vec();
        let signature = compute_temp_cert_signature(auth_key, key_pair.public_key_raw())
            .map_err(RealityError::HandshakeFailed)?;
        replace_cert_signature(&mut cert_der, &signature)?;

        let cert_der = CertificateDer::from(cert_der);
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).map_err(|_| {
            RealityError::HandshakeFailed("Failed to serialize private key".to_string())
        })?;

        Ok((cert_der, key_der))
    }

    /// Fallback to target website
    /// 回退到目标网站
    ///
    /// When authentication fails, proxy the connection to the real target
    /// to make it appear as legitimate traffic.
    /// 当认证失败时，将连接代理到真实目标，使其看起来像合法流量。
    async fn fallback_to_target<S>(&self, stream: S) -> RealityResult<RealityConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !self.config.enable_fallback {
            return Err(RealityError::AuthFailed(
                "authentication failed and fallback disabled".to_string(),
            ));
        }

        debug!("Falling back to target: {}", self.config.target);

        // Connect to real target
        let target_stream = TcpStream::connect(&self.config.target)
            .await
            .map_err(|e| RealityError::TargetFailed(format!("failed to connect: {e}")))?;

        info!("Fallback connection established to {}", self.config.target);

        Ok(RealityConnection::Fallback {
            client: Box::new(stream),
            target: target_stream,
        })
    }
}

#[derive(Clone, Debug)]
struct TargetChain {
    intermediates: Vec<CertificateDer<'static>>,
    template: Option<TargetCertTemplate>,
}

#[derive(Clone, Debug, Default)]
struct TargetCertTemplate {
    common_name: Option<String>,
    dns_names: Vec<String>,
    not_before: Option<time::OffsetDateTime>,
    not_after: Option<time::OffsetDateTime>,
}

impl RealityAcceptor {
    async fn ensure_target_chain(&self, server_name: &str) -> Option<TargetChain> {
        {
            let guard = self.target_chain.read().await;
            if let Some(chain) = guard.as_ref() {
                return Some(chain.clone());
            }
        }

        match self.fetch_target_chain(server_name).await {
            Ok(chain) => {
                let mut guard = self.target_chain.write().await;
                *guard = Some(chain.clone());
                drop(guard);
                Some(chain)
            }
            Err(e) => {
                warn!("REALITY target chain capture failed: {}", e);
                None
            }
        }
    }

    async fn fetch_target_chain(&self, server_name: &str) -> RealityResult<TargetChain> {
        let target = self.config.target.clone();
        let stream = TcpStream::connect(&target)
            .await
            .map_err(|e| RealityError::TargetFailed(format!("failed to connect: {e}")))?;

        crate::ensure_crypto_provider();
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let server_name = rustls_pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| RealityError::TargetFailed(format!("invalid server name: {e:?}")))?;

        let tls_stream = timeout(
            Duration::from_secs(5),
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| RealityError::TargetFailed("target TLS handshake timeout".to_string()))?
        .map_err(|e| RealityError::TargetFailed(format!("target TLS handshake failed: {e}")))?;

        let (_, session) = tls_stream.get_ref();
        let certs = session.peer_certificates().ok_or_else(|| {
            RealityError::TargetFailed("target did not provide certificates".to_string())
        })?;

        let mut intermediates = Vec::new();
        for cert in certs.iter().skip(1) {
            intermediates.push(CertificateDer::from(cert.as_ref().to_vec()));
        }

        let template = certs
            .first()
            .and_then(|cert| build_template_from_leaf(cert.as_ref()).ok());

        Ok(TargetChain {
            intermediates,
            template,
        })
    }
}

#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
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

fn build_certificate_params(
    server_name: &str,
    template: Option<&TargetCertTemplate>,
) -> Result<CertificateParams, String> {
    let mut dns_names = template.map(|t| t.dns_names.clone()).unwrap_or_default();
    if dns_names.is_empty() {
        dns_names.push(server_name.to_string());
    }

    let mut params = CertificateParams::new(dns_names)
        .map_err(|e| format!("invalid SANs for cert params: {e}"))?;

    let mut dn = DistinguishedName::new();
    if let Some(t) = template
        && let Some(cn) = &t.common_name
    {
        dn.push(DnType::CommonName, cn.clone());
    } else {
        dn.push(DnType::CommonName, server_name.to_string());
    }
    params.distinguished_name = dn;

    if let Some(t) = template {
        if let Some(nb) = t.not_before {
            params.not_before = nb;
        }
        if let Some(na) = t.not_after {
            params.not_after = na;
        }
    }

    Ok(params)
}

fn build_template_from_leaf(cert_der: &[u8]) -> Result<TargetCertTemplate, String> {
    let (_, cert) =
        parse_x509_certificate(cert_der).map_err(|e| format!("parse x509 cert: {e}"))?;

    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(ToString::to_string);

    let mut dns_names = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                dns_names.push((*dns).to_string());
            }
        }
    }

    Ok(TargetCertTemplate {
        common_name,
        dns_names,
        not_before: Some(cert.validity().not_before.to_datetime()),
        not_after: Some(cert.validity().not_after.to_datetime()),
    })
}

fn replace_cert_signature(cert_der: &mut [u8], signature: &[u8]) -> RealityResult<()> {
    let mut idx = 0usize;
    if cert_der.get(idx) != Some(&0x30) {
        return Err(RealityError::HandshakeFailed(
            "Invalid certificate: expected sequence".to_string(),
        ));
    }
    idx += 1;
    let (cert_len, cert_len_len) = read_der_length(&cert_der[idx..])?;
    idx += cert_len_len;
    if idx + cert_len > cert_der.len() {
        return Err(RealityError::HandshakeFailed(
            "Invalid certificate length".to_string(),
        ));
    }

    if cert_der.get(idx) != Some(&0x30) {
        return Err(RealityError::HandshakeFailed(
            "Invalid certificate: expected tbsCertificate".to_string(),
        ));
    }
    idx += 1;
    let (tbs_len, tbs_len_len) = read_der_length(&cert_der[idx..])?;
    idx += tbs_len_len + tbs_len;

    if cert_der.get(idx) != Some(&0x30) {
        return Err(RealityError::HandshakeFailed(
            "Invalid certificate: expected signatureAlgorithm".to_string(),
        ));
    }
    idx += 1;
    let (alg_len, alg_len_len) = read_der_length(&cert_der[idx..])?;
    idx += alg_len_len + alg_len;

    if cert_der.get(idx) != Some(&0x03) {
        return Err(RealityError::HandshakeFailed(
            "Invalid certificate: expected signatureValue".to_string(),
        ));
    }
    idx += 1;
    let (sig_len, sig_len_len) = read_der_length(&cert_der[idx..])?;
    idx += sig_len_len;
    if sig_len < 1 {
        return Err(RealityError::HandshakeFailed(
            "Invalid certificate signature length".to_string(),
        ));
    }
    let unused_bits = *cert_der.get(idx).ok_or_else(|| {
        RealityError::HandshakeFailed("Invalid certificate signature".to_string())
    })?;
    if unused_bits != 0 {
        return Err(RealityError::HandshakeFailed(
            "Unsupported certificate signature padding".to_string(),
        ));
    }
    idx += 1;

    let sig_bytes_len = sig_len - 1;
    if sig_bytes_len != signature.len() {
        return Err(RealityError::HandshakeFailed(
            "Signature length mismatch".to_string(),
        ));
    }
    let end = idx + sig_bytes_len;
    if end > cert_der.len() {
        return Err(RealityError::HandshakeFailed(
            "Invalid certificate signature bounds".to_string(),
        ));
    }

    cert_der[idx..end].copy_from_slice(signature);
    Ok(())
}

fn read_der_length(data: &[u8]) -> RealityResult<(usize, usize)> {
    let first = *data
        .first()
        .ok_or_else(|| RealityError::HandshakeFailed("Invalid DER length".to_string()))?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }

    let num_bytes = (first & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        return Err(RealityError::HandshakeFailed(
            "Unsupported DER length encoding".to_string(),
        ));
    }
    if data.len() < 1 + num_bytes {
        return Err(RealityError::HandshakeFailed(
            "Truncated DER length".to_string(),
        ));
    }
    let mut len = 0usize;
    for b in &data[1..=num_bytes] {
        len = (len << 8) | (*b as usize);
    }
    Ok((len, 1 + num_bytes))
}

/// REALITY connection type
/// REALITY 连接类型
pub enum RealityConnection {
    /// Authenticated proxy connection
    /// 已认证的代理连接
    Proxy(crate::TlsIoStream),

    /// Fallback connection (proxy to real target)
    /// 回退连接（代理到真实目标）
    Fallback {
        client: Box<dyn FallbackStream>,
        target: TcpStream,
    },
}

impl RealityConnection {
    /// Check if this is a proxy connection
    /// 检查是否为代理连接
    pub const fn is_proxy(&self) -> bool {
        matches!(self, Self::Proxy(_))
    }

    /// Check if this is a fallback connection
    /// 检查是否为回退连接
    pub const fn is_fallback(&self) -> bool {
        matches!(self, Self::Fallback { .. })
    }

    /// Handle the connection based on type
    /// 根据类型处理连接
    ///
    /// - Proxy: return the encrypted stream for application layer
    /// - Proxy: 返回用于应用层的加密流
    /// - Fallback: bidirectionally copy traffic between client and target
    /// - Fallback: 在客户端和目标之间双向复制流量
    ///
    /// # Errors
    /// # 错误
    /// Returns an error if relaying data between client and target fails.
    /// 如果在客户端和目标之间中继数据失败，则返回错误。
    pub async fn handle(self) -> io::Result<Option<crate::TlsIoStream>> {
        match self {
            Self::Proxy(stream) => Ok(Some(stream)),
            Self::Fallback {
                mut client,
                mut target,
            } => {
                // Bidirectional copy between client and target
                debug!("Starting fallback traffic relay");

                match tokio::io::copy_bidirectional(&mut client, &mut target).await {
                    Ok((client_to_target, target_to_client)) => {
                        debug!(
                            "Fallback relay complete: client->target={}, target->client={}",
                            client_to_target, target_to_client
                        );
                    }
                    Err(e) => {
                        warn!("Fallback relay error: {}", e);
                        return Err(e);
                    }
                }

                Ok(None)
            }
        }
    }
}

/// Stream wrapper that replays buffered data before reading from underlying stream
/// 在从底层流读取之前重放缓冲数据的流包装器
struct ReplayStream<S> {
    inner: S,
    buffer: Vec<u8>,
    position: usize,
}

impl<S> ReplayStream<S> {
    const fn new(inner: S, buffer: Vec<u8>) -> Self {
        Self {
            inner,
            buffer,
            position: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // First, return buffered data
        if self.position < self.buffer.len() {
            let remaining = &self.buffer[self.position..];
            let to_copy = std::cmp::min(remaining.len(), buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.position += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }

        // Then read from underlying stream
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Implementation notes for full REALITY server:
//
// 1. ClientHello Parsing:
//    - Parse TLS record layer
//    - Extract handshake message
//    - Parse ClientHello structure
//    - Extract extensions (SNI, REALITY-specific)
//
// 2. Certificate Generation:
//    - Create temporary CA certificate
//    - Sign with temporary private key
//    - Include in ServerHello
//    - Client validates against shared secret
//
// 3. Target Certificate Stealing:
//    - Connect to real target
//    - Perform TLS handshake
//    - Extract certificate chain
//    - Present to client (if fallback)
//
// 4. Fallback Mechanism:
//    - On auth failure, become transparent proxy
//    - Copy traffic bidirectionally
//    - Maintain connection state
//    - Ensure indistinguishable from real target

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::manual_string_new)]
mod tests {
    use super::*;
    use x509_parser::oid_registry::OID_SIG_ED25519;
    use x509_parser::prelude::parse_x509_certificate;

    #[test]
    fn test_reality_acceptor_creation() {
        let config = RealityServerConfig {
            target: "www.apple.com:443".to_string(),
            server_names: vec!["example.com".to_string()],
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_ids: vec!["01ab".to_string()],
            handshake_timeout: 5,
            enable_fallback: true,
        };

        let acceptor = RealityAcceptor::new(config);
        assert!(acceptor.is_ok());
    }

    #[test]
    fn test_reality_acceptor_invalid_config() {
        let config = RealityServerConfig {
            target: "".to_string(), // Invalid: empty target
            server_names: vec!["example.com".to_string()],
            private_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(),
            short_ids: vec![],
            handshake_timeout: 5,
            enable_fallback: true,
        };

        let acceptor = RealityAcceptor::new(config);
        assert!(acceptor.is_err());
    }

    #[test]
    fn test_temporary_cert_signature_hmac() {
        let auth_key = [0x11u8; 32];
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let mut cert_der = cert.der().to_vec();
        let signature = compute_temp_cert_signature(&auth_key, key_pair.public_key_raw()).unwrap();
        replace_cert_signature(&mut cert_der, &signature).unwrap();

        let (_, parsed) = parse_x509_certificate(&cert_der).unwrap();
        assert_eq!(parsed.signature_algorithm.algorithm, OID_SIG_ED25519);
        assert_eq!(parsed.signature_value.data, signature.as_slice());
    }

    #[test]
    fn test_target_template_from_leaf() {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
        ])
        .unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "example.com");
        let cert = params.self_signed(&key_pair).unwrap();

        let template = build_template_from_leaf(cert.der().as_ref()).unwrap();
        assert_eq!(template.common_name, Some("example.com".to_string()));
        assert!(template.dns_names.contains(&"example.com".to_string()));
        assert!(template.dns_names.contains(&"www.example.com".to_string()));
        assert!(template.not_before.is_some());
        assert!(template.not_after.is_some());
    }
}
