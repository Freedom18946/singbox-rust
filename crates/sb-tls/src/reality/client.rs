//! REALITY client implementation

use super::config::RealityClientConfig;
use super::handshake::RealityHandshake;
use super::{RealityError, RealityResult};
use crate::TlsConnector;
use async_trait::async_trait;
use std::io::{self, Read};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

const REALITY_TLS_READ_CHUNK: usize = 4096;

fn reality_tls_protocol_error(err: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Concrete REALITY client stream that keeps access to both rustls and the
/// underlying transport.
pub struct RealityClientTlsStream<S> {
    inner: tokio_rustls::client::TlsStream<S>,
}

impl<S> RealityClientTlsStream<S> {
    pub(crate) fn new(inner: tokio_rustls::client::TlsStream<S>) -> Self {
        Self { inner }
    }

    pub fn get_mut(&mut self) -> (&mut S, &mut rustls::client::ClientConnection) {
        self.inner.get_mut()
    }
}

impl<S> RealityClientTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn read_tls(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            {
                let (_, conn) = self.inner.get_mut();
                match conn.reader().read(buf) {
                    Ok(read) => return Ok(read),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => return Err(err),
                }
            }

            if self.buffered_raw_tls_len() > 0 {
                let (_, conn) = self.inner.get_mut();
                conn.process_new_packets_until_plaintext()
                    .map_err(reality_tls_protocol_error)?;
                if self.pending_tls_plaintext_len() > 0 {
                    continue;
                }
            }

            let mut wire = [0u8; REALITY_TLS_READ_CHUNK];
            let read = self.inner.get_mut().0.read(&mut wire).await?;
            if read == 0 {
                let (_, conn) = self.inner.get_mut();
                let mut eof = io::empty();
                let _ = conn.read_tls(&mut eof)?;
                return Ok(0);
            }

            let mut input = &wire[..read];
            let accepted = {
                let (_, conn) = self.inner.get_mut();
                conn.read_tls(&mut input)?
            };
            if accepted != read {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "REALITY TLS read accepted a partial in-memory network read",
                ));
            }

            let (_, conn) = self.inner.get_mut();
            conn.process_new_packets_until_plaintext()
                .map_err(reality_tls_protocol_error)?;
        }
    }

    pub async fn write_tls_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf).await
    }

    pub async fn flush_tls(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }

    pub async fn shutdown_tls(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    pub fn pending_tls_plaintext_len(&mut self) -> usize {
        let (_, conn) = self.inner.get_mut();
        conn.pending_plaintext_len()
    }

    pub fn take_pending_tls_plaintext(&mut self) -> Vec<u8> {
        let (_, conn) = self.inner.get_mut();
        conn.take_pending_plaintext()
    }

    pub fn buffered_raw_tls_len(&mut self) -> usize {
        let (_, conn) = self.inner.get_mut();
        conn.buffered_read_tls_len()
    }

    pub fn take_buffered_raw_tls(&mut self) -> Vec<u8> {
        let (_, conn) = self.inner.get_mut();
        conn.take_buffered_read_tls()
    }

    pub async fn read_raw(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.get_mut().0.read(buf).await
    }

    pub async fn write_raw_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.get_mut().0.write_all(buf).await
    }

    pub async fn flush_raw(&mut self) -> io::Result<()> {
        self.inner.get_mut().0.flush().await
    }

    pub async fn shutdown_raw(&mut self) -> io::Result<()> {
        self.inner.get_mut().0.shutdown().await
    }
}

impl<S> tokio::io::AsyncRead for RealityClientTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> tokio::io::AsyncWrite for RealityClientTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
        config.validate().map_err(RealityError::InvalidConfig)?;
        config
            .public_key_bytes()
            .map_err(RealityError::InvalidConfig)?;

        debug!(
            "Created REALITY connector for target: {}, server_name: {}",
            config.target, config.server_name
        );

        Ok(Self {
            config: Arc::new(config),
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
        Ok(Box::new(self.reality_handshake_stream(stream).await?))
    }

    pub async fn connect_stream<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> io::Result<RealityClientTlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!(
            "REALITY connect_stream: server_name={}, target={}",
            server_name, self.config.target
        );

        self.reality_handshake_stream(stream)
            .await
            .map_err(io::Error::other)
    }

    async fn reality_handshake_stream<S>(
        &self,
        stream: S,
    ) -> RealityResult<RealityClientTlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        RealityHandshake::new(self.config.clone())?
            .perform_stream(stream)
            .await
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
            target: String::new(), // Invalid: empty target
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

    #[tokio::test]
    async fn test_read_tls_stops_before_coalesced_raw_bytes() {
        crate::ensure_crypto_provider();

        const TLS_PAYLOAD: &[u8] = b"vision-direct-frame";
        const RAW_PAYLOAD: &[u8] = b"raw-after-direct";

        let (acceptor, connector) = test_tls_pair();
        let (client_io, server_io) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut server_tls = acceptor.accept(server_io).await.unwrap();
            server_tls.write_all(TLS_PAYLOAD).await.unwrap();
            server_tls.flush().await.unwrap();

            let (raw_io, _) = server_tls.get_mut();
            raw_io.write_all(RAW_PAYLOAD).await.unwrap();
            raw_io.flush().await.unwrap();
        });

        let client_tls = connector
            .connect(test_server_name(), client_io)
            .await
            .unwrap();
        server.await.unwrap();

        let mut stream = RealityClientTlsStream::new(client_tls);
        let mut output = [0u8; 64];
        let read = stream.read_tls(&mut output).await.unwrap();

        assert_eq!(&output[..read], TLS_PAYLOAD);
        assert_eq!(stream.buffered_raw_tls_len(), RAW_PAYLOAD.len());
        assert_eq!(stream.take_buffered_raw_tls(), RAW_PAYLOAD);
    }

    #[tokio::test]
    async fn test_read_tls_waits_for_fragmented_tls_record() {
        crate::ensure_crypto_provider();

        let (acceptor, connector) = test_tls_pair();
        let payload = vec![0x5a; REALITY_TLS_READ_CHUNK * 2 + 37];
        let server_payload = payload.clone();
        let (client_io, server_io) = tokio::io::duplex(REALITY_TLS_READ_CHUNK * 8);

        let server = tokio::spawn(async move {
            let mut server_tls = acceptor.accept(server_io).await.unwrap();
            server_tls.write_all(&server_payload).await.unwrap();
            server_tls.flush().await.unwrap();
        });

        let client_tls = connector
            .connect(test_server_name(), client_io)
            .await
            .unwrap();
        let mut stream = RealityClientTlsStream::new(client_tls);
        let mut output = vec![0u8; payload.len()];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_tls(&mut output),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(read > 0);
        assert_eq!(&output[..read], &payload[..read]);
        server.await.unwrap();
    }

    fn test_tls_pair() -> (tokio_rustls::TlsAcceptor, tokio_rustls::TlsConnector) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::danger::NoVerify::new()))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        (acceptor, connector)
    }

    fn test_server_name() -> rustls::pki_types::ServerName<'static> {
        rustls::pki_types::ServerName::try_from("localhost").unwrap()
    }
}
