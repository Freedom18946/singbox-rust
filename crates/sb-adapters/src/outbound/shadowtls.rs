//! ShadowTLS outbound connector adapter.
//!
//! IMPORTANT:
//! The previous implementation modeled ShadowTLS as a standalone "TLS + HTTP
//! CONNECT tunnel". That does not match sing-box ShadowTLS semantics, where
//! ShadowTLS acts as a transport wrapper/detour rather than a leaf protocol
//! that serializes the final destination itself.
//!
//! Until transport-wrapper chaining is implemented, this adapter remains
//! registrable but rejects standalone leaf dialing at runtime so parity
//! evidence is not contaminated by the legacy tunnel model.

use crate::outbound::prelude::*;
use std::time::Duration;

#[cfg(feature = "adapter-shadowtls")]
mod tls_helper {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

#[cfg(feature = "adapter-shadowtls")]
use tls_helper::NoVerifier;
#[cfg(feature = "adapter-shadowtls")]
use {
    hmac::{Hmac, Mac},
    sha1::Sha1,
    std::pin::Pin,
    std::task::{Context, Poll},
    tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
};

#[cfg(feature = "adapter-shadowtls")]
type HmacSha1 = Hmac<Sha1>;

#[cfg(feature = "adapter-shadowtls")]
struct HashTrackedReadStream<S> {
    inner: S,
    hasher: HmacSha1,
}

#[cfg(feature = "adapter-shadowtls")]
impl<S> HashTrackedReadStream<S> {
    fn new(inner: S, password: &str) -> Self {
        Self {
            inner,
            hasher: HmacSha1::new_from_slice(password.as_bytes())
                .expect("hmac accepts any key length"),
        }
    }

    fn into_inner(self) -> (S, [u8; 8]) {
        let mut prefix = [0u8; 8];
        let digest = self.hasher.finalize().into_bytes();
        prefix.copy_from_slice(&digest[..8]);
        (self.inner, prefix)
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl<S: AsyncRead + Unpin> AsyncRead for HashTrackedReadStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled = &buf.filled()[before..];
                if !filled.is_empty() {
                    self.hasher.update(filled);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(feature = "adapter-shadowtls")]
impl<S: AsyncWrite + Unpin> AsyncWrite for HashTrackedReadStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(feature = "adapter-shadowtls")]
async fn read_exact_or_eof<R>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "early eof",
            ));
        }
        filled += n;
    }
    Ok(true)
}

#[cfg(feature = "adapter-shadowtls")]
async fn read_shadowtls_application_record<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 5];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    if header[0] != 23 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected TLS record type: {}", header[0]),
        ));
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; length];
    read_exact_or_eof(reader, &mut payload).await?;
    Ok(Some(payload))
}

#[cfg(feature = "adapter-shadowtls")]
async fn write_tls12_record<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0u8; 5];
    header[0] = 23;
    header[1] = 0x03;
    header[2] = 0x03;
    header[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await
}

#[cfg(feature = "adapter-shadowtls")]
async fn write_chunked_tls12_records<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    const MAX_TLS12_RECORD: usize = 16 * 1024;
    for chunk in payload.chunks(MAX_TLS12_RECORD) {
        write_tls12_record(writer, chunk).await?;
    }
    Ok(())
}

#[cfg(feature = "adapter-shadowtls")]
async fn run_v2_bridge<S>(io: S, local: DuplexStream, first_prefix: [u8; 8]) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut io_read, mut io_write) = tokio::io::split(io);
    let (mut local_read, mut local_write) = tokio::io::split(local);

    let client_to_server = async move {
        let mut buf = [0u8; 16 * 1024];
        let mut pending_prefix = Some(first_prefix);
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                io_write.shutdown().await?;
                return Ok::<(), std::io::Error>(());
            }
            if let Some(prefix) = pending_prefix.take() {
                let mut payload = Vec::with_capacity(prefix.len() + n);
                payload.extend_from_slice(&prefix);
                payload.extend_from_slice(&buf[..n]);
                write_tls12_record(&mut io_write, &payload).await?;
            } else {
                write_chunked_tls12_records(&mut io_write, &buf[..n]).await?;
            }
        }
    };

    let server_to_client = async move {
        while let Some(payload) = read_shadowtls_application_record(&mut io_read).await? {
            local_write.write_all(&payload).await?;
        }
        local_write.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    tokio::try_join!(client_to_server, server_to_client)?;
    Ok(())
}

#[cfg(feature = "adapter-shadowtls")]
fn spawn_v2_bridge<S>(io: S, first_prefix: [u8; 8]) -> BoxedStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (user_stream, bridge_stream) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        if let Err(err) = run_v2_bridge(io, bridge_stream, first_prefix).await {
            tracing::debug!(error = %err, "shadowtls v2 bridge closed");
        }
    });
    Box::new(user_stream)
}

/// Configuration for ShadowTLS outbound adapter
#[derive(Debug, Clone)]
pub struct ShadowTlsAdapterConfig {
    /// Decoy TLS server hostname or IP
    pub server: String,
    /// Decoy TLS server port (usually 443)
    pub port: u16,
    /// ShadowTLS protocol version.
    pub version: u8,
    /// Shared password for ShadowTLS authentication.
    pub password: String,
    /// SNI to present during TLS handshake
    pub sni: String,
    /// Optional ALPN protocol (e.g., "h2", "http/1.1")
    pub alpn: Option<String>,
    /// Skip certificate verification (INSECURE; for testing only)
    pub skip_cert_verify: bool,
    /// Optional uTLS fingerprint name for outbound TLS layer.
    pub utls_fingerprint: Option<String>,
}

impl Default for ShadowTlsAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            version: 1,
            password: String::new(),
            sni: "example.com".to_string(),
            alpn: Some("http/1.1".to_string()),
            skip_cert_verify: false,
            utls_fingerprint: None,
        }
    }
}

/// ShadowTLS outbound adapter connector
#[derive(Debug, Clone)]
pub struct ShadowTlsConnector {
    cfg: ShadowTlsAdapterConfig,
}

impl ShadowTlsConnector {
    pub fn new(cfg: ShadowTlsAdapterConfig) -> Self {
        Self { cfg }
    }

    #[cfg(feature = "adapter-shadowtls")]
    fn build_tls_config(&self, tls12_only: bool) -> tokio_rustls::rustls::ClientConfig
    where
        Self: Sized,
    {
        use std::sync::Arc;
        use tokio_rustls::rustls::ClientConfig;

        let mut tls_config = if self.cfg.skip_cert_verify {
            let builder = if tls12_only {
                ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            } else {
                ClientConfig::builder()
            };
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            let root_store = tokio_rustls::rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let builder = if tls12_only {
                ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            } else {
                ClientConfig::builder()
            };
            builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        if let Some(alpn) = self.cfg.alpn.as_ref() {
            let protos: Vec<Vec<u8>> = alpn
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.as_bytes().to_vec())
                .collect();
            if !protos.is_empty() {
                tls_config.alpn_protocols = protos;
            }
        }

        tls_config
    }

    #[cfg(feature = "adapter-shadowtls")]
    async fn perform_tls_handshake<S>(
        &self,
        stream: S,
        tls12_only: bool,
    ) -> Result<tokio_rustls::client::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use std::sync::Arc;
        use tokio_rustls::TlsConnector;

        let tls_config = self.build_tls_config(tls12_only);
        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(self.cfg.sni.as_str())
            .map_err(|e| AdapterError::Other(format!("Invalid ShadowTLS server name: {e}")))?
            .to_owned();

        connector
            .connect(server_name, stream)
            .await
            .map_err(|e| AdapterError::Other(format!("ShadowTLS TLS handshake failed: {e}")))
    }

    #[cfg(feature = "adapter-shadowtls")]
    async fn perform_v1_tls_camouflage<S>(&self, stream: S) -> Result<S>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let tls_stream = self.perform_tls_handshake(stream, true).await?;
        let (stream, _) = tls_stream.into_inner();
        Ok(stream)
    }

    #[cfg(feature = "adapter-shadowtls")]
    pub async fn connect_detour_stream(&self, host: &str, port: u16) -> Result<BoxedStream> {
        tracing::debug!(
            requested_host = host,
            requested_port = port,
            wrapper_server = %self.cfg.server,
            wrapper_port = self.cfg.port,
            "shadowtls detour wrapper ignoring requested endpoint and dialing configured wrapper server"
        );

        let tcp_stream = crate::outbound::detour::connect_tcp_stream(
            &self.cfg.server,
            self.cfg.port,
            None,
            Duration::from_secs(30),
        )
        .await?;
        match self.cfg.version {
            1 => {
                let raw_stream = self.perform_v1_tls_camouflage(tcp_stream).await?;
                Ok(Box::new(raw_stream))
            }
            2 => {
                let hash_stream = HashTrackedReadStream::new(tcp_stream, &self.cfg.password);
                let tls_stream = self.perform_tls_handshake(hash_stream, false).await?;
                let (hash_stream, _) = tls_stream.into_inner();
                let (raw_stream, first_prefix) = hash_stream.into_inner();
                Ok(spawn_v2_bridge(raw_stream, first_prefix))
            }
            _ => Err(AdapterError::Protocol(format!(
                "ShadowTLS runtime wrapper currently supports versions 1 and 2 only; configured version {} still requires protocol-specific encapsulation",
                self.cfg.version
            ))),
        }
    }
}

#[async_trait]
impl OutboundConnector for ShadowTlsConnector {
    fn name(&self) -> &'static str {
        "shadowtls"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-shadowtls"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowtls",
        });

        #[cfg(feature = "adapter-shadowtls")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-shadowtls"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-shadowtls",
        });

        #[cfg(feature = "adapter-shadowtls")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "ShadowTLS outbound only supports TCP".to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("shadowtls", &target);
            tracing::warn!(
                server = %self.cfg.server,
                port = self.cfg.port,
                version = self.cfg.version,
                sni = %self.cfg.sni,
                target = %format!("{}:{}", target.host, target.port),
                "shadowtls standalone leaf dial rejected; transport-wrapper remodel is required"
            );
            Err(AdapterError::Protocol(format!(
                "ShadowTLS standalone leaf dialing is disabled for version {}: sing-box parity requires a transport-wrapper/detour model, not the legacy TLS+CONNECT tunnel",
                self.cfg.version
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadowtls_connector_name() {
        let c = ShadowTlsConnector::new(ShadowTlsAdapterConfig::default());
        assert_eq!(c.name(), "shadowtls");
    }
}
