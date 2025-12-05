//! AnyTLS outbound connector implementation
//!
//! This module provides AnyTLS protocol support for outbound connections.
//! It establishes a TLS connection with AnyTLS authentication and padding,
//! then multiplexes streams over it.

use crate::outbound::prelude::*;
use anyhow::{anyhow, Context, Result};
use anytls_rs::padding::PaddingFactory;
use anytls_rs::session::Session;
use anytls_rs::util::auth::hash_password;
use bytes::Bytes;
use sb_core::adapter::OutboundConnector;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::rustls::{self, pki_types};
use tokio_rustls::TlsConnector;

/// AnyTLS configuration
#[derive(Debug, Clone)]
pub struct AnyTlsConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub padding: Option<Vec<String>>,
    pub tls: Arc<rustls::ClientConfig>,
    pub server_name: pki_types::ServerName<'static>,
}

/// AnyTLS outbound connector
#[derive(Clone)]
pub struct AnyTlsConnector {
    config: Arc<AnyTlsConfig>,
    session: Arc<Mutex<Option<Arc<Session>>>>,
}

impl AnyTlsConnector {
    pub fn new(config: AnyTlsConfig) -> Self {
        Self {
            config: Arc::new(config),
            session: Arc::new(Mutex::new(None)),
        }
    }

    async fn get_or_create_session(&self) -> Result<Arc<Session>> {
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.as_ref() {
            if !session.is_closed() {
                return Ok(session.clone());
            }
        }

        // Create new session
        let session = self.connect_session().await?;
        let session = Arc::new(session);
        *guard = Some(session.clone());

        // Spawn background tasks for the session
        let session_clone = session.clone();
        tokio::spawn(async move {
            if let Err(err) = session_clone.recv_loop().await {
                tracing::debug!(error = %err, "AnyTLS session recv loop exited");
            }
        });

        let session_clone = session.clone();
        tokio::spawn(async move {
            if let Err(err) = session_clone.process_stream_data().await {
                tracing::debug!(error = %err, "AnyTLS session process loop exited");
            }
        });

        Ok(session)
    }

    async fn connect_session(&self) -> Result<Session> {
        let addr_str = format!("{}:{}", self.config.server, self.config.port);
        let stream = TcpStream::connect(&addr_str)
            .await
            .with_context(|| format!("failed to connect to {}", addr_str))?;

        let connector = TlsConnector::from(self.config.tls.clone());
        let tls_stream = connector
            .connect(self.config.server_name.clone(), stream)
            .await
            .with_context(|| "TLS handshake failed")?;

        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        // Perform AnyTLS authentication
        self.authenticate(&mut reader, &mut writer).await?;

        // Create session
        let padding_factory = if let Some(lines) = &self.config.padding {
            let joined = lines.join("\n");
            Arc::new(PaddingFactory::new(joined.as_bytes()).map_err(|e| anyhow!(e))?)
        } else {
            PaddingFactory::default()
        };

        let session = Session::new_client(reader, writer, padding_factory, None);
        Ok(session)
    }

    async fn authenticate<R, W>(&self, _reader: &mut R, writer: &mut W) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let password_hash = hash_password(&self.config.password);
        writer.write_all(&password_hash).await?;

        // Send padding if configured (client side usually sends 0 padding for auth?
        // Protocol: Client sends Hash(32) + PaddingLen(2) + Padding
        // Server verifies hash.

        // We need to send padding length 0 for now as initial handshake
        // Or does AnyTLS require padding in handshake?
        // Looking at inbound:
        // reader.read_exact(&mut provided) (32 bytes)
        // reader.read_exact(&mut padding_len) (2 bytes)
        // reader.read_exact(&mut padding)

        // So we must send padding length.
        let padding_len: u16 = 0; // TODO: Implement random padding for handshake?
        writer.write_all(&padding_len.to_be_bytes()).await?;

        // If we had padding, we would write it here.

        writer.flush().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl OutboundConnector for AnyTlsConnector {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        let session = self
            .get_or_create_session()
            .await
            .map_err(std::io::Error::other)?;

        // Open a stream on the session
        let (stream, _rx) = session
            .open_stream()
            .await
            .map_err(|e| std::io::Error::other(format!("failed to open stream: {}", e)))?;

        // Send target address (SOCKS5 style)
        // Protocol: ATYP + ADDR + PORT
        // We need to write this to the stream.
        // But `stream` is `anytls_rs::session::Stream`.
        // We need to bridge it to a TcpStream.

        // Create loopback pair
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;

        let server_task = tokio::spawn(async move { listener.accept().await.map(|(s, _)| s) });

        let client_stream = TcpStream::connect(local_addr).await?;
        let server_stream = server_task.await??;

        // Write target address to the AnyTLS stream *through* the bridge?
        // No, we should write it directly to the AnyTLS stream before bridging.
        // Wait, `stream` is a `Stream` object. It has `reader()` and `send_data()`.
        // It doesn't implement AsyncRead/AsyncWrite directly?
        // In inbound `relay_stream`, it uses `stream.reader()` (lock) and `stream.send_data()`.

        // We need to wrap `Stream` into AsyncRead/AsyncWrite or bridge manually.
        // Let's bridge manually.

        let stream_reader = stream.reader().clone();
        let stream_writer = stream.clone(); // Stream is Arc-like or handle?
                                            // Stream is Arc<Stream> in inbound. Here `open_stream` returns `Arc<Stream>`.

        // Send target address
        let mut target_buf = Vec::new();
        // SOCKS5 address format
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    target_buf.push(0x01);
                    target_buf.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    target_buf.push(0x04);
                    target_buf.extend_from_slice(&v6.octets());
                }
            }
        } else {
            target_buf.push(0x03);
            let host_bytes = host.as_bytes();
            if host_bytes.len() > 255 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "host too long",
                ));
            }
            target_buf.push(host_bytes.len() as u8);
            target_buf.extend_from_slice(host_bytes);
        }
        target_buf.extend_from_slice(&port.to_be_bytes());

        stream_writer
            .send_data(Bytes::from(target_buf))
            .map_err(|e| std::io::Error::other(format!("failed to send target: {}", e)))?;

        // Bridge tasks
        let (mut local_read, mut local_write) = server_stream.into_split();

        // Remote -> Local
        let reader_clone = stream_reader.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = {
                    let mut guard = reader_clone.lock().await;
                    match guard.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => break,
                    }
                };
                if n == 0 {
                    let _ = local_write.shutdown().await;
                    break;
                }
                if local_write.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });

        // Local -> Remote
        let writer_clone = stream_writer.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match local_read.read(&mut buf).await {
                    Ok(0) => {
                        // EOF
                        // Send FIN? AnyTLS stream doesn't have explicit FIN in API maybe?
                        // It has `close()`.
                        // writer_clone.close();
                        break;
                    }
                    Ok(n) => {
                        if writer_clone
                            .send_data(Bytes::copy_from_slice(&buf[..n]))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(client_stream)
    }
}

impl std::fmt::Debug for AnyTlsConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnyTlsConnector")
            .field("config", &self.config)
            .finish()
    }
}

impl TryFrom<&sb_config::ir::OutboundIR> for AnyTlsConnector {
    type Error = anyhow::Error;

    fn try_from(ir: &sb_config::ir::OutboundIR) -> Result<Self> {
        // Extract required fields
        let server = ir
            .server
            .as_ref()
            .ok_or_else(|| anyhow!("AnyTLS outbound requires 'server' field"))?
            .clone();

        let port = ir
            .port
            .ok_or_else(|| anyhow!("AnyTLS outbound requires 'port' field"))?;

        let password = ir
            .password
            .as_ref()
            .ok_or_else(|| anyhow!("AnyTLS outbound requires 'password' field"))?
            .clone();

        // Optional padding scheme
        let padding = ir.anytls_padding.clone();

        // Build TLS client configuration
        let mut root_store = rustls::RootCertStore::empty();

        // Add system root certificates
        let certs_result = rustls_native_certs::load_native_certs();
        for cert in certs_result.certs {
            root_store.add(cert).ok();
        }
        if let Some(e) = certs_result.errors.first() {
            tracing::warn!("Failed to load some native root certificates: {}", e);
        }

        // Add custom CA certificates if provided
        if !ir.tls_ca_pem.is_empty() {
            for pem_str in &ir.tls_ca_pem {
                let mut reader = std::io::Cursor::new(pem_str.as_bytes());
                let certs = rustls_pemfile::certs(&mut reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("failed to parse CA PEM")?;
                for cert in certs {
                    root_store.add(cert).ok();
                }
            }
        }

        for ca_path in &ir.tls_ca_paths {
            let pem_data = std::fs::read_to_string(ca_path)
                .with_context(|| format!("failed to read CA file: {}", ca_path))?;
            let mut reader = std::io::Cursor::new(pem_data.as_bytes());
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("failed to parse CA PEM")?;
            for cert in certs {
                root_store.add(cert).ok();
            }
        }

        let builder = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let mut config = builder;

        // Set ALPN if provided
        if let Some(alpn) = &ir.tls_alpn {
            config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        }

        // Disable certificate verification if requested
        if ir.skip_cert_verify.unwrap_or(false) {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerification));
        }

        // Determine server name for TLS SNI
        let server_name_str = ir.tls_sni.as_ref().unwrap_or(&server).clone();

        let server_name = pki_types::ServerName::try_from(server_name_str.as_str())
            .map_err(|_| anyhow!("invalid server name: {}", server_name_str))?
            .to_owned();

        let anytls_config = AnyTlsConfig {
            server,
            port,
            password,
            padding,
            tls: Arc::new(config),
            server_name,
        };

        Ok(AnyTlsConnector::new(anytls_config))
    }
}

// Custom certificate verifier that skips all verification
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
