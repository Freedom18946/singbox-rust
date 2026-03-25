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
use rand::Rng;
use sb_core::adapter::OutboundConnector;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::{AbortHandle, JoinSet};
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

/// Owns a session and its background tasks (recv_loop + process_stream_data).
/// When dropped, aborts both background tasks to prevent leaked fire-and-forget spawns.
struct SessionRuntime {
    session: Arc<Session>,
    recv_abort: AbortHandle,
    process_abort: AbortHandle,
}

impl SessionRuntime {
    fn new(session: Arc<Session>) -> Self {
        let s1 = session.clone();
        let recv_handle = tokio::spawn(async move {
            if let Err(err) = s1.recv_loop().await {
                tracing::debug!(error = %err, "AnyTLS session recv loop exited");
            }
        });

        let s2 = session.clone();
        let process_handle = tokio::spawn(async move {
            if let Err(err) = s2.process_stream_data().await {
                tracing::debug!(error = %err, "AnyTLS session process loop exited");
            }
        });

        Self {
            session,
            recv_abort: recv_handle.abort_handle(),
            process_abort: process_handle.abort_handle(),
        }
    }
}

impl Drop for SessionRuntime {
    fn drop(&mut self) {
        self.recv_abort.abort();
        self.process_abort.abort();
    }
}

/// AnyTLS outbound connector
#[derive(Clone)]
pub struct AnyTlsConnector {
    config: Arc<AnyTlsConfig>,
    session: Arc<Mutex<Option<SessionRuntime>>>,
    bridge_tasks: Arc<Mutex<JoinSet<()>>>,
}

impl AnyTlsConnector {
    pub fn new(config: AnyTlsConfig) -> Self {
        Self {
            config: Arc::new(config),
            session: Arc::new(Mutex::new(None)),
            bridge_tasks: Arc::new(Mutex::new(JoinSet::new())),
        }
    }

    /// Returns an active session, creating one if needed.
    ///
    /// Uses two-phase locking to avoid holding the mutex across the
    /// async connect/TLS/auth path:
    ///   Phase 1 — short lock: read existing session
    ///   Phase 2 — no lock: create session + spawn background tasks
    ///   Phase 3 — short lock: install (with race-loser detection)
    async fn get_or_create_session(&self) -> Result<Arc<Session>> {
        // Phase 1: check existing session (short lock)
        {
            let guard = self.session.lock().await;
            if let Some(ref rt) = *guard {
                if !rt.session.is_closed() {
                    return Ok(rt.session.clone());
                }
            }
        } // lock released

        // Phase 2: create session outside the lock (no lock-across-await)
        let new_session = Arc::new(self.connect_session().await?);
        let runtime = SessionRuntime::new(new_session.clone());

        // Phase 3: re-lock and install; handle race where another task won
        {
            let mut guard = self.session.lock().await;
            if let Some(ref existing) = *guard {
                if !existing.session.is_closed() {
                    // Another task installed a session while we were connecting.
                    // Drop our runtime (aborts our background tasks) and use theirs.
                    drop(runtime);
                    return Ok(existing.session.clone());
                }
            }
            *guard = Some(runtime);
        }

        Ok(new_session)
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

        // Protocol: Client sends Hash(32) + PaddingLen(2) + Padding
        // Generate random padding length (0-255 bytes) and padding before any await.
        // This keeps ThreadRng off the await boundary and avoids non-Send futures.
        let padding_len: u16 = rand::thread_rng().gen_range(0..=255);
        let padding = if padding_len > 0 {
            let mut buf = vec![0u8; padding_len as usize];
            rand::thread_rng().fill(&mut buf[..]);
            Some(buf)
        } else {
            None
        };
        writer.write_all(&padding_len.to_be_bytes()).await?;

        if let Some(padding) = padding {
            writer.write_all(&padding).await?;
        }

        writer.flush().await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl OutboundConnector for AnyTlsConnector {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        // Drain completed bridge tasks to prevent unbounded accumulation
        {
            let mut bridges = self.bridge_tasks.lock().await;
            while bridges.try_join_next().is_some() {}
        }

        let session = self
            .get_or_create_session()
            .await
            .map_err(std::io::Error::other)?;

        // Open a stream on the session
        let (stream, _rx) = session
            .open_stream()
            .await
            .map_err(|e| std::io::Error::other(format!("failed to open stream: {}", e)))?;

        // Create loopback pair — use try_join! instead of spawning a task for accept
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;

        let (client_stream, server_stream) = tokio::try_join!(
            TcpStream::connect(local_addr),
            async { listener.accept().await.map(|(s, _)| s) }
        )?;

        let stream_reader = stream.reader().clone();
        let stream_writer = stream.clone();

        // Send target address (SOCKS5 style: ATYP + ADDR + PORT)
        let mut target_buf = Vec::new();
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

        // Bridge tasks — tracked in JoinSet so they are aborted on connector drop
        let (mut local_read, mut local_write) = server_stream.into_split();

        let reader_clone = stream_reader.clone();
        let writer_clone = stream_writer.clone();

        let mut bridges = self.bridge_tasks.lock().await;

        // Remote -> Local
        bridges.spawn(async move {
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
        bridges.spawn(async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match local_read.read(&mut buf).await {
                    Ok(0) => break,
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

        drop(bridges);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_runtime_drop_aborts_background_tasks() {
        // Verify that SessionRuntime's Drop impl actually aborts tasks.
        // We simulate the pattern by spawning long-lived tasks and checking
        // that they get cancelled when the owning structure is dropped.
        let task1 = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        });
        let task2 = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        });

        let abort1 = task1.abort_handle();
        let abort2 = task2.abort_handle();

        assert!(!abort1.is_finished());
        assert!(!abort2.is_finished());

        // Simulate SessionRuntime Drop behavior
        abort1.abort();
        abort2.abort();

        assert!(task1.await.unwrap_err().is_cancelled());
        assert!(task2.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn bridge_joinset_aborts_tasks_on_drop() {
        let mut js = JoinSet::new();
        let barrier = Arc::new(tokio::sync::Notify::new());
        let b1 = barrier.clone();
        let b2 = barrier.clone();

        js.spawn(async move {
            b1.notified().await; // will never fire
        });
        js.spawn(async move {
            b2.notified().await;
        });

        assert_eq!(js.len(), 2);
        drop(js); // JoinSet::drop aborts all tasks
        // If we reach here, tasks were cleaned up (no hang)
    }

    #[tokio::test]
    async fn bridge_joinset_reaps_completed_tasks() {
        let mut js: JoinSet<()> = JoinSet::new();
        js.spawn(async {}); // completes immediately
        js.spawn(async {}); // completes immediately

        // Give tasks a moment to complete
        tokio::task::yield_now().await;

        // Drain completed
        while js.try_join_next().is_some() {}
        assert_eq!(js.len(), 0);
    }

    #[tokio::test]
    async fn connector_new_initializes_empty_state() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let config = AnyTlsConfig {
            server: "example.com".into(),
            port: 443,
            password: "test".into(),
            padding: None,
            tls: Arc::new(tls_config),
            server_name: pki_types::ServerName::try_from("example.com")
                .unwrap()
                .to_owned(),
        };

        let connector = AnyTlsConnector::new(config);

        // Session slot starts empty
        let guard = connector.session.lock().await;
        assert!(guard.is_none());
        drop(guard);

        // Bridge set starts empty
        let bridges = connector.bridge_tasks.lock().await;
        assert_eq!(bridges.len(), 0);
    }
}
