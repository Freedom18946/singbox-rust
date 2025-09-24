//! Naive HTTP/2 CONNECT outbound implementation
//!
//! Provides HTTP/2 CONNECT proxy functionality for tunneling TCP connections
//! through HTTP/2 streams with optional authentication.

#[cfg(feature = "out_naive")]
use async_trait::async_trait;
#[cfg(feature = "out_naive")]
use base64::Engine;
#[cfg(feature = "out_naive")]
use hyper::{Body, Request, StatusCode, Uri};
#[cfg(feature = "out_naive")]
use std::io;
#[cfg(feature = "out_naive")]
use std::sync::Arc;
#[cfg(feature = "out_naive")]
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

#[cfg(feature = "out_naive")]
use super::types::{HostPort, OutboundTcp};

#[cfg(feature = "out_naive")]
#[derive(Clone, Debug)]
pub struct NaiveH2Config {
    pub proxy_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub skip_cert_verify: bool,
}

#[cfg(feature = "out_naive")]
pub struct NaiveH2Outbound {
    config: NaiveH2Config,
    proxy_uri: Uri,
}

#[cfg(feature = "out_naive")]
impl NaiveH2Outbound {
    pub fn new(config: NaiveH2Config) -> anyhow::Result<Self> {
        // Parse proxy URL
        let proxy_uri: Uri = config
            .proxy_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid proxy URL: {}", e))?;

        Ok(Self { config, proxy_uri })
    }

    fn parse_url(&self) -> anyhow::Result<(String, u16, Option<String>)> {
        let host = self.proxy_uri.host().unwrap_or("localhost").to_string();
        let port = self.proxy_uri.port_u16().unwrap_or(443);

        let auth = if let (Some(username), Some(password)) =
            (&self.config.username, &self.config.password)
        {
            Some(format!("{}:{}", username, password))
        } else {
            None
        };

        Ok((host, port, auth))
    }
}

#[cfg(feature = "out_naive")]
#[async_trait]
impl OutboundTcp for NaiveH2Outbound {
    type IO = hyper::upgrade::Upgraded;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::labels::{record_connect_total, Proto, ResultTag};
        use crate::metrics::outbound::{
            record_connect_attempt, record_connect_error, record_connect_success,
            OutboundErrorClass,
        };

        record_connect_attempt(crate::outbound::OutboundKind::Http);

        let start = std::time::Instant::now();

        // Parse URL components
        let (host, port, auth) = self.parse_url().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("URL parse error: {}", e),
            )
        })?;

        // 1. TCP connection
        let tcp_stream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| {
                record_connect_total(Proto::NaiveH2, ResultTag::ConnectFail);
                e
            })?;

        // 2. TLS handshake with HTTP/2 ALPN
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        // Configure HTTP/2 ALPN
        client_config.alpn_protocols = vec![b"h2".to_vec()];

        if self.config.skip_cert_verify
            && std::env::var("SB_NAIVE_ALLOW_INSECURE").ok() == Some("1".to_string())
        {
            tracing::warn!("Naive H2: insecure mode enabled, certificate verification disabled");
        }

        let client_config = Arc::new(client_config);
        let connector = TlsConnector::from(client_config);
        let server_name = ServerName::try_from(host.clone()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid SNI: {}", e))
        })?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                record_connect_total(Proto::NaiveH2, ResultTag::TlsFail);
                io::Error::new(io::ErrorKind::Other, format!("TLS handshake failed: {}", e))
            })?;

        // 3. Create HTTP/2 client using hyper 0.14 API
        let (mut send_request, connection) = hyper::client::conn::handshake(tls_stream)
            .await
            .map_err(|e| {
                record_connect_total(Proto::NaiveH2, ResultTag::HandshakeFail);
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("HTTP/2 handshake failed: {}", e),
                )
            })?;

        // Spawn connection task
        tokio::spawn(async move {
            let _ = connection.await;
        });

        // 4. Send CONNECT request
        let authority = format!("{}:{}", target.host, target.port);
        let mut req_builder = Request::builder()
            .method("CONNECT")
            .uri(&authority)
            .header("Host", &authority);

        // Add authentication if provided
        if let Some(auth_str) = auth {
            let auth_value = base64::engine::general_purpose::STANDARD.encode(auth_str.as_bytes());
            req_builder =
                req_builder.header("Proxy-Authorization", format!("Basic {}", auth_value));
        }

        let req = req_builder.body(Body::empty()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Request build error: {}", e),
            )
        })?;

        let response = send_request.send_request(req).await.map_err(|e| {
            record_connect_total(Proto::NaiveH2, ResultTag::ProtocolError);
            io::Error::new(
                io::ErrorKind::Other,
                format!("HTTP/2 request failed: {}", e),
            )
        })?;

        // Check response status
        if response.status() != StatusCode::OK {
            record_connect_total(Proto::NaiveH2, ResultTag::HttpNon200);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("CONNECT failed with status: {}", response.status()),
            ));
        }

        // Upgrade to get the tunnel
        let upgraded = hyper::upgrade::on(response).await.map_err(|e| {
            record_connect_total(Proto::NaiveH2, ResultTag::ProtocolError);
            io::Error::new(io::ErrorKind::Other, format!("HTTP upgrade failed: {}", e))
        })?;

        record_connect_success(crate::outbound::OutboundKind::Http);
        record_connect_total(Proto::NaiveH2, ResultTag::Ok);

        // Record timing metrics
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::labels::record_handshake_duration;
            record_handshake_duration(Proto::NaiveH2, start.elapsed().as_millis() as f64);
        }

        Ok(upgraded)
    }

    fn protocol_name(&self) -> &'static str {
        "naive-h2"
    }
}

#[cfg(not(feature = "out_naive"))]
pub struct NaiveH2Config;

#[cfg(not(feature = "out_naive"))]
impl NaiveH2Config {
    pub fn new() -> Self {
        Self
    }
}
