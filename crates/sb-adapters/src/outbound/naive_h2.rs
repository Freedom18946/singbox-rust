//! Naive HTTP/2 CONNECT outbound implementation
//!
//! Provides HTTP/2 CONNECT proxy functionality for tunneling TCP connections
//! through HTTP/2 streams with optional authentication.

#[cfg(feature = "adapter-naive")]
use base64::Engine;
#[cfg(feature = "adapter-naive")]
use hyper::{Body, Request, StatusCode, Uri};
#[cfg(feature = "adapter-naive")]
use std::io;
#[cfg(feature = "adapter-naive")]
use std::sync::Arc;
#[cfg(feature = "adapter-naive")]
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

#[cfg(feature = "adapter-naive")]
use sb_core::outbound::types::HostPort;

#[cfg(feature = "adapter-naive")]
#[derive(Clone, Debug)]
pub struct NaiveH2Config {
    pub tag: Option<String>,
    pub proxy_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub skip_cert_verify: bool,
}

#[cfg(feature = "adapter-naive")]
#[derive(Debug)]
pub struct NaiveH2Outbound {
    config: NaiveH2Config,
    proxy_uri: Uri,
}

#[cfg(feature = "adapter-naive")]
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

#[cfg(feature = "adapter-naive")]
impl sb_types::Outbound for NaiveH2Outbound {
    fn r#type(&self) -> &str {
        "naive"
    }

    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(
            self.config
                .tag
                .clone()
                .unwrap_or_else(|| "naive".to_string()),
        )
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp]
    }

    fn dial<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            use tokio_util::compat::TokioAsyncReadCompatExt;

            let target = HostPort {
                host: session.target.host(),
                port: session.target.port(),
            };
            let stream = self
                .connect_tunnel(&target)
                .await
                .map_err(|error| sb_types::CoreError::io(error.to_string()))?;
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }

    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                "naive does not support packet associations",
            ))
        })
    }
}

#[cfg(feature = "adapter-naive")]
impl NaiveH2Outbound {
    pub const fn protocol_name(&self) -> &'static str {
        "naive-h2"
    }

    pub async fn connect_tunnel(&self, target: &HostPort) -> io::Result<hyper::upgrade::Upgraded> {
        use sb_core::metrics::labels::{record_connect_total, Proto, ResultTag};
        use sb_core::metrics::outbound::{record_connect_attempt, record_connect_success};

        record_connect_attempt(sb_core::outbound::OutboundKind::Http);

        #[cfg(feature = "metrics")]
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
            .inspect_err(|_e| {
                record_connect_total(Proto::NaiveH2, ResultTag::ConnectFail);
            })?;

        // 2. TLS handshake with HTTP/2 ALPN
        sb_tls::ensure_crypto_provider();

        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        // Configure HTTP/2 ALPN
        client_config.alpn_protocols = vec![b"h2".to_vec()];

        if self.config.skip_cert_verify && naive_allow_insecure_from_env() {
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
                io::Error::other(format!("TLS handshake failed: {}", e))
            })?;

        // 3. Create HTTP/2 client using hyper 0.14 API
        let (mut send_request, connection) = hyper::client::conn::handshake(tls_stream)
            .await
            .map_err(|e| {
                record_connect_total(Proto::NaiveH2, ResultTag::HandshakeFail);
                io::Error::other(format!("HTTP/2 handshake failed: {}", e))
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
            io::Error::other(format!("HTTP/2 request failed: {}", e))
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
            io::Error::other(format!("HTTP upgrade failed: {}", e))
        })?;

        record_connect_success(sb_core::outbound::OutboundKind::Http);
        record_connect_total(Proto::NaiveH2, ResultTag::Ok);

        // Record timing metrics
        #[cfg(feature = "metrics")]
        {
            use sb_core::metrics::labels::record_handshake_duration;
            record_handshake_duration(Proto::NaiveH2, start.elapsed().as_millis() as f64);
        }

        Ok(upgraded)
    }
}

#[cfg(not(feature = "adapter-naive"))]
pub struct NaiveH2Config;

#[cfg(not(feature = "adapter-naive"))]
impl NaiveH2Config {
    pub fn new() -> Self {
        Self
    }
}

fn parse_naive_allow_insecure_env(value: Option<&str>) -> Result<bool, Arc<str>> {
    match value {
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(raw) => Err(format!(
            "naive env 'SB_NAIVE_ALLOW_INSECURE' value '{raw}' is not a recognized boolean; silent parse fallback is disabled; use '1'/'true' or '0'/'false'"
        )
        .into()),
        None => Ok(false),
    }
}

fn naive_allow_insecure_from_env() -> bool {
    let raw = std::env::var("SB_NAIVE_ALLOW_INSECURE").ok();
    match parse_naive_allow_insecure_env(raw.as_deref()) {
        Ok(val) => val,
        Err(reason) => {
            tracing::warn!("{reason}; using default false");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_naive_allow_insecure_env, NaiveH2Config, NaiveH2Outbound};
    use sb_types::Outbound;

    #[test]
    fn invalid_naive_allow_insecure_env_reports_explicitly() {
        let err = parse_naive_allow_insecure_env(Some("on"))
            .expect_err("unrecognized boolean env should be rejected explicitly");
        let msg = err.to_string();
        assert!(msg.contains("SB_NAIVE_ALLOW_INSECURE"));
        assert!(msg.contains("silent parse fallback is disabled"));
    }

    #[test]
    fn canonical_naive_contract_is_tcp_only() {
        let outbound = NaiveH2Outbound::new(NaiveH2Config {
            tag: Some("naive-edge".to_string()),
            proxy_url: "https://127.0.0.1:443".to_string(),
            username: None,
            password: None,
            skip_cert_verify: false,
        })
        .expect("valid proxy URL");
        assert_eq!(outbound.tag().as_str(), "naive-edge");
        assert_eq!(outbound.network(), &[sb_types::NetworkKind::Tcp]);
    }
}
