#[cfg(feature = "out_trojan")]
use super::crypto_types::{HostPort, OutboundTcp};
#[cfg(feature = "out_trojan")]
use async_trait::async_trait;
#[cfg(feature = "out_trojan")]
use rustls::pki_types::ServerName;
#[cfg(feature = "out_trojan")]
use rustls::ClientConfig;
#[cfg(feature = "out_trojan")]
use std::sync::Arc;
#[cfg(feature = "out_trojan")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(feature = "out_trojan")]
use tokio_rustls::TlsConnector;

#[cfg(feature = "out_trojan")]
#[derive(Clone, Debug)]
pub struct TrojanConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: bool,
    // Transport extras
    pub transport: Option<Vec<String>>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub h2_path: Option<String>,
    pub h2_host: Option<String>,
    pub http_upgrade_path: Option<String>,
    pub http_upgrade_headers: Vec<(String, String)>,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub grpc_authority: Option<String>,
    pub grpc_metadata: Vec<(String, String)>,
}

#[cfg(feature = "out_trojan")]
impl TrojanConfig {
    pub fn new(server: String, port: u16, password: String, sni: String) -> Self {
        Self {
            server,
            port,
            password,
            sni,
            alpn: None,
            skip_cert_verify: false,
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            http_upgrade_path: None,
            http_upgrade_headers: Vec::new(),
            grpc_service: None,
            grpc_method: None,
            grpc_authority: None,
            grpc_metadata: Vec::new(),
        }
    }

    pub fn with_alpn(mut self, alpn: Vec<String>) -> Self {
        self.alpn = Some(alpn);
        self
    }

    pub fn with_skip_cert_verify(mut self, skip: bool) -> Self {
        self.skip_cert_verify = skip;
        self
    }
}

#[cfg(feature = "out_trojan")]
#[derive(Debug)]
pub struct TrojanOutbound {
    config: TrojanConfig,
    tls_config: Arc<ClientConfig>,
}

#[cfg(feature = "out_trojan")]
impl TrojanOutbound {
    pub fn new(config: TrojanConfig) -> std::io::Result<Self> {
        // Ensure a CryptoProvider is installed for rustls 0.23
        #[allow(unused_must_use)]
        {
            #[cfg(feature = "tls_rustls")]
            {
                use rustls::crypto::ring;
                let _ = ring::default_provider().install_default();
            }
        }
        // Create TLS configuration for Trojan
        // Root store with system roots
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let insecure_env = std::env::var("SB_TROJAN_SKIP_CERT_VERIFY")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if config.skip_cert_verify || insecure_env {
            tracing::warn!("Trojan: insecure mode enabled, certificate verification disabled");
            #[cfg(feature = "tls_rustls")]
            {
                let v = crate::tls::danger::NoVerify::new();
                tls_config
                    .dangerous()
                    .set_certificate_verifier(std::sync::Arc::new(v));
            }
        }

        // Configure ALPN if specified
        if let Ok(alpn_env) = std::env::var("SB_TROJAN_ALPN") {
            if !alpn_env.is_empty() {
                tls_config.alpn_protocols = vec![alpn_env.as_bytes().to_vec()];
            }
        } else if let Some(alpn) = &config.alpn {
            if !alpn.is_empty() {
                tls_config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
            }
        }

        let tls_config = std::sync::Arc::new(tls_config);

        Ok(Self { config, tls_config })
    }
}

// V2Ray transport integration (feature-gated)
#[cfg(all(feature = "out_trojan", feature = "v2ray_transport"))]
#[async_trait]
impl crate::outbound::traits::OutboundConnectorIo for TrojanOutbound {
    async fn connect_tcp_io(
        &self,
        ctx: &crate::types::ConnCtx,
    ) -> crate::error::SbResult<sb_transport::IoStream> {
        use sb_transport::Dialer as _;
        use sb_transport::TransportBuilder;

        let target = HostPort {
            host: match &ctx.dst.host {
                crate::types::Host::Name(d) => d.to_string(),
                crate::types::Host::Ip(ip) => ip.to_string(),
            },
            port: ctx.dst.port,
        };

        // Build layered transport via unified mapper. For Trojan, always pass SNI to imply TLS.
        let alpn_csv = self.config.alpn.as_ref().map(|v| v.join(","));
        let chain_opt = self.config.transport.as_deref();
        let builder = crate::runtime::transport::map::apply_layers(
            TransportBuilder::tcp(),
            chain_opt,
            Some(self.config.sni.as_str()),
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
            None,
        );

        let mut stream = builder
            .build()
            .connect(self.config.server.as_str(), self.config.port)
            .await
            .map_err(|e| crate::error::SbError::other(format!("transport dial failed: {}", e)))?;

        // Perform Trojan handshake over the established stream
        Self::handshake_on(&self.config.password, &target, &mut *stream)
            .await
            .map_err(crate::error::SbError::from)?;

        Ok(stream)
    }
}

#[cfg(feature = "out_trojan")]
#[async_trait]
impl OutboundTcp for TrojanOutbound {
    type IO = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

    async fn connect(&self, target: &HostPort) -> std::io::Result<Self::IO> {
        let _start = std::time::Instant::now();

        // Step 1: TCP connect to Trojan server
        let tcp = tokio::net::TcpStream::connect((self.config.server.as_str(), self.config.port))
            .await
            .inspect_err(|_e| {
                #[cfg(feature = "metrics")]
                crate::telemetry::outbound_connect(
                    "trojan",
                    "error",
                    Some(crate::telemetry::err_kind(_e)),
                );
            })?;

        #[cfg(feature = "metrics")]
        crate::telemetry::outbound_connect("trojan", "ok", None);

        // Step 2: TLS handshake
        let connector = TlsConnector::from(self.tls_config.clone());
        let server_name = ServerName::try_from(self.config.sni.clone())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid SNI"))?;

        let mut tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            #[cfg(feature = "metrics")]
            crate::telemetry::outbound_handshake("trojan", "error", Some("tls_handshake"));
            std::io::Error::other(format!("TLS handshake failed: {}", e))
        })?;

        // Step 3: Trojan protocol handshake
        let handshake_result = self.perform_trojan_handshake(&mut tls_stream, target).await;

        let _elapsed = _start.elapsed();
        match handshake_result {
            Ok(()) => {
                #[cfg(feature = "metrics")]
                {
                    crate::telemetry::outbound_handshake("trojan", "ok", None);
                    if let Ok(ms) = u64::try_from(_elapsed.as_millis()) {
                        crate::metrics::outbound::handshake_duration_histogram()
                            .with_label_values(&["trojan"])
                            .observe(ms as f64);
                    }
                }
                Ok(tls_stream)
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                crate::telemetry::outbound_handshake(
                    "trojan",
                    "error",
                    Some(crate::telemetry::err_kind(&e)),
                );
                Err(e)
            }
        }
    }

    fn protocol_name(&self) -> &'static str {
        "trojan"
    }
}

#[cfg(feature = "out_trojan")]
impl TrojanOutbound {
    async fn perform_trojan_handshake(
        &self,
        tls_stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
        target: &HostPort,
    ) -> std::io::Result<()> {
        // Trojan protocol: password + CRLF + CONNECT request + CRLF + CRLF
        let request = format!(
            "{}\r\nCONNECT {} {}\r\n\r\n",
            self.config.password, target.host, target.port
        );

        tls_stream.write_all(request.as_bytes()).await?;

        // Read server response with timeout and tolerance
        let response_result = Self::read_server_response_on(tls_stream).await;

        match response_result {
            Ok(true) => {
                // Received proper 200 OK response
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("trojan_handshake_total", "result" => "ok", "response" => "200").increment(1);
                }
            }
            Ok(false) => {
                // Received response but not 200 OK, tolerate it
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("trojan_handshake_total", "result" => "ok", "response" => "non_200").increment(1);
                }
            }
            Err(_) => {
                // No response or timeout, tolerate it for compatibility
                #[cfg(feature = "metrics")]
                {
                    metrics::counter!("trojan_handshake_total", "result" => "ok", "response" => "empty").increment(1);
                }
            }
        }

        Ok(())
    }

    /// Read server response with timeout and error tolerance
    /// Returns Ok(true) for 200 response, Ok(false) for other response, Err for timeout/no response
    async fn read_server_response_on<S: AsyncRead + Unpin + ?Sized>(
        s: &mut S,
    ) -> std::io::Result<bool> {
        use tokio::time::{timeout, Duration};

        // Configure response timeout (shorter than handshake timeout)
        let response_timeout = Duration::from_millis(
            std::env::var("SB_TROJAN_RESPONSE_TIMEOUT_MS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
        );

        let mut response_buf = [0u8; 512];

        match timeout(response_timeout, s.read(&mut response_buf)).await {
            Ok(Ok(n)) => {
                if n == 0 {
                    // Connection closed immediately
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed by server",
                    ))
                } else {
                    let response = &response_buf[..n];

                    // Check for HTTP 200 OK response
                    if response.starts_with(b"HTTP/1.1 200")
                        || response.starts_with(b"HTTP/1.0 200")
                    {
                        Ok(true)
                    } else {
                        // Non-200 response, but still a response
                        Ok(false)
                    }
                }
            }
            Ok(Err(e)) => {
                // Read error
                Err(e)
            }
            Err(_) => {
                // Timeout - this is acceptable for some Trojan servers
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "server response timeout (tolerated)",
                ))
            }
        }
    }
}

impl TrojanOutbound {
    pub(crate) async fn handshake_on<S: AsyncRead + AsyncWrite + Unpin + Send + ?Sized>(
        password: &str,
        target: &HostPort,
        stream: &mut S,
    ) -> std::io::Result<()> {
        // Compose Trojan request over the existing stream
        let request = format!(
            "{}\r\nCONNECT {} {}\r\n\r\n",
            password, target.host, target.port
        );
        stream.write_all(request.as_bytes()).await?;
        let _ = Self::read_server_response_on(stream).await; // tolerant
        Ok(())
    }
}

#[cfg(not(feature = "out_trojan"))]
mod stub {
    use super::super::crypto_types::{HostPort, OutboundTcp};
    use async_trait::async_trait;

    #[derive(Clone, Debug)]
    pub struct TrojanConfig;

    impl TrojanConfig {
        pub fn new(_server: String, _port: u16, _password: String, _sni: String) -> Self {
            Self
        }
    }

    pub struct TrojanOutbound;

    impl TrojanOutbound {
        pub fn new(_config: TrojanConfig) -> std::io::Result<Self> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Trojan support not compiled in",
            ))
        }
    }

    #[async_trait]
    impl OutboundTcp for TrojanOutbound {
        type IO = tokio::net::TcpStream;

        async fn connect(&self, _target: &HostPort) -> std::io::Result<Self::IO> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Trojan support not compiled in",
            ))
        }

        fn protocol_name(&self) -> &'static str {
            "trojan"
        }
    }
}

#[cfg(not(feature = "out_trojan"))]
pub use stub::{TrojanConfig, TrojanOutbound};
