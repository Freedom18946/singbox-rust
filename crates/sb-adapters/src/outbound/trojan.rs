//! Trojan outbound connector implementation
//!
//! This module provides Trojan protocol support for outbound connections.
//! Trojan is a proxy protocol that disguises traffic as TLS traffic.
//! Supports both TCP and UDP relay.

use crate::outbound::prelude::*;
use crate::transport_config::TransportConfig;
use std::sync::Arc;

#[cfg(feature = "adapter-trojan")]
mod tls_helper {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    /// No-op certificate verifier for testing (INSECURE - skips all verification)
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

#[cfg(feature = "adapter-trojan")]
use tls_helper::NoVerifier;

/// Parse a Trojan `server` endpoint string into `(host, port)`.
///
/// Accepts:
/// - `domain:port` (e.g. `trojan.example.com:443`)
/// - `IPv4:port` (e.g. `127.0.0.1:443`)
/// - `[IPv6]:port` (e.g. `[::1]:443`)
///
/// Rejects empty hosts, missing ports, non-numeric ports, port 0, and bare
/// (non-bracketed) IPv6 literals — bare IPv6 strings such as `::1:443` are
/// ambiguous because the port boundary cannot be located deterministically.
///
/// Unlike `SocketAddr::parse`, this does **not** require the host to be an
/// IP literal. DNS resolution happens later, at the transport layer, so a
/// hostname server is no longer a synchronous local failure.
fn parse_server_endpoint(server: &str) -> Result<(String, u16)> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return Err(AdapterError::Other(
            "Invalid server address: endpoint is empty".to_string(),
        ));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let close = rest.find(']').ok_or_else(|| {
            AdapterError::Other(format!(
                "Invalid server address: bracketed IPv6 missing ']' in '{}'",
                trimmed
            ))
        })?;
        let host = &rest[..close];
        let port_str = rest[close + 1..].strip_prefix(':').ok_or_else(|| {
            AdapterError::Other(format!(
                "Invalid server address: missing ':port' after IPv6 in '{}'",
                trimmed
            ))
        })?;
        if host.is_empty() {
            return Err(AdapterError::Other(
                "Invalid server address: empty IPv6 host".to_string(),
            ));
        }
        let port = parse_port(port_str, trimmed)?;
        return Ok((host.to_string(), port));
    }
    let colon_count = trimmed.matches(':').count();
    if colon_count == 0 {
        return Err(AdapterError::Other(format!(
            "Invalid server address: missing ':port' in '{}'",
            trimmed
        )));
    }
    if colon_count > 1 {
        return Err(AdapterError::Other(format!(
            "Invalid server address: bare IPv6 must be bracketed in '{}'",
            trimmed
        )));
    }
    let (host, port_str) = trimmed.rsplit_once(':').ok_or_else(|| {
        AdapterError::Other(format!(
            "Invalid server address: missing ':port' in '{}'",
            trimmed
        ))
    })?;
    if host.is_empty() {
        return Err(AdapterError::Other(
            "Invalid server address: empty host".to_string(),
        ));
    }
    let port = parse_port(port_str, trimmed)?;
    Ok((host.to_string(), port))
}

fn parse_port(port_str: &str, original: &str) -> Result<u16> {
    if port_str.is_empty() {
        return Err(AdapterError::Other(format!(
            "Invalid server address: empty port in '{}'",
            original
        )));
    }
    let port: u16 = port_str.parse().map_err(|_| {
        AdapterError::Other(format!(
            "Invalid server address: invalid port '{}' in '{}'",
            port_str, original
        ))
    })?;
    if port == 0 {
        return Err(AdapterError::Other(format!(
            "Invalid server address: port 0 not allowed in '{}'",
            original
        )));
    }
    Ok(port)
}

/// Trojan configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrojanConfig {
    /// Server address (host:port)
    pub server: String,
    /// Connection tag
    #[serde(default)]
    pub tag: Option<String>,
    /// Password for authentication
    pub password: String,
    /// Connection timeout in seconds
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// SNI for TLS handshake
    #[serde(default)]
    pub sni: Option<String>,
    /// Optional ALPN protocols to advertise
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    /// Skip certificate verification
    #[serde(default)]
    pub skip_cert_verify: bool,
    /// Optional outbound detour tag for the TCP underlay.
    #[serde(default)]
    pub detour: Option<String>,
    /// Transport layer (TCP/WebSocket/gRPC/HTTPUpgrade)
    #[serde(default)]
    pub transport_layer: TransportConfig,
    /// Optional REALITY TLS configuration for outbound
    #[cfg(feature = "tls_reality")]
    #[serde(default)]
    pub reality: Option<sb_tls::RealityClientConfig>,
    /// Multiplex configuration
    #[serde(default)]
    pub multiplex: Option<sb_transport::multiplex::MultiplexConfig>,
}

/// Trojan outbound connector
#[derive(Clone, Default)]
pub struct TrojanConnector {
    _config: Option<TrojanConfig>,
    /// Transport dialer with optional TLS and Multiplex layers
    #[cfg(feature = "sb-transport")]
    dialer: Option<std::sync::Arc<dyn sb_transport::Dialer>>,
}

impl std::fmt::Debug for TrojanConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrojanConnector")
            .field("_config", &self._config)
            .field("dialer", &"<dialer>")
            .finish()
    }
}

impl TrojanConnector {
    pub fn new(config: TrojanConfig) -> Self {
        // Create dialer with transport layer and multiplex layers
        // Note: TLS is handled separately for Trojan (mandatory protocol requirement)
        #[cfg(feature = "sb-transport")]
        let dialer = {
            let tls_config = None; // TLS handled separately in dial()

            #[cfg(feature = "transport_mux")]
            let multiplex_config = config.multiplex.as_ref();
            #[cfg(not(feature = "transport_mux"))]
            let multiplex_config = None;

            Some(
                config
                    .transport_layer
                    .create_dialer_with_layers(tls_config, multiplex_config),
            )
        };

        Self {
            _config: Some(config),
            #[cfg(feature = "sb-transport")]
            dialer,
        }
    }

    #[cfg(feature = "adapter-trojan")]
    async fn perform_standard_tls_handshake<S>(
        &self,
        stream: S,
        config: &TrojanConfig,
    ) -> Result<tokio_rustls::client::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use std::sync::Arc;
        use tokio_rustls::{rustls::ClientConfig, TlsConnector};

        // Create TLS config
        let mut tls_config = if config.skip_cert_verify {
            // Disable certificate verification (insecure, for testing only)
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            // Use webpki-roots for certificate verification
            let root_store = tokio_rustls::rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Advertise ALPN if provided
        if let Some(alpn) = &config.alpn {
            if !alpn.is_empty() {
                tls_config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
            }
        }

        let connector = TlsConnector::from(Arc::new(tls_config));

        // Determine server name for SNI. Prefer the explicit `config.sni`
        // when present; otherwise reuse the hostname half of the parsed
        // endpoint so bracketed IPv6 (`[::1]:443`) and IPv4:port both
        // produce a usable `ServerName` instead of the fragile
        // `split(':').next()` shape that strips IPv6 to `[`.
        let server_name = if let Some(ref sni) = config.sni {
            sni.clone()
        } else {
            match parse_server_endpoint(&config.server) {
                Ok((host, _port)) => host,
                Err(_) => "localhost".to_string(),
            }
        };

        let domain = rustls_pki_types::ServerName::try_from(server_name.as_str())
            .map_err(|e| AdapterError::Other(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tls_stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| AdapterError::Other(format!("TLS handshake failed: {}", e)))?;

        Ok(tls_stream)
    }

    /// Create canonical UDP relay association.
    #[cfg(feature = "adapter-trojan")]
    pub async fn udp_relay_dial(&self, session: &Session) -> Result<sb_types::BoxedPacketConn> {
        use sha2::{Digest, Sha224};
        use tokio::io::AsyncWriteExt;
        use tokio::net::{lookup_host, UdpSocket};

        let config = self
            ._config
            .as_ref()
            .ok_or_else(|| AdapterError::Other("Trojan config not set".to_string()))?;

        tracing::debug!(
            server = %config.server,
            target = %session.target,
            "Creating Trojan UDP relay"
        );

        if config.detour.is_some()
            && config.transport_layer.transport_type()
                != crate::transport_config::TransportType::Tcp
        {
            return Err(AdapterError::Protocol(
                "Trojan detour currently supports plain TCP transport only".to_string(),
            ));
        }

        // Parse server endpoint and resolve to a SocketAddr.
        //
        // UDP relay needs a concrete `SocketAddr` for both the local UDP
        // socket connect and the outgoing UDP ASSOCIATE record. When
        // `config.server` carries a hostname we resolve it explicitly via
        // `tokio::net::lookup_host` and pick the first address. This is a
        // bounded, single-pick resolution: it does NOT round-robin across
        // resolved IPs, and an IPv6-only result will fail the IPv4-only
        // ATYP encoding below — both behaviors are pre-existing UDP relay
        // limitations and are recorded in
        // `agents-only/archive/mt_real_02/mt_trojan_fresh_sample_intake.md` rather than
        // fixed silently in this round.
        let (server_host, server_port) = parse_server_endpoint(&config.server)?;
        let server_addr: std::net::SocketAddr =
            match lookup_host((server_host.as_str(), server_port)).await {
                Ok(mut addrs) => addrs.next().ok_or_else(|| {
                    AdapterError::Network(format!(
                        "Trojan UDP relay DNS resolution returned no addresses for '{}:{}'",
                        server_host, server_port
                    ))
                })?,
                Err(e) => {
                    return Err(AdapterError::Network(format!(
                        "Trojan UDP relay DNS resolution failed for '{}:{}': {}",
                        server_host, server_port, e
                    )))
                }
            };

        // Step 1: Establish TCP connection for UDP ASSOCIATE command
        let tcp_stream = crate::outbound::detour::connect_tcp_stream(
            &server_addr.ip().to_string(),
            server_addr.port(),
            config.detour.as_deref(),
            std::time::Duration::from_secs(config.connect_timeout_sec.unwrap_or(30)),
        )
        .await?;

        // Step 2: Perform TLS handshake
        let mut tls_stream = self
            .perform_standard_tls_handshake(tcp_stream, config)
            .await?;

        // Step 3: Send UDP ASSOCIATE command (CMD=0x03)
        let mut request = Vec::new();

        // Password hash (SHA224)
        let mut hasher = Sha224::new();
        hasher.update(config.password.as_bytes());
        let password_hash = hasher.finalize();
        request.extend_from_slice(hex::encode(password_hash).as_bytes());
        request.extend_from_slice(b"\r\n");

        // Command: UDP ASSOCIATE (0x03)
        request.push(0x03);

        // Address: server itself for UDP associate
        request.push(0x01); // IPv4
        request.extend_from_slice(
            &server_addr
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1))
                .octets(),
        );
        request.extend_from_slice(&server_addr.port().to_be_bytes());
        request.extend_from_slice(b"\r\n");

        // Send UDP ASSOCIATE request
        tls_stream
            .write_all(&request)
            .await
            .map_err(AdapterError::Io)?;
        tls_stream.flush().await.map_err(AdapterError::Io)?;

        // Step 4: Create UDP socket for actual data transfer
        let udp_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(AdapterError::Io)?;

        udp_socket
            .connect(server_addr)
            .await
            .map_err(|e| AdapterError::Network(format!("UDP connect failed: {}", e)))?;

        // Create Trojan UDP socket wrapper
        let trojan_udp = TrojanUdpSocket::new(
            Arc::new(udp_socket),
            session.target.clone(),
            session.packet.idle_timeout,
        )?;

        Ok(Box::new(trojan_udp))
    }
}

impl TrojanConnector {
    pub const fn name(&self) -> &'static str {
        "trojan"
    }

    pub async fn start(&self) -> Result<()> {
        Ok(())
    }

    pub async fn dial(&self, session: &Session) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-trojan"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-trojan",
        });

        #[cfg(feature = "adapter-trojan")]
        {
            use sha2::{Digest, Sha224};
            use tokio::io::AsyncWriteExt;

            let config = self
                ._config
                .as_ref()
                .ok_or_else(|| AdapterError::Other("Trojan config not set".to_string()))?;

            let target = &session.target;
            let host = target.host();
            let port = target.port();
            let _span = crate::outbound::span_dial("trojan", target);

            // Update comment: Multiplex is now integrated via transport layer
            // Trojan protocol flow with V2Ray transports:
            // Transport (TCP/WebSocket/gRPC) -> TLS (REALITY or standard) -> Multiplex -> Trojan Protocol
            tracing::debug!(
                "Using transport dialer for Trojan connection (transport: {:?})",
                config.transport_layer.transport_type()
            );

            // Step 1: Establish base connection via dialer (handles transport layer + multiplex)
            // Honor caller connect timeout, taking stricter configured ceiling.
            // configured connect_timeout_sec (default 30s): a short session timeout fails fast while a
            // configured ceiling still applies. `_opts` keeps its underscore name because the
            // feature-off dial arm above does not use it. (package09; supersedes package08 follow-up #2)
            let timeout = session
                .connect
                .connect_timeout
                .min(std::time::Duration::from_secs(
                    config.connect_timeout_sec.unwrap_or(30),
                ));

            // Parse server endpoint into (host, port). DNS resolution is
            // deferred to the transport layer, so a hostname server no
            // longer fails synchronously here.
            let (server_host, server_port) = parse_server_endpoint(&config.server)?;

            if config.detour.is_some()
                && (config.transport_layer.transport_type()
                    != crate::transport_config::TransportType::Tcp
                    || config.multiplex.is_some())
            {
                return Err(AdapterError::Protocol(
                    "Trojan detour currently supports plain TCP without multiplex".to_string(),
                ));
            }

            #[cfg(feature = "sb-transport")]
            let base_stream = {
                if config.detour.is_some() {
                    crate::outbound::detour::connect_tcp_stream(
                        &server_host,
                        server_port,
                        config.detour.as_deref(),
                        timeout,
                    )
                    .await?
                } else if let Some(ref dialer) = self.dialer {
                    let stream =
                        tokio::time::timeout(timeout, dialer.connect(&server_host, server_port))
                            .await
                            .map_err(|_| AdapterError::Timeout(timeout))?
                            .map_err(|e| {
                                AdapterError::Other(format!("Transport dial failed: {}", e))
                            })?;
                    crate::traits::from_transport_stream(stream)
                } else {
                    // Fallback to direct TCP connection (resolves hostname via DNS)
                    let tcp_stream = tokio::time::timeout(
                        timeout,
                        tokio::net::TcpStream::connect((server_host.as_str(), server_port)),
                    )
                    .await
                    .map_err(|_| AdapterError::Timeout(timeout))?
                    .map_err(AdapterError::Io)?;
                    Box::new(tcp_stream) as BoxedStream
                }
            };

            #[cfg(not(feature = "sb-transport"))]
            let base_stream = {
                crate::outbound::detour::connect_tcp_stream(
                    &server_host,
                    server_port,
                    config.detour.as_deref(),
                    timeout,
                )
                .await?
            };

            // Step 2: Perform TLS handshake
            #[cfg(feature = "tls_reality")]
            let mut stream: BoxedStream = if let Some(ref reality_cfg) = config.reality {
                // Use REALITY TLS
                use sb_tls::TlsConnector;
                let reality_connector = sb_tls::reality::RealityConnector::new(reality_cfg.clone())
                    .map_err(|e| {
                        AdapterError::Other(format!("Failed to create REALITY connector: {}", e))
                    })?;

                let server_name = reality_cfg.server_name.clone();
                let tls_stream = reality_connector
                    .connect(base_stream, &server_name)
                    .await
                    .map_err(|e| AdapterError::Other(format!("REALITY handshake failed: {}", e)))?;

                Box::new(tls_stream)
            } else {
                // Use standard TLS
                let tls_stream = self
                    .perform_standard_tls_handshake(base_stream, config)
                    .await?;
                Box::new(tls_stream)
            };

            #[cfg(not(feature = "tls_reality"))]
            let mut stream: BoxedStream = {
                // Use standard TLS
                let tls_stream = self
                    .perform_standard_tls_handshake(base_stream, config)
                    .await?;
                Box::new(tls_stream)
            };

            // Step 3: Perform Trojan handshake

            // Trojan request format:
            // [SHA224(password)][CRLF][CMD][ATYP][DST.ADDR][DST.PORT][CRLF]
            // CMD: 0x01 for CONNECT
            // ATYP: 0x01 (IPv4), 0x03 (Domain), 0x04 (IPv6)

            let mut request = Vec::new();

            // Password hash (SHA224)
            let mut hasher = Sha224::new();
            hasher.update(config.password.as_bytes());
            let password_hash = hasher.finalize();
            request.extend_from_slice(hex::encode(password_hash).as_bytes());
            request.extend_from_slice(b"\r\n");

            // Command: CONNECT (0x01)
            request.push(0x01);

            // Address type and address
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                match ip {
                    std::net::IpAddr::V4(ipv4) => {
                        request.push(0x01); // IPv4
                        request.extend_from_slice(&ipv4.octets());
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        request.push(0x04); // IPv6
                        request.extend_from_slice(&ipv6.octets());
                    }
                }
            } else {
                // Domain name
                request.push(0x03); // Domain
                request.push(host.len() as u8);
                request.extend_from_slice(host.as_bytes());
            }

            // Port (big-endian)
            request.extend_from_slice(&port.to_be_bytes());
            request.extend_from_slice(b"\r\n");

            // Send Trojan request
            stream.write_all(&request).await.map_err(AdapterError::Io)?;
            stream.flush().await.map_err(AdapterError::Io)?;

            // Trojan doesn't send a response for CONNECT, connection is ready
            Ok(Box::new(stream) as BoxedStream)
        }
    }
}

impl sb_types::Outbound for TrojanConnector {
    fn r#type(&self) -> &str {
        "trojan"
    }
    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(
            self._config
                .as_ref()
                .and_then(|config| config.tag.clone())
                .unwrap_or_else(|| "trojan".to_string()),
        )
    }
    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
    }
    fn dial<'a>(
        &'a self,
        session: &'a Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            use tokio_util::compat::TokioAsyncReadCompatExt;
            let stream = TrojanConnector::dial(self, session)
                .await
                .map_err(|error| crate::outbound::core_error(error, session))?;
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }
    fn listen_packet<'a>(
        &'a self,
        session: &'a Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async move {
            #[cfg(feature = "adapter-trojan")]
            {
                self.udp_relay_dial(session)
                    .await
                    .map_err(|error| crate::outbound::core_error(error, session))
            }
            #[cfg(not(feature = "adapter-trojan"))]
            {
                Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "Trojan UDP support is not compiled",
                ))
            }
        })
    }
}

/// Trojan canonical UDP packet association.
#[cfg(feature = "adapter-trojan")]
#[derive(Debug)]
pub struct TrojanUdpSocket {
    socket: Arc<tokio::net::UdpSocket>,
    state: crate::outbound::PacketState,
}

#[cfg(feature = "adapter-trojan")]
impl TrojanUdpSocket {
    pub fn new(
        socket: Arc<tokio::net::UdpSocket>,
        target: TargetAddr,
        idle_timeout: std::time::Duration,
    ) -> Result<Self> {
        Ok(Self {
            socket,
            state: crate::outbound::PacketState::new(target, idle_timeout),
        })
    }

    /// Encode Trojan UDP packet
    /// Format: CMD(0x03) + ATYP + DST.ADDR + PORT + PAYLOAD
    fn encode_packet(&self, data: &[u8], target: &TargetAddr) -> Result<Vec<u8>> {
        let mut packet = Vec::new();
        let host = target.host();

        // CMD: UDP (0x03)
        packet.push(0x03);

        // Address type and address
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(ipv4) => {
                    packet.push(0x01); // IPv4
                    packet.extend_from_slice(&ipv4.octets());
                }
                std::net::IpAddr::V6(ipv6) => {
                    packet.push(0x04); // IPv6
                    packet.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            // Domain name
            packet.push(0x03); // Domain
            let hostname_bytes = host.as_bytes();
            if hostname_bytes.len() > 255 {
                return Err(AdapterError::InvalidConfig("Hostname too long"));
            }
            packet.push(hostname_bytes.len() as u8);
            packet.extend_from_slice(hostname_bytes);
        }

        // Port
        packet.extend_from_slice(&target.port().to_be_bytes());

        // Payload
        packet.extend_from_slice(data);

        Ok(packet)
    }

    /// Parse Trojan UDP packet and extract payload
    fn decode_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.is_empty() {
            return Err(AdapterError::Protocol("Empty packet".to_string()));
        }

        // CMD should be 0x03
        if packet[0] != 0x03 {
            return Err(AdapterError::Protocol(format!(
                "Invalid CMD: {}",
                packet[0]
            )));
        }

        let mut offset = 1;

        // Parse address type
        if packet.len() < offset + 1 {
            return Err(AdapterError::Protocol("Packet too short".to_string()));
        }

        let atyp = packet[offset];
        offset += 1;

        match atyp {
            0x01 => {
                // IPv4: 4 bytes + 2 bytes port
                offset += 4 + 2;
            }
            0x03 => {
                // Domain: length byte + domain + 2 bytes port
                if packet.len() < offset + 1 {
                    return Err(AdapterError::Protocol("Invalid domain length".to_string()));
                }
                let domain_len = packet[offset] as usize;
                offset += 1 + domain_len + 2;
            }
            0x04 => {
                // IPv6: 16 bytes + 2 bytes port
                offset += 16 + 2;
            }
            _ => {
                return Err(AdapterError::Protocol(format!("Invalid ATYP: {}", atyp)));
            }
        }

        if offset > packet.len() {
            return Err(AdapterError::Protocol("Packet truncated".to_string()));
        }

        // Return payload
        Ok(packet[offset..].to_vec())
    }
}

#[cfg(feature = "adapter-trojan")]
impl sb_types::PacketConn for TrojanUdpSocket {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        destination: &'a TargetAddr,
    ) -> sb_types::BoxFuture<'a, Result<usize, sb_types::CoreError>> {
        Box::pin(async move {
            self.state.ensure_open()?;
            self.state.set_target(destination);
            let packet = self
                .encode_packet(payload, destination)
                .map_err(|error| sb_types::CoreError::protocol(error.to_string()))?;
            let sent = crate::outbound::with_packet_deadline(
                self.state.write_deadline(),
                self.socket.send(&packet),
            )
            .await?;
            if sent == packet.len() {
                Ok(payload.len())
            } else {
                Err(sb_types::CoreError::io("partial Trojan UDP packet sent"))
            }
        })
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> sb_types::BoxFuture<'a, Result<(usize, TargetAddr), sb_types::CoreError>> {
        Box::pin(async move {
            self.state.ensure_open()?;
            let mut packet = vec![0_u8; buffer.len() + 256];
            let (size, _) = crate::outbound::with_packet_deadline(
                self.state.read_deadline(),
                self.socket.recv_from(&mut packet),
            )
            .await?;
            let payload = self
                .decode_packet(&packet[..size])
                .map_err(|error| sb_types::CoreError::protocol(error.to_string()))?;
            if payload.len() > buffer.len() {
                return Err(sb_types::CoreError::io("packet buffer too small"));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), self.state.target()))
        })
    }

    fn close(&self) -> sb_types::BoxFuture<'_, Result<(), sb_types::CoreError>> {
        self.state.close();
        Box::pin(async { Ok(()) })
    }
    fn local_addr(&self) -> Option<TargetAddr> {
        self.socket.local_addr().ok().map(TargetAddr::socket)
    }
    fn set_deadline(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        self.state.set_deadline(deadline);
        Ok(())
    }
    fn set_read_deadline(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        self.state.set_read_deadline(deadline);
        Ok(())
    }
    fn set_write_deadline(
        &self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), sb_types::CoreError> {
        self.state.set_write_deadline(deadline);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_connector_creation() {
        let config = TrojanConfig {
            server: "127.0.0.1:443".to_string(),
            tag: Some("test".to_string()),
            password: "test-password".to_string(),
            connect_timeout_sec: Some(30),
            sni: Some("example.com".to_string()),
            alpn: None,
            skip_cert_verify: false,
            detour: None,
            transport_layer: TransportConfig::default(),
            #[cfg(feature = "tls_reality")]
            reality: None,
            multiplex: None,
        };

        let connector = TrojanConnector::new(config);
        assert_eq!(connector.name(), "trojan");
    }

    #[test]
    fn parse_server_endpoint_accepts_domain() {
        let (host, port) = parse_server_endpoint("trojan.example.com:443").unwrap();
        assert_eq!(host, "trojan.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_server_endpoint_accepts_ipv4() {
        let (host, port) = parse_server_endpoint("127.0.0.1:443").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_server_endpoint_accepts_bracketed_ipv6() {
        let (host, port) = parse_server_endpoint("[::1]:443").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);

        let (host2, port2) = parse_server_endpoint("[2001:db8::1]:8443").unwrap();
        assert_eq!(host2, "2001:db8::1");
        assert_eq!(port2, 8443);
    }

    #[test]
    fn parse_server_endpoint_rejects_missing_port() {
        let err = parse_server_endpoint("trojan.example.com").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("Invalid server address")));
        assert!(format!("{err}").to_lowercase().contains("missing"));
    }

    #[test]
    fn parse_server_endpoint_rejects_empty_port() {
        let err = parse_server_endpoint("trojan.example.com:").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("Invalid server address")));
    }

    #[test]
    fn parse_server_endpoint_rejects_non_numeric_port() {
        let err = parse_server_endpoint("trojan.example.com:abc").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("Invalid server address")));
        assert!(format!("{err}").contains("invalid port"));
    }

    #[test]
    fn parse_server_endpoint_rejects_port_zero() {
        let err = parse_server_endpoint("trojan.example.com:0").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("Invalid server address")));
    }

    #[test]
    fn parse_server_endpoint_rejects_empty_host() {
        let err = parse_server_endpoint(":443").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("empty host")));
    }

    #[test]
    fn parse_server_endpoint_rejects_empty_endpoint() {
        let err = parse_server_endpoint("").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("empty")));
    }

    #[test]
    fn parse_server_endpoint_rejects_bare_ipv6() {
        // Bare (unbracketed) IPv6 has multiple ':' and is ambiguous.
        let err = parse_server_endpoint("::1:443").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("must be bracketed")));
    }

    #[test]
    fn parse_server_endpoint_rejects_unclosed_bracket() {
        let err = parse_server_endpoint("[::1:443").unwrap_err();
        assert!(matches!(err, AdapterError::Other(ref m) if m.contains("missing ']'")));
    }

    #[test]
    fn parse_server_endpoint_handles_register_built_string() {
        // Mirrors `register.rs:1007` which builds `cfg.server` via
        // `format!("{}:{}", server, port)` from a hostname server.
        let (host, port) =
            parse_server_endpoint(&format!("{}:{}", "trojan.example.invalid", 10113)).unwrap();
        assert_eq!(host, "trojan.example.invalid");
        assert_eq!(port, 10113);
    }

    /// Pure-Rust mirror of the SNI fallback inside
    /// `perform_standard_tls_handshake`. Kept in sync via the
    /// `sni_fallback_handles_*` tests below.
    fn sni_for_test(config_sni: Option<&str>, server: &str) -> String {
        if let Some(sni) = config_sni {
            return sni.to_string();
        }
        match parse_server_endpoint(server) {
            Ok((host, _port)) => host,
            Err(_) => "localhost".to_string(),
        }
    }

    #[test]
    fn sni_fallback_uses_explicit_sni_when_present() {
        assert_eq!(
            sni_for_test(Some("explicit.sni.example"), "ignored.example.invalid:443"),
            "explicit.sni.example"
        );
    }

    #[test]
    fn sni_fallback_handles_domain_without_sni() {
        assert_eq!(
            sni_for_test(None, "trojan.example.invalid:443"),
            "trojan.example.invalid"
        );
    }

    #[test]
    fn sni_fallback_handles_ipv4_without_sni() {
        assert_eq!(sni_for_test(None, "127.0.0.1:443"), "127.0.0.1");
    }

    #[test]
    fn sni_fallback_handles_bracketed_ipv6_without_sni() {
        // Pre-FRESH-13 the fallback used `split(':').next()` which
        // returned `[`. The new behaviour returns the unbracketed host.
        assert_eq!(sni_for_test(None, "[2001:db8::1]:443"), "2001:db8::1");
    }

    #[test]
    fn sni_fallback_localhost_when_endpoint_invalid() {
        assert_eq!(sni_for_test(None, "no-port-here"), "localhost");
    }

    // ---- CAL-28: Trojan UDP packet encode/decode (pure local, no network) ----
    // encode_packet/decode_packet never touch the socket, so a loopback-bound
    // UdpSocket is enough to exercise every ATYP branch and error path offline.

    async fn loopback_udp_socket() -> TrojanUdpSocket {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        TrojanUdpSocket::new(
            std::sync::Arc::new(udp),
            TargetAddr::domain("fixture", 1),
            std::time::Duration::from_secs(300),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn trojan_udp_roundtrip_ipv4() {
        let sock = loopback_udp_socket().await;
        let target = TargetAddr::from_host_port("1.2.3.4", 4433);
        let packet = sock.encode_packet(b"ping", &target).unwrap();
        assert_eq!(packet[0], 0x03, "CMD must be UDP (0x03)");
        assert_eq!(packet[1], 0x01, "ATYP must be IPv4 (0x01)");
        assert_eq!(&packet[2..6], &[1u8, 2, 3, 4][..], "IPv4 octets");
        assert_eq!(&packet[6..8], &4433u16.to_be_bytes()[..], "port big-endian");
        assert_eq!(&packet[8..], &b"ping"[..], "payload trails the header");
        assert_eq!(sock.decode_packet(&packet).unwrap(), b"ping".to_vec());
    }

    #[tokio::test]
    async fn trojan_udp_roundtrip_ipv6() {
        let sock = loopback_udp_socket().await;
        let target = TargetAddr::from_host_port("2001:db8::1", 443);
        let packet = sock.encode_packet(b"x", &target).unwrap();
        assert_eq!(packet[0], 0x03);
        assert_eq!(packet[1], 0x04, "ATYP must be IPv6 (0x04)");
        assert_eq!(sock.decode_packet(&packet).unwrap(), b"x".to_vec());
    }

    #[tokio::test]
    async fn trojan_udp_roundtrip_domain() {
        let sock = loopback_udp_socket().await;
        let target = TargetAddr::domain("example.com", 8080);
        let packet = sock.encode_packet(b"payload", &target).unwrap();
        assert_eq!(packet[0], 0x03);
        assert_eq!(packet[1], 0x03, "ATYP must be Domain (0x03)");
        assert_eq!(
            packet[2] as usize,
            "example.com".len(),
            "domain length prefix"
        );
        assert_eq!(sock.decode_packet(&packet).unwrap(), b"payload".to_vec());
    }

    #[tokio::test]
    async fn trojan_udp_encode_rejects_overlong_domain() {
        let sock = loopback_udp_socket().await;
        let long_host = "a".repeat(256);
        let target = TargetAddr::domain(long_host, 443);
        assert!(
            sock.encode_packet(b"d", &target).is_err(),
            "domain longer than 255 bytes must be rejected"
        );
    }

    #[tokio::test]
    async fn trojan_udp_decode_rejects_malformed() {
        let sock = loopback_udp_socket().await;
        assert!(sock.decode_packet(b"").is_err(), "empty packet");
        assert!(sock.decode_packet(&[0x01u8, 0x01]).is_err(), "non-UDP CMD");
        assert!(sock.decode_packet(&[0x03u8, 0x09]).is_err(), "invalid ATYP");
        assert!(
            sock.decode_packet(&[0x03u8, 0x01, 1, 2]).is_err(),
            "truncated IPv4 addr/port"
        );
        assert!(
            sock.decode_packet(&[0x03u8, 0x03]).is_err(),
            "missing domain length byte"
        );
    }
}
