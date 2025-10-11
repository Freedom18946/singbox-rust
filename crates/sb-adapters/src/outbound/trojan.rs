//! Trojan outbound connector implementation
//!
//! This module provides Trojan protocol support for outbound connections.
//! Trojan is a proxy protocol that disguises traffic as TLS traffic.
//! Supports both TCP and UDP relay.

use crate::outbound::prelude::*;
use crate::traits::OutboundDatagram;
use std::sync::Arc;

#[cfg(feature = "adapter-trojan")]
mod tls_helper {
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    /// No-op certificate verifier for testing (INSECURE - skips all verification)
    #[derive(Debug)]
    pub struct NoVerifier;

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
    /// Skip certificate verification
    #[serde(default)]
    pub skip_cert_verify: bool,
    /// Optional REALITY TLS configuration for outbound
    #[cfg(feature = "tls_reality")]
    #[serde(default)]
    pub reality: Option<sb_tls::RealityClientConfig>,
    /// Multiplex configuration
    #[serde(default)]
    pub multiplex: Option<sb_transport::multiplex::MultiplexConfig>,
}

/// Trojan outbound connector
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct TrojanConnector {
    _config: Option<TrojanConfig>,
    multiplex_dialer: Option<std::sync::Arc<sb_transport::multiplex::MultiplexDialer>>,
}

impl TrojanConnector {
    pub fn new(config: TrojanConfig) -> Self {
        // Create multiplex dialer if configured
        let multiplex_dialer = if let Some(mux_config) = config.multiplex.clone() {
            let tcp_dialer = Box::new(sb_transport::TcpDialer) as Box<dyn sb_transport::Dialer>;
            Some(std::sync::Arc::new(sb_transport::multiplex::MultiplexDialer::new(mux_config, tcp_dialer)))
        } else {
            None
        };

        Self {
            _config: Some(config),
            multiplex_dialer,
        }
    }

    #[cfg(feature = "adapter-trojan")]
    async fn perform_standard_tls_handshake(
        &self,
        tcp_stream: tokio::net::TcpStream,
        config: &TrojanConfig,
    ) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        use tokio_rustls::{TlsConnector, rustls::ClientConfig};
        use std::sync::Arc;

        // Create TLS config
        let tls_config = if config.skip_cert_verify {
            // Disable certificate verification (insecure, for testing only)
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            // Use webpki-roots for certificate verification
            let root_store = tokio_rustls::rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
            };
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));
        
        // Determine server name for SNI
        let server_name = if let Some(ref sni) = config.sni {
            sni.clone()
        } else {
            // Extract hostname from server address
            config.server.split(':').next().unwrap_or("localhost").to_string()
        };

        let domain = rustls_pki_types::ServerName::try_from(server_name.as_str())
            .map_err(|e| AdapterError::Other(format!("Invalid server name: {}", e)))?
            .to_owned();

        let tls_stream = connector.connect(domain, tcp_stream)
            .await
            .map_err(|e| AdapterError::Other(format!("TLS handshake failed: {}", e)))?;

        Ok(tls_stream)
    }

    /// Create UDP relay connection (returns OutboundDatagram)
    #[cfg(feature = "adapter-trojan")]
    pub async fn udp_relay_dial(&self, target: Target) -> Result<Box<dyn OutboundDatagram>> {
        use sha2::{Sha224, Digest};
        use tokio::io::AsyncWriteExt;
        use tokio::net::UdpSocket;

        let config = self._config.as_ref().ok_or_else(|| {
            AdapterError::Other("Trojan config not set".to_string())
        })?;

        tracing::debug!(
            server = %config.server,
            target = %format!("{}:{}", target.host, target.port),
            "Creating Trojan UDP relay"
        );

        // Parse server address
        let server_addr: std::net::SocketAddr = config.server
            .parse()
            .map_err(|e| AdapterError::Other(format!("Invalid server address: {}", e)))?;

        // Step 1: Establish TCP connection for UDP ASSOCIATE command
        let tcp_stream = tokio::net::TcpStream::connect(&config.server)
            .await
            .map_err(AdapterError::Io)?;

        // Step 2: Perform TLS handshake
        let mut tls_stream = self.perform_standard_tls_handshake(tcp_stream, config).await?;

        // Step 3: Send UDP ASSOCIATE command (CMD=0x03)
        let mut request = Vec::new();

        // Password hash (SHA224)
        let mut hasher = Sha224::new();
        hasher.update(config.password.as_bytes());
        let password_hash = hasher.finalize();
        request.extend_from_slice(&hex::encode(password_hash).as_bytes());
        request.extend_from_slice(b"\r\n");

        // Command: UDP ASSOCIATE (0x03)
        request.push(0x03);

        // Address: server itself for UDP associate
        request.push(0x01); // IPv4
        request.extend_from_slice(&server_addr.ip().to_string().parse::<std::net::Ipv4Addr>()
            .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1)).octets());
        request.extend_from_slice(&server_addr.port().to_be_bytes());
        request.extend_from_slice(b"\r\n");

        // Send UDP ASSOCIATE request
        tls_stream.write_all(&request).await.map_err(AdapterError::Io)?;
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
            config.password.clone(),
        )?;

        Ok(Box::new(trojan_udp))
    }
}


#[async_trait]
impl OutboundConnector for TrojanConnector {
    fn name(&self) -> &'static str {
        "trojan"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-trojan"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-trojan",
        });

        #[cfg(feature = "adapter-trojan")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-trojan"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-trojan",
        });

        #[cfg(feature = "adapter-trojan")]
        {
            use sha2::{Sha224, Digest};
            use tokio::io::AsyncWriteExt;
            
            let config = self._config.as_ref().ok_or_else(|| {
                AdapterError::Other("Trojan config not set".to_string())
            })?;

            let _span = crate::outbound::span_dial("trojan", &target);

            // Note: Multiplex support for Trojan outbound is configured but not yet fully implemented
            // Trojan protocol flow is: TCP -> TLS -> Trojan Protocol
            // Multiplex would need to be: TCP -> TLS -> Multiplex -> Trojan Protocol
            // This requires architectural changes to wrap TLS streams with multiplex
            if config.multiplex.is_some() {
                tracing::warn!("Multiplex configuration present but not yet fully implemented for Trojan outbound");
            }

            // Parse server address
            let server_addr = config.server.clone();
            
            // Step 1: Establish TCP connection to Trojan server
            let tcp_stream = tokio::net::TcpStream::connect(&server_addr)
                .await
                .map_err(AdapterError::Io)?;

            // Step 2: Perform TLS handshake
            #[cfg(feature = "tls_reality")]
            let mut stream: BoxedStream = if let Some(ref reality_cfg) = config.reality {
                // Use REALITY TLS
                use sb_tls::TlsConnector;
                let reality_connector = sb_tls::reality::RealityConnector::new(reality_cfg.clone())
                    .map_err(|e| AdapterError::Other(format!("Failed to create REALITY connector: {}", e)))?;
                
                let server_name = reality_cfg.server_name.clone();
                let tls_stream = reality_connector.connect(tcp_stream, &server_name)
                    .await
                    .map_err(|e| AdapterError::Other(format!("REALITY handshake failed: {}", e)))?;
                
                Box::new(tls_stream)
            } else {
                // Use standard TLS
                let tls_stream = self.perform_standard_tls_handshake(tcp_stream, config).await?;
                Box::new(tls_stream)
            };
            
            #[cfg(not(feature = "tls_reality"))]
            let mut stream: BoxedStream = {
                // Use standard TLS
                let tls_stream = self.perform_standard_tls_handshake(tcp_stream, config).await?;
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
            request.extend_from_slice(&hex::encode(password_hash).as_bytes());
            request.extend_from_slice(b"\r\n");
            
            // Command: CONNECT (0x01)
            request.push(0x01);
            
            // Address type and address
            if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
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
                request.push(target.host.len() as u8);
                request.extend_from_slice(target.host.as_bytes());
            }
            
            // Port (big-endian)
            request.extend_from_slice(&target.port.to_be_bytes());
            request.extend_from_slice(b"\r\n");
            
            // Send Trojan request
            stream.write_all(&request).await.map_err(AdapterError::Io)?;
            stream.flush().await.map_err(AdapterError::Io)?;
            
            // Trojan doesn't send a response for CONNECT, connection is ready
            Ok(Box::new(stream) as BoxedStream)
        }
    }
}

/// Trojan UDP socket wrapper that implements OutboundDatagram
#[cfg(feature = "adapter-trojan")]
#[derive(Debug)]
pub struct TrojanUdpSocket {
    socket: Arc<tokio::net::UdpSocket>,
    password: String,
    target_addr: tokio::sync::Mutex<Option<Target>>,
}

#[cfg(feature = "adapter-trojan")]
impl TrojanUdpSocket {
    pub fn new(socket: Arc<tokio::net::UdpSocket>, password: String) -> Result<Self> {
        Ok(Self {
            socket,
            password,
            target_addr: tokio::sync::Mutex::new(None),
        })
    }

    /// Set target address for subsequent operations
    pub async fn set_target(&self, target: Target) {
        let mut addr = self.target_addr.lock().await;
        *addr = Some(target);
    }

    /// Encode Trojan UDP packet
    /// Format: CMD(0x03) + ATYP + DST.ADDR + PORT + PAYLOAD
    fn encode_packet(&self, data: &[u8], target: &Target) -> Result<Vec<u8>> {
        let mut packet = Vec::new();

        // CMD: UDP (0x03)
        packet.push(0x03);

        // Address type and address
        if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
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
            let hostname_bytes = target.host.as_bytes();
            if hostname_bytes.len() > 255 {
                return Err(AdapterError::InvalidConfig("Hostname too long"));
            }
            packet.push(hostname_bytes.len() as u8);
            packet.extend_from_slice(hostname_bytes);
        }

        // Port
        packet.extend_from_slice(&target.port.to_be_bytes());

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
            return Err(AdapterError::Protocol(format!("Invalid CMD: {}", packet[0])));
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
#[async_trait]
impl OutboundDatagram for TrojanUdpSocket {
    async fn send_to(&self, payload: &[u8]) -> Result<usize> {
        // Get target address
        let target = {
            let addr_lock = self.target_addr.lock().await;
            addr_lock
                .as_ref()
                .ok_or_else(|| AdapterError::Other("Target address not set".to_string()))?
                .clone()
        };

        // Encode packet
        let packet = self.encode_packet(payload, &target)?;

        // Send to Trojan server
        let sent = self
            .socket
            .send(&packet)
            .await
            .map_err(AdapterError::Io)?;

        tracing::trace!(
            target = %format!("{}:{}", target.host, target.port),
            sent = sent,
            "Trojan UDP packet sent"
        );

        Ok(payload.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<usize> {
        // Receive from Trojan server
        let (n, _peer) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(AdapterError::Io)?;

        // Decode packet
        let payload = self.decode_packet(&buf[..n])?;

        // Copy payload back to buffer
        if payload.len() > buf.len() {
            return Err(AdapterError::Other("Buffer too small".to_string()));
        }

        buf[..payload.len()].copy_from_slice(&payload);

        tracing::trace!(
            received = n,
            payload_len = payload.len(),
            "Trojan UDP packet received"
        );

        Ok(payload.len())
    }

    async fn close(&self) -> Result<()> {
        tracing::debug!("Trojan UDP socket closed");
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
            skip_cert_verify: false,
            #[cfg(feature = "tls_reality")]
            reality: None,
            multiplex: None,
        };

        let connector = TrojanConnector::new(config);
        assert_eq!(connector.name(), "trojan");
    }
}
