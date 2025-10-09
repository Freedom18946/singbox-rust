//! Trojan outbound connector implementation
//!
//! This module provides Trojan protocol support for outbound connections.
//! Trojan is a proxy protocol that disguises traffic as TLS traffic.

use crate::outbound::prelude::*;

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
}

/// Trojan outbound connector
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct TrojanConnector {
    _config: Option<TrojanConfig>,
}

impl TrojanConnector {
    pub fn new(config: TrojanConfig) -> Self {
        Self {
            _config: Some(config),
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
        };

        let connector = TrojanConnector::new(config);
        assert_eq!(connector.name(), "trojan");
    }
}
