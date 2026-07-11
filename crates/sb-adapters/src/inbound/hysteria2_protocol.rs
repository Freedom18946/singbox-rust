//! Hysteria2 server protocol relocated from sb-core.

#[cfg(feature = "adapter-hysteria2")]
pub(super) mod inbound {
    //! Hysteria2 inbound (server) implementation
    //!
    //! Provides Hysteria2 protocol server support for accepting connections
    //! with password authentication, Salamander obfuscation, and UDP relay.

    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
    use sha2::{Digest, Sha256};
    use std::io;
    // keep single Arc import (already present above)
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::sync::Mutex;
    use tracing::{debug, info, warn};

    /// Hysteria2 server configuration
    #[derive(Clone, Debug)]
    pub struct Hysteria2ServerConfig {
        pub listen: SocketAddr,
        pub users: Vec<Hysteria2User>,
        pub cert: String,
        pub key: String,
        pub congestion_control: Option<String>,
        pub salamander: Option<String>,
        pub obfs: Option<String>,
        pub masquerade: Option<MasqueradeConfig>,
    }

    /// Hysteria2 Masquerade configuration
    #[derive(Clone, Debug)]
    pub enum MasqueradeConfig {
        String {
            content: String,
            headers: Vec<(String, String)>,
            status_code: u16,
        },
        File {
            directory: String,
        },
        Proxy {
            url: String,
            rewrite_host: bool,
        },
    }

    /// Hysteria2 user with password
    #[derive(Clone, Debug)]
    pub struct Hysteria2User {
        pub password: String,
    }

    /// Hysteria2 inbound server
    pub struct Hysteria2Inbound {
        config: Hysteria2ServerConfig,
        endpoint: Arc<Mutex<Option<Endpoint>>>,
    }

    /// Accepted Hysteria2 UDP association.
    pub struct Hysteria2UdpSession {
        connection: Connection,
        session_id: [u8; 8],
    }

    impl Hysteria2Inbound {
        pub fn new(config: Hysteria2ServerConfig) -> Self {
            Self {
                config,
                endpoint: Arc::new(Mutex::new(None)),
            }
        }

        /// Start the Hysteria2 server
        pub async fn start(&self) -> io::Result<()> {
            info!("Hysteria2 server starting on {}", self.config.listen);

            // Load TLS certificate and key
            let certs = load_certs(&self.config.cert)?;
            let key = load_private_key(&self.config.key)?;

            // Configure QUIC server with the protocol ALPN expected by clients.
            sb_tls::ensure_crypto_provider();
            let mut tls_config = quinn::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| io::Error::other(format!("TLS configuration error: {e}")))?;
            tls_config.alpn_protocols = vec![b"hysteria2".to_vec()];
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
                .map_err(|e| io::Error::other(format!("QUIC TLS configuration error: {e}")))?;
            let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));

            // Configure transport parameters
            let mut transport_config = quinn::TransportConfig::default();

            // Set congestion control algorithm
            if let Some(ref cc) = self.config.congestion_control {
                match cc.as_str() {
                    "cubic" => {
                        transport_config.congestion_controller_factory(Arc::new(
                            quinn::congestion::CubicConfig::default(),
                        ));
                    }
                    "bbr" => {
                        transport_config.congestion_controller_factory(Arc::new(
                            quinn::congestion::BbrConfig::default(),
                        ));
                    }
                    "new_reno" => {
                        transport_config.congestion_controller_factory(Arc::new(
                            quinn::congestion::NewRenoConfig::default(),
                        ));
                    }
                    _ => {
                        warn!(
                            "Unknown congestion control algorithm: {}, using default",
                            cc
                        );
                    }
                }
            }

            server_config.transport_config(Arc::new(transport_config));

            // Create QUIC endpoint
            let endpoint = Endpoint::server(server_config, self.config.listen)?;
            info!("Hysteria2 server listening on {}", self.config.listen);

            // Store endpoint
            let mut ep = self.endpoint.lock().await;
            *ep = Some(endpoint);

            Ok(())
        }

        /// Accept a new connection
        pub async fn accept(&self) -> io::Result<(Hysteria2Stream, SocketAddr)> {
            let endpoint = {
                let ep = self.endpoint.lock().await;
                ep.as_ref()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "Server not started")
                    })?
                    .clone()
            };

            // Accept incoming connection
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "No connection"))?;

            let connection = incoming
                .await
                .map_err(|e| io::Error::other(format!("Connection failed: {}", e)))?;

            let peer = connection.remote_address();
            debug!("Hysteria2: new connection from {}", peer);

            // Perform authentication
            self.authenticate(&connection).await?;

            // Accept bidirectional stream for the actual proxy connection
            let (send_stream, recv_stream) = connection
                .accept_bi()
                .await
                .map_err(|e| io::Error::other(format!("Failed to accept stream: {}", e)))?;

            let stream = Hysteria2Stream {
                send: send_stream,
                recv: recv_stream,
                connection,
            };

            Ok((stream, peer))
        }

        /// Accept and authenticate a UDP association.
        pub async fn accept_udp(&self) -> io::Result<Hysteria2UdpSession> {
            let endpoint = {
                let ep = self.endpoint.lock().await;
                ep.as_ref()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "Server not started")
                    })?
                    .clone()
            };

            // Accept incoming connection for UDP
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "No connection"))?;

            let connection = incoming
                .await
                .map_err(|e| io::Error::other(format!("Connection failed: {}", e)))?;

            // Perform authentication
            self.authenticate(&connection).await?;

            // Read and validate the association initialization datagram.
            let datagram = connection
                .read_datagram()
                .await
                .map_err(|e| io::Error::other(format!("UDP recv failed: {}", e)))?;
            let mut data = datagram.to_vec();
            self.apply_deobfuscation(&mut data);
            if data.len() != 9 || data[0] != 0x03 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Hysteria2 UDP association initialization",
                ));
            }

            let mut session_id = [0u8; 8];
            session_id.copy_from_slice(&data[1..9]);
            Ok(Hysteria2UdpSession {
                connection,
                session_id,
            })
        }

        /// Authenticate a connection
        async fn authenticate(&self, connection: &Connection) -> io::Result<()> {
            // Accept authentication stream
            let (mut send_stream, mut recv_stream) = connection
                .accept_bi()
                .await
                .map_err(|e| io::Error::other(format!("Failed to accept auth stream: {}", e)))?;

            // Read authentication packet
            let mut auth_packet = vec![0u8; 1024];
            let bytes_read = recv_stream
                .read(&mut auth_packet)
                .await
                .map_err(|e| io::Error::other(format!("Auth read failed: {}", e)))?
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "Auth stream closed")
                })?;

            auth_packet.truncate(bytes_read);

            // Apply deobfuscation if configured
            self.apply_deobfuscation(&mut auth_packet);

            // Verify authentication
            if auth_packet.is_empty() || auth_packet[0] != 0x01 {
                // Try masquerade if configured
                if let Some(ref masq) = self.config.masquerade {
                    self.perform_masquerade(&mut send_stream, masq).await?;
                    // After masquerade, we close the connection or stream implicitly by returning error
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Masquerade triggered (invalid auth packet)",
                    ));
                }

                send_stream
                    .write_all(&[0x01])
                    .await
                    .map_err(|e| io::Error::other(format!("Auth response write failed: {}", e)))?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Invalid auth packet",
                ));
            }

            // Extract auth hash (32 bytes after command byte)
            if auth_packet.len() < 33 {
                send_stream
                    .write_all(&[0x01])
                    .await
                    .map_err(|e| io::Error::other(format!("Auth response write failed: {}", e)))?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Auth packet too short",
                ));
            }

            let client_hash = &auth_packet[1..33];

            // Verify against configured users
            let mut authenticated = false;
            for user in &self.config.users {
                let expected_hash = self.generate_auth_hash(&user.password);
                if client_hash == expected_hash {
                    authenticated = true;
                    break;
                }
            }

            if authenticated {
                // Send success response
                send_stream
                    .write_all(&[0x00])
                    .await
                    .map_err(|e| io::Error::other(format!("Auth response write failed: {}", e)))?;
                debug!("Hysteria2: authentication successful");
                Ok(())
            } else {
                // Try masquerade if configured
                if let Some(ref masq) = self.config.masquerade {
                    self.perform_masquerade(&mut send_stream, masq).await?;
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Authentication failed: invalid password (masquerade triggered)",
                    ));
                }

                // Send failure response
                send_stream
                    .write_all(&[0x01])
                    .await
                    .map_err(|e| io::Error::other(format!("Auth response write failed: {}", e)))?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Authentication failed: invalid password",
                ))
            }
        }

        /// Generate authentication hash
        fn generate_auth_hash(&self, password: &str) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            hasher.update(b"hysteria2-auth");

            // Add salamander obfuscation if configured
            if let Some(ref salamander) = self.config.salamander {
                hasher.update(salamander.as_bytes());
            }

            let mut result = [0u8; 32];
            result.copy_from_slice(&hasher.finalize()[..32]);
            result
        }

        /// Apply deobfuscation to data if configured
        fn apply_deobfuscation(&self, data: &mut [u8]) {
            if let Some(ref obfs_key) = self.config.obfs {
                // Simple XOR deobfuscation with key
                let key_bytes = obfs_key.as_bytes();
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte ^= key_bytes[i % key_bytes.len()];
                }
            }
        }

        async fn perform_masquerade(
            &self,
            send_stream: &mut SendStream,
            config: &MasqueradeConfig,
        ) -> io::Result<()> {
            match config {
                MasqueradeConfig::String {
                    content,
                    headers: _, // Headers ignored in simple string masquerade for now
                    status_code,
                } => {
                    // Simple HTTP response simulation
                    // Note: Real HTTP/3 requires standard framing (QPACK etc), doing raw text write
                    // might strictly be HTTP/0.9ish style or invalid for H3, but fulfills logic stub for now.
                    // Improving this to real HTTP/3 is future work.
                    let response = format!(
                        "HTTP/1.1 {} Masquerade\r\nContent-Length: {}\r\n\r\n{}",
                        status_code,
                        content.len(),
                        content
                    );
                    send_stream
                        .write_all(response.as_bytes())
                        .await
                        .map_err(|e| io::Error::other(format!("Masquerade write failed: {}", e)))?;

                    // Gracefully finish stream
                    let _ = send_stream.finish();
                    Ok(())
                }
                _ => {
                    // File and Proxy not yet implemented, fallback to 404 string
                    let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
                    send_stream.write_all(response.as_bytes()).await.ok();
                    let _ = send_stream.finish();
                    Ok(())
                }
            }
        }
    }

    impl Hysteria2UdpSession {
        /// Receive one client datagram and its requested destination.
        pub async fn recv_from(&self) -> io::Result<(Vec<u8>, sb_types::TargetAddr)> {
            let datagram = self
                .connection
                .read_datagram()
                .await
                .map_err(|error| io::Error::other(format!("UDP recv failed: {error}")))?;
            let data = datagram.as_ref();
            if data.len() < 9 || data[..8] != self.session_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Hysteria2 UDP session id",
                ));
            }
            let (destination, payload_offset) = decode_target(data, 8)?;
            Ok((data[payload_offset..].to_vec(), destination))
        }

        /// Send one relay response and its source address to the client.
        pub fn send_to(&self, data: &[u8], source: &sb_types::TargetAddr) -> io::Result<()> {
            let mut packet = Vec::with_capacity(data.len() + 32);
            packet.extend_from_slice(&self.session_id);
            encode_target(&mut packet, source)?;
            packet.extend_from_slice(data);
            self.connection
                .send_datagram(packet.into())
                .map_err(|error| io::Error::other(format!("UDP send failed: {error}")))
        }
    }

    fn encode_target(packet: &mut Vec<u8>, target: &sb_types::TargetAddr) -> io::Result<()> {
        match target {
            sb_types::TargetAddr::Socket(address) => match address.ip() {
                std::net::IpAddr::V4(ip) => {
                    packet.push(0x01);
                    packet.extend_from_slice(&ip.octets());
                }
                std::net::IpAddr::V6(ip) => {
                    packet.push(0x04);
                    packet.extend_from_slice(&ip.octets());
                }
            },
            sb_types::TargetAddr::Domain(host, _) => {
                let length = u8::try_from(host.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "domain name too long")
                })?;
                packet.push(0x03);
                packet.push(length);
                packet.extend_from_slice(host.as_bytes());
            }
        }
        packet.extend_from_slice(&target.port().to_be_bytes());
        Ok(())
    }

    fn decode_target(
        packet: &[u8],
        mut offset: usize,
    ) -> io::Result<(sb_types::TargetAddr, usize)> {
        let atyp = *packet
            .get(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing address type"))?;
        offset += 1;
        match atyp {
            0x01 => {
                let address = packet.get(offset..offset + 4).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "short IPv4 address")
                })?;
                offset += 4;
                let port = read_port(packet, &mut offset)?;
                Ok((
                    sb_types::TargetAddr::Socket(SocketAddr::from((
                        std::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]),
                        port,
                    ))),
                    offset,
                ))
            }
            0x04 => {
                let address = packet.get(offset..offset + 16).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "short IPv6 address")
                })?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(address);
                offset += 16;
                let port = read_port(packet, &mut offset)?;
                Ok((
                    sb_types::TargetAddr::Socket(SocketAddr::from((
                        std::net::Ipv6Addr::from(octets),
                        port,
                    ))),
                    offset,
                ))
            }
            0x03 => {
                let length = *packet.get(offset).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing domain length")
                })? as usize;
                offset += 1;
                let host = packet.get(offset..offset + length).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "short domain address")
                })?;
                offset += length;
                let host = std::str::from_utf8(host)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain"))?;
                let port = read_port(packet, &mut offset)?;
                Ok((sb_types::TargetAddr::domain(host, port), offset))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported address type",
            )),
        }
    }

    fn read_port(packet: &[u8], offset: &mut usize) -> io::Result<u16> {
        let bytes = packet.get(*offset..*offset + 2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "missing destination port")
        })?;
        *offset += 2;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Hysteria2 stream wrapper
    pub struct Hysteria2Stream {
        send: SendStream,
        recv: RecvStream,
        #[allow(dead_code)]
        connection: Connection,
    }

    impl AsyncRead for Hysteria2Stream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Hysteria2Stream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            use std::task::Poll;
            match std::pin::Pin::new(&mut self.send).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.send).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
        }
    }

    /// Parse PEM-encoded certificates
    fn load_certs(pem: &str) -> io::Result<Vec<CertificateDer<'static>>> {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::other(format!("Failed to parse certificates: {}", e)))?;
        Ok(certs)
    }

    /// Parse PEM-encoded private key
    fn load_private_key(pem: &str) -> io::Result<PrivateKeyDer<'static>> {
        let mut cursor = std::io::Cursor::new(pem.as_bytes());
        loop {
            match rustls_pemfile::read_one(&mut cursor)
                .map_err(|e| io::Error::other(format!("Failed to parse private key: {}", e)))?
            {
                Some(rustls_pemfile::Item::Pkcs8Key(k)) => {
                    return Ok(PrivateKeyDer::Pkcs8(k));
                }
                Some(rustls_pemfile::Item::Pkcs1Key(k)) => {
                    return Ok(PrivateKeyDer::Pkcs1(k));
                }
                Some(rustls_pemfile::Item::Sec1Key(k)) => {
                    return Ok(PrivateKeyDer::Sec1(k));
                }
                Some(_other) => continue,
                None => break,
            }
        }
        Err(io::Error::other("No private key found in PEM data"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_auth_hash_generation() {
            let config = Hysteria2ServerConfig {
                listen: "0.0.0.0:443".parse().unwrap(),
                users: vec![Hysteria2User {
                    password: "test_password".to_string(),
                }],
                cert: String::new(),
                key: String::new(),
                congestion_control: None,
                salamander: None,
                obfs: None,
                masquerade: None,
            };

            let inbound = Hysteria2Inbound::new(config);
            let hash = inbound.generate_auth_hash("test_password");

            // Hash should be deterministic
            let hash2 = inbound.generate_auth_hash("test_password");
            assert_eq!(hash, hash2);

            // Different passwords should produce different hashes
            let hash3 = inbound.generate_auth_hash("different_password");
            assert_ne!(hash, hash3);
        }

        #[test]
        fn test_obfuscation() {
            let config = Hysteria2ServerConfig {
                listen: "0.0.0.0:443".parse().unwrap(),
                users: vec![],
                cert: String::new(),
                key: String::new(),
                congestion_control: None,
                salamander: None,
                obfs: Some("test_key".to_string()),
                masquerade: None,
            };

            let inbound = Hysteria2Inbound::new(config);

            let mut data = vec![0x01, 0x02, 0x03, 0x04];
            let original = data.clone();

            // Apply deobfuscation
            inbound.apply_deobfuscation(&mut data);

            // Data should be modified
            assert_ne!(data, original);

            // Applying again should restore original (XOR property)
            inbound.apply_deobfuscation(&mut data);
            assert_eq!(data, original);
        }
    }
}
