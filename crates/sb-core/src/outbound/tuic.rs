//! TUIC outbound implementation
//!
//! Provides TUIC (TCP over QUIC) protocol support for secure TCP tunneling
//! over QUIC connections with UUID-based authentication.

#[cfg(feature = "out_tuic")]
use async_trait::async_trait;
#[cfg(feature = "out_tuic")]
use std::io;
#[cfg(feature = "out_tuic")]
use std::net::SocketAddr;
#[cfg(feature = "out_tuic")]
use std::sync::Arc;

#[cfg(feature = "out_tuic")]
use super::quic::common::QuicConfig;
#[cfg(feature = "out_tuic")]
use super::types::{HostPort, OutboundTcp};
#[cfg(feature = "out_tuic")]
use crate::adapter::{UdpOutboundFactory, UdpOutboundSession};

#[cfg(feature = "out_tuic")]
#[derive(Clone, Debug)]
pub struct TuicConfig {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub token: String,
    pub password: Option<String>,
    pub congestion_control: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
    pub tls_ca_paths: Vec<String>,
    pub tls_ca_pem: Vec<String>,
    pub udp_relay_mode: UdpRelayMode,
    pub udp_over_stream: bool,
    /// Attempt QUIC 0-RTT handshake if supported by transport
    pub zero_rtt_handshake: bool,
}

#[cfg(feature = "out_tuic")]
#[derive(Clone, Debug, Default)]
pub enum UdpRelayMode {
    #[default]
    Native,
    Quic,
}

#[cfg(feature = "out_tuic")]
#[derive(Clone, Debug)]
pub struct TuicOutbound {
    config: TuicConfig,
    quic_config: QuicConfig,
    connection_pool: Arc<tokio::sync::Mutex<Option<quinn::Connection>>>,
}

#[cfg(feature = "out_tuic")]
impl TuicOutbound {
    pub fn new(config: TuicConfig) -> anyhow::Result<Self> {
        // Build QUIC configuration for TUIC
        let alpn = if let Some(ref alpn_list) = config.alpn {
            alpn_list
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect::<Vec<_>>()
        } else {
            vec![b"tuic".to_vec()]
        };

        let quic_config = QuicConfig::new(config.server.clone(), config.port)
            .with_alpn(alpn)
            .with_allow_insecure(config.skip_cert_verify)
            .with_sni(config.sni.clone())
            .with_extra_ca_paths(config.tls_ca_paths.clone())
            .with_extra_ca_pem(config.tls_ca_pem.clone())
            .with_enable_0rtt(config.zero_rtt_handshake);

        Ok(Self {
            config,
            quic_config,
            connection_pool: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    /// Perform TUIC protocol handshake and authentication
    async fn tuic_handshake(
        &self,
        stream: &mut super::quic::io::QuicBidiStream,
        target_host: &str,
        target_port: u16,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // TUIC v5 protocol handshake
        // 1. Send authentication with UUID and token
        let auth_data = self.build_auth_packet()?;
        stream.write_all(&auth_data).await?;

        // 2. Send connect request for target
        let connect_data = self.build_connect_packet(target_host, target_port)?;
        stream.write_all(&connect_data).await?;

        // 3. Read response and verify success
        let mut response = [0u8; 16];
        stream.read_exact(&mut response).await?;

        if response[0] != 0x00 {
            return Err(anyhow::anyhow!(
                "TUIC authentication failed: {:02x}",
                response[0]
            ));
        }

        log::info!(
            "TUIC handshake completed successfully for {}:{}",
            target_host,
            target_port
        );
        Ok(())
    }

    /// Create a TCP proxy that relays data through TUIC stream
    async fn create_tcp_proxy(
        &self,
        tuic_stream: super::quic::io::QuicBidiStream,
    ) -> std::io::Result<tokio::net::TcpStream> {
        // Create a local TCP server and connect to it to simulate a pair
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Accept connection in background
        let server_task =
            tokio::spawn(async move { listener.accept().await.map(|(stream, _)| stream) });

        // Connect to the listener
        let client = tokio::net::TcpStream::connect(addr).await?;
        let server = server_task.await.map_err(std::io::Error::other)??;

        // Spawn a background task to relay data between TCP and TUIC streams
        tokio::spawn(async move {
            if let Err(e) = Self::relay_streams(server, tuic_stream).await {
                log::warn!("TUIC stream relay error: {}", e);
            }
        });

        Ok(client)
    }

    /// Get or create QUIC connection with simple backoff
    async fn get_connection(&self) -> io::Result<quinn::Connection> {
        if let Some(conn) = {
            let g = self.connection_pool.lock().await;
            g.as_ref().cloned()
        } {
            if conn.close_reason().is_none() {
                #[cfg(feature = "metrics")]
                metrics::counter!("tuic_pool_reuse_total").increment(1);
                return Ok(conn);
            }
        }

        let max_retries = std::env::var("SB_TUIC_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3)
            .min(8);
        let base_ms = std::env::var("SB_TUIC_BACKOFF_MS_BASE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200u64);
        let cap_ms = std::env::var("SB_TUIC_BACKOFF_MS_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2_000u64);

        let server_addr: SocketAddr = format!("{}:{}", self.config.server, self.config.port)
            .parse()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid server address: {}", e),
                )
            })?;
        let quinn_config = self.create_quinn_config()?;
        let server_name = if self.config.server.parse::<std::net::IpAddr>().is_ok() {
            if self.quic_config.allow_insecure {
                "localhost"
            } else {
                &self.config.server
            }
        } else {
            &self.config.server
        };

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match tuic_quic_connect(&quinn_config, server_addr, server_name).await {
                Ok(conn) => {
                    let mut g = self.connection_pool.lock().await;
                    *g = Some(conn.clone());
                    #[cfg(feature = "metrics")]
                    metrics::counter!("tuic_connect_retries_total", "result"=>"ok").increment(1);
                    return Ok(conn);
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("tuic_connect_retries_total", "result"=>"fail").increment(1);
                    if attempt >= max_retries {
                        return Err(io::Error::other(format!("QUIC connection failed: {}", e)));
                    }
                    let exp = attempt.saturating_sub(1).min(8);
                    let mut delay = base_ms.saturating_mul(1u64 << exp);
                    delay = delay.min(cap_ms);
                    let jitter = fastrand::u64(..(delay / 5 + 1));
                    tokio::time::sleep(std::time::Duration::from_millis(delay + jitter)).await;
                }
            }
        }
    }

    /// Relay data between TCP stream and TUIC stream
    async fn relay_streams(
        mut tcp_stream: tokio::net::TcpStream,
        mut tuic_stream: super::quic::io::QuicBidiStream,
    ) -> anyhow::Result<()> {
        use tokio::io::copy_bidirectional;

        // Use the streams directly for bidirectional copy
        match copy_bidirectional(&mut tcp_stream, &mut tuic_stream).await {
            Ok((sent, received)) => {
                log::debug!(
                    "TUIC relay completed: sent {} bytes, received {} bytes",
                    sent,
                    received
                );
                Ok(())
            }
            Err(e) => {
                log::warn!("TUIC relay error: {}", e);
                Err(anyhow::anyhow!("Stream relay failed: {}", e))
            }
        }
    }

    /// Build TUIC authentication packet
    fn build_auth_packet(&self) -> anyhow::Result<Vec<u8>> {
        let mut packet = Vec::new();

        // TUIC v5 auth packet format:
        // [Version(1)] [Command(1)] [UUID(16)] [Token_Len(2)] [Token(N)]
        packet.push(0x05); // Version 5
        packet.push(0x01); // Auth command

        // UUID
        packet.extend_from_slice(self.config.uuid.as_bytes());

        // Token
        let token_bytes = self.config.token.as_bytes();
        packet.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        packet.extend_from_slice(token_bytes);

        Ok(packet)
    }

    /// Build TUIC connect packet
    fn build_connect_packet(&self, host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
        self.build_command_packet(0x02, host, port)
    }

    /// Build TUIC UDP associate packet
    pub fn build_udp_associate_packet(&self, host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
        self.build_command_packet(0x03, host, port)
    }

    /// Build TUIC command packet (shared logic for connect and UDP associate)
    fn build_command_packet(&self, command: u8, host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
        let mut packet = Vec::new();

        // TUIC v5 command packet format:
        // [Command(1)] [Address_Type(1)] [Address(N)] [Port(2)]
        packet.push(command);

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
            packet.push(0x03);
            packet.push(host.len() as u8);
            packet.extend_from_slice(host.as_bytes());
        }

        // Port
        packet.extend_from_slice(&port.to_be_bytes());

        Ok(packet)
    }

    /// Encode UDP packet for TUIC UDP over stream mode
    /// Format: [Length(2)] [Fragment_ID(1)] [Fragment_Total(1)] [Address_Type(1)] [Address(N)] [Port(2)] [Data(N)]
    pub fn encode_udp_packet(
        &self,
        target_host: &str,
        target_port: u16,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Reserve space for length (will be filled at the end)
        packet.extend_from_slice(&[0u8; 2]);

        // Fragment ID and total (no fragmentation for now)
        packet.push(0); // Fragment ID
        packet.push(1); // Fragment total (1 = no fragmentation)

        // Address type and address
        if let Ok(ip) = target_host.parse::<std::net::IpAddr>() {
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
            packet.push(0x03);
            packet.push(target_host.len() as u8);
            packet.extend_from_slice(target_host.as_bytes());
        }

        // Port
        packet.extend_from_slice(&target_port.to_be_bytes());

        // Data
        packet.extend_from_slice(data);

        // Fill in length (total packet length excluding the length field itself)
        let length = (packet.len() - 2) as u16;
        packet[0..2].copy_from_slice(&length.to_be_bytes());

        Ok(packet)
    }

    /// Decode UDP packet from TUIC UDP over stream mode
    /// Returns (target_host, target_port, data)
    pub fn decode_udp_packet(data: &[u8]) -> anyhow::Result<(String, u16, Vec<u8>)> {
        if data.len() < 2 {
            return Err(anyhow::anyhow!("UDP packet too short"));
        }

        let mut offset = 0;

        // Read length
        let length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + length {
            return Err(anyhow::anyhow!("UDP packet length mismatch"));
        }

        // Skip fragment ID and total
        offset += 2;

        // Read address type
        let addr_type = data[offset];
        offset += 1;

        // Parse address
        let host = match addr_type {
            0x01 => {
                // IPv4
                if data.len() < offset + 4 {
                    return Err(anyhow::anyhow!("Invalid IPv4 address"));
                }
                let ipv4 = std::net::Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                );
                offset += 4;
                ipv4.to_string()
            }
            0x03 => {
                // Domain
                let len = data[offset] as usize;
                offset += 1;
                if data.len() < offset + len {
                    return Err(anyhow::anyhow!("Invalid domain length"));
                }
                let domain = String::from_utf8(data[offset..offset + len].to_vec())
                    .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in domain"))?;
                offset += len;
                domain
            }
            0x04 => {
                // IPv6
                if data.len() < offset + 16 {
                    return Err(anyhow::anyhow!("Invalid IPv6 address"));
                }
                let mut ipv6_bytes = [0u8; 16];
                ipv6_bytes.copy_from_slice(&data[offset..offset + 16]);
                let ipv6 = std::net::Ipv6Addr::from(ipv6_bytes);
                offset += 16;
                ipv6.to_string()
            }
            _ => return Err(anyhow::anyhow!("Unknown address type: {}", addr_type)),
        };

        // Read port
        if data.len() < offset + 2 {
            return Err(anyhow::anyhow!("Missing port"));
        }
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Remaining data is the UDP payload
        let payload = data[offset..].to_vec();

        Ok((host, port, payload))
    }

    fn create_quinn_config(&self) -> io::Result<quinn::ClientConfig> {
        use rustls::{ClientConfig as RustlsConfig, RootCertStore};
        use std::sync::Arc;

        // Root store with system roots (webpki-roots)
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Build rustls client config
        let mut tls_config = RustlsConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Apply ALPN protocols, e.g., ["tuic"]
        tls_config.alpn_protocols = self.quic_config.alpn.clone();

        // Optional: allow insecure for testing as per config
        if self.quic_config.allow_insecure {
            #[cfg(feature = "tls_rustls")]
            {
                use crate::tls::danger::NoVerify;
                tls_config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(NoVerify::new()));
            }
        }

        // Use platform verifier for TLS roots; ALPN/SNI can be provided on connect.
        quinn::ClientConfig::try_with_platform_verifier().map_err(io::Error::other)
    }

    /// Authenticates connection (reserved for advanced auth flows)
    #[allow(dead_code)]
    async fn authenticate(&self, connection: &quinn::Connection) -> io::Result<()> {
        // Open authentication stream
        let (mut send_stream, mut recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("Failed to open auth stream: {}", e)))?;

        // Send authentication packet
        // TUIC authentication typically includes UUID and token
        let mut auth_packet = Vec::new();
        auth_packet.push(0x01); // Auth command
        auth_packet.extend_from_slice(self.config.uuid.as_bytes());
        auth_packet.extend_from_slice(self.config.token.as_bytes());

        send_stream
            .write_all(&auth_packet)
            .await
            .map_err(|e| io::Error::other(format!("Auth write failed: {}", e)))?;

        send_stream
            .finish()
            .map_err(|e| io::Error::other(format!("Auth finish failed: {}", e)))?;

        // Read authentication response
        let mut response = [0u8; 1];
        recv_stream
            .read_exact(&mut response)
            .await
            .map_err(|e| io::Error::other(format!("Auth read failed: {}", e)))?;

        if response[0] != 0x00 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("TUIC authentication failed with code: {}", response[0]),
            ));
        }

        Ok(())
    }

    /// Creates TUIC tunnel (reserved for multiplexed connections)
    #[allow(dead_code)]
    async fn create_tunnel(
        &self,
        connection: &quinn::Connection,
        target: &HostPort,
    ) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
        // Open bidirectional stream for the tunnel
        let (mut send_stream, recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("Failed to open tunnel stream: {}", e)))?;

        // Send CONNECT request
        let mut connect_packet = Vec::new();
        connect_packet.push(0x02); // Connect command

        // Encode target address
        let target_bytes = format!("{}:{}", target.host, target.port);
        connect_packet.push(target_bytes.len() as u8);
        connect_packet.extend_from_slice(target_bytes.as_bytes());

        send_stream
            .write_all(&connect_packet)
            .await
            .map_err(|e| io::Error::other(format!("Connect write failed: {}", e)))?;

        Ok((send_stream, recv_stream))
    }
}

#[cfg(feature = "out_tuic")]
#[async_trait]
impl OutboundTcp for TuicOutbound {
    type IO = crate::outbound::quic::io::QuicBidiStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{record_connect_attempt, record_connect_success};
        use crate::metrics::record_outbound_error;

        record_connect_attempt(crate::outbound::OutboundKind::Tuic);

        #[cfg(feature = "metrics")]
        let start = std::time::Instant::now();

        // Get or create pooled QUIC connection
        let connection = match self.get_connection().await {
            Ok(c) => c,
            Err(e) => {
                record_outbound_error(crate::outbound::OutboundKind::Direct, &e);
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("tuic_connect_total", "result" => "quic_fail").increment(1);
                }
                return Err(e);
            }
        };

        // Open a stream and perform TUIC handshake, then return wrapped stream
        let (send_stream, recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| io::Error::other(format!("Failed to open bi stream: {}", e)))?;
        let mut quic_stream =
            crate::outbound::quic::io::QuicBidiStream::new(send_stream, recv_stream);
        if let Err(e) = self
            .tuic_handshake(&mut quic_stream, &target.host, target.port)
            .await
        {
            record_outbound_error(
                crate::outbound::OutboundKind::Direct,
                &io::Error::other(e.to_string()),
            );
            return Err(io::Error::other("TUIC handshake failed"));
        }

        record_connect_success(crate::outbound::OutboundKind::Direct);

        // Record TUIC-specific metrics
        #[cfg(feature = "metrics")]
        {
            use metrics::{counter, histogram};
            counter!("tuic_connect_total", "result" => "ok").increment(1);
            histogram!("tuic_handshake_ms").record(start.elapsed().as_millis() as f64);
        }

        // Wrap streams for compatibility
        Ok(quic_stream)
    }

    fn protocol_name(&self) -> &'static str {
        "tuic"
    }
}

#[cfg(feature = "out_tuic")]
impl TuicOutbound {
    /// Create UDP transport for TUIC
    pub async fn create_udp_transport(&self) -> io::Result<TuicUdpTransport> {
        // Parse server address
        let server_addr: SocketAddr = format!("{}:{}", self.config.server, self.config.port)
            .parse()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid server address: {}", e),
                )
            })?;

        // Create quinn ClientConfig
        let quinn_config = self.create_quinn_config()?;

        // Establish QUIC connection to server
        let server_name = if self.config.server.parse::<std::net::IpAddr>().is_ok() {
            if self.quic_config.allow_insecure {
                "localhost"
            } else {
                &self.config.server
            }
        } else {
            &self.config.server
        };

        let connection = tuic_quic_connect(&quinn_config, server_addr, server_name)
            .await
            .map_err(|e| io::Error::other(format!("QUIC connection failed: {}", e)))?;

        Ok(TuicUdpTransport::new(connection, self.config.clone()))
    }
}

#[cfg(feature = "out_tuic")]
async fn tuic_quic_connect(
    config: &quinn::ClientConfig,
    server_addr: std::net::SocketAddr,
    server_name: &str,
) -> Result<quinn::Connection, Box<dyn std::error::Error + Send + Sync>> {
    // Create QUIC endpoint
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(config.clone());

    // Connect to server
    let connection = endpoint.connect(server_addr, server_name)?.await?;

    tracing::debug!("QUIC connection established to {}", server_addr);
    Ok(connection)
}

#[cfg(feature = "out_tuic")]
pub struct TuicStream {
    send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
}

#[cfg(feature = "out_tuic")]
impl tokio::io::AsyncRead for TuicStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;

        Pin::new(&mut self.recv_stream).poll_read(cx, buf)
    }
}

#[cfg(feature = "out_tuic")]
impl tokio::io::AsyncWrite for TuicStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        use std::pin::Pin;

        match Pin::new(&mut self.send_stream).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        use std::pin::Pin;

        match Pin::new(&mut self.send_stream).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        use std::pin::Pin;

        match Pin::new(&mut self.send_stream).poll_shutdown(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(io::Error::other(e.to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(feature = "out_tuic")]
#[async_trait::async_trait]
impl crate::adapter::OutboundConnector for TuicOutbound {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        // Establish QUIC connection first
        #[cfg(feature = "metrics")]
        let t0 = std::time::Instant::now();
        #[cfg(feature = "metrics")]
        {
            use crate::metrics::outbound::{record_connect_attempt, OutboundKind};
            record_connect_attempt(OutboundKind::Tuic);
            metrics::counter!("tuic_connect_total", "result" => "attempt").increment(1);
        }
        let conn = match super::quic::common::connect(&self.quic_config).await {
            Ok(c) => c,
            Err(e) => {
                #[cfg(feature = "metrics")]
                {
                    use crate::metrics::outbound::{
                        record_connect_error, OutboundErrorClass, OutboundKind,
                    };
                    record_connect_error(OutboundKind::Tuic, OutboundErrorClass::Handshake);
                    metrics::counter!("tuic_connect_total", "result" => "error").increment(1);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e,
                ));
            }
        };

        // Open a bidirectional stream for TUIC protocol
        let (send_stream, recv_stream) = conn
            .open_bi()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;

        // Perform TUIC handshake and authentication
        let mut tuic_stream = super::quic::io::QuicBidiStream::new(send_stream, recv_stream);
        // TUIC protocol: Send authentication and target request
        if let Err(e) = self.tuic_handshake(&mut tuic_stream, host, port).await {
            #[cfg(feature = "metrics")]
            {
                use crate::metrics::outbound::{
                    record_connect_error, OutboundErrorClass, OutboundKind,
                };
                record_connect_error(OutboundKind::Tuic, OutboundErrorClass::Handshake);
                metrics::counter!("tuic_connect_total", "result" => "error").increment(1);
            }
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, e));
        }

        #[cfg(feature = "metrics")]
        {
            use crate::metrics::outbound::{
                record_connect_duration, record_connect_success, OutboundKind,
            };
            record_connect_success(OutboundKind::Tuic);
            record_connect_duration(t0.elapsed().as_millis() as f64);
            metrics::counter!("tuic_connect_total", "result" => "ok").increment(1);
            metrics::histogram!("tuic_handshake_ms").record(t0.elapsed().as_millis() as f64);
        }

        // Create async TcpStream proxy
        self.create_tcp_proxy(tuic_stream).await
    }
}

#[cfg(not(feature = "out_tuic"))]
pub struct TuicConfig;

/// TUIC UDP transport for UDP relay
#[cfg(feature = "out_tuic")]
#[derive(Debug)]
pub struct TuicUdpTransport {
    pub connection: quinn::Connection,
    pub config: TuicConfig,
}

#[cfg(feature = "out_tuic")]
impl TuicUdpTransport {
    pub fn new(connection: quinn::Connection, config: TuicConfig) -> Self {
        Self { connection, config }
    }

    /// Send UDP packet over QUIC stream (UDP over stream mode)
    pub async fn send_udp_over_stream(
        &self,
        data: &[u8],
        target_host: &str,
        target_port: u16,
    ) -> std::io::Result<usize> {
        // Open a new unidirectional stream for each UDP packet
        let mut send_stream = self
            .connection
            .open_uni()
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to open uni stream: {}", e)))?;

        // Encode UDP packet
        let packet = TuicOutbound::encode_udp_packet_static(target_host, target_port, data)
            .map_err(|e| std::io::Error::other(format!("Failed to encode UDP packet: {}", e)))?;

        // Send packet
        send_stream
            .write_all(&packet)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to write UDP packet: {}", e)))?;

        send_stream
            .finish()
            .map_err(|e| std::io::Error::other(format!("Failed to finish stream: {}", e)))?;

        #[cfg(feature = "metrics")]
        {
            metrics::counter!("udp_quic_send_total", "proto"=>"tuic").increment(1);
            metrics::counter!("udp_quic_send_bytes_total", "proto"=>"tuic")
                .increment(data.len() as u64);
        }
        Ok(data.len())
    }

    /// Receive UDP packet over QUIC stream (UDP over stream mode)
    pub async fn recv_udp_over_stream(&self) -> std::io::Result<(Vec<u8>, String, u16)> {
        // Accept a unidirectional stream
        let mut recv_stream =
            self.connection.accept_uni().await.map_err(|e| {
                std::io::Error::other(format!("Failed to accept uni stream: {}", e))
            })?;

        // Read the entire packet (up to 64KB)
        let packet = recv_stream
            .read_to_end(1024 * 64)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to read UDP packet: {}", e)))?;

        // Decode packet
        let (host, port, data) = TuicOutbound::decode_udp_packet(&packet)
            .map_err(|e| std::io::Error::other(format!("Failed to decode UDP packet: {}", e)))?;
        #[cfg(feature = "metrics")]
        {
            metrics::counter!("udp_quic_recv_total", "proto"=>"tuic").increment(1);
            metrics::counter!("udp_quic_recv_bytes_total", "proto"=>"tuic")
                .increment(data.len() as u64);
        }
        Ok((data, host, port))
    }
}

#[cfg(feature = "out_tuic")]
#[async_trait]
impl UdpOutboundSession for TuicUdpTransport {
    async fn send_to(&self, data: &[u8], host: &str, port: u16) -> std::io::Result<()> {
        let _ = self.send_udp_over_stream(data, host, port).await?;
        Ok(())
    }

    async fn recv_from(&self) -> std::io::Result<(Vec<u8>, std::net::SocketAddr)> {
        let (payload, host, port) = self.recv_udp_over_stream().await?;
        let addr = tokio::net::lookup_host((host.as_str(), port))
            .await
            .ok()
            .and_then(|mut it| it.next())
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], port)));
        Ok((payload, addr))
    }
}

#[cfg(feature = "out_tuic")]
impl TuicOutbound {
    /// Static version of encode_udp_packet for use in TuicUdpTransport
    pub fn encode_udp_packet_static(
        target_host: &str,
        target_port: u16,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let packet = Vec::new();
        let mut packet = packet;

        // Reserve space for length (will be filled at the end)
        packet.extend_from_slice(&[0u8; 2]);

        // Fragment ID and total (no fragmentation for now)
        packet.push(0); // Fragment ID
        packet.push(1); // Fragment total (1 = no fragmentation)

        // Address type and address
        if let Ok(ip) = target_host.parse::<std::net::IpAddr>() {
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
            packet.push(0x03);
            packet.push(target_host.len() as u8);
            packet.extend_from_slice(target_host.as_bytes());
        }

        // Port
        packet.extend_from_slice(&target_port.to_be_bytes());

        // Data
        packet.extend_from_slice(data);

        // Fill in length (total packet length excluding the length field itself)
        let length = (packet.len() - 2) as u16;
        packet[0..2].copy_from_slice(&length.to_be_bytes());

        Ok(packet)
    }
}

#[cfg(feature = "out_tuic")]
impl UdpOutboundFactory for TuicOutbound {
    fn open_session(
        &self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = std::io::Result<Arc<dyn UdpOutboundSession>>> + Send>,
    > {
        let this = self.clone();
        Box::pin(async move {
            #[cfg(feature = "metrics")]
            metrics::counter!("udp_session_open_total", "proto"=>"tuic", "stage"=>"attempt")
                .increment(1);
            let sess = match this.create_udp_transport().await {
                Ok(s) => {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("udp_session_open_total", "proto"=>"tuic", "result"=>"ok")
                        .increment(1);
                    s
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    metrics::counter!("udp_session_open_total", "proto"=>"tuic", "result"=>"error")
                        .increment(1);
                    return Err(e);
                }
            };
            Ok(Arc::new(sess) as Arc<dyn UdpOutboundSession>)
        })
    }
}

#[cfg(not(feature = "out_tuic"))]
pub struct TuicConfig;

#[cfg(not(feature = "out_tuic"))]
impl TuicConfig {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
#[cfg(feature = "out_tuic")]
mod tests;
