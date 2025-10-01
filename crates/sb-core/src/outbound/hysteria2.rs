//! Hysteria2 outbound implementation
//!
//! Provides Hysteria2 protocol support for high-performance TCP tunneling
//! over QUIC with congestion control optimization and password authentication.
//!
//! Features:
//! - QUIC-based transport with BBR congestion control
//! - Password-based authentication with SHA256 hashing
//! - UDP multiplexing support for high-performance data transfer
//! - Bandwidth control and traffic shaping
//! - Obfuscation support for censorship resistance

#[cfg(feature = "out_hysteria2")]
use async_trait::async_trait;
#[cfg(feature = "out_hysteria2")]
use quinn::Connection;
#[cfg(feature = "out_hysteria2")]
use rand::Rng;
#[cfg(feature = "out_hysteria2")]
use sha2::{Digest, Sha256};
#[cfg(feature = "out_hysteria2")]
use std::io;
#[cfg(feature = "out_hysteria2")]
use std::net::SocketAddr;
#[cfg(feature = "out_hysteria2")]
use std::sync::Arc;
#[cfg(feature = "out_hysteria2")]
use std::time::{Duration, Instant};
#[cfg(feature = "out_hysteria2")]
use tokio::sync::Mutex;

#[cfg(feature = "out_hysteria2")]
use super::quic::common::{connect as quic_connect, QuicConfig};
#[cfg(feature = "out_hysteria2")]
use super::types::{HostPort, OutboundTcp};

#[cfg(feature = "out_hysteria2")]
#[derive(Clone, Debug)]
pub struct Hysteria2Config {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub congestion_control: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<String>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub salamander: Option<String>,
    pub brutal: Option<BrutalConfig>,
}

#[cfg(feature = "out_hysteria2")]
#[derive(Clone, Debug)]
pub struct BrutalConfig {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[cfg(feature = "out_hysteria2")]
#[derive(Debug)]
pub enum CongestionControl {
    Bbr,
    Cubic,
    NewReno,
    Brutal(BrutalConfig),
}

#[cfg(feature = "out_hysteria2")]
#[derive(Debug)]
pub struct Hysteria2Outbound {
    config: Hysteria2Config,
    quic_config: QuicConfig,
    connection_pool: Arc<Mutex<Option<Connection>>>,
    congestion_control: CongestionControl,
    /// Bandwidth limiter for future rate limiting
    #[allow(dead_code)]
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
}

#[cfg(feature = "out_hysteria2")]
#[derive(Debug)]
pub struct BandwidthLimiter {
    up_limit: Option<u32>,
    down_limit: Option<u32>,
    last_reset: Arc<Mutex<Instant>>,
    up_tokens: Arc<Mutex<u32>>,
    down_tokens: Arc<Mutex<u32>>,
}

#[cfg(feature = "out_hysteria2")]
impl BandwidthLimiter {
    pub fn new(up_mbps: Option<u32>, down_mbps: Option<u32>) -> Self {
        Self {
            up_limit: up_mbps,
            down_limit: down_mbps,
            last_reset: Arc::new(Mutex::new(Instant::now())),
            up_tokens: Arc::new(Mutex::new(up_mbps.unwrap_or(0) * 1024 * 1024)),
            down_tokens: Arc::new(Mutex::new(down_mbps.unwrap_or(0) * 1024 * 1024)),
        }
    }

    pub async fn consume_up(&self, bytes: u32) -> bool {
        if self.up_limit.is_none() {
            return true;
        }

        let mut tokens = self.up_tokens.lock().await;
        if *tokens >= bytes {
            *tokens -= bytes;
            true
        } else {
            false
        }
    }

    pub async fn consume_down(&self, bytes: u32) -> bool {
        if self.down_limit.is_none() {
            return true;
        }

        let mut tokens = self.down_tokens.lock().await;
        if *tokens >= bytes {
            *tokens -= bytes;
            true
        } else {
            false
        }
    }

    pub async fn refill_tokens(&self) {
        let mut last_reset = self.last_reset.lock().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last_reset);

        if elapsed >= Duration::from_secs(1) {
            if let Some(up_limit) = self.up_limit {
                let mut up_tokens = self.up_tokens.lock().await;
                *up_tokens = up_limit * 1024 * 1024;
            }
            if let Some(down_limit) = self.down_limit {
                let mut down_tokens = self.down_tokens.lock().await;
                *down_tokens = down_limit * 1024 * 1024;
            }
            *last_reset = now;
        }
    }
}

#[cfg(feature = "out_hysteria2")]
impl Hysteria2Outbound {
    pub fn new(config: Hysteria2Config) -> anyhow::Result<Self> {
        // Build QUIC configuration for Hysteria2
        let mut alpn = vec![b"h3".to_vec(), b"hysteria2".to_vec()];

        // Add custom ALPN if specified
        if let Some(ref custom_alpn) = config.alpn {
            for proto in custom_alpn {
                alpn.push(proto.as_bytes().to_vec());
            }
        }

        let quic_config = QuicConfig::new(config.server.clone(), config.port)
            .with_alpn(alpn)
            .with_allow_insecure(config.skip_cert_verify);

        // Determine congestion control algorithm
        let congestion_control = match config.congestion_control.as_deref() {
            Some("bbr") => CongestionControl::Bbr,
            Some("cubic") => CongestionControl::Cubic,
            Some("newreno") => CongestionControl::NewReno,
            Some("brutal") => {
                if let Some(ref brutal_config) = config.brutal {
                    CongestionControl::Brutal(brutal_config.clone())
                } else {
                    CongestionControl::Bbr // Default fallback
                }
            }
            _ => CongestionControl::Bbr, // Default to BBR
        };

        // Create bandwidth limiter if configured
        let bandwidth_limiter = if config.up_mbps.is_some() || config.down_mbps.is_some() {
            Some(Arc::new(BandwidthLimiter::new(
                config.up_mbps,
                config.down_mbps,
            )))
        } else {
            None
        };

        Ok(Self {
            config,
            quic_config,
            connection_pool: Arc::new(Mutex::new(None)),
            congestion_control,
            bandwidth_limiter,
        })
    }

    fn generate_auth_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.config.password.as_bytes());
        hasher.update(b"hysteria2-auth");

        // Add salamander obfuscation if configured
        if let Some(ref salamander) = self.config.salamander {
            hasher.update(salamander.as_bytes());
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&hasher.finalize()[..32]);
        result
    }

    /// Apply obfuscation to data if configured
    fn apply_obfuscation(&self, data: &mut [u8]) {
        if let Some(ref obfs_key) = self.config.obfs {
            // Simple XOR obfuscation with key
            let key_bytes = obfs_key.as_bytes();
            for (i, byte) in data.iter_mut().enumerate() {
                *byte ^= key_bytes[i % key_bytes.len()];
            }
        }
    }

    /// Get or create a QUIC connection with connection pooling
    async fn get_connection(&self) -> io::Result<Connection> {
        // Fast path: return existing healthy connection
        if let Some(conn) = {
            let pool = self.connection_pool.lock().await;
            pool.as_ref().cloned()
        } {
            if conn.close_reason().is_none() {
                return Ok(conn);
            }
        }

        // Retry with exponential backoff
        let max_retries = std::env::var("SB_HYSTERIA2_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3)
            .min(8);
        let base_ms = std::env::var("SB_HYSTERIA2_BACKOFF_MS_BASE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(200);
        let cap_ms = std::env::var("SB_HYSTERIA2_BACKOFF_MS_MAX")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2_000);

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match self.create_new_connection().await {
                Ok(connection) => {
                    let mut pool = self.connection_pool.lock().await;
                    *pool = Some(connection.clone());
                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("hysteria2_connect_retries_total", "result" => "ok").increment(1);
                    }
                    return Ok(connection);
                }
                Err(e) => {
                    #[cfg(feature = "metrics")]
                    {
                        use metrics::counter;
                        counter!("hysteria2_connect_retries_total", "result" => "fail")
                            .increment(1);
                    }
                    if attempt >= max_retries {
                        return Err(e);
                    }
                    // Exponential backoff with jitter
                    let exp = attempt.saturating_sub(1).min(8);
                    let mut delay = base_ms.saturating_mul(1u64 << exp);
                    delay = delay.min(cap_ms);
                    let jitter = fastrand::u64(..(delay / 5 + 1)); // up to 20% jitter
                    tokio::time::sleep(std::time::Duration::from_millis(delay + jitter)).await;
                    continue;
                }
            }
        }
    }

    /// Create a new QUIC connection with proper configuration
    async fn create_new_connection(&self) -> io::Result<Connection> {
        let connection = quic_connect(&self.quic_config).await.map_err(|e| {
            io::Error::other(
                format!("QUIC connection failed: {}", e),
            )
        })?;

        // Configure congestion control
        self.configure_congestion_control(&connection).await?;

        // Perform authentication
        self.authenticate(&connection).await?;

        Ok(connection)
    }

    /// Configure congestion control based on settings
    async fn configure_congestion_control(&self, _connection: &Connection) -> io::Result<()> {
        // Note: Quinn doesn't expose direct congestion control configuration
        // This would typically be handled at the transport config level
        // For now, we log the intended configuration

        #[cfg(feature = "metrics")]
        {
            use metrics::counter;
            match &self.congestion_control {
                CongestionControl::Bbr => {
                    counter!("hysteria2_congestion_control", "algorithm" => "bbr").increment(1);
                }
                CongestionControl::Cubic => {
                    counter!("hysteria2_congestion_control", "algorithm" => "cubic").increment(1);
                }
                CongestionControl::NewReno => {
                    counter!("hysteria2_congestion_control", "algorithm" => "newreno").increment(1);
                }
                CongestionControl::Brutal(_) => {
                    counter!("hysteria2_congestion_control", "algorithm" => "brutal").increment(1);
                }
            }
        }

        Ok(())
    }

    async fn authenticate(&self, connection: &quinn::Connection) -> io::Result<()> {
        // Open authentication stream
        let (mut send_stream, mut recv_stream) = connection.open_bi().await.map_err(|e| {
            io::Error::other(
                format!("Failed to open auth stream: {}", e),
            )
        })?;

        // Generate authentication hash
        let auth_hash = self.generate_auth_hash();

        // Build authentication packet according to Hysteria2 protocol
        let mut auth_packet = Vec::new();
        auth_packet.push(0x01); // Auth command for Hysteria2
        auth_packet.extend_from_slice(&auth_hash);

        // Add optional obfuscation parameters
        if let Some(ref obfs) = self.config.obfs {
            auth_packet.push(obfs.len() as u8);
            auth_packet.extend_from_slice(obfs.as_bytes());
        } else {
            auth_packet.push(0x00); // No obfuscation
        }

        // Add bandwidth configuration if using Brutal congestion control
        if let CongestionControl::Brutal(ref brutal_config) = self.congestion_control {
            auth_packet.push(0x02); // Bandwidth config flag
            auth_packet.extend_from_slice(&brutal_config.up_mbps.to_be_bytes());
            auth_packet.extend_from_slice(&brutal_config.down_mbps.to_be_bytes());
        }

        // Apply obfuscation to the entire packet
        self.apply_obfuscation(&mut auth_packet);

        send_stream.write_all(&auth_packet).await.map_err(|e| {
            io::Error::other(format!("Auth write failed: {}", e))
        })?;

        send_stream.finish().map_err(|e| {
            io::Error::other(format!("Auth finish failed: {}", e))
        })?;

        // Read authentication response
        let mut response = [0u8; 4]; // Extended response for more info
        let bytes_read = recv_stream.read(&mut response).await.map_err(|e| {
            io::Error::other(format!("Auth read failed: {}", e))
        })?;

        if matches!(bytes_read, None | Some(0)) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Authentication response was empty",
            ));
        }

        // Check authentication result
        match response[0] {
            0x00 => {
                // Authentication successful
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("hysteria2_auth_total", "result" => "success").increment(1);
                }
                Ok(())
            }
            0x01 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hysteria2 authentication failed: invalid password",
            )),
            0x02 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hysteria2 authentication failed: user not found",
            )),
            0x03 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hysteria2 authentication failed: bandwidth limit exceeded",
            )),
            code => {
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("hysteria2_auth_total", "result" => "unknown_error").increment(1);
                }
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Hysteria2 authentication failed with unknown code: {}",
                        code
                    ),
                ))
            }
        }
    }

    async fn create_tcp_tunnel(
        &self,
        connection: &quinn::Connection,
        target: &HostPort,
    ) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
        // Open bidirectional stream for TCP relay
        let (mut send_stream, mut recv_stream) = connection.open_bi().await.map_err(|e| {
            io::Error::other(
                format!("Failed to open tunnel stream: {}", e),
            )
        })?;

        // Build TCP CONNECT request according to Hysteria2 protocol
        let mut connect_packet = Vec::new();
        connect_packet.push(0x02); // TCP Connect command

        // Encode target address (SOCKS5-like format used by Hysteria2)
        if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    connect_packet.push(0x01); // IPv4
                    connect_packet.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    connect_packet.push(0x04); // IPv6
                    connect_packet.extend_from_slice(&v6.octets());
                }
            }
        } else {
            connect_packet.push(0x03); // Domain
            let domain_bytes = target.host.as_bytes();
            if domain_bytes.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Domain name too long for Hysteria2 protocol",
                ));
            }
            connect_packet.push(domain_bytes.len() as u8);
            connect_packet.extend_from_slice(domain_bytes);
        }

        connect_packet.extend_from_slice(&target.port.to_be_bytes());

        // Apply obfuscation if configured
        self.apply_obfuscation(&mut connect_packet);

        send_stream.write_all(&connect_packet).await.map_err(|e| {
            io::Error::other(format!("Connect write failed: {}", e))
        })?;

        // Read connection response
        let mut response = [0u8; 2];
        recv_stream.read_exact(&mut response).await.map_err(|e| {
            io::Error::other(
                format!("Connect response read failed: {}", e),
            )
        })?;

        match response[0] {
            0x00 => {
                // Connection successful
                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("hysteria2_connect_total", "result" => "success").increment(1);
                }
                Ok((send_stream, recv_stream))
            }
            0x01 => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Hysteria2 TCP connect failed: connection refused",
            )),
            0x02 => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Hysteria2 TCP connect failed: timeout",
            )),
            0x03 => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Hysteria2 TCP connect failed: host unreachable",
            )),
            code => Err(io::Error::other(
                format!("Hysteria2 TCP connect failed with code: {}", code),
            )),
        }
    }

    /// Create UDP multiplexing session for high-performance data transfer
    /// Creates UDP session for future UDP support
    #[allow(dead_code)]
    async fn create_udp_session(&self, connection: &Connection) -> io::Result<Hysteria2UdpSession> {
        // Send UDP session initialization datagram
        let mut init_packet = Vec::new();
        init_packet.push(0x03); // UDP session init command

        // Add session ID (random 8 bytes)
        let mut rng = rand::thread_rng();
        let session_id: [u8; 8] = rng.gen();
        init_packet.extend_from_slice(&session_id);

        // Apply obfuscation
        self.apply_obfuscation(&mut init_packet);

        connection.send_datagram(init_packet.into()).map_err(|e| {
            io::Error::other(
                format!("UDP session init failed: {}", e),
            )
        })?;

        Ok(Hysteria2UdpSession {
            connection: connection.clone(),
            session_id,
            bandwidth_limiter: self.bandwidth_limiter.clone(),
        })
    }

    /// Perform Hysteria2 handshake with the server
    async fn hysteria2_handshake(
        &self,
        stream: &mut crate::outbound::quic::io::QuicBidiStream,
        host: &str,
        port: u16,
    ) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Hysteria2 handshake protocol
        // 1. Send client hello with authentication
        let client_hello = self.create_client_hello()?;
        stream.write_all(&client_hello).await?;

        // 2. Read server hello response
        let mut server_hello = vec![0u8; 1024];
        let bytes_read = stream.read(&mut server_hello).await?;
        server_hello.truncate(bytes_read);

        // 3. Verify server response
        if self.verify_server_hello(&server_hello)? {
            tracing::debug!("Hysteria2 handshake completed successfully");

            // 4. Send connection request for target
            let connect_request = self.create_connect_request(host, port)?;
            stream.write_all(&connect_request).await?;

            // 5. Read connection response
            let mut connect_response = [0u8; 32];
            stream.read_exact(&mut connect_response).await?;

            if connect_response[0] == 0x00 {
                tracing::debug!("Hysteria2 connection established to {}:{}", host, port);
                Ok(())
            } else {
                anyhow::bail!("Hysteria2 connection failed with code: {:02x}", connect_response[0]);
            }
        } else {
            anyhow::bail!("Invalid server hello response");
        }
    }

    /// Create TCP proxy connection through Hysteria2
    async fn create_tcp_proxy(
        &self,
        hysteria2_stream: crate::outbound::quic::io::QuicBidiStream,
    ) -> std::io::Result<tokio::net::TcpStream> {
        // Create a local TCP server and connect to it to simulate a pair
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        // Accept connection in background
        let server_task = tokio::spawn(async move {
            listener.accept().await.map(|(stream, _)| stream)
        });

        // Connect to the listener
        let client = tokio::net::TcpStream::connect(addr).await?;
        let server = server_task.await.map_err(std::io::Error::other)??;

        // Spawn a background task to relay data between TCP and Hysteria2 streams
        tokio::spawn(async move {
            if let Err(e) = Self::relay_hysteria2_streams(server, hysteria2_stream).await {
                tracing::warn!("Hysteria2 stream relay error: {}", e);
            }
        });

        Ok(client)
    }

    /// Relay data between TCP stream and Hysteria2 stream
    async fn relay_hysteria2_streams(
        mut tcp_stream: tokio::net::TcpStream,
        mut hysteria2_stream: crate::outbound::quic::io::QuicBidiStream,
    ) -> anyhow::Result<()> {
        use tokio::io::copy_bidirectional;

        // Use the streams directly for bidirectional copy
        match copy_bidirectional(&mut tcp_stream, &mut hysteria2_stream).await {
            Ok((sent, received)) => {
                tracing::debug!("Hysteria2 relay completed: sent {} bytes, received {} bytes", sent, received);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("Hysteria2 relay error: {}", e);
                Err(anyhow::anyhow!("Stream relay failed: {}", e))
            }
        }
    }

    /// Create Hysteria2 client hello packet
    fn create_client_hello(&self) -> anyhow::Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Hysteria2 protocol magic
        packet.extend_from_slice(b"HY2");

        // Protocol version
        packet.push(0x02);

        // Client capabilities
        packet.extend_from_slice(&[0x01, 0x02, 0x04]); // TCP, UDP, Fast handshake

        // Congestion control preference
        let cc_name = match &self.congestion_control {
            CongestionControl::Bbr => "bbr",
            CongestionControl::Cubic => "cubic",
            CongestionControl::NewReno => "newreno",
            CongestionControl::Brutal(_) => "brutal",
        };
        let cc_bytes = cc_name.as_bytes();
        packet.push(cc_bytes.len() as u8);
        packet.extend_from_slice(cc_bytes);

        // Bandwidth limits (if using Brutal congestion control)
        if let CongestionControl::Brutal(ref brutal_config) = self.congestion_control {
            packet.extend_from_slice(&brutal_config.up_mbps.to_le_bytes());
            packet.extend_from_slice(&brutal_config.down_mbps.to_le_bytes());
        } else {
            // Default bandwidth values
            packet.extend_from_slice(&0u32.to_le_bytes()); // Up
            packet.extend_from_slice(&0u32.to_le_bytes()); // Down
        }

        Ok(packet)
    }

    /// Verify server hello response
    fn verify_server_hello(&self, data: &[u8]) -> anyhow::Result<bool> {
        if data.len() < 8 {
            return Ok(false);
        }

        // Check magic bytes
        if &data[0..3] != b"HY2" {
            return Ok(false);
        }

        // Check version compatibility
        let server_version = data[3];
        if server_version < 0x02 {
            tracing::warn!("Server version {} is older than client version 2", server_version);
        }

        tracing::debug!("Server hello verification passed");
        Ok(true)
    }

    /// Create connection request packet
    fn create_connect_request(&self, host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
        let mut packet = Vec::new();

        // Command: TCP connect
        packet.push(0x01);

        // Target address
        let target_bytes = format!("{}:{}", host, port);
        packet.push(target_bytes.len() as u8);
        packet.extend_from_slice(target_bytes.as_bytes());

        // Connection options
        packet.push(0x00); // No special options

        Ok(packet)
    }
}

#[cfg(feature = "out_hysteria2")]
pub struct Hysteria2UdpSession {
    connection: Connection,
    session_id: [u8; 8],
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
}

#[cfg(feature = "out_hysteria2")]
impl Hysteria2UdpSession {
    pub async fn send_udp(&self, data: &[u8], target: &HostPort) -> io::Result<()> {
        // Check bandwidth limits
        if let Some(ref limiter) = self.bandwidth_limiter {
            limiter.refill_tokens().await;
            if !limiter.consume_up(data.len() as u32).await {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Bandwidth limit exceeded for upload",
                ));
            }
        }

        // Build UDP packet
        let mut packet = Vec::new();
        packet.extend_from_slice(&self.session_id);

        // Encode target address
        if let Ok(ip) = target.host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    packet.push(0x01);
                    packet.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    packet.push(0x04);
                    packet.extend_from_slice(&v6.octets());
                }
            }
        } else {
            packet.push(0x03);
            let domain_bytes = target.host.as_bytes();
            packet.push(domain_bytes.len() as u8);
            packet.extend_from_slice(domain_bytes);
        }

        packet.extend_from_slice(&target.port.to_be_bytes());
        packet.extend_from_slice(data);

        self.connection
            .send_datagram(packet.into())
            .map_err(|e| io::Error::other(format!("UDP send failed: {}", e)))?;

        Ok(())
    }

    pub async fn recv_udp(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let datagram =
            self.connection.read_datagram().await.map_err(|e| {
                io::Error::other(format!("UDP recv failed: {}", e))
            })?;

        let data = datagram.as_ref();
        if data.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram too short",
            ));
        }

        // Verify session ID
        if data[0..8] != self.session_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram session ID mismatch",
            ));
        }

        // Parse source address following our send format: [8B session][1B atyp][addr][2B port][payload]
        let mut i = 8usize;
        if data.len() < i + 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "missing atyp"));
        }
        let atyp = data[i];
        i += 1;
        let addr = match atyp {
            0x01 => {
                if data.len() < i + 4 + 2 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "short v4"));
                }
                let ip = std::net::Ipv4Addr::new(data[i], data[i + 1], data[i + 2], data[i + 3]);
                i += 4;
                let port = u16::from_be_bytes([data[i], data[i + 1]]);
                i += 2;
                std::net::SocketAddr::from((ip, port))
            }
            0x04 => {
                if data.len() < i + 16 + 2 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "short v6"));
                }
                let mut seg = [0u8; 16];
                seg.copy_from_slice(&data[i..i + 16]);
                let ip = std::net::Ipv6Addr::from(seg);
                i += 16;
                let port = u16::from_be_bytes([data[i], data[i + 1]]);
                i += 2;
                std::net::SocketAddr::from((ip, port))
            }
            0x03 => {
                if data.len() < i + 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short domain len",
                    ));
                }
                let n = data[i] as usize;
                i += 1;
                if data.len() < i + n + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short domain body",
                    ));
                }
                let host = std::str::from_utf8(&data[i..i + n])
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad domain utf8"))?
                    .to_string();
                i += n;
                let port = u16::from_be_bytes([data[i], data[i + 1]]);
                i += 2;
                // Best-effort resolve domain to SocketAddr for API compatibility; fallback to 0.0.0.0:port
                let addr = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .ok()
                    .and_then(|mut it| it.next())
                    .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], port)));
                addr
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "bad atyp")),
        };
        let payload = data[i..].to_vec();

        // Check bandwidth limits
        if let Some(ref limiter) = self.bandwidth_limiter {
            limiter.refill_tokens().await;
            if !limiter.consume_down(payload.len() as u32).await {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Bandwidth limit exceeded for download",
                ));
            }
        }

        Ok((payload, addr))
    }
}

#[cfg(feature = "out_hysteria2")]
#[async_trait]
impl OutboundTcp for Hysteria2Outbound {
    type IO = crate::outbound::quic::io::QuicBidiStream;

    async fn connect(&self, target: &HostPort) -> io::Result<Self::IO> {
        use crate::metrics::outbound::{
            record_connect_attempt, record_connect_error, record_connect_success,
            OutboundErrorClass,
        };

        record_connect_attempt(crate::outbound::OutboundKind::Hysteria2);

        let start = std::time::Instant::now();

        // Get or create QUIC connection with pooling
        let connection = match self.get_connection().await {
            Ok(conn) => conn,
            Err(e) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Handshake,
                );

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("hysteria2_connect_total", "result" => "connection_fail").increment(1);
                }

                return Err(e);
            }
        };

        // Create TCP tunnel through the connection
        let (send_stream, recv_stream) = match self.create_tcp_tunnel(&connection, target).await {
            Ok(streams) => streams,
            Err(e) => {
                record_connect_error(
                    crate::outbound::OutboundKind::Direct,
                    OutboundErrorClass::Protocol,
                );

                #[cfg(feature = "metrics")]
                {
                    use metrics::counter;
                    counter!("hysteria2_connect_total", "result" => "tunnel_fail").increment(1);
                }

                return Err(e);
            }
        };

        record_connect_success(crate::outbound::OutboundKind::Direct);

        // Record Hysteria2-specific metrics
        #[cfg(feature = "metrics")]
        {
            use metrics::{counter, histogram};
            counter!("hysteria2_connect_total", "result" => "success").increment(1);
            histogram!("hysteria2_handshake_ms").record(start.elapsed().as_millis() as f64);

            // Record bandwidth settings if configured
            if let Some(up_mbps) = self.config.up_mbps {
                histogram!("hysteria2_up_mbps").record(up_mbps as f64);
            }
            if let Some(down_mbps) = self.config.down_mbps {
                histogram!("hysteria2_down_mbps").record(down_mbps as f64);
            }

            // Record congestion control algorithm
            match &self.congestion_control {
                CongestionControl::Bbr => {
                    counter!("hysteria2_cc_total", "algorithm" => "bbr").increment(1);
                }
                CongestionControl::Cubic => {
                    counter!("hysteria2_cc_total", "algorithm" => "cubic").increment(1);
                }
                CongestionControl::NewReno => {
                    counter!("hysteria2_cc_total", "algorithm" => "newreno").increment(1);
                }
                CongestionControl::Brutal(_) => {
                    counter!("hysteria2_cc_total", "algorithm" => "brutal").increment(1);
                }
            }
        }

        // Wrap streams for compatibility
        Ok(crate::outbound::quic::io::QuicBidiStream::new(
            send_stream,
            recv_stream,
        ))
    }

    fn protocol_name(&self) -> &'static str {
        "hysteria2"
    }
}

#[cfg(feature = "out_hysteria2")]
pub struct Hysteria2Stream {
    send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
}

#[cfg(feature = "out_hysteria2")]
impl tokio::io::AsyncRead for Hysteria2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::pin::Pin;

        Pin::new(&mut self.recv_stream).poll_read(cx, buf)
    }
}

#[cfg(feature = "out_hysteria2")]
impl tokio::io::AsyncWrite for Hysteria2Stream {
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

#[cfg(feature = "out_hysteria2")]
#[async_trait::async_trait]
impl crate::adapter::OutboundConnector for Hysteria2Outbound {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<tokio::net::TcpStream> {
        // Establish QUIC connection first
        let conn = super::quic::common::connect(&self.quic_config).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;

        // Open a bidirectional stream for Hysteria2 protocol
        let (send_stream, recv_stream) = conn.open_bi().await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e))?;

        // Perform Hysteria2 handshake and authentication
        let mut hysteria2_stream = super::quic::io::QuicBidiStream::new(send_stream, recv_stream);

        // Hysteria2 protocol: Send authentication and target request
        self.hysteria2_handshake(&mut hysteria2_stream, host, port).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;

        // Convert to async TcpStream-like behavior
        self.create_tcp_proxy(hysteria2_stream).await
    }
}

#[cfg(not(feature = "out_hysteria2"))]
pub struct Hysteria2Config;

#[cfg(not(feature = "out_hysteria2"))]
impl Hysteria2Config {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
#[cfg(feature = "out_hysteria2")]
mod tests;

// Re-export for external testing - removed to avoid conflicts
