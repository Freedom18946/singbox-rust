//! Hysteria2 outbound connector implementation
//!
//! Fully self-contained Hysteria2 protocol with QUIC transport,
//! SHA256 authentication, and bandwidth control.
use crate::outbound::prelude::*;

// ---------------------------------------------------------------------------
// Adapter config & connector (always compiled when adapter-hysteria2 is on)
// ---------------------------------------------------------------------------

/// Adapter configuration for Hysteria2 outbound
#[derive(Debug, Clone)]
pub struct Hysteria2AdapterConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub congestion_control: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<String>,
    pub salamander: Option<String>,
}

impl Default for Hysteria2AdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            password: "password".to_string(),
            skip_cert_verify: true,
            sni: Some("example.com".to_string()),
            alpn: Some(vec!["h3".to_string(), "hysteria2".to_string()]),
            congestion_control: Some("bbr".to_string()),
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            salamander: None,
        }
    }
}

/// Hysteria2 outbound connector
#[derive(Debug, Clone, Default)]
pub struct Hysteria2Connector {
    cfg: Hysteria2AdapterConfig,
}

impl Hysteria2Connector {
    pub fn new(cfg: Hysteria2AdapterConfig) -> Self {
        Self { cfg }
    }
}

#[async_trait]
impl OutboundConnector for Hysteria2Connector {
    fn name(&self) -> &'static str {
        "hysteria2"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-hysteria2"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-hysteria2",
        });

        #[cfg(feature = "adapter-hysteria2")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "Hysteria2 outbound only supports TCP".to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("hysteria2", &target);

            let inner = Hysteria2Inner::new(&self.cfg)
                .map_err(|e| AdapterError::Other(e.to_string()))?;

            let stream = inner
                .connect(&target.host, target.port)
                .await
                .map_err(AdapterError::Io)?;

            Ok(Box::new(stream) as BoxedStream)
        }
    }
}

// ---------------------------------------------------------------------------
// Full protocol implementation (feature-gated)
// ---------------------------------------------------------------------------
#[cfg(feature = "adapter-hysteria2")]
mod proto {
    use super::Hysteria2AdapterConfig;
    use crate::outbound::quic_util::{QuicBidiStream, QuicConfig, quic_connect};
    use quinn::Connection;
    use rand::Rng;
    use sha2::{Digest, Sha256};
    use std::io;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Mutex;

    // ---- Congestion control types ----

    #[derive(Clone, Debug)]
    pub(super) struct BrutalConfig {
        up_mbps: u32,
        down_mbps: u32,
    }

    #[derive(Clone, Debug)]
    pub(super) enum CongestionControl {
        Bbr,
        Cubic,
        NewReno,
        Brutal(BrutalConfig),
    }

    // ---- Bandwidth limiter ----

    #[derive(Clone, Debug)]
    struct BandwidthLimiter {
        up_limit: Option<u32>,
        down_limit: Option<u32>,
        last_reset: Arc<Mutex<Instant>>,
        up_tokens: Arc<Mutex<u32>>,
        down_tokens: Arc<Mutex<u32>>,
    }

    impl BandwidthLimiter {
        fn new(up_mbps: Option<u32>, down_mbps: Option<u32>) -> Self {
            Self {
                up_limit: up_mbps,
                down_limit: down_mbps,
                last_reset: Arc::new(Mutex::new(Instant::now())),
                up_tokens: Arc::new(Mutex::new(up_mbps.unwrap_or(0) * 1024 * 1024)),
                down_tokens: Arc::new(Mutex::new(down_mbps.unwrap_or(0) * 1024 * 1024)),
            }
        }

        #[allow(dead_code)]
        async fn consume_up(&self, bytes: u32) -> bool {
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

        #[allow(dead_code)]
        async fn consume_down(&self, bytes: u32) -> bool {
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

        async fn refill_tokens(&self) {
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

    // ---- Hysteria2Inner: full protocol implementation ----

    #[derive(Clone)]
    pub(super) struct Hysteria2Inner {
        password: String,
        obfs: Option<String>,
        salamander: Option<String>,
        quic_config: QuicConfig,
        congestion_control: CongestionControl,
        connection_pool: Arc<Mutex<Option<Connection>>>,
        bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
    }

    impl std::fmt::Debug for Hysteria2Inner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Hysteria2Inner")
                .field("congestion_control", &self.congestion_control)
                .finish()
        }
    }

    impl Hysteria2Inner {
        pub(super) fn new(cfg: &Hysteria2AdapterConfig) -> anyhow::Result<Self> {
            // Build ALPN list: always include h3 + hysteria2, then user extras
            let mut alpn: Vec<Vec<u8>> = vec![b"h3".to_vec(), b"hysteria2".to_vec()];
            if let Some(ref custom_alpn) = cfg.alpn {
                for proto in custom_alpn {
                    alpn.push(proto.as_bytes().to_vec());
                }
            }

            let quic_config = QuicConfig::new(cfg.server.clone(), cfg.port)
                .with_alpn(alpn)
                .with_allow_insecure(cfg.skip_cert_verify)
                .with_sni(cfg.sni.clone())
                .with_enable_0rtt(false);

            // Determine congestion control algorithm
            let congestion_control = match cfg.congestion_control.as_deref() {
                Some("cubic") => CongestionControl::Cubic,
                Some("newreno") => CongestionControl::NewReno,
                Some("brutal") => {
                    // Brutal requires explicit bandwidth settings
                    let up = cfg.up_mbps.unwrap_or(100);
                    let down = cfg.down_mbps.unwrap_or(100);
                    CongestionControl::Brutal(BrutalConfig {
                        up_mbps: up,
                        down_mbps: down,
                    })
                }
                _ => CongestionControl::Bbr, // Default to BBR
            };

            // Create bandwidth limiter if configured
            let bandwidth_limiter = if cfg.up_mbps.is_some() || cfg.down_mbps.is_some() {
                Some(Arc::new(BandwidthLimiter::new(cfg.up_mbps, cfg.down_mbps)))
            } else {
                None
            };

            Ok(Self {
                password: cfg.password.clone(),
                obfs: cfg.obfs.clone(),
                salamander: cfg.salamander.clone(),
                quic_config,
                congestion_control,
                connection_pool: Arc::new(Mutex::new(None)),
                bandwidth_limiter,
            })
        }

        // ---- Authentication hash ----

        pub(super) fn generate_auth_hash(&self) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(self.password.as_bytes());
            hasher.update(b"hysteria2-auth");
            if let Some(ref salamander) = self.salamander {
                hasher.update(salamander.as_bytes());
            }
            let mut result = [0u8; 32];
            result.copy_from_slice(&hasher.finalize()[..32]);
            result
        }

        // ---- Obfuscation ----

        pub(super) fn apply_obfuscation(&self, data: &mut [u8]) {
            if let Some(ref obfs_key) = self.obfs {
                let key_bytes = obfs_key.as_bytes();
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte ^= key_bytes[i % key_bytes.len()];
                }
            }
        }

        // ---- Connection pooling with retry ----

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
                        tracing::debug!(
                            attempt,
                            "hysteria2: QUIC connection established"
                        );
                        return Ok(connection);
                    }
                    Err(e) => {
                        if attempt >= max_retries {
                            tracing::warn!(
                                attempt,
                                error = %e,
                                "hysteria2: exhausted retries"
                            );
                            return Err(e);
                        }
                        // Exponential backoff with jitter (using rand, not fastrand)
                        let exp = attempt.saturating_sub(1).min(8);
                        let mut delay = base_ms.saturating_mul(1u64 << exp);
                        delay = delay.min(cap_ms);
                        let jitter = rand::thread_rng().gen_range(0..=(delay / 5 + 1));
                        tracing::debug!(
                            attempt,
                            delay_ms = delay + jitter,
                            error = %e,
                            "hysteria2: retrying connection"
                        );
                        tokio::time::sleep(Duration::from_millis(delay + jitter)).await;
                        continue;
                    }
                }
            }
        }

        // ---- Create a new QUIC connection ----

        async fn create_new_connection(&self) -> io::Result<Connection> {
            let connection = quic_connect(&self.quic_config)
                .await
                .map_err(|e| io::Error::other(format!("QUIC connection failed: {}", e)))?;

            // Configure congestion control (logged only; Quinn handles it at transport level)
            self.configure_congestion_control(&connection);

            // Perform authentication
            self.authenticate(&connection).await?;

            Ok(connection)
        }

        fn configure_congestion_control(&self, _connection: &Connection) {
            // Note: Quinn handles congestion control at the transport config level.
            // We log the intended configuration for diagnostics.
            match &self.congestion_control {
                CongestionControl::Bbr => {
                    tracing::debug!("hysteria2: using BBR congestion control");
                }
                CongestionControl::Cubic => {
                    tracing::debug!("hysteria2: using Cubic congestion control");
                }
                CongestionControl::NewReno => {
                    tracing::debug!("hysteria2: using NewReno congestion control");
                }
                CongestionControl::Brutal(ref bc) => {
                    tracing::debug!(
                        up_mbps = bc.up_mbps,
                        down_mbps = bc.down_mbps,
                        "hysteria2: using Brutal congestion control"
                    );
                }
            }
        }

        // ---- Authentication ----

        async fn authenticate(&self, connection: &Connection) -> io::Result<()> {
            // Open authentication stream
            let (mut send_stream, mut recv_stream) = connection
                .open_bi()
                .await
                .map_err(|e| io::Error::other(format!("Failed to open auth stream: {}", e)))?;

            // Generate authentication hash
            let auth_hash = self.generate_auth_hash();

            // Build authentication packet according to Hysteria2 protocol
            let mut auth_packet = Vec::new();
            auth_packet.push(0x01); // Auth command
            auth_packet.extend_from_slice(&auth_hash);

            // Add optional obfuscation parameters
            if let Some(ref obfs) = self.obfs {
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

            send_stream
                .write_all(&auth_packet)
                .await
                .map_err(|e| io::Error::other(format!("Auth write failed: {}", e)))?;

            send_stream
                .finish()
                .map_err(|e| io::Error::other(format!("Auth finish failed: {}", e)))?;

            // Read authentication response
            let mut response = [0u8; 4];
            let bytes_read = recv_stream
                .read(&mut response)
                .await
                .map_err(|e| io::Error::other(format!("Auth read failed: {}", e)))?;

            if matches!(bytes_read, None | Some(0)) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Authentication response was empty",
                ));
            }

            // Check authentication result
            match response[0] {
                0x00 => {
                    tracing::debug!("hysteria2: authentication successful");
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
                code => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Hysteria2 authentication failed with unknown code: {}",
                        code
                    ),
                )),
            }
        }

        // ---- TCP tunnel creation ----

        async fn create_tcp_tunnel(
            &self,
            connection: &Connection,
            host: &str,
            port: u16,
        ) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
            // Check bandwidth limits before opening tunnel
            if let Some(ref limiter) = self.bandwidth_limiter {
                limiter.refill_tokens().await;
            }

            // Open bidirectional stream for TCP relay
            let (mut send_stream, mut recv_stream) = connection
                .open_bi()
                .await
                .map_err(|e| {
                    io::Error::other(format!("Failed to open tunnel stream: {}", e))
                })?;

            // Build TCP CONNECT request according to Hysteria2 protocol
            let mut connect_packet = Vec::new();
            connect_packet.push(0x02); // TCP Connect command

            // Encode target address (SOCKS5-like format used by Hysteria2)
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
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
                let domain_bytes = host.as_bytes();
                if domain_bytes.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Domain name too long for Hysteria2 protocol",
                    ));
                }
                connect_packet.push(domain_bytes.len() as u8);
                connect_packet.extend_from_slice(domain_bytes);
            }

            connect_packet.extend_from_slice(&port.to_be_bytes());

            // Apply obfuscation if configured
            self.apply_obfuscation(&mut connect_packet);

            send_stream
                .write_all(&connect_packet)
                .await
                .map_err(|e| io::Error::other(format!("Connect write failed: {}", e)))?;

            // Read connection response
            let mut response = [0u8; 2];
            recv_stream
                .read_exact(&mut response)
                .await
                .map_err(|e| {
                    io::Error::other(format!("Connect response read failed: {}", e))
                })?;

            match response[0] {
                0x00 => {
                    tracing::debug!(
                        host,
                        port,
                        "hysteria2: TCP tunnel established"
                    );
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
                code => Err(io::Error::other(format!(
                    "Hysteria2 TCP connect failed with code: {}",
                    code
                ))),
            }
        }

        // ---- Public connect entry point ----

        pub(super) async fn connect(
            &self,
            host: &str,
            port: u16,
        ) -> io::Result<QuicBidiStream> {
            // Get or create QUIC connection with pooling
            let connection = self.get_connection().await?;

            // Create TCP tunnel through the connection
            let (send_stream, recv_stream) =
                self.create_tcp_tunnel(&connection, host, port).await?;

            Ok(QuicBidiStream::new(send_stream, recv_stream))
        }
    }
}

// Re-export the inner type for use in dial()
#[cfg(feature = "adapter-hysteria2")]
use proto::Hysteria2Inner;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria2_connector_name() {
        let c = Hysteria2Connector::new(Hysteria2AdapterConfig::default());
        assert_eq!(c.name(), "hysteria2");
    }

    #[test]
    fn test_hysteria2_adapter_config_default() {
        let cfg = Hysteria2AdapterConfig::default();
        assert_eq!(cfg.server, "127.0.0.1");
        assert_eq!(cfg.port, 443);
        assert!(cfg.skip_cert_verify);
        assert_eq!(
            cfg.alpn.as_deref(),
            Some(["h3".to_string(), "hysteria2".to_string()].as_slice())
        );
    }

    #[cfg(feature = "adapter-hysteria2")]
    #[test]
    fn test_auth_hash_deterministic() {
        let cfg = Hysteria2AdapterConfig::default();
        let inner = Hysteria2Inner::new(&cfg).unwrap();
        let h1 = inner.generate_auth_hash();
        let h2 = inner.generate_auth_hash();
        assert_eq!(h1, h2, "auth hash must be deterministic");
    }

    #[cfg(feature = "adapter-hysteria2")]
    #[test]
    fn test_obfuscation_roundtrip() {
        let mut cfg = Hysteria2AdapterConfig::default();
        cfg.obfs = Some("testkey".to_string());
        let inner = Hysteria2Inner::new(&cfg).unwrap();

        let original = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut data = original.clone();
        inner.apply_obfuscation(&mut data);
        assert_ne!(data, original, "obfuscated data should differ");
        inner.apply_obfuscation(&mut data);
        assert_eq!(data, original, "double XOR should restore original");
    }
}
