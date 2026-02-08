//! TUIC outbound adapter
//!
//! Fully self-contained TUIC v5 implementation over QUIC.
//! Uses `super::quic_util` for QUIC connection establishment and
//! bidirectional stream I/O. No dependency on sb-core's protocol stack.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use crate::outbound::prelude::*;

/// Adapter configuration for TUIC outbound
#[derive(Debug, Clone)]
pub struct TuicAdapterConfig {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub token: String,
    pub password: Option<String>,
    pub congestion_control: Option<String>,
    pub alpn: Option<String>,
    pub skip_cert_verify: bool,
    pub udp_relay_mode: TuicUdpRelayMode,
    pub udp_over_stream: bool,
}

/// UDP relay mode for TUIC
#[derive(Debug, Clone, Default)]
pub enum TuicUdpRelayMode {
    #[default]
    Native,
    Quic,
}

impl Default for TuicAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            uuid: uuid::Uuid::new_v4(),
            token: "password".to_string(),
            password: None,
            congestion_control: Some("cubic".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: false,
            udp_relay_mode: TuicUdpRelayMode::Native,
            udp_over_stream: false,
        }
    }
}

/// TUIC outbound connector adapter
///
/// Manages a pooled QUIC connection and implements the TUIC v5 protocol
/// handshake (authentication + connect) on each new bidirectional stream.
#[cfg(feature = "adapter-tuic")]
#[derive(Debug)]
pub struct TuicConnector {
    cfg: TuicAdapterConfig,
    quic_config: super::quic_util::QuicConfig,
    pool: tokio::sync::Mutex<Option<quinn::Connection>>,
}

#[cfg(not(feature = "adapter-tuic"))]
#[derive(Debug, Clone, Default)]
pub struct TuicConnector {
    cfg: TuicAdapterConfig,
}

// ---------------------------------------------------------------------------
// Feature-gated implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "adapter-tuic")]
impl TuicConnector {
    /// Create new TUIC connector with configuration
    pub fn new(cfg: TuicAdapterConfig) -> Self {
        let alpn = if let Some(ref alpn_str) = cfg.alpn {
            alpn_str
                .split(',')
                .map(|s| s.trim().as_bytes().to_vec())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
        } else {
            vec![b"tuic".to_vec()]
        };

        let quic_config = super::quic_util::QuicConfig::new(cfg.server.clone(), cfg.port)
            .with_alpn(alpn)
            .with_allow_insecure(cfg.skip_cert_verify)
            .with_enable_0rtt(false);

        Self {
            cfg,
            quic_config,
            pool: tokio::sync::Mutex::new(None),
        }
    }

    // ----- connection pool with retry + exponential backoff ----------------

    /// Return a live pooled QUIC connection or establish a new one.
    ///
    /// Retries with exponential backoff and random jitter (using `rand`).
    async fn get_connection(&self) -> std::io::Result<quinn::Connection> {
        // Fast path: reuse live connection
        {
            let guard = self.pool.lock().await;
            if let Some(ref conn) = *guard {
                if conn.close_reason().is_none() {
                    return Ok(conn.clone());
                }
            }
        }

        let max_retries: u32 = std::env::var("SB_TUIC_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3)
            .min(8);
        let base_ms: u64 = std::env::var("SB_TUIC_BACKOFF_MS_BASE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);
        let cap_ms: u64 = std::env::var("SB_TUIC_BACKOFF_MS_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2_000);

        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match super::quic_util::quic_connect(&self.quic_config).await {
                Ok(conn) => {
                    let mut guard = self.pool.lock().await;
                    *guard = Some(conn.clone());
                    tracing::debug!(
                        server = %self.cfg.server,
                        port = self.cfg.port,
                        attempt,
                        "TUIC QUIC connection established"
                    );
                    return Ok(conn);
                }
                Err(e) => {
                    if attempt >= max_retries {
                        return Err(std::io::Error::other(format!(
                            "QUIC connection to {}:{} failed after {} attempts: {}",
                            self.cfg.server, self.cfg.port, attempt, e
                        )));
                    }
                    let exp = attempt.saturating_sub(1).min(8);
                    let mut delay = base_ms.saturating_mul(1u64 << exp);
                    delay = delay.min(cap_ms);
                    // Add random jitter (up to ~20% of delay)
                    let jitter = {
                        use rand::Rng;
                        let mut rng = rand::thread_rng();
                        rng.gen_range(0..=(delay / 5 + 1))
                    };
                    tracing::warn!(
                        server = %self.cfg.server,
                        port = self.cfg.port,
                        attempt,
                        delay_ms = delay + jitter,
                        error = %e,
                        "TUIC QUIC connect failed, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(delay + jitter)).await;
                }
            }
        }
    }

    // ----- TUIC v5 protocol ------------------------------------------------

    /// Build TUIC v5 authentication packet.
    ///
    /// Wire format: `[Version(1)] [Command(1)] [UUID(16)] [Token_Len(2)] [Token(N)]`
    fn build_auth_packet(&self) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(2 + 16 + 2 + self.cfg.token.len());
        pkt.push(0x05); // version 5
        pkt.push(0x01); // auth command
        pkt.extend_from_slice(self.cfg.uuid.as_bytes());
        let token_bytes = self.cfg.token.as_bytes();
        pkt.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        pkt.extend_from_slice(token_bytes);
        pkt
    }

    /// Build TUIC v5 command packet (connect or UDP associate).
    ///
    /// Wire format: `[Command(1)] [AddrType(1)] [Addr(N)] [Port(2)]`
    fn build_command_packet(command: u8, host: &str, port: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(1 + 1 + host.len() + 2 + 2);
        pkt.push(command);

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    pkt.push(0x01);
                    pkt.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    pkt.push(0x04);
                    pkt.extend_from_slice(&v6.octets());
                }
            }
        } else {
            // domain
            pkt.push(0x03);
            pkt.push(host.len() as u8);
            pkt.extend_from_slice(host.as_bytes());
        }

        pkt.extend_from_slice(&port.to_be_bytes());
        pkt
    }

    /// Build a TUIC v5 CONNECT packet.
    fn build_connect_packet(host: &str, port: u16) -> Vec<u8> {
        Self::build_command_packet(0x02, host, port)
    }

    /// Perform the full TUIC v5 handshake on a bidirectional QUIC stream:
    ///   1. Send auth packet (UUID + token)
    ///   2. Send connect request (target addr + port)
    ///   3. Read 16-byte response; first byte must be 0x00 for success
    async fn tuic_handshake(
        &self,
        stream: &mut super::quic_util::QuicBidiStream,
        target_host: &str,
        target_port: u16,
    ) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 1. Auth
        let auth = self.build_auth_packet();
        stream
            .write_all(&auth)
            .await
            .map_err(|e| std::io::Error::other(format!("TUIC auth write: {e}")))?;

        // 2. Connect
        let connect = Self::build_connect_packet(target_host, target_port);
        stream
            .write_all(&connect)
            .await
            .map_err(|e| std::io::Error::other(format!("TUIC connect write: {e}")))?;

        // 3. Response
        let mut response = [0u8; 16];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| std::io::Error::other(format!("TUIC handshake read: {e}")))?;

        if response[0] != 0x00 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("TUIC authentication failed: status {:02x}", response[0]),
            ));
        }

        tracing::info!(
            target_host,
            target_port,
            "TUIC handshake completed successfully"
        );
        Ok(())
    }

    // ----- UDP packet helpers (kept public for potential future UDP relay) --

    /// Encode a UDP-over-stream packet.
    ///
    /// Wire format:
    /// `[Length(2)] [FragID(1)] [FragTotal(1)] [AddrType(1)] [Addr(N)] [Port(2)] [Data(N)]`
    #[allow(dead_code)]
    pub fn encode_udp_packet(
        target_host: &str,
        target_port: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(2 + 2 + 1 + target_host.len() + 2 + 2 + data.len());

        // length placeholder
        pkt.extend_from_slice(&[0u8; 2]);

        // fragment: id=0, total=1 (no fragmentation)
        pkt.push(0);
        pkt.push(1);

        // address
        if let Ok(ip) = target_host.parse::<std::net::IpAddr>() {
            match ip {
                std::net::IpAddr::V4(v4) => {
                    pkt.push(0x01);
                    pkt.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    pkt.push(0x04);
                    pkt.extend_from_slice(&v6.octets());
                }
            }
        } else {
            pkt.push(0x03);
            pkt.push(target_host.len() as u8);
            pkt.extend_from_slice(target_host.as_bytes());
        }

        // port + payload
        pkt.extend_from_slice(&target_port.to_be_bytes());
        pkt.extend_from_slice(data);

        // fill length (excludes the 2-byte length prefix itself)
        let length = (pkt.len() - 2) as u16;
        pkt[0..2].copy_from_slice(&length.to_be_bytes());

        pkt
    }

    /// Decode a UDP-over-stream packet.
    ///
    /// Returns `(host, port, payload)`.
    #[allow(dead_code)]
    pub fn decode_udp_packet(data: &[u8]) -> std::io::Result<(String, u16, Vec<u8>)> {
        if data.len() < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP packet too short",
            ));
        }

        let mut off = 0usize;

        // length header
        let length = u16::from_be_bytes([data[off], data[off + 1]]) as usize;
        off += 2;

        if data.len() < off + length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "UDP packet length mismatch",
            ));
        }

        // skip fragment id + total
        off += 2;

        // address type
        let addr_type = data[off];
        off += 1;

        let host = match addr_type {
            0x01 => {
                if data.len() < off + 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid IPv4 address in UDP packet",
                    ));
                }
                let v4 = std::net::Ipv4Addr::new(
                    data[off],
                    data[off + 1],
                    data[off + 2],
                    data[off + 3],
                );
                off += 4;
                v4.to_string()
            }
            0x03 => {
                let len = data[off] as usize;
                off += 1;
                if data.len() < off + len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid domain length in UDP packet",
                    ));
                }
                let domain = String::from_utf8(data[off..off + len].to_vec()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid UTF-8 in domain",
                    )
                })?;
                off += len;
                domain
            }
            0x04 => {
                if data.len() < off + 16 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Invalid IPv6 address in UDP packet",
                    ));
                }
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&data[off..off + 16]);
                off += 16;
                std::net::Ipv6Addr::from(bytes).to_string()
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unknown TUIC address type: {other}"),
                ));
            }
        };

        if data.len() < off + 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Missing port in UDP packet",
            ));
        }
        let port = u16::from_be_bytes([data[off], data[off + 1]]);
        off += 2;

        let payload = data[off..].to_vec();
        Ok((host, port, payload))
    }
}

#[cfg(feature = "adapter-tuic")]
impl Clone for TuicConnector {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            quic_config: self.quic_config.clone(),
            pool: tokio::sync::Mutex::new(None), // new pool for clone
        }
    }
}

#[cfg(feature = "adapter-tuic")]
impl Default for TuicConnector {
    fn default() -> Self {
        Self::new(TuicAdapterConfig::default())
    }
}

#[cfg(not(feature = "adapter-tuic"))]
impl TuicConnector {
    pub fn new(cfg: TuicAdapterConfig) -> Self {
        Self { cfg }
    }
}

// ---------------------------------------------------------------------------
// OutboundConnector trait implementation
// ---------------------------------------------------------------------------

#[async_trait]
impl OutboundConnector for TuicConnector {
    fn name(&self) -> &'static str {
        "tuic"
    }

    async fn start(&self) -> Result<()> {
        #[cfg(not(feature = "adapter-tuic"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-tuic feature not enabled",
        });

        #[cfg(feature = "adapter-tuic")]
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        #[cfg(not(feature = "adapter-tuic"))]
        return Err(AdapterError::NotImplemented {
            what: "adapter-tuic feature not enabled",
        });

        #[cfg(feature = "adapter-tuic")]
        {
            if target.kind != TransportKind::Tcp {
                return Err(AdapterError::Protocol(
                    "TUIC outbound only supports TCP (UDP support via create_udp_transport)"
                        .to_string(),
                ));
            }

            let _span = crate::outbound::span_dial("tuic", &target);

            // 1. Get or create pooled QUIC connection
            let connection = self.get_connection().await.map_err(AdapterError::Io)?;

            // 2. Open a bidirectional QUIC stream
            let (send_stream, recv_stream) = connection.open_bi().await.map_err(|e| {
                AdapterError::Io(std::io::Error::other(format!(
                    "Failed to open QUIC bi-stream: {e}"
                )))
            })?;

            let mut quic_stream =
                super::quic_util::QuicBidiStream::new(send_stream, recv_stream);

            // 3. Perform TUIC v5 handshake (auth + connect)
            self.tuic_handshake(&mut quic_stream, &target.host, target.port)
                .await
                .map_err(AdapterError::Io)?;

            // 4. Return the authenticated stream as BoxedStream
            Ok(Box::new(quic_stream) as BoxedStream)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tuic_connector_name() {
        let c = TuicConnector::new(TuicAdapterConfig::default());
        assert_eq!(c.name(), "tuic");
    }

    #[test]
    fn test_tuic_config_default() {
        let cfg = TuicAdapterConfig::default();
        assert_eq!(cfg.server, "127.0.0.1");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.token, "password");
        assert!(!cfg.skip_cert_verify);
        assert!(!cfg.udp_over_stream);
    }

    #[test]
    fn test_tuic_config_with_custom_values() {
        let uuid = uuid::Uuid::new_v4();
        let cfg = TuicAdapterConfig {
            server: "example.com".to_string(),
            port: 8443,
            uuid,
            token: "custom-token".to_string(),
            password: Some("custom-password".to_string()),
            congestion_control: Some("bbr".to_string()),
            alpn: Some("h3".to_string()),
            skip_cert_verify: true,
            udp_relay_mode: TuicUdpRelayMode::Quic,
            udp_over_stream: true,
        };

        assert_eq!(cfg.server, "example.com");
        assert_eq!(cfg.port, 8443);
        assert_eq!(cfg.uuid, uuid);
        assert_eq!(cfg.token, "custom-token");
        assert_eq!(cfg.password, Some("custom-password".to_string()));
        assert_eq!(cfg.congestion_control, Some("bbr".to_string()));
        assert_eq!(cfg.alpn, Some("h3".to_string()));
        assert!(cfg.skip_cert_verify);
        assert!(matches!(cfg.udp_relay_mode, TuicUdpRelayMode::Quic));
        assert!(cfg.udp_over_stream);
    }

    #[test]
    fn test_tuic_udp_relay_mode_default() {
        let mode = TuicUdpRelayMode::default();
        assert!(matches!(mode, TuicUdpRelayMode::Native));
    }

    #[test]
    fn test_tuic_connector_creation() {
        let cfg = TuicAdapterConfig {
            server: "test.example.com".to_string(),
            port: 9443,
            uuid: uuid::Uuid::new_v4(),
            token: "test-token".to_string(),
            password: None,
            congestion_control: Some("cubic".to_string()),
            alpn: Some("tuic".to_string()),
            skip_cert_verify: false,
            udp_relay_mode: TuicUdpRelayMode::Native,
            udp_over_stream: false,
        };

        let connector = TuicConnector::new(cfg.clone());
        assert_eq!(connector.cfg.server, cfg.server);
        assert_eq!(connector.cfg.port, cfg.port);
        assert_eq!(connector.cfg.token, cfg.token);
    }

    #[test]
    fn test_tuic_connector_default() {
        let connector = TuicConnector::default();
        assert_eq!(connector.name(), "tuic");
        assert_eq!(connector.cfg.server, "127.0.0.1");
        assert_eq!(connector.cfg.port, 443);
    }

    #[cfg(feature = "adapter-tuic")]
    #[tokio::test]
    async fn test_tuic_connector_start_with_feature() {
        let connector = TuicConnector::default();
        let result = connector.start().await;
        assert!(result.is_ok());
    }

    #[cfg(not(feature = "adapter-tuic"))]
    #[tokio::test]
    async fn test_tuic_connector_start_without_feature() {
        let connector = TuicConnector::default();
        let result = connector.start().await;
        assert!(result.is_err());

        if let Err(AdapterError::NotImplemented { what }) = result {
            assert!(what.contains("adapter-tuic"));
        } else {
            panic!("Expected NotImplemented error");
        }
    }

    #[test]
    fn test_tuic_config_validation_server() {
        let cfg = TuicAdapterConfig {
            server: "".to_string(),
            ..TuicAdapterConfig::default()
        };

        // Empty server should still create config (validation happens at connection time)
        assert_eq!(cfg.server, "");
    }

    #[test]
    fn test_tuic_config_validation_port() {
        let cfg = TuicAdapterConfig {
            port: 0,
            ..TuicAdapterConfig::default()
        };

        // Port 0 should still create config (validation happens at connection time)
        assert_eq!(cfg.port, 0);
    }

    #[test]
    fn test_tuic_config_clone() {
        let cfg1 = TuicAdapterConfig::default();
        let cfg2 = cfg1.clone();

        assert_eq!(cfg1.server, cfg2.server);
        assert_eq!(cfg1.port, cfg2.port);
        assert_eq!(cfg1.token, cfg2.token);
    }

    #[test]
    fn test_tuic_connector_clone() {
        let connector1 = TuicConnector::default();
        let connector2 = connector1.clone();

        assert_eq!(connector1.name(), connector2.name());
        assert_eq!(connector1.cfg.server, connector2.cfg.server);
    }

    #[test]
    fn test_tuic_config_debug() {
        let cfg = TuicAdapterConfig::default();
        let debug_str = format!("{:?}", cfg);

        // Should contain key fields
        assert!(debug_str.contains("server"));
        assert!(debug_str.contains("port"));
        assert!(debug_str.contains("token"));
    }

    #[test]
    fn test_tuic_udp_relay_mode_variants() {
        let native = TuicUdpRelayMode::Native;
        let quic = TuicUdpRelayMode::Quic;

        // Test that variants are different
        assert!(matches!(native, TuicUdpRelayMode::Native));
        assert!(matches!(quic, TuicUdpRelayMode::Quic));
    }

    // ------- protocol packet unit tests ------------------------------------

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_build_auth_packet() {
        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let connector = TuicConnector::new(TuicAdapterConfig {
            uuid,
            token: "hello".to_string(),
            ..TuicAdapterConfig::default()
        });

        let pkt = connector.build_auth_packet();

        assert_eq!(pkt[0], 0x05); // version
        assert_eq!(pkt[1], 0x01); // auth command
        assert_eq!(&pkt[2..18], uuid.as_bytes()); // UUID
        let token_len = u16::from_be_bytes([pkt[18], pkt[19]]);
        assert_eq!(token_len, 5);
        assert_eq!(&pkt[20..25], b"hello");
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_build_connect_packet_domain() {
        let pkt = TuicConnector::build_connect_packet("example.com", 443);

        assert_eq!(pkt[0], 0x02); // connect command
        assert_eq!(pkt[1], 0x03); // domain
        assert_eq!(pkt[2], 11);   // domain length
        assert_eq!(&pkt[3..14], b"example.com");
        let port = u16::from_be_bytes([pkt[14], pkt[15]]);
        assert_eq!(port, 443);
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_build_connect_packet_ipv4() {
        let pkt = TuicConnector::build_connect_packet("127.0.0.1", 8080);

        assert_eq!(pkt[0], 0x02); // connect
        assert_eq!(pkt[1], 0x01); // IPv4
        assert_eq!(&pkt[2..6], &[127, 0, 0, 1]);
        let port = u16::from_be_bytes([pkt[6], pkt[7]]);
        assert_eq!(port, 8080);
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_build_connect_packet_ipv6() {
        let pkt = TuicConnector::build_connect_packet("::1", 9090);

        assert_eq!(pkt[0], 0x02);
        assert_eq!(pkt[1], 0x04); // IPv6
        let expected: [u8; 16] = std::net::Ipv6Addr::LOCALHOST.octets();
        assert_eq!(&pkt[2..18], &expected);
        let port = u16::from_be_bytes([pkt[18], pkt[19]]);
        assert_eq!(port, 9090);
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_encode_decode_udp_packet_domain() {
        let data = b"hello world";
        let encoded = TuicConnector::encode_udp_packet("example.com", 443, data);
        let (host, port, payload) = TuicConnector::decode_udp_packet(&encoded).unwrap();

        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(payload, data);
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_encode_decode_udp_packet_ipv4() {
        let data = b"test payload";
        let encoded = TuicConnector::encode_udp_packet("10.0.0.1", 1234, data);
        let (host, port, payload) = TuicConnector::decode_udp_packet(&encoded).unwrap();

        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 1234);
        assert_eq!(payload, data);
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_encode_decode_udp_packet_ipv6() {
        let data = b"v6 data";
        let encoded = TuicConnector::encode_udp_packet("::1", 5678, data);
        let (host, port, payload) = TuicConnector::decode_udp_packet(&encoded).unwrap();

        assert_eq!(host, "::1");
        assert_eq!(port, 5678);
        assert_eq!(payload, data);
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_decode_udp_packet_too_short() {
        let result = TuicConnector::decode_udp_packet(&[0x00]);
        assert!(result.is_err());
    }

    #[cfg(feature = "adapter-tuic")]
    #[test]
    fn test_decode_udp_packet_length_mismatch() {
        // claim 255 bytes of payload but only provide header
        let data = [0x00, 0xFF, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50];
        let result = TuicConnector::decode_udp_packet(&data);
        assert!(result.is_err());
    }
}
