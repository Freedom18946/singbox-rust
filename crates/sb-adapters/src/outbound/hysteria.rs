//! Hysteria v1 outbound connector implementation
use crate::outbound::prelude::*;

/// Hysteria v1 adapter configuration
#[derive(Debug, Clone)]
pub struct HysteriaAdapterConfig {
    pub server: String,
    pub port: u16,
    pub protocol: String,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub obfs: Option<String>,
    pub auth: Option<String>,
    pub alpn: Vec<String>,
    pub recv_window_conn: Option<u64>,
    pub recv_window: Option<u64>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
}

impl Default for HysteriaAdapterConfig {
    fn default() -> Self {
        Self {
            server: "127.0.0.1".to_string(),
            port: 443,
            protocol: "udp".to_string(),
            up_mbps: 10,
            down_mbps: 50,
            obfs: None,
            auth: None,
            alpn: vec!["hysteria".to_string()],
            recv_window_conn: None,
            recv_window: None,
            skip_cert_verify: false,
            sni: None,
        }
    }
}

/// Hysteria v1 outbound connector
#[derive(Debug, Clone, Default)]
pub struct HysteriaConnector {
    cfg: HysteriaAdapterConfig,
}

impl HysteriaConnector {
    pub fn new(cfg: HysteriaAdapterConfig) -> Self {
        Self { cfg }
    }
}

#[async_trait]
impl OutboundConnector for HysteriaConnector {
    fn name(&self) -> &'static str {
        "hysteria"
    }

    async fn start(&self) -> Result<()> {
        Ok(())
    }

    async fn dial(&self, target: Target, _opts: DialOpts) -> Result<BoxedStream> {
        if target.kind != TransportKind::Tcp {
            return Err(AdapterError::Protocol(
                "Hysteria v1 outbound only supports TCP".to_string(),
            ));
        }

        let _span = crate::outbound::span_dial("hysteria", &target);

        // Build QUIC config with ALPN and insecure settings
        let alpn_bytes: Vec<Vec<u8>> = if self.cfg.alpn.is_empty() {
            vec![b"hysteria".to_vec()]
        } else {
            self.cfg.alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
        };

        let quic_cfg = super::quic_util::QuicConfig::new(
            self.cfg.server.clone(),
            self.cfg.port,
        )
        .with_alpn(alpn_bytes)
        .with_allow_insecure(self.cfg.skip_cert_verify)
        .with_sni(self.cfg.sni.clone());

        // Establish QUIC connection
        tracing::debug!(
            server = %self.cfg.server,
            port = self.cfg.port,
            "hysteria v1: establishing QUIC connection"
        );
        let connection = super::quic_util::quic_connect(&quic_cfg)
            .await
            .map_err(|e| AdapterError::Other(format!("QUIC connection failed: {}", e)))?;

        // Perform Hysteria v1 handshake
        tracing::debug!("hysteria v1: performing handshake");
        hysteria_handshake(&connection, &self.cfg)
            .await
            .map_err(|e| AdapterError::Io(e))?;

        // Create TCP tunnel to the target
        tracing::debug!(
            host = %target.host,
            port = target.port,
            "hysteria v1: creating TCP tunnel"
        );
        let (send, recv) = create_tcp_tunnel(&connection, &target.host, target.port)
            .await
            .map_err(|e| AdapterError::Io(e))?;

        Ok(Box::new(super::quic_util::QuicBidiStream::new(send, recv)) as BoxedStream)
    }
}

/// Perform Hysteria v1 handshake over the given QUIC connection.
///
/// Sends protocol version, bandwidth config, auth, and obfs to the server
/// on a bidirectional stream, then reads the response status.
async fn hysteria_handshake(
    connection: &quinn::Connection,
    cfg: &HysteriaAdapterConfig,
) -> std::io::Result<()> {
    use bytes::{BufMut, BytesMut};

    // Open handshake stream
    let (mut send_stream, mut recv_stream) = connection
        .open_bi()
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to open handshake stream: {}", e)))?;

    // Build handshake packet
    let mut handshake = BytesMut::new();

    // Protocol version (v1)
    handshake.put_u8(0x01);

    // Bandwidth configuration
    handshake.put_u32(cfg.up_mbps);
    handshake.put_u32(cfg.down_mbps);

    // Authentication
    if let Some(ref auth) = cfg.auth {
        handshake.put_u8(auth.len() as u8);
        handshake.put_slice(auth.as_bytes());
    } else {
        handshake.put_u8(0);
    }

    // Obfuscation
    if let Some(ref obfs) = cfg.obfs {
        handshake.put_u8(obfs.len() as u8);
        handshake.put_slice(obfs.as_bytes());
    } else {
        handshake.put_u8(0);
    }

    // Send handshake
    send_stream
        .write_all(&handshake)
        .await
        .map_err(|e| std::io::Error::other(format!("Handshake write failed: {}", e)))?;

    send_stream
        .finish()
        .map_err(|e| std::io::Error::other(format!("Handshake finish failed: {}", e)))?;

    // Read handshake response (2 bytes: status + reserved)
    let mut response = [0u8; 2];
    recv_stream
        .read_exact(&mut response)
        .await
        .map_err(|e| std::io::Error::other(format!("Handshake response read failed: {}", e)))?;

    // Check response status
    match response[0] {
        0x00 => {
            tracing::debug!("hysteria v1: handshake succeeded");
            Ok(())
        }
        0x01 => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Hysteria v1 authentication failed",
        )),
        code => Err(std::io::Error::other(format!(
            "Hysteria v1 handshake failed with code: {}",
            code
        ))),
    }
}

/// Create a TCP tunnel through the Hysteria v1 connection.
///
/// Sends a connect command (0x01) with SOCKS5-like target address encoding,
/// then returns the bidirectional QUIC streams for data transfer.
async fn create_tcp_tunnel(
    connection: &quinn::Connection,
    host: &str,
    port: u16,
) -> std::io::Result<(quinn::SendStream, quinn::RecvStream)> {
    use bytes::{BufMut, BytesMut};

    // Open bidirectional stream for tunneling
    let (mut send_stream, recv_stream) = connection
        .open_bi()
        .await
        .map_err(|e| std::io::Error::other(format!("Failed to open tunnel stream: {}", e)))?;

    // Build connect request
    let mut request = BytesMut::new();
    request.put_u8(0x01); // Command: TCP connect

    // Encode target address (SOCKS5-like format)
    encode_target_address(&mut request, host, port)?;

    // Send connect request
    send_stream
        .write_all(&request)
        .await
        .map_err(|e| std::io::Error::other(format!("Connect request write failed: {}", e)))?;

    Ok((send_stream, recv_stream))
}

/// Encode a target address into a buffer using SOCKS5-like format.
///
/// - IPv4: `0x01` + 4 bytes octets + 2 bytes port
/// - IPv6: `0x04` + 16 bytes octets + 2 bytes port
/// - Domain: `0x03` + 1 byte length + domain bytes + 2 bytes port
fn encode_target_address(
    buffer: &mut bytes::BytesMut,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    use bytes::BufMut;

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                buffer.put_u8(0x01);
                buffer.put_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                buffer.put_u8(0x04);
                buffer.put_slice(&v6.octets());
            }
        }
    } else {
        buffer.put_u8(0x03);
        let domain_bytes = host.as_bytes();
        if domain_bytes.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Domain name too long",
            ));
        }
        buffer.put_u8(domain_bytes.len() as u8);
        buffer.put_slice(domain_bytes);
    }
    buffer.put_u16(port);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria_connector_name() {
        let c = HysteriaConnector::new(HysteriaAdapterConfig::default());
        assert_eq!(c.name(), "hysteria");
    }

    #[test]
    fn test_hysteria_config_default() {
        let cfg = HysteriaAdapterConfig::default();
        assert_eq!(cfg.server, "127.0.0.1");
        assert_eq!(cfg.port, 443);
        assert_eq!(cfg.protocol, "udp");
        assert_eq!(cfg.up_mbps, 10);
        assert_eq!(cfg.down_mbps, 50);
        assert_eq!(cfg.obfs, None);
        assert_eq!(cfg.auth, None);
        assert_eq!(cfg.alpn, vec!["hysteria".to_string()]);
        assert!(!cfg.skip_cert_verify);
    }

    #[test]
    fn test_encode_target_address_ipv4() {
        let mut buf = bytes::BytesMut::new();
        encode_target_address(&mut buf, "192.168.1.1", 8080).unwrap();
        assert_eq!(buf[0], 0x01); // IPv4
        assert_eq!(&buf[1..5], &[192, 168, 1, 1]);
        assert_eq!(&buf[5..7], &8080u16.to_be_bytes());
        assert_eq!(buf.len(), 1 + 4 + 2);
    }

    #[test]
    fn test_encode_target_address_ipv6() {
        let mut buf = bytes::BytesMut::new();
        encode_target_address(&mut buf, "::1", 443).unwrap();
        assert_eq!(buf[0], 0x04); // IPv6
        assert_eq!(buf.len(), 1 + 16 + 2);
    }

    #[test]
    fn test_encode_target_address_domain() {
        let mut buf = bytes::BytesMut::new();
        encode_target_address(&mut buf, "example.com", 443).unwrap();
        assert_eq!(buf[0], 0x03); // Domain
        assert_eq!(buf[1], 11); // "example.com".len()
        assert_eq!(&buf[2..13], b"example.com");
        assert_eq!(&buf[13..15], &443u16.to_be_bytes());
        assert_eq!(buf.len(), 1 + 1 + 11 + 2);
    }

    #[test]
    fn test_encode_target_address_domain_too_long() {
        let mut buf = bytes::BytesMut::new();
        let long_domain = "a".repeat(256);
        let result = encode_target_address(&mut buf, &long_domain, 443);
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_packet_structure() {
        use bytes::{BufMut, BytesMut};

        let mut handshake = BytesMut::new();
        handshake.put_u8(0x01); // version
        handshake.put_u32(100); // up_mbps
        handshake.put_u32(200); // down_mbps
        let auth = "test-auth";
        handshake.put_u8(auth.len() as u8);
        handshake.put_slice(auth.as_bytes());
        let obfs = "test-obfs";
        handshake.put_u8(obfs.len() as u8);
        handshake.put_slice(obfs.as_bytes());

        assert_eq!(handshake[0], 0x01);
        assert_eq!(handshake.len(), 1 + 8 + 1 + 9 + 1 + 9);
    }

    #[test]
    fn test_handshake_packet_without_auth_obfs() {
        use bytes::{BufMut, BytesMut};

        let mut handshake = BytesMut::new();
        handshake.put_u8(0x01); // version
        handshake.put_u32(100); // up_mbps
        handshake.put_u32(200); // down_mbps
        handshake.put_u8(0);    // no auth
        handshake.put_u8(0);    // no obfs

        assert_eq!(handshake.len(), 1 + 8 + 1 + 1);
    }

    #[test]
    fn test_tcp_connect_request_structure() {
        use bytes::{BufMut, BytesMut};

        let mut request = BytesMut::new();
        request.put_u8(0x01); // TCP connect command
        encode_target_address(&mut request, "192.168.1.1", 8080).unwrap();

        assert_eq!(request[0], 0x01); // command
        assert_eq!(request[1], 0x01); // IPv4 address type
        assert_eq!(request.len(), 1 + 1 + 4 + 2);
    }
}
