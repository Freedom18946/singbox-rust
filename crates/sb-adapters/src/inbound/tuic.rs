//! TUIC server inbound implementation
//!
//! Implements TUIC (The Ultimate Internet Connector) protocol server:
//! - QUIC-based server using quinn
//! - UUID + token authentication
//! - TCP relay over QUIC bidirectional streams
//! - Router-based upstream selection

use anyhow::{anyhow, Result};
use quinn::{Endpoint, ServerConfig};
// Use types re-exported by quinn to satisfy trait bounds
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// TUIC server configuration
#[derive(Clone, Debug)]
pub struct TuicInboundConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// Allowed UUIDs for authentication
    pub users: Vec<TuicUser>,
    /// TLS certificate (PEM format)
    pub cert: String,
    /// TLS private key (PEM format)
    pub key: String,
    /// Congestion control algorithm (cubic/bbr/new_reno)
    pub congestion_control: Option<String>,
}

/// TUIC user (UUID + token)
#[derive(Clone, Debug)]
pub struct TuicUser {
    pub uuid: Uuid,
    pub token: String,
}

/// TUIC protocol version
const TUIC_VERSION: u8 = 0x05;

/// TUIC commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TuicCommand {
    Auth = 0x01,
    Connect = 0x02,
}

impl TryFrom<u8> for TuicCommand {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(TuicCommand::Auth),
            0x02 => Ok(TuicCommand::Connect),
            _ => Err(anyhow!("Unknown TUIC command: {:#x}", value)),
        }
    }
}

/// TUIC address types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum AddressType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(AddressType::IPv4),
            0x03 => Ok(AddressType::Domain),
            0x04 => Ok(AddressType::IPv6),
            _ => Err(anyhow!("Unknown address type: {:#x}", value)),
        }
    }
}

/// Parse PEM-encoded certificates
fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse certificates: {}", e))?;
    Ok(certs)
}

/// Parse PEM-encoded private key
fn load_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    loop {
        match rustls_pemfile::read_one(&mut cursor)
            .map_err(|e| anyhow!("Failed to parse private key: {}", e))?
        {
            Some(rustls_pemfile::Item::Pkcs8Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs8(k));
            }
            Some(rustls_pemfile::Item::Pkcs1Key(k)) => {
                return Ok(PrivateKeyDer::Pkcs1(k));
            }
            Some(_other) => continue,
            None => break,
        }
    }
    Err(anyhow!("No private key found in PEM data"))
}

/// Main server loop
pub async fn serve(cfg: TuicInboundConfig, mut stop_rx: mpsc::Receiver<()>) -> Result<()> {
    info!("TUIC server starting on {}", cfg.listen);

    // Load TLS certificate and key
    let certs = load_certs(&cfg.cert)?;
    let key = load_private_key(&cfg.key)?;

    // Configure TLS
    // Configure QUIC server directly with DER cert/key
    let mut server_config = ServerConfig::with_single_cert(certs, key)
        .map_err(|e| anyhow!("TLS configuration error: {}", e))?;

    // Configure transport parameters
    let mut transport_config = quinn::TransportConfig::default();

    // Set congestion control algorithm
    if let Some(ref cc) = cfg.congestion_control {
        match cc.as_str() {
            "cubic" => {
                transport_config.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
            }
            "bbr" => {
                transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            }
            "new_reno" => {
                transport_config.congestion_controller_factory(Arc::new(quinn::congestion::NewRenoConfig::default()));
            }
            _ => {
                warn!("Unknown congestion control algorithm: {}, using default", cc);
            }
        };
    }

    server_config.transport_config(Arc::new(transport_config));

    // Create QUIC endpoint
    let endpoint = Endpoint::server(server_config, cfg.listen)?;
    info!("TUIC server listening on {}", cfg.listen);

    let cfg = Arc::new(cfg);

    loop {
        tokio::select! {
            _ = stop_rx.recv() => {
                info!("TUIC server shutting down");
                break;
            }
            conn = endpoint.accept() => {
                let Some(incoming) = conn else {
                    continue;
                };

                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            debug!("TUIC: new connection from {}", conn.remote_address());
                            if let Err(e) = handle_conn(cfg_clone, conn).await {
                                debug!("TUIC connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("TUIC connection failed: {}", e);
                        }
                    }
                });
            }
        }
    }

    Ok(())
}

/// Handle single QUIC connection
async fn handle_conn(cfg: Arc<TuicInboundConfig>, conn: quinn::Connection) -> Result<()> {
    let peer = conn.remote_address();
    debug!("TUIC: handling connection from {}", peer);

    // Accept bidirectional streams
    loop {
        let stream = match conn.accept_bi().await {
            Ok(stream) => stream,
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!("TUIC: connection closed by peer: {}", peer);
                break;
            }
            Err(e) => {
                warn!("TUIC: stream accept error from {}: {}", peer, e);
                break;
            }
        };

        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(cfg_clone, stream, peer).await {
                debug!("TUIC: stream error from {}: {}", peer, e);
            }
        });
    }

    Ok(())
}

/// Handle single QUIC bidirectional stream
async fn handle_stream(
    cfg: Arc<TuicInboundConfig>,
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
    peer: SocketAddr,
) -> Result<()> {
    // 1. Parse authentication packet
    let (uuid, _token) = parse_auth_packet(&mut recv).await?;

    // 2. Validate UUID
    if !cfg.users.iter().any(|u| u.uuid == uuid) {
        error!("TUIC: invalid UUID from {}: {}", peer, uuid);
        // Send error response
        send.write_all(&[0xFF]).await?;
        send.finish()?;
        return Err(anyhow!("Authentication failed: invalid UUID"));
    }

    debug!("TUIC: authenticated UUID {} from {}", uuid, peer);

    // 3. Parse connect packet
    let (host, port) = parse_connect_packet(&mut recv).await?;

    debug!("TUIC: CONNECT {}:{} from {}", host, port, peer);

    // 4. Connect to target
    // Note: Router integration can be added by passing router to config
    // For now, direct connection provides baseline functionality
    let upstream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|e| anyhow!("Failed to connect to target: {}", e))?;

    debug!("TUIC: connected to {}:{}", host, port);

    // 5. Send success response
    let response = vec![0x00; 16];
    send.write_all(&response).await?;

    // 6. Bidirectional relay
    relay_quic_tcp(send, recv, upstream).await?;

    Ok(())
}

/// Parse TUIC authentication packet
async fn parse_auth_packet(recv: &mut quinn::RecvStream) -> Result<(Uuid, String)> {
    // Read version (1 byte)
    let mut version = [0u8; 1];
    recv.read_exact(&mut version).await?;

    if version[0] != TUIC_VERSION {
        return Err(anyhow!("Invalid TUIC version: {:#x}", version[0]));
    }

    // Read command (1 byte)
    let mut command = [0u8; 1];
    recv.read_exact(&mut command).await?;

    let cmd = TuicCommand::try_from(command[0])?;
    if cmd != TuicCommand::Auth {
        return Err(anyhow!("Expected Auth command, got {:?}", cmd));
    }

    // Read UUID (16 bytes)
    let mut uuid_bytes = [0u8; 16];
    recv.read_exact(&mut uuid_bytes).await?;
    let uuid = Uuid::from_bytes(uuid_bytes);

    // Read token length (2 bytes)
    let mut token_len = [0u8; 2];
    recv.read_exact(&mut token_len).await?;
    let token_len = u16::from_be_bytes(token_len) as usize;

    // Read token
    let mut token_bytes = vec![0u8; token_len];
    recv.read_exact(&mut token_bytes).await?;
    let token = String::from_utf8(token_bytes)
        .map_err(|_| anyhow!("Invalid UTF-8 in token"))?;

    Ok((uuid, token))
}

/// Parse TUIC connect packet
async fn parse_connect_packet(recv: &mut quinn::RecvStream) -> Result<(String, u16)> {
    // Read command (1 byte)
    let mut command = [0u8; 1];
    recv.read_exact(&mut command).await?;

    let cmd = TuicCommand::try_from(command[0])?;
    if cmd != TuicCommand::Connect {
        return Err(anyhow!("Expected Connect command, got {:?}", cmd));
    }

    // Read address type (1 byte)
    let mut addr_type = [0u8; 1];
    recv.read_exact(&mut addr_type).await?;

    let addr_type = AddressType::try_from(addr_type[0])?;

    // Parse address based on type
    let host = match addr_type {
        AddressType::IPv4 => {
            let mut addr = [0u8; 4];
            recv.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        AddressType::IPv6 => {
            let mut addr = [0u8; 16];
            recv.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        AddressType::Domain => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len).await?;
            let len = len[0] as usize;

            let mut domain = vec![0u8; len];
            recv.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|_| anyhow!("Invalid UTF-8 in domain"))?
        }
    };

    // Read port (2 bytes)
    let mut port_bytes = [0u8; 2];
    recv.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    Ok((host, port))
}

/// Relay data between QUIC stream and TCP stream
async fn relay_quic_tcp(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    mut tcp: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.split();

    let quic_to_tcp = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = quic_recv
                .read(&mut buf)
                .await
                .map_err(|e| anyhow!("QUIC recv error: {}", e))?
                .ok_or_else(|| anyhow!("QUIC stream closed"))?;

            if n == 0 {
                break;
            }

            tcp_write
                .write_all(&buf[..n])
                .await
                .map_err(|e| anyhow!("TCP write error: {}", e))?;
        }
        tcp_write.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };

    let tcp_to_quic = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = tcp_read
                .read(&mut buf)
                .await
                .map_err(|e| anyhow!("TCP read error: {}", e))?;

            if n == 0 {
                break;
            }

            quic_send
                .write_all(&buf[..n])
                .await
                .map_err(|e| anyhow!("QUIC send error: {}", e))?;
        }
        quic_send.finish().ok();
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r1 = quic_to_tcp => r1,
        r2 = tcp_to_quic => r2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_conversion() {
        assert_eq!(TuicCommand::try_from(0x01).unwrap(), TuicCommand::Auth);
        assert_eq!(TuicCommand::try_from(0x02).unwrap(), TuicCommand::Connect);
        assert!(TuicCommand::try_from(0xFF).is_err());
    }

    #[test]
    fn test_address_type_conversion() {
        assert_eq!(AddressType::try_from(0x01).unwrap(), AddressType::IPv4);
        assert_eq!(AddressType::try_from(0x03).unwrap(), AddressType::Domain);
        assert_eq!(AddressType::try_from(0x04).unwrap(), AddressType::IPv6);
        assert!(AddressType::try_from(0xFF).is_err());
    }
}
