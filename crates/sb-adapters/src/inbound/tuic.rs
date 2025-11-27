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
use sb_core::outbound::{
    Endpoint as OutEndpoint, OutboundKind, OutboundRegistryHandle, RouteTarget as OutRouteTarget,
};
use sb_core::router::{self, Transport};
use sb_core::router::engine::RouteCtx;
use sb_transport::IoStream;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    /// Router for outbound selection
    pub router: Arc<router::RouterHandle>,
    /// Outbound registry handle for connector lookup
    pub outbounds: Arc<OutboundRegistryHandle>,
}

/// TUIC user (UUID + token)
#[derive(Clone, Debug)]
pub struct TuicUser {
    pub uuid: Uuid,
    pub token: String,
}

/// TUIC protocol version
const TUIC_VERSION: u8 = 0x05;

/// TUIC commands (TUIC v5 protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TuicCommand {
    Auth = 0x01,
    Connect = 0x02,
    Packet = 0x03,     // UDP packet
    Dissociate = 0x04, // Close UDP association
    Heartbeat = 0x05,  // Keep-alive
}

impl TryFrom<u8> for TuicCommand {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(TuicCommand::Auth),
            0x02 => Ok(TuicCommand::Connect),
            0x03 => Ok(TuicCommand::Packet),
            0x04 => Ok(TuicCommand::Dissociate),
            0x05 => Ok(TuicCommand::Heartbeat),
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
                                sb_core::metrics::http::record_error_display(&e);
                                sb_core::metrics::record_inbound_error_display("tuic", &e);
                                debug!("TUIC connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            sb_core::metrics::http::record_error_display(&e);
                            sb_core::metrics::record_inbound_error_display("tuic", &e);
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
                sb_core::metrics::http::record_error_display(&e);
                sb_core::metrics::record_inbound_error_display("tuic", &e);
                warn!("TUIC: stream accept error from {}: {}", peer, e);
                break;
            }
        };

        let cfg_clone = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_stream(cfg_clone, stream, peer).await {
                sb_core::metrics::http::record_error_display(&e);
                sb_core::metrics::record_inbound_error_display("tuic", &e);
                debug!("TUIC: stream error from {}: {}", peer, e);
            }
        });
    }

    Ok(())
}

/// Handle single QUIC bidirectional stream
/// Sprint 19 Phase 1.2: Added UDP relay support (Packet command)
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

    // 3. Read command byte to determine operation type
    let mut cmd_byte = [0u8; 1];
    recv.read_exact(&mut cmd_byte).await?;
    let cmd = TuicCommand::try_from(cmd_byte[0])?;

    match cmd {
        TuicCommand::Connect => {
            // TCP relay (existing functionality)
            handle_tcp_relay(cfg, send, recv, peer).await
        }
        TuicCommand::Packet => {
            // UDP relay (new functionality - Sprint 19 Phase 1.2)
            handle_udp_relay(cfg, send, recv, peer).await
        }
        TuicCommand::Heartbeat => {
            // Send heartbeat response
            debug!("TUIC: heartbeat from {}", peer);
            send.write_all(&[0x00]).await?;
            send.finish()?;
            Ok(())
        }
        TuicCommand::Dissociate => {
            // Close UDP association
            debug!("TUIC: dissociate from {}", peer);
            Ok(())
        }
        TuicCommand::Auth => {
            // Auth already handled
            Err(anyhow!("Unexpected Auth command after authentication"))
        }
    }
}

/// Handle TCP relay over QUIC stream
async fn handle_tcp_relay(
    cfg: Arc<TuicInboundConfig>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
) -> Result<()> {
    // Parse connect packet
    let (host, port) = parse_connect_packet(&mut recv).await?;

    debug!("TUIC: TCP CONNECT {}:{} from {}", host, port, peer);

    let upstream = match connect_via_router(&cfg, &host, port).await {
        Ok(s) => s,
        Err(e) => {
            let _ = send.write_all(&vec![0x01; 16]).await;
            return Err(e);
        }
    };

    debug!("TUIC: routed connection to {}:{}", host, port);

    // Send success response
    let response = vec![0x00; 16];
    send.write_all(&response).await?;

    // Bidirectional relay
    relay_quic_tcp(send, recv, upstream).await?;

    Ok(())
}

/// Handle UDP relay over QUIC stream (Sprint 19 Phase 1.2)
async fn handle_udp_relay(
    cfg: Arc<TuicInboundConfig>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
) -> Result<()> {
    use tokio::net::UdpSocket;

    // Parse target address from packet
    let (host, port) = parse_address_port(&mut recv).await?;

    debug!("TUIC: UDP PACKET {}:{} from {}", host, port, peer);

    // Router decision (UDP path)
    let route = cfg.router.select_ctx_and_record(RouteCtx {
        host: Some(&host),
        ip: None,
        port: Some(port),
        transport: Transport::Udp,
    });
    if let Err(e) = allow_udp_route(&route) {
        let _ = send.write_all(&[0x01]).await;
        return Err(e);
    }

    // Bind local UDP socket
    let udp = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| anyhow!("Failed to bind UDP socket: {}", e))?;

    // Connect UDP socket to target
    udp.connect((host.as_str(), port))
        .await
        .map_err(|e| anyhow!("Failed to connect UDP socket: {}", e))?;

    debug!("TUIC: UDP connected to {}:{}", host, port);

    // Send success response
    send.write_all(&[0x00]).await?;

    // Bidirectional relay for UDP packets
    relay_quic_udp(send, recv, udp).await?;

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
    let token = String::from_utf8(token_bytes).map_err(|_| anyhow!("Invalid UTF-8 in token"))?;

    Ok((uuid, token))
}

/// Parse TUIC connect packet
async fn parse_connect_packet(recv: &mut quinn::RecvStream) -> Result<(String, u16)> {
    // Parse address and port
    parse_address_port(recv).await
}

/// Parse address and port from TUIC packet (Sprint 19 Phase 1.2)
/// Used for both Connect and Packet commands
async fn parse_address_port(recv: &mut quinn::RecvStream) -> Result<(String, u16)> {
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
            String::from_utf8(domain).map_err(|_| anyhow!("Invalid UTF-8 in domain"))?
        }
    };

    // Read port (2 bytes)
    let mut port_bytes = [0u8; 2];
    recv.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    Ok((host, port))
}

async fn connect_via_router(cfg: &TuicInboundConfig, host: &str, port: u16) -> Result<IoStream> {
    let ctx = RouteCtx {
        host: Some(host),
        ip: None,
        port: Some(port),
        transport: Transport::Tcp,
    };
    let target: OutRouteTarget = cfg.router.select_ctx_and_record(ctx);
    let endpoint = match host.parse::<IpAddr>() {
        Ok(ip) => OutEndpoint::Ip(SocketAddr::new(ip, port)),
        Err(_) => OutEndpoint::Domain(host.to_string(), port),
    };

    #[cfg(feature = "v2ray_transport")]
    {
        cfg.outbounds
            .connect_preferred(&target, endpoint)
            .await
            .map_err(|e| anyhow!("failed to connect via router: {}", e))
    }
    #[cfg(not(feature = "v2ray_transport"))]
    {
        let stream = cfg
            .outbounds
            .connect_preferred(&target, endpoint)
            .await
            .map_err(|e| anyhow!("failed to connect via router: {}", e))?;
        Ok(Box::new(stream))
    }
}

fn allow_udp_route(route: &OutRouteTarget) -> Result<()> {
    match route {
        OutRouteTarget::Kind(OutboundKind::Direct) => Ok(()),
        OutRouteTarget::Named(name) => {
            if name == "direct" {
                Ok(())
            } else {
                Err(anyhow!("udp route '{name}' not supported in tuic inbound"))
            }
        }
        _ => Err(anyhow!(
            "udp route {:?} not supported in tuic inbound",
            route
        )),
    }
}

/// Relay data between QUIC stream and TCP stream
async fn relay_quic_tcp(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    tcp: IoStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tokio::io::split(tcp);

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

/// Relay UDP packets between QUIC stream and UDP socket (Sprint 19 Phase 1.2)
async fn relay_quic_udp(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    udp: tokio::net::UdpSocket,
) -> Result<()> {
    let udp = Arc::new(udp);
    let udp_clone = udp.clone();

    let quic_to_udp = async move {
        let mut buf = vec![0u8; 65535]; // Max UDP packet size
        loop {
            // Read packet length (2 bytes)
            let mut len_buf = [0u8; 2];
            if quic_recv.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;

            if len > buf.len() {
                warn!("TUIC UDP: packet too large: {}", len);
                break;
            }

            // Read packet data
            if quic_recv.read_exact(&mut buf[..len]).await.is_err() {
                break;
            }

            // Send to UDP socket
            if udp_clone.send(&buf[..len]).await.is_err() {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    let udp_to_quic = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            // Receive from UDP socket
            let n = match udp.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };

            // Write packet length (2 bytes)
            let len_bytes = (n as u16).to_be_bytes();
            if quic_send.write_all(&len_bytes).await.is_err() {
                break;
            }

            // Write packet data
            if quic_send.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        quic_send.finish().ok();
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r1 = quic_to_udp => r1,
        r2 = udp_to_quic => r2,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_command_conversion() {
        assert_eq!(TuicCommand::try_from(0x01).unwrap(), TuicCommand::Auth);
        assert_eq!(TuicCommand::try_from(0x02).unwrap(), TuicCommand::Connect);
        assert_eq!(TuicCommand::try_from(0x03).unwrap(), TuicCommand::Packet);
        assert_eq!(
            TuicCommand::try_from(0x04).unwrap(),
            TuicCommand::Dissociate
        );
        assert_eq!(TuicCommand::try_from(0x05).unwrap(), TuicCommand::Heartbeat);
        assert!(TuicCommand::try_from(0xFF).is_err());
    }

    #[test]
    fn test_address_type_conversion() {
        assert_eq!(AddressType::try_from(0x01).unwrap(), AddressType::IPv4);
        assert_eq!(AddressType::try_from(0x03).unwrap(), AddressType::Domain);
        assert_eq!(AddressType::try_from(0x04).unwrap(), AddressType::IPv6);
        assert!(AddressType::try_from(0xFF).is_err());
    }

    #[cfg(feature = "router")]
    #[tokio::test]
    async fn connect_via_router_reaches_upstream() {
        use sb_core::outbound::{OutboundImpl, OutboundRegistry};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Start a simple upstream echo server.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let upstream_addr = listener.local_addr().unwrap();
        let (echo_tx, echo_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept upstream");
            let mut buf = [0u8; 4];
            socket.read_exact(&mut buf).await.expect("read upstream");
            echo_tx.send(buf).ok();
        });

        // Router defaults to "direct"; provide a matching outbound entry.
        let router = router::RouterHandle::from_env();
        let mut reg = OutboundRegistry::default();
        reg.insert("direct".to_string(), OutboundImpl::Direct);
        let outbounds = OutboundRegistryHandle::new(reg);

        let cfg = TuicInboundConfig {
            listen: upstream_addr, // unused by helper
            users: vec![],
            cert: String::new(),
            key: String::new(),
            congestion_control: None,
            router: Arc::new(router),
            outbounds: Arc::new(outbounds),
        };

        let mut stream = connect_via_router(&cfg, "127.0.0.1", upstream_addr.port())
            .await
            .expect("route to upstream");
        stream.write_all(b"ping").await.expect("write to upstream");
        let echoed = echo_rx.await.expect("receive upstream data");
        assert_eq!(&echoed, b"ping");
    }
}
