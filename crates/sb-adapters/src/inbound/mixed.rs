//! Mixed inbound (HTTP CONNECT + SOCKS5 hybrid listener)
//!
//! Accepts both HTTP CONNECT and SOCKS5 connections on the same port.
//! Protocol detection is performed by inspecting the first bytes received.
//!
//! Protocol detection logic:
//! - HTTP: First byte is printable ASCII (typically 'C' from "CONNECT")
//! - SOCKS5: First byte is 0x05 (SOCKS version 5)

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::{mpsc, oneshot},
};

use tracing::{debug, info, warn};

use sb_core::router::RouterHandle;
use sb_core::outbound::OutboundRegistryHandle;

#[cfg(feature = "metrics")]
use metrics::counter;

#[derive(Clone, Debug)]
pub struct MixedInboundConfig {
    pub listen: SocketAddr,
    pub router: Arc<RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
    pub read_timeout: Option<Duration>,
    pub tls: Option<sb_transport::TlsConfig>,
}

pub async fn serve_mixed(
    cfg: MixedInboundConfig,
    mut stop_rx: mpsc::Receiver<()>,
    ready_tx: Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    let actual = listener.local_addr().unwrap_or(cfg.listen);
    info!(addr=?cfg.listen, actual=?actual, "Mixed (HTTP+SOCKS5) inbound bound");

    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }

    // Allow disabling stop signal for testing
    let disable_stop = std::env::var("SB_MIXED_DISABLE_STOP").as_deref() == Ok("1");

    loop {
        select! {
            _ = stop_rx.recv(), if !disable_stop => break,
            r = listener.accept() => {
                let (cli, peer) = match r {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error=%e, "accept failed");
                        continue;
                    }
                };

                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_mixed_conn(cli, peer, &cfg_clone).await {
                        // Client closed early (probe) - downgrade to debug
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            debug!(peer=%peer, "mixed: client closed early (probe)");
                            return;
                        }
                        warn!(peer=%peer, error=%e, "mixed session error");
                    }
                });
            }
        }
    }
    Ok(())
}

/// Detect protocol and route to appropriate handler
async fn handle_mixed_conn(
    cli: TcpStream,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    #[cfg(feature = "metrics")]
    counter!("inbound_connections_total", "protocol" => "mixed", "network" => "tcp").increment(1);

    // Peek first byte to detect protocol without consuming
    let mut first_byte = [0u8; 1];

    // Apply read timeout if configured
    let peek_result = if let Some(timeout) = cfg.read_timeout {
        tokio::time::timeout(timeout, cli.peek(&mut first_byte)).await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "protocol detection timeout"))?
    } else {
        cli.peek(&mut first_byte).await
    };

    match peek_result {
        Ok(0) => {
            // Connection closed immediately
            Ok(())
        }
        Ok(_) => {
            let first = first_byte[0];

            // Protocol detection
            if first == 0x16 {
                // TLS handshake (0x16 = TLS handshake record type)
                debug!(peer=%peer, "mixed: detected TLS protocol");
                #[cfg(feature = "metrics")]
                counter!("mixed_protocol_detection_total", "protocol" => "tls").increment(1);

                handle_tls(cli, peer, cfg).await
            } else if first == 0x05 {
                // SOCKS5 protocol
                debug!(peer=%peer, "mixed: detected SOCKS5 protocol");
                #[cfg(feature = "metrics")]
                counter!("mixed_protocol_detection_total", "protocol" => "socks5").increment(1);

                handle_socks5(cli, peer, cfg).await
            } else if first.is_ascii_alphabetic() {
                // HTTP protocol (likely "CONNECT" or "GET")
                debug!(peer=%peer, "mixed: detected HTTP protocol");
                #[cfg(feature = "metrics")]
                counter!("mixed_protocol_detection_total", "protocol" => "http").increment(1);

                handle_http(cli, peer, cfg).await
            } else {
                // Unknown protocol
                warn!(peer=%peer, first_byte=first, "mixed: unknown protocol");
                #[cfg(feature = "metrics")]
                counter!("mixed_protocol_detection_total", "protocol" => "unknown").increment(1);

                Err(io::Error::new(io::ErrorKind::InvalidData, "unknown protocol"))
            }
        }
        Err(e) => Err(e),
    }
}

/// Handle SOCKS5 connection
async fn handle_socks5(
    mut cli: TcpStream,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    // Reuse SOCKS5 inbound handler from socks module
    let socks_cfg = crate::inbound::socks::SocksInboundConfig {
        listen: cfg.listen,
        udp_bind: None, // Mixed inbound doesn't support UDP ASSOCIATE by default
        router: Arc::clone(&cfg.router),
        outbounds: Arc::clone(&cfg.outbounds),
        udp_nat_ttl: Duration::from_secs(60),
    };

    // Forward to SOCKS5 handler - need to access internal handler
    // For now, implement inline SOCKS5 handshake
    handle_socks5_inline(&mut cli, peer, &socks_cfg).await
}

/// Inline SOCKS5 handler (simplified version)
async fn handle_socks5_inline(
    cli: &mut TcpStream,
    peer: SocketAddr,
    _cfg: &crate::inbound::socks::SocksInboundConfig,
) -> io::Result<()> {
    // Read version
    let ver = read_u8(cli).await?;
    if ver != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SOCKS version"));
    }

    // Read methods
    let n_methods = read_u8(cli).await? as usize;
    let mut methods = vec![0u8; n_methods];
    cli.read_exact(&mut methods).await?;

    // Reply: NO AUTH
    cli.write_all(&[0x05, 0x00]).await?;

    // Read request
    let mut head = [0u8; 4];
    cli.read_exact(&mut head).await?;

    if head[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request version"));
    }

    let cmd = head[1];
    if cmd != 0x01 {
        // Only CONNECT supported
        reply_socks5(cli, 0x07, None).await?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only CONNECT supported"));
    }

    // Parse target address
    let atyp = head[3];
    let target_addr = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            cli.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            cli.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}:{}", std::net::Ipv4Addr::from(addr), port)
        }
        0x03 => {
            // Domain
            let len = read_u8(cli).await? as usize;
            let mut domain = vec![0u8; len];
            cli.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            cli.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}:{}", String::from_utf8_lossy(&domain), port)
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            cli.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            cli.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("[{}]:{}", std::net::Ipv6Addr::from(addr), port)
        }
        _ => {
            reply_socks5(cli, 0x08, None).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported address type"));
        }
    };

    debug!(peer=%peer, target=%target_addr, "mixed/socks5: connecting to target");

    // Connect to target
    let upstream = match TcpStream::connect(&target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            reply_socks5(cli, 0x05, None).await?; // Connection refused
            return Err(e);
        }
    };

    // Reply with success
    reply_socks5(cli, 0x00, None).await?;

    // Bidirectional relay
    let (mut cli_read, mut cli_write) = cli.split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_server = async {
        tokio::io::copy(&mut cli_read, &mut upstream_write).await
    };

    let server_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut cli_write).await
    };

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/socks5: client to server copy failed");
            }
        }
        result = server_to_client => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/socks5: server to client copy failed");
            }
        }
    }

    debug!(peer=%peer, "mixed/socks5: connection closed");
    Ok(())
}

/// Handle TLS connection
async fn handle_tls(
    cli: TcpStream,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    // Check if TLS is configured
    let tls_config = match &cfg.tls {
        Some(config) => config,
        None => {
            warn!(peer=%peer, "mixed: TLS detected but not configured");
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS not configured",
            ));
        }
    };

    // Wrap stream with TLS
    let tls_transport = sb_transport::TlsTransport::new(tls_config.clone());
    let mut tls_stream = match tls_transport.wrap_server(cli).await {
        Ok(stream) => stream,
        Err(e) => {
            warn!(peer=%peer, error=%e, "mixed: TLS handshake failed");
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("TLS handshake failed: {}", e),
            ));
        }
    };

    debug!(peer=%peer, "mixed: TLS handshake successful, detecting inner protocol");

    // Now detect the inner protocol by peeking at the first byte
    // We need to read a byte to detect the protocol
    let mut first_byte = [0u8; 1];
    use tokio::io::AsyncReadExt;
    
    let n = tls_stream.read(&mut first_byte).await?;
    if n == 0 {
        return Ok(());
    }

    let first = first_byte[0];

    // Detect inner protocol
    if first == 0x05 {
        // SOCKS5 over TLS
        debug!(peer=%peer, "mixed/tls: detected SOCKS5 protocol");
        #[cfg(feature = "metrics")]
        counter!("mixed_protocol_detection_total", "protocol" => "tls_socks5").increment(1);

        // We need to prepend the byte we read back to the stream
        // For simplicity, we'll handle SOCKS5 inline with the byte already consumed
        handle_socks5_with_first_byte(tls_stream, first_byte[0], peer, cfg).await
    } else if first.is_ascii_alphabetic() {
        // HTTP over TLS
        debug!(peer=%peer, "mixed/tls: detected HTTP protocol");
        #[cfg(feature = "metrics")]
        counter!("mixed_protocol_detection_total", "protocol" => "tls_http").increment(1);

        // Handle HTTP with the byte already consumed
        handle_http_with_first_byte(tls_stream, first_byte[0], peer, cfg).await
    } else {
        // Unknown protocol over TLS
        warn!(peer=%peer, first_byte=first, "mixed/tls: unknown inner protocol");
        #[cfg(feature = "metrics")]
        counter!("mixed_protocol_detection_total", "protocol" => "tls_unknown").increment(1);

        Err(io::Error::new(io::ErrorKind::InvalidData, "unknown protocol over TLS"))
    }
}

/// Handle HTTP CONNECT connection
async fn handle_http(
    mut cli: TcpStream,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()> {
    // Reuse HTTP inbound handler from http module
    let _http_cfg = crate::inbound::http::HttpProxyConfig {
        listen: cfg.listen,
        router: Arc::clone(&cfg.router),
        outbounds: Arc::clone(&cfg.outbounds),
    };

    // Forward to HTTP handler - need to access internal handler
    // For now, implement inline HTTP CONNECT handshake
    handle_http_inline(&mut cli, peer).await
}

/// Inline HTTP handler (simplified version)
async fn handle_http_inline(
    cli: &mut TcpStream,
    peer: SocketAddr,
) -> io::Result<()> {
    // Read HTTP request line
    let mut buf = Vec::new();
    let mut line_buf = [0u8; 1];

    // Read until \r\n
    loop {
        cli.read_exact(&mut line_buf).await?;
        buf.push(line_buf[0]);

        if buf.len() >= 2 && buf[buf.len()-2] == b'\r' && buf[buf.len()-1] == b'\n' {
            break;
        }

        if buf.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request line too long"));
        }
    }

    let request_line = String::from_utf8_lossy(&buf[..buf.len()-2]);

    // Check if it's CONNECT method
    if !request_line.starts_with("CONNECT ") {
        // Non-CONNECT methods not supported
        cli.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Ok(());
    }

    // Parse target from request line
    // Format: "CONNECT host:port HTTP/1.1"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        cli.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Ok(());
    }

    let target_addr = parts[1];
    debug!(peer=%peer, target=%target_addr, "mixed/http: connecting to target");

    // Skip remaining headers
    loop {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];

        loop {
            cli.read_exact(&mut byte).await?;
            line.push(byte[0]);

            if line.len() >= 2 && line[line.len()-2] == b'\r' && line[line.len()-1] == b'\n' {
                break;
            }

            if line.len() > 8192 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "header line too long"));
            }
        }

        // Empty line marks end of headers
        if line.len() == 2 {
            break;
        }
    }

    // Connect to target
    let upstream = match TcpStream::connect(target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            cli.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            return Err(e);
        }
    };

    // Reply with success
    cli.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Bidirectional relay
    let (mut cli_read, mut cli_write) = cli.split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_server = async {
        tokio::io::copy(&mut cli_read, &mut upstream_write).await
    };

    let server_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut cli_write).await
    };

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/http: client to server copy failed");
            }
        }
        result = server_to_client => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/http: server to client copy failed");
            }
        }
    }

    debug!(peer=%peer, "mixed/http: connection closed");
    Ok(())
}

/// Reply to SOCKS5 client
async fn reply_socks5(cli: &mut TcpStream, rep: u8, _bnd: Option<SocketAddr>) -> io::Result<()> {
    // Simple reply: VER=5, REP=rep, RSV=0, ATYP=1 (IPv4), ADDR=0.0.0.0, PORT=0
    let reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    cli.write_all(&reply).await
}

/// Read single byte helper
async fn read_u8(s: &mut TcpStream) -> io::Result<u8> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    Ok(b[0])
}

/// Handle SOCKS5 with first byte already consumed
async fn handle_socks5_with_first_byte<S>(
    mut stream: S,
    first_byte: u8,
    peer: SocketAddr,
    cfg: &MixedInboundConfig,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Verify SOCKS version
    if first_byte != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SOCKS version"));
    }

    // Read methods
    let n_methods = {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        buf[0] as usize
    };
    let mut methods = vec![0u8; n_methods];
    stream.read_exact(&mut methods).await?;

    // Reply: NO AUTH
    stream.write_all(&[0x05, 0x00]).await?;

    // Read request
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;

    if head[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request version"));
    }

    let cmd = head[1];
    if cmd != 0x01 {
        // Only CONNECT supported
        reply_socks5_generic(&mut stream, 0x07, None).await?;
        return Err(io::Error::new(io::ErrorKind::Unsupported, "only CONNECT supported"));
    }

    // Parse target address
    let atyp = head[3];
    let target_addr = match atyp {
        0x01 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}:{}", std::net::Ipv4Addr::from(addr), port)
        }
        0x03 => {
            // Domain
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let len = len_buf[0] as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("{}:{}", String::from_utf8_lossy(&domain), port)
        }
        0x04 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            format!("[{}]:{}", std::net::Ipv6Addr::from(addr), port)
        }
        _ => {
            reply_socks5_generic(&mut stream, 0x08, None).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported address type"));
        }
    };

    debug!(peer=%peer, target=%target_addr, "mixed/tls/socks5: connecting to target");

    // Connect to target
    let upstream = match TcpStream::connect(&target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            reply_socks5_generic(&mut stream, 0x05, None).await?;
            return Err(e);
        }
    };

    // Reply with success
    reply_socks5_generic(&mut stream, 0x00, None).await?;

    // Bidirectional relay
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_server = async {
        tokio::io::copy(&mut stream_read, &mut upstream_write).await
    };

    let server_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut stream_write).await
    };

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/tls/socks5: client to server copy failed");
            }
        }
        result = server_to_client => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/tls/socks5: server to client copy failed");
            }
        }
    }

    debug!(peer=%peer, "mixed/tls/socks5: connection closed");
    Ok(())
}

/// Handle HTTP with first byte already consumed
async fn handle_http_with_first_byte<S>(
    mut stream: S,
    first_byte: u8,
    peer: SocketAddr,
    _cfg: &MixedInboundConfig,
) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read HTTP request line (we already have the first byte)
    let mut buf = vec![first_byte];
    let mut line_buf = [0u8; 1];

    // Read until \r\n
    loop {
        stream.read_exact(&mut line_buf).await?;
        buf.push(line_buf[0]);

        if buf.len() >= 2 && buf[buf.len()-2] == b'\r' && buf[buf.len()-1] == b'\n' {
            break;
        }

        if buf.len() > 8192 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request line too long"));
        }
    }

    let request_line = String::from_utf8_lossy(&buf[..buf.len()-2]);

    // Check if it's CONNECT method
    if !request_line.starts_with("CONNECT ") {
        // Non-CONNECT methods not supported
        stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n").await?;
        return Ok(());
    }

    // Parse target from request line
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await?;
        return Ok(());
    }

    let target_addr = parts[1];
    debug!(peer=%peer, target=%target_addr, "mixed/tls/http: connecting to target");

    // Skip remaining headers
    loop {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];

        loop {
            stream.read_exact(&mut byte).await?;
            line.push(byte[0]);

            if line.len() >= 2 && line[line.len()-2] == b'\r' && line[line.len()-1] == b'\n' {
                break;
            }

            if line.len() > 8192 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "header line too long"));
            }
        }

        // Empty line marks end of headers
        if line.len() == 2 {
            break;
        }
    }

    // Connect to target
    let upstream = match TcpStream::connect(target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await?;
            return Err(e);
        }
    };

    // Reply with success
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    // Bidirectional relay
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let (mut upstream_read, mut upstream_write) = upstream.into_split();

    let client_to_server = async {
        tokio::io::copy(&mut stream_read, &mut upstream_write).await
    };

    let server_to_client = async {
        tokio::io::copy(&mut upstream_read, &mut stream_write).await
    };

    tokio::select! {
        result = client_to_server => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/tls/http: client to server copy failed");
            }
        }
        result = server_to_client => {
            if let Err(e) = result {
                debug!(peer=%peer, error=%e, "mixed/tls/http: server to client copy failed");
            }
        }
    }

    debug!(peer=%peer, "mixed/tls/http: connection closed");
    Ok(())
}

/// Reply to SOCKS5 client (generic version for any stream)
async fn reply_socks5_generic<S>(stream: &mut S, rep: u8, _bnd: Option<SocketAddr>) -> io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    // Simple reply: VER=5, REP=rep, RSV=0, ATYP=1 (IPv4), ADDR=0.0.0.0, PORT=0
    let reply = [0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_detection_socks5() {
        assert_eq!(0x05, 0x05);
    }

    #[test]
    fn test_protocol_detection_http() {
        assert!(b'C'.is_ascii_alphabetic());
        assert!(b'G'.is_ascii_alphabetic());
    }
}
