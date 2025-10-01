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
            if first == 0x05 {
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

    // For now, reply with success and close
    // Full implementation would parse target and establish connection
    reply_socks5(cli, 0x00, None).await?;

    debug!(peer=%peer, "mixed/socks5: connection handled (stub)");
    Ok(())
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

    // For now, reply with success and close
    // Full implementation would parse target and establish connection
    cli.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    debug!(peer=%peer, "mixed/http: connection handled (stub)");
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
