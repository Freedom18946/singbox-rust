//! Enhanced SOCKS5 UDP Associate implementation with real forwarding
//!
//! This module provides production-ready SOCKS5 UDP forwarding with:
//! - O(log N) NAT table eviction using binary heap
//! - Comprehensive metrics and error classification
//! - Environment-controlled features for safety

use anyhow::{bail, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

use sb_core::net::udp_nat::{NatKey, NatMap, TargetAddr, UpstreamError, record_upstream_failure, update_flow_metrics};
use sb_core::net::datagram::UdpTargetAddr;
use sb_core::outbound::udp_socks5;
use sb_core::router::rules::{Decision as RDecision, RouteCtx};
use sb_core::router::rules as rules_global;
use sb_core::error::SbError;

#[cfg(feature = "metrics")]
use metrics::{counter, gauge, histogram};

/// Check if SOCKS UDP is enabled via environment
fn socks_udp_enabled() -> bool {
    std::env::var("SB_SOCKS_UDP_ENABLE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Get UDP NAT TTL from environment
fn nat_ttl_from_env() -> Duration {
    std::env::var("SB_UDP_NAT_TTL")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(30))
}

/// Parse SOCKS5 UDP datagram header
/// Returns (target_addr, header_length) on success
fn parse_socks5_udp_header(buf: &[u8]) -> Result<(TargetAddr, usize)> {
    if buf.len() < 4 {
        bail!(SbError::parse("SOCKS5 UDP header too short"));
    }

    // Check reserved fields and fragment
    if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        bail!(SbError::parse("Invalid SOCKS5 UDP reserved fields or fragment"));
    }

    let atyp = buf[3];
    let mut offset = 4;

    let target = match atyp {
        0x01 => {
            // IPv4
            if buf.len() < offset + 6 {
                bail!(SbError::parse("IPv4 address too short"));
            }
            let ip = std::net::Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
            offset += 4;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            TargetAddr::Ip(SocketAddr::from((ip, port)))
        }
        0x04 => {
            // IPv6
            if buf.len() < offset + 18 {
                bail!(SbError::parse("IPv6 address too short"));
            }
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[offset..offset + 16])?);
            offset += 16;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            TargetAddr::Ip(SocketAddr::from((ip, port)))
        }
        0x03 => {
            // Domain name
            if buf.len() < offset + 1 {
                bail!(SbError::parse("Domain length field missing"));
            }
            let domain_len = buf[offset] as usize;
            offset += 1;
            if buf.len() < offset + domain_len + 2 {
                bail!(SbError::parse("Domain name or port missing"));
            }
            let host = std::str::from_utf8(&buf[offset..offset + domain_len])
                .map_err(|e| SbError::parse(format!("invalid domain utf8: {}", e)))?
                .to_string();
            offset += domain_len;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            TargetAddr::Domain { host, port }
        }
        _ => bail!(SbError::addr(format!("Invalid address type: {}", atyp))),
    };

    Ok((target, offset))
}

/// Encode SOCKS5 UDP reply header for response
fn encode_socks5_udp_reply(target: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut reply = Vec::with_capacity(32 + payload.len());

    // Reserved fields and fragment
    reply.extend_from_slice(&[0, 0, 0]);

    match target {
        SocketAddr::V4(addr) => {
            reply.push(0x01); // IPv4
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            reply.push(0x04); // IPv6
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
    }

    reply.extend_from_slice(payload);
    reply
}

/// Create upstream UDP socket for direct connection
async fn create_upstream_socket(target: &TargetAddr) -> Result<Arc<UdpSocket>> {
    let socket = match target {
        TargetAddr::Ip(addr) => {
            let sock = UdpSocket::bind("0.0.0.0:0").await
                .map_err(|e| anyhow::Error::from(SbError::from(e)))?;
            sock.connect(addr).await
                .map_err(|e| anyhow::Error::from(SbError::from(e)))?;
            sock
        }
        TargetAddr::Domain { host, port } => {
            // For domain targets, resolve and connect
            let addr = tokio::net::lookup_host(format!("{}:{}", host, port))
                .await
                .map_err(|e| anyhow::Error::from(SbError::dns(format!("resolve failed: {}", e))))?
                .next()
                .ok_or_else(|| anyhow::Error::from(SbError::dns(format!("Failed to resolve domain: {}", host))))?;
            let sock = UdpSocket::bind("0.0.0.0:0").await
                .map_err(|e| anyhow::Error::from(SbError::from(e)))?;
            sock.connect(addr).await
                .map_err(|e| anyhow::Error::from(SbError::from(e)))?;
            sock
        }
    };

    Ok(Arc::new(socket))
}

/// Apply routing rules for UDP traffic
fn apply_routing_rules(target: &TargetAddr) -> RDecision {
    if let Some(engine) = rules_global::global() {
        let (domain, port, ip) = match target {
            TargetAddr::Domain { host, port } => (Some(host.as_str()), Some(*port), None),
            TargetAddr::Ip(addr) => (None, Some(addr.port()), Some(addr.ip())),
        };

        let ctx = RouteCtx {
            domain,
            ip,
            transport_udp: true,
            port,
        };

        engine.decide(&ctx)
    } else {
        RDecision::Direct
    }
}

/// Enhanced SOCKS5 UDP service
pub async fn serve_socks5_udp_enhanced(socket: Arc<UdpSocket>) -> Result<()> {
    if !socks_udp_enabled() {
        tracing::info!("SOCKS5 UDP service disabled via SB_SOCKS_UDP_ENABLE");
        return Ok(());
    }

    tracing::info!("Starting enhanced SOCKS5 UDP service on {}", socket.local_addr()?);

    // Initialize NAT map with TTL from environment
    let ttl = nat_ttl_from_env();
    let nat_map = Arc::new(NatMap::new(Some(ttl)));

    // Start background evictor
    {
        let nat_map_clone = Arc::clone(&nat_map);
        tokio::spawn(async move {
            nat_map_clone.run_evictor().await;
        });
    }

    // Update service metrics
    #[cfg(feature = "metrics")]
    {
        gauge!("socks_udp_service_active").set(1.0);
    }

    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let (bytes_received, client_addr) = match socket.recv_from(&mut buffer).await {
            Ok(result) => result,
            Err(e) => {
                #[cfg(feature = "metrics")]
                counter!("socks_udp_error_total", "class" => "recv_error").increment(1);
                tracing::debug!("UDP recv error: {}", e);
                continue;
            }
        };

        if bytes_received == 0 {
            continue;
        }

        #[cfg(feature = "metrics")]
        {
            counter!("udp_pkts_in_total").increment(1);
            counter!("udp_bytes_in_total").increment(bytes_received as u64);
        }

        // Parse SOCKS5 UDP header
        let (target, header_len) = match parse_socks5_udp_header(&buffer[..bytes_received]) {
            Ok(result) => result,
            Err(e) => {
                #[cfg(feature = "metrics")]
                counter!("socks_udp_error_total", "class" => "parse_error").increment(1);
                tracing::debug!("Failed to parse SOCKS5 UDP header: {}", e);
                continue;
            }
        };

        // Apply routing rules
        let decision = apply_routing_rules(&target);
        match decision {
            RDecision::Reject => {
                #[cfg(feature = "metrics")]
                counter!("socks_udp_error_total", "class" => "rejected").increment(1);
                continue;
            }
            RDecision::Proxy(_) => {
                // Proxy via upstream SOCKS5 if configured (SB_UDP_PROXY_MODE=socks5 and address provided)
                if std::env::var("SB_UDP_PROXY_MODE")
                    .ok()
                    .map(|v| v.eq_ignore_ascii_case("socks5"))
                    .unwrap_or(false)
                {
                    let udp_target = match &target {
                        TargetAddr::Ip(sa) => UdpTargetAddr::Ip(*sa),
                        TargetAddr::Domain { host, port } => UdpTargetAddr::Domain {
                            host: host.clone(),
                            port: *port,
                        },
                    };
                    let payload = &buffer[header_len..bytes_received];
                    match udp_socks5::sendto_via_socks5(&socket, payload, &udp_target).await {
                        Ok(_n) => {
                            #[cfg(feature = "metrics")]
                            {
                                counter!("udp_pkts_out_total").increment(1);
                                counter!("udp_bytes_out_total").increment(payload.len() as u64);
                            }
                            // Rely on SOCKS5 upstream conn to deliver replies; not handled here.
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!("UDP proxy send failed: {}", e);
                            // fall through to direct when allowed
                        }
                    }
                }
            }
            RDecision::Direct => {}
        }

        let payload = &buffer[header_len..bytes_received];
        let nat_key = NatKey {
            client: client_addr,
            dst: target.clone(),
        };

        // Get or create upstream socket
        let upstream_socket = match nat_map.get(&nat_key).await {
            Some(existing) => existing,
            None => {
                match create_upstream_socket(&target).await {
                    Ok(new_socket) => {
                        if nat_map.insert(nat_key.clone(), new_socket.clone()).await {
                            // Start response handler for new connection
                            spawn_response_handler(
                                Arc::clone(&socket),
                                Arc::clone(&new_socket),
                                client_addr,
                                target.clone(),
                            );
                            new_socket
                        } else {
                            #[cfg(feature = "metrics")]
                            counter!("socks_udp_error_total", "class" => "nat_capacity").increment(1);
                            continue;
                        }
                    }
                    Err(e) => {
                        record_upstream_failure(&e);
                        continue;
                    }
                }
            }
        };

        // Forward payload to upstream
        if let Err(e) = upstream_socket.send(payload).await {
            record_upstream_failure(&e.into());
            continue;
        }

        #[cfg(feature = "metrics")]
        {
            counter!("udp_pkts_out_total").increment(1);
            counter!("udp_bytes_out_total").increment(payload.len() as u64);
        }
    }
}

/// Spawn a task to handle responses from upstream back to client
fn spawn_response_handler(
    listen_socket: Arc<UdpSocket>,
    upstream_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    target: TargetAddr,
) {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];

        loop {
            match upstream_socket.recv(&mut buffer).await {
                Ok(bytes_received) => {
                    if bytes_received == 0 {
                        break;
                    }

                    // For IP targets, we can get the actual source address
                    let reply_addr = match &target {
                        TargetAddr::Ip(addr) => *addr,
                        TargetAddr::Domain { host: _, port } => {
                            // Use a placeholder - we should track actual resolved address
                            SocketAddr::from(([127, 0, 0, 1], *port))
                        }
                    };

                    let reply = encode_socks5_udp_reply(&reply_addr, &buffer[..bytes_received]);

                    if let Err(e) = listen_socket.send_to(&reply, client_addr).await {
                        tracing::debug!("Failed to send UDP response to client: {}", e);
                        break;
                    }

                    #[cfg(feature = "metrics")]
                    {
                        counter!("udp_pkts_in_total").increment(1);
                        counter!("udp_bytes_in_total").increment(bytes_received as u64);
                    }
                }
                Err(e) => {
                    tracing::debug!("UDP upstream recv error: {}", e);
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_socks5_udp_header_ipv4() {
        let mut buf = vec![0, 0, 0, 0x01]; // Reserved fields + IPv4 type
        buf.extend_from_slice(&[192, 168, 1, 1]); // IP address
        buf.extend_from_slice(&[0x00, 0x50]); // Port 80
        buf.extend_from_slice(b"test payload");

        let (target, header_len) = parse_socks5_udp_header(&buf).unwrap();
        assert_eq!(header_len, 10);

        match target {
            TargetAddr::Ip(addr) => {
                assert_eq!(addr.ip(), std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
                assert_eq!(addr.port(), 80);
            }
            _ => panic!("Expected IP target"),
        }
    }

    #[test]
    fn test_parse_socks5_udp_header_domain() {
        let mut buf = vec![0, 0, 0, 0x03]; // Reserved fields + Domain type
        buf.push(11); // Domain length
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&[0x01, 0xBB]); // Port 443
        buf.extend_from_slice(b"test payload");

        let (target, header_len) = parse_socks5_udp_header(&buf).unwrap();
        assert_eq!(header_len, 18);

        match target {
            TargetAddr::Domain { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected domain target"),
        }
    }

    #[test]
    fn test_parse_socks5_udp_header_invalid() {
        // Test short buffer
        let buf = vec![0, 0];
        assert!(parse_socks5_udp_header(&buf).is_err());

        // Test invalid reserved fields
        let buf = vec![1, 0, 0, 0x01];
        assert!(parse_socks5_udp_header(&buf).is_err());

        // Test invalid address type
        let buf = vec![0, 0, 0, 0xFF];
        assert!(parse_socks5_udp_header(&buf).is_err());
    }
}
