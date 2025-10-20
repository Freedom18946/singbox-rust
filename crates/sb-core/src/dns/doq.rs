// cfg is already applied at module inclusion site
use crate::dns::transport::DnsTransport;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Perform a single DNS-over-QUIC query using the unified DoQ transport.
///
/// - `server`: QUIC server socket address (e.g., 1.1.1.1:853)
/// - `server_name`: SNI / TLS name (e.g., "cloudflare-dns.com")
/// - `host`: domain to resolve
/// - `qtype`: 1 (A), 28 (AAAA), etc.
/// - `timeout_ms`: per-operation timeout
pub async fn query_doq_once(
    server: SocketAddr,
    server_name: &str,
    host: &str,
    qtype: u16,
    timeout_ms: u64,
) -> Result<(Vec<IpAddr>, Option<u32>)> {
    // Build DNS wire-format query
    let req_bytes = crate::dns::udp::build_query(host, qtype)?;

    // DoQ transport handles QUIC connection, ALPN, and length-prefixed framing
    let transport = crate::dns::transport::DoqTransport::new(server, server_name.to_string())?;
    let resp_bytes = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        transport.query(&req_bytes),
    )
    .await??;

    // Parse DNS wire-format response
    let (ips, ttl) = crate::dns::udp::parse_answers(&resp_bytes, qtype)?;
    Ok((ips, ttl))
}
