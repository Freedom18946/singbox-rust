use crate::dns::transport::DnsTransport;
use anyhow::Result;
use std::net::IpAddr;
use std::time::Duration;

/// Perform a single DNS-over-HTTPS query using the unified transport layer.
///
/// Behavior:
/// - Builds a DNS wire-format query for `host`/`qtype`
/// - Uses DoH transport with adaptive GET/POST selection
/// - Honors provided `timeout_ms`
/// - Parses wire-format response and returns (IPs, optional TTL)
pub async fn query_doh_once(
    url: &str,
    host: &str,
    qtype: u16,
    timeout_ms: u64,
) -> Result<(Vec<IpAddr>, Option<u32>)> {
    // Build DNS query (wire format)
    let req_bytes = crate::dns::udp::build_query(host, qtype)?;

    // Use the new unified DoH transport (reqwest-based, GET/POST adaptive)
    let transport = crate::dns::transport::DohTransport::new(url.to_string())?
        .with_timeout(Duration::from_millis(timeout_ms));

    // Execute query and parse response
    let resp_bytes = transport.query(&req_bytes).await?;
    let (ips, ttl) = crate::dns::udp::parse_answers(&resp_bytes, qtype)?;
    Ok((ips, ttl))
}
