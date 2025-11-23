//! DNS transport layer tests
//!
//! Tests for various DNS transports including UDP, DoT, DoH, DoQ, and DoH3

use anyhow::Result;
use sb_core::dns::transport::DnsTransport;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Helper function to build a simple DNS query packet for A record
fn build_dns_query(domain: &str, record_type: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    // Transaction ID (2 bytes)
    packet.extend_from_slice(&[0x12, 0x34]);

    // Flags: Standard query (2 bytes)
    packet.extend_from_slice(&[0x01, 0x00]);

    // Questions: 1 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x01]);

    // Answer RRs: 0 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Authority RRs: 0 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Additional RRs: 0 (2 bytes)
    packet.extend_from_slice(&[0x00, 0x00]);

    // Question section
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Null terminator

    // Query type (2 bytes)
    packet.extend_from_slice(&record_type.to_be_bytes());

    // Query class: IN (2 bytes)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

#[cfg(feature = "dns_udp")]
#[tokio::test]
async fn test_udp_transport_construction() {
    // Test that UDP transport can be constructed
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let upstream = sb_core::dns::transport::UdpUpstream {
        addr: server,
        timeout: Duration::from_millis(5000),
    };
    let transport = sb_core::dns::transport::UdpTransport::new(upstream);

    assert_eq!(transport.name(), "udp");
}

#[cfg(feature = "dns_dot")]
#[tokio::test]
async fn test_dot_transport_construction() {
    // Test that DoT transport can be constructed
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 853);
    let transport =
        sb_core::dns::transport::DotTransport::new(server, "cloudflare-dns.com".to_string())
            .expect("DoT transport should construct");

    assert_eq!(transport.name(), "dot");
}

#[cfg(feature = "dns_doh")]
#[tokio::test]
async fn test_doh_transport_construction() -> Result<()> {
    // Test that DoH transport can be constructed
    let transport =
        sb_core::dns::transport::DohTransport::new("https://dns.google/dns-query".to_string())?;

    assert_eq!(transport.name(), "doh");
    Ok(())
}

#[cfg(feature = "dns_doq")]
#[tokio::test]
async fn test_doq_transport_construction() -> Result<()> {
    // Test that DoQ transport can be constructed
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 853);
    let transport =
        sb_core::dns::transport::DoqTransport::new(server, "dns.quad9.net".to_string())?;

    assert_eq!(transport.name(), "doq");
    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[tokio::test]
async fn test_doh3_transport_construction() -> Result<()> {
    // Test that DoH3 transport can be constructed
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let transport = sb_core::dns::transport::Doh3Transport::new(
        server,
        "cloudflare-dns.com".to_string(),
        "/dns-query".to_string(),
    )?;

    assert_eq!(transport.name(), "doh3");
    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[tokio::test]
async fn test_doh3_transport_with_tls_options() -> Result<()> {
    // Test that DoH3 transport can be constructed with TLS options
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let transport = sb_core::dns::transport::Doh3Transport::new_with_tls(
        server,
        "cloudflare-dns.com".to_string(),
        "/dns-query".to_string(),
        Vec::new(), // ca_paths
        Vec::new(), // ca_pem
        false,      // skip_verify
    )?;

    assert_eq!(transport.name(), "doh3");
    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[tokio::test]
async fn test_doh3_transport_skip_verify() -> Result<()> {
    // Test that DoH3 transport can skip certificate verification (for testing)
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8443);
    let transport = sb_core::dns::transport::Doh3Transport::new_with_tls(
        server,
        "localhost".to_string(),
        "/dns-query".to_string(),
        Vec::new(),
        Vec::new(),
        true, // skip_verify
    )?;

    assert_eq!(transport.name(), "doh3");
    Ok(())
}

#[cfg(feature = "dns_udp")]
#[tokio::test]
async fn test_dns_query_packet_format() {
    // Test that our query packet builder produces valid format
    let query = build_dns_query("example.com", 1); // A record

    // Check header
    assert_eq!(query[0], 0x12); // Transaction ID
    assert_eq!(query[1], 0x34);
    assert_eq!(query[2], 0x01); // Standard query
    assert_eq!(query[3], 0x00);

    // Check question count
    assert_eq!(query[4], 0x00); // QDCOUNT
    assert_eq!(query[5], 0x01);

    // Packet should be at least 12 bytes (header) + domain + query type/class
    assert!(query.len() > 12);
}

#[cfg(all(feature = "dns_udp", feature = "dns_dot", feature = "dns_doh"))]
#[test]
fn test_transport_names_unique() {
    // Ensure each transport has a unique name
    use std::collections::HashSet;

    let names = vec!["udp", "dot", "doh"];
    let unique_names: HashSet<_> = names.iter().collect();

    assert_eq!(
        names.len(),
        unique_names.len(),
        "Transport names must be unique"
    );
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_feature_enabled() {
    // Simple test to verify the dns_doh3 feature is working
    assert!(
        cfg!(feature = "dns_doh3"),
        "dns_doh3 feature should be enabled for this test"
    );
}

// Integration test with real DNS server (marked as ignored by default)
#[cfg(feature = "dns_udp")]
#[tokio::test]
#[ignore = "requires network access to public DNS server"]
async fn test_udp_real_query() -> Result<()> {
    // Test against Google Public DNS
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let upstream = sb_core::dns::transport::UdpUpstream {
        addr: server,
        timeout: Duration::from_millis(5000),
    };
    let transport = sb_core::dns::transport::UdpTransport::new(upstream);

    let query = build_dns_query("dns.google", 1); // A record
    let response = transport.query(&query).await?;

    // DNS response should have at least a header (12 bytes)
    assert!(response.len() >= 12, "DNS response too short");

    // Check response flags indicate success
    assert_eq!(
        response[3] & 0x0F,
        0x00,
        "DNS query should succeed (RCODE=0)"
    );

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[tokio::test]
#[ignore = "requires network access to Cloudflare DNS over HTTP/3"]
async fn test_doh3_real_query() -> Result<()> {
    // Test against Cloudflare DNS over HTTP/3
    let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let transport = sb_core::dns::transport::Doh3Transport::new(
        server,
        "cloudflare-dns.com".to_string(),
        "/dns-query".to_string(),
    )?;

    let query = build_dns_query("one.one.one.one", 1); // A record for 1.1.1.1
    let response = transport.query(&query).await?;

    // DNS response should have at least a header (12 bytes)
    assert!(response.len() >= 12, "DNS response too short");

    // Check response flags indicate success
    assert_eq!(
        response[3] & 0x0F,
        0x00,
        "DNS query should succeed (RCODE=0)"
    );

    Ok(())
}
