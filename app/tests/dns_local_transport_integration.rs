//! Integration tests for DNS local transport.
//!
//! Tests LocalTransport query/response and LocalUpstream integration
//! with system DNS resolver.

use sb_core::dns::transport::{DnsTransport, LocalTransport};
use sb_core::dns::upstream::LocalUpstream;
use sb_core::dns::{DnsUpstream, RecordType};

#[tokio::test]
async fn test_local_transport_resolves_localhost() {
    let transport = LocalTransport::new();

    // Build A query for localhost
    let query = build_dns_query("localhost", 1); // Type A

    let response = transport
        .query(&query)
        .await
        .expect("Failed to query localhost");

    // Response should contain valid DNS packet
    assert!(response.len() > 12, "Response too short");
    assert_eq!(&response[0..2], &query[0..2], "Transaction ID mismatch");
    assert_eq!(response[2] & 0x80, 0x80, "QR bit not set (not a response)");
}

#[tokio::test]
async fn test_local_upstream_resolves_public_domain() {
    let upstream = LocalUpstream::new(None);

    // Try to resolve a well-known public domain
    let result = upstream.query("dns.google", RecordType::A).await;

    // May fail in restricted network environments, so be lenient
    if let Ok(answer) = result {
        assert!(!answer.ips.is_empty(), "No IPs returned for dns.google");
        assert!(
            answer.ips.iter().any(|ip| ip.is_ipv4()),
            "Expected IPv4 address"
        );
        assert!(answer.ttl.as_secs() > 0, "TTL should be positive");
    } else {
        // In offline/restricted environments, skip the test
        println!("Skipping test: network unavailable or dns.google unreachable");
    }
}

#[tokio::test]
async fn test_local_upstream_tag_naming() {
    let upstream1 = LocalUpstream::new(None);
    let upstream2 = LocalUpstream::new(Some("home"));

    assert_eq!(upstream1.name(), "local");
    assert_eq!(upstream2.name(), "local::home");
}

#[tokio::test]
async fn test_local_transport_handles_aaaa_query() {
    let transport = LocalTransport::new();

    let query = build_dns_query("localhost", 28); // Type AAAA (IPv6)

    let response = transport
        .query(&query)
        .await
        .expect("Failed to query localhost AAAA");

    assert!(response.len() > 12, "Response too short");
    // Transaction ID should match
    assert_eq!(&response[0..2], &query[0..2]);
}

#[tokio::test]
async fn test_local_upstream_handles_nonexistent_domain() {
    let upstream = LocalUpstream::new(None);

    let result = upstream
        .query(
            "this-domain-definitely-does-not-exist-12345678.invalid",
            RecordType::A,
        )
        .await;

    // Should either return error or empty result
    match result {
        Ok(answer) => {
            // Some resolvers may return empty, others may error
            assert!(
                answer.ips.is_empty(),
                "Should not resolve non-existent domain"
            );
        }
        Err(_) => {
            // Expected - domain doesn't exist
        }
    }
}

#[tokio::test]
async fn test_local_transport_preserves_transaction_id() {
    let transport = LocalTransport::new();

    // Use different transaction IDs
    let mut query1 = build_dns_query("example.com", 1);
    query1[0] = 0xAB;
    query1[1] = 0xCD;

    let mut query2 = build_dns_query("example.org", 1);
    query2[0] = 0x12;
    query2[1] = 0x34;

    let response1 = transport.query(&query1).await.ok();
    let response2 = transport.query(&query2).await.ok();

    if let Some(r1) = response1 {
        assert_eq!(r1[0], 0xAB);
        assert_eq!(r1[1], 0xCD);
    }

    if let Some(r2) = response2 {
        assert_eq!(r2[0], 0x12);
        assert_eq!(r2[1], 0x34);
    }
}

#[tokio::test]
async fn test_local_upstream_health_check() {
    let upstream = LocalUpstream::new(None);

    // Health check queries localhost
    let is_healthy = upstream.health_check().await;

    // Should always be healthy (localhost resolution)
    assert!(is_healthy, "Local upstream health check should always pass");
}

#[tokio::test]
async fn test_local_transport_rejects_invalid_packet() {
    let transport = LocalTransport::new();

    // Too short packet
    let invalid_query = vec![0u8; 5];

    let result = transport.query(&invalid_query).await;
    assert!(result.is_err(), "Should reject too-short packet");
}

#[tokio::test]
async fn test_local_transport_handles_empty_result() {
    let transport = LocalTransport::new();

    // Query for unsupported type (e.g., MX record type 15)
    let query = build_dns_query("localhost", 15); // Type MX

    let result = transport.query(&query).await;

    // Should return valid response, even if empty answer section
    if let Ok(response) = result {
        assert!(response.len() >= 12, "Response should have valid header");
        // Check it's a response packet
        assert_eq!(response[2] & 0x80, 0x80);
    }
}

// Helper function to build DNS query packets
fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut packet = vec![];

    // Transaction ID (default 0x1234)
    packet.extend_from_slice(&[0x12, 0x34]);

    // Flags: standard query (0x0100), recursion desired
    packet.extend_from_slice(&[0x01, 0x00]);

    // Counts: 1 question, 0 answers/authority/additional
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // QNAME: encode domain as labels
    for label in domain.split('.') {
        assert!(label.len() < 64, "DNS label too long (max 63 chars)");
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // Null terminator

    // QTYPE (2 bytes, big-endian)
    packet.extend_from_slice(&qtype.to_be_bytes());

    // QCLASS: IN = 1 (2 bytes, big-endian)
    packet.extend_from_slice(&1u16.to_be_bytes());

    packet
}
