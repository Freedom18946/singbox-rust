#![cfg(feature = "adapter-dns")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! DNS outbound connector integration tests
//!
//! These tests verify DNS outbound connector implementation including:
//! - Configuration validation
//! - Transport protocol handling (UDP, TCP, DoT, DoH, DoQ)
//! - Connector construction
//! - Dial mechanics

use sb_adapters::outbound::dns::{DnsConfig, DnsConnector, DnsTransport};
use sb_adapters::outbound::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

// ============================================================================
// DnsTransport Tests
// ============================================================================

#[test]
fn test_dns_transport_equality() {
    assert_eq!(DnsTransport::Udp, DnsTransport::Udp);
    assert_ne!(DnsTransport::Udp, DnsTransport::Tcp);
    assert_ne!(DnsTransport::DoT, DnsTransport::DoH);
    assert_ne!(DnsTransport::DoH, DnsTransport::DoQ);
}

#[test]
fn test_dns_transport_clone_debug() {
    let transport = DnsTransport::Udp;
    let _cloned = transport.clone();
    let _debug = format!("{:?}", transport);
}

// ============================================================================
// DnsConfig Tests
// ============================================================================

#[test]
fn test_dns_config_default() {
    let config = DnsConfig::default();

    // Default server is Google DNS
    assert_eq!(config.server, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

    // Default transport is UDP
    assert_eq!(config.transport, DnsTransport::Udp);

    // Port should be None (use default)
    assert!(config.port.is_none());

    // EDNS0 should be enabled
    assert!(config.enable_edns0);
    assert_eq!(config.edns0_buffer_size, 1232);

    // Timeouts should be reasonable
    assert_eq!(config.timeout, Duration::from_secs(5));
    assert_eq!(config.query_timeout, Duration::from_secs(3));
}

#[test]
fn test_dns_config_custom() {
    let config = DnsConfig {
        server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), // Cloudflare DNS
        port: Some(5353),
        transport: DnsTransport::Tcp,
        timeout: Duration::from_secs(10),
        tls_server_name: Some("cloudflare-dns.com".to_string()),
        query_timeout: Duration::from_secs(5),
        enable_edns0: false,
        edns0_buffer_size: 512,
        doh_url: None,
    };

    assert_eq!(config.server, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(config.port, Some(5353));
    assert_eq!(config.transport, DnsTransport::Tcp);
    assert!(!config.enable_edns0);
}

#[test]
fn test_dns_config_ipv6() {
    let config = DnsConfig {
        server: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        port: None,
        transport: DnsTransport::Udp,
        timeout: Duration::from_secs(5),
        tls_server_name: None,
        query_timeout: Duration::from_secs(3),
        enable_edns0: true,
        edns0_buffer_size: 1232,
        doh_url: None,
    };

    assert!(config.server.is_ipv6());
}

#[test]
fn test_dns_config_all_transports() {
    // Verify all transport types can be used in config
    for transport in [
        DnsTransport::Udp,
        DnsTransport::Tcp,
        DnsTransport::DoT,
        DnsTransport::DoH,
        DnsTransport::DoQ,
    ] {
        let config = DnsConfig {
            transport: transport.clone(),
            ..DnsConfig::default()
        };
        assert_eq!(config.transport, transport);
    }
}

// ============================================================================
// DnsConnector Tests
// ============================================================================

#[test]
fn test_dns_connector_new() {
    let config = DnsConfig::default();
    let connector = DnsConnector::new(config);
    assert_eq!(connector.name(), "dns");
}

#[test]
fn test_dns_connector_default() {
    let connector = DnsConnector::default();
    assert_eq!(connector.name(), "dns");
}

#[test]
fn test_dns_connector_implements_outbound_connector() {
    fn assert_outbound_connector<T: OutboundConnector>() {}
    assert_outbound_connector::<DnsConnector>();
}

#[test]
fn test_dns_connector_implements_debug_clone() {
    let connector = DnsConnector::default();
    let _debug = format!("{:?}", connector);
    let _cloned = connector.clone();
}

// ============================================================================
// Async Tests
// ============================================================================

#[tokio::test]
async fn test_dns_connector_start() {
    let connector = DnsConnector::default();
    let result = connector.start().await;
    // Start may warn about connectivity but should not fail
    assert!(result.is_ok(), "DNS connector start should succeed");
}

#[tokio::test]
async fn test_dns_connector_dial_udp() {
    let config = DnsConfig {
        server: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        port: Some(53),
        transport: DnsTransport::Udp,
        timeout: Duration::from_secs(5),
        tls_server_name: None,
        query_timeout: Duration::from_secs(3),
        enable_edns0: true,
        edns0_buffer_size: 1232,
        doh_url: None,
    };

    let connector = DnsConnector::new(config);
    let target = Target::udp("example.com", 53);
    let opts = DialOpts::new();

    // DNS dial creates connection to DNS server
    let result = connector.dial(target, opts).await;
    assert!(
        result.is_ok(),
        "UDP DNS dial should succeed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_dns_connector_dial_tcp() {
    let config = DnsConfig {
        server: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        port: Some(53),
        transport: DnsTransport::Tcp,
        timeout: Duration::from_secs(5),
        tls_server_name: None,
        query_timeout: Duration::from_secs(3),
        enable_edns0: true,
        edns0_buffer_size: 1232,
        doh_url: None,
    };

    let connector = DnsConnector::new(config);
    let target = Target::tcp("example.com", 53);
    let opts = DialOpts::new();

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_ok(),
        "TCP DNS dial should succeed: {:?}",
        result.err()
    );
}

#[tokio::test]
#[ignore] // Network behavior varies - may succeed immediately on some systems
async fn test_dns_connector_timeout() {
    // Use a non-routable IP
    let config = DnsConfig {
        server: IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1)),
        port: Some(53),
        transport: DnsTransport::Tcp,
        timeout: Duration::from_millis(500), // Short timeout
        tls_server_name: None,
        query_timeout: Duration::from_secs(1),
        enable_edns0: true,
        edns0_buffer_size: 1232,
        doh_url: None,
    };

    let connector = DnsConnector::new(config);
    let target = Target::tcp("example.com", 53);
    let opts = DialOpts::new();

    let start = std::time::Instant::now();
    let result = connector.dial(target, opts).await;
    let elapsed = start.elapsed();

    // Should fail and respect timeout
    assert!(result.is_err(), "Should fail on non-routable IP");
    assert!(
        elapsed < Duration::from_secs(5),
        "Should respect timeout, took {:?}",
        elapsed
    );
}

// ============================================================================
// DoH and DoQ Tests (feature-gated)
// ============================================================================

#[cfg(feature = "dns_doh")]
#[tokio::test]
async fn test_dns_connector_dial_doh() {
    let config = DnsConfig {
        server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        port: None,
        transport: DnsTransport::DoH,
        timeout: Duration::from_secs(10),
        tls_server_name: Some("cloudflare-dns.com".to_string()),
        query_timeout: Duration::from_secs(5),
        enable_edns0: true,
        edns0_buffer_size: 1232,
        doh_url: Some("https://cloudflare-dns.com/dns-query".to_string()),
    };

    let connector = DnsConnector::new(config);
    let target = Target::tcp("example.com", 443);
    let opts = DialOpts::new();

    let result = connector.dial(target, opts).await;
    assert!(
        result.is_ok(),
        "DoH DNS dial should succeed: {:?}",
        result.err()
    );
}

#[test]
fn test_dns_config_with_doh_url() {
    let config = DnsConfig {
        server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        port: None,
        transport: DnsTransport::DoH,
        timeout: Duration::from_secs(10),
        tls_server_name: Some("cloudflare-dns.com".to_string()),
        query_timeout: Duration::from_secs(5),
        enable_edns0: true,
        edns0_buffer_size: 1232,
        doh_url: Some("https://dns.google/dns-query".to_string()),
    };

    assert_eq!(
        config.doh_url,
        Some("https://dns.google/dns-query".to_string())
    );
}
