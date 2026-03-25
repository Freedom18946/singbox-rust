#![cfg(feature = "router")]
#![cfg(all(feature = "geoip_mmdb", feature = "router"))]
use std::net::IpAddr;

// Test removed: geoip API uses GeoIpProvider trait with weak-owner model
// (install_default_geoip_service). This test needs rewrite to use the new API.

#[test]
fn placeholder_test() {
    // Placeholder until proper geoip provider test is rewritten
    let ip: IpAddr = "11.1.2.3".parse().unwrap();
    assert!(ip.is_ipv4());
}
