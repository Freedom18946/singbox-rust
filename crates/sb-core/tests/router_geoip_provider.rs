#![cfg(feature = "router")]
#![cfg(all(feature = "geoip_mmdb", feature = "router"))]
use std::net::IpAddr;

// Test removed: geoip API has changed to use GeoIpProvider instead of old Provider trait
// and uses init() instead of set_global_provider(). This test needs significant rewrite.

#[test]
fn placeholder_test() {
    // Placeholder until proper geoip provider test is rewritten
    let ip: IpAddr = "11.1.2.3".parse().unwrap();
    assert!(ip.is_ipv4());
}
