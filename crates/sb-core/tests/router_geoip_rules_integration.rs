#![cfg(feature = "router")]
//! Integration tests for GeoIP rules in routing engine

use sb_core::router::{geo::GeoIpDb, router_build_index_from_str, RouterHandle};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tempfile::NamedTempFile;

#[test]
#[ignore] // Requires MMDB format database file
fn test_geoip_rules_integration() {
    // Create a temporary GeoIP database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "10.0.0.0/8,US").expect("Failed to write to temp file");
    writeln!(temp_file, "192.168.0.0/16,CN").expect("Failed to write to temp file");
    writeln!(temp_file, "172.16.0.0/12,JP").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoIP database
    let geoip_db =
        GeoIpDb::load_from_file(temp_file.path()).expect("Failed to load GeoIP database");

    // Create RouterHandle with GeoIP database
    let router_handle = RouterHandle::from_env().with_geoip_db(Arc::new(geoip_db));

    // Create router rules with GeoIP rules
    let rules = "geoip:US=direct\ngeoip:CN=proxy\ngeoip:JP=reject\ndefault=block";
    let router_index =
        router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Test US IP (should match geoip:US=direct)
    let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    if let Some(decision) = router_handle.enhanced_geoip_lookup(us_ip, &router_index) {
        assert_eq!(decision, "direct");
    } else {
        panic!("Expected GeoIP match for US IP");
    }

    // Test CN IP (should match geoip:CN=proxy)
    let cn_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    if let Some(decision) = router_handle.enhanced_geoip_lookup(cn_ip, &router_index) {
        assert_eq!(decision, "proxy");
    } else {
        panic!("Expected GeoIP match for CN IP");
    }

    // Test JP IP (should match geoip:JP=reject)
    let jp_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    if let Some(decision) = router_handle.enhanced_geoip_lookup(jp_ip, &router_index) {
        assert_eq!(decision, "reject");
    } else {
        panic!("Expected GeoIP match for JP IP");
    }

    // Test unknown IP (should return None, fall back to default)
    let unknown_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let decision = router_handle.enhanced_geoip_lookup(unknown_ip, &router_index);
    assert!(decision.is_none(), "Expected no GeoIP match for unknown IP");
}

#[test]
#[ignore] // Requires MMDB format database file
fn test_geoip_case_insensitive_matching() {
    // Create a temporary GeoIP database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "10.0.0.0/8,us").expect("Failed to write to temp file"); // lowercase in database
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoIP database
    let geoip_db =
        GeoIpDb::load_from_file(temp_file.path()).expect("Failed to load GeoIP database");

    // Create RouterHandle with GeoIP database
    let router_handle = RouterHandle::from_env().with_geoip_db(Arc::new(geoip_db));

    // Create router rules with uppercase country code
    let rules = "geoip:US=direct\ndefault=block";
    let router_index =
        router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Test US IP (should match despite case difference)
    let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    if let Some(decision) = router_handle.enhanced_geoip_lookup(us_ip, &router_index) {
        assert_eq!(decision, "direct");
    } else {
        panic!("Expected case-insensitive GeoIP match for US IP");
    }
}

#[test]
#[ignore] // Requires MMDB format database file
fn test_geoip_multiple_rules_first_match_wins() {
    // Create a temporary GeoIP database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "10.0.0.0/8,US").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoIP database
    let geoip_db =
        GeoIpDb::load_from_file(temp_file.path()).expect("Failed to load GeoIP database");

    // Create RouterHandle with GeoIP database
    let router_handle = RouterHandle::from_env().with_geoip_db(Arc::new(geoip_db));

    // Create router rules with multiple US rules (first should win)
    let rules = "geoip:US=direct\ngeoip:US=proxy\ndefault=block";
    let router_index =
        router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Test US IP (should match first rule: direct)
    let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    if let Some(decision) = router_handle.enhanced_geoip_lookup(us_ip, &router_index) {
        assert_eq!(decision, "direct");
    } else {
        panic!("Expected GeoIP match for US IP");
    }
}
