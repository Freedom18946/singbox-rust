//! Integration tests for GeoIP database support in routing engine

use sb_core::router::{
    geo::{GeoIpDb, GeoIpManager},
    RouterHandle,
};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tempfile::NamedTempFile;

#[test]
fn test_router_handle_with_geoip_db() {
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

    // Verify that the GeoIP database is set
    assert!(router_handle.geoip_db().is_some());

    let geoip_db_ref = router_handle.geoip_db().unwrap();

    // Test IP lookups
    let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(geoip_db_ref.lookup_country(us_ip), Some("US".to_string()));

    let cn_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(geoip_db_ref.lookup_country(cn_ip), Some("CN".to_string()));

    let jp_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    assert_eq!(geoip_db_ref.lookup_country(jp_ip), Some("JP".to_string()));

    // Test unknown IP
    let unknown_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(geoip_db_ref.lookup_country(unknown_ip), None);
}

#[test]
fn test_router_handle_with_geoip_file() {
    // Create a temporary GeoIP database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "203.0.113.0/24,AU").expect("Failed to write to temp file");
    writeln!(temp_file, "198.51.100.0/24,CA").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Create RouterHandle with GeoIP file
    let router_handle = RouterHandle::from_env()
        .with_geoip_file(temp_file.path())
        .expect("Failed to load GeoIP from file");

    // Verify that the GeoIP database is set
    assert!(router_handle.geoip_db().is_some());

    let geoip_db_ref = router_handle.geoip_db().unwrap();

    // Test IP lookups
    let au_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    assert_eq!(geoip_db_ref.lookup_country(au_ip), Some("AU".to_string()));

    let ca_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    assert_eq!(geoip_db_ref.lookup_country(ca_ip), Some("CA".to_string()));
}

#[test]
fn test_geoip_manager_multiple_databases() {
    // Create first database
    let mut temp_file1 = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file1, "10.0.0.0/8,US").expect("Failed to write to temp file");
    temp_file1.flush().expect("Failed to flush temp file");

    let geoip_db1 =
        GeoIpDb::load_from_file(temp_file1.path()).expect("Failed to load GeoIP database 1");

    // Create second database
    let mut temp_file2 = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file2, "192.168.0.0/16,CN").expect("Failed to write to temp file");
    temp_file2.flush().expect("Failed to flush temp file");

    let geoip_db2 =
        GeoIpDb::load_from_file(temp_file2.path()).expect("Failed to load GeoIP database 2");

    // Create GeoIP manager with multiple databases
    let mut manager = GeoIpManager::new();
    manager.set_primary(Arc::new(geoip_db1));
    manager.add_fallback(Arc::new(geoip_db2));

    // Test lookups from primary database
    let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(manager.lookup_country(us_ip), Some("US".to_string()));

    // Test lookups from fallback database
    let cn_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(manager.lookup_country(cn_ip), Some("CN".to_string()));

    // Test unknown IP
    let unknown_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(manager.lookup_country(unknown_ip), None);
}

#[test]
fn test_geoip_database_stats() {
    // Create a temporary GeoIP database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "10.0.0.0/8,US").expect("Failed to write to temp file");
    writeln!(temp_file, "192.168.0.0/16,CN").expect("Failed to write to temp file");
    writeln!(temp_file, "172.16.0.0/12,JP").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoIP database
    let geoip_db =
        GeoIpDb::load_from_file(temp_file.path()).expect("Failed to load GeoIP database");

    // Get database statistics
    let stats = geoip_db.stats();

    // Verify statistics
    assert_eq!(stats.total_countries, 3);
    assert!(stats.database_size > 0);
    assert_eq!(stats.cache_size, 0); // No lookups performed yet

    // Perform a lookup to populate cache
    let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    let _country = geoip_db.lookup_country(us_ip);

    // Note: In the current implementation, cache is not actually used in lookup_country
    // This is a placeholder for when caching is properly implemented
}

#[test]
fn test_geoip_available_countries() {
    // Create a temporary GeoIP database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "10.0.0.0/8,US").expect("Failed to write to temp file");
    writeln!(temp_file, "192.168.0.0/16,CN").expect("Failed to write to temp file");
    writeln!(temp_file, "172.16.0.0/12,JP").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoIP database
    let geoip_db =
        GeoIpDb::load_from_file(temp_file.path()).expect("Failed to load GeoIP database");

    // Get available countries
    let countries = geoip_db.available_countries();

    // Verify available countries (note: these are from the placeholder implementation)
    assert_eq!(countries.len(), 3);
    assert!(countries.contains(&"US".to_string()));
    assert!(countries.contains(&"CN".to_string()));
    assert!(countries.contains(&"JP".to_string()));
}

#[test]
fn test_geoip_lookup_with_country_matching() {
    // Create a temporary GeoIP database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "10.0.0.0/8,US").expect("Failed to write to temp file");
    writeln!(temp_file, "192.168.0.0/16,CN").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoIP database
    let geoip_db =
        GeoIpDb::load_from_file(temp_file.path()).expect("Failed to load GeoIP database");

    // Test country matching
    let us_ip = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    assert!(geoip_db.lookup(us_ip, "US"));
    assert!(!geoip_db.lookup(us_ip, "CN"));
    assert!(!geoip_db.lookup(us_ip, "JP"));

    let cn_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert!(geoip_db.lookup(cn_ip, "CN"));
    assert!(!geoip_db.lookup(cn_ip, "US"));
    assert!(!geoip_db.lookup(cn_ip, "JP"));

    // Test case insensitive matching
    assert!(geoip_db.lookup(us_ip, "us"));
    assert!(geoip_db.lookup(cn_ip, "cn"));
}
