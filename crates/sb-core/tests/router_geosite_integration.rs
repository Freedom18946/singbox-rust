#![cfg(feature = "router")]
//! Integration tests for GeoSite database support in routing engine

use sb_core::router::{
    geo::{GeoSiteDb, GeoSiteManager},
    RouterHandle,
};
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_router_handle_with_geosite_db() {
    // Create a temporary GeoSite database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "google:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "google:suffix:.googleapis.com").expect("Failed to write to temp file");
    writeln!(temp_file, "ads:keyword:ads").expect("Failed to write to temp file");
    writeln!(temp_file, "social:exact:facebook.com").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoSite database
    let geosite_db =
        GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

    // Create RouterHandle with GeoSite database
    let router_handle = RouterHandle::from_env().with_geosite_db(Arc::new(geosite_db));

    // Verify that the GeoSite database is set
    assert!(router_handle.geosite_db().is_some());

    let geosite_db_ref = router_handle.geosite_db().unwrap();

    // Test domain lookups
    assert!(geosite_db_ref.match_domain("google.com", "google"));
    assert!(geosite_db_ref.match_domain("maps.googleapis.com", "google"));
    assert!(geosite_db_ref.match_domain("googleads.com", "ads"));
    assert!(geosite_db_ref.match_domain("facebook.com", "social"));

    // Test non-matches
    assert!(!geosite_db_ref.match_domain("yahoo.com", "google"));
    assert!(!geosite_db_ref.match_domain("twitter.com", "social"));
}

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_router_handle_with_geosite_file() {
    // Create a temporary GeoSite database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "streaming:exact:youtube.com").expect("Failed to write to temp file");
    writeln!(temp_file, "streaming:suffix:.youtube.com").expect("Failed to write to temp file");
    writeln!(temp_file, "cdn:keyword:cdn").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Create RouterHandle with GeoSite file
    let router_handle = RouterHandle::from_env()
        .with_geosite_file(temp_file.path())
        .expect("Failed to load GeoSite from file");

    // Verify that the GeoSite database is set
    assert!(router_handle.geosite_db().is_some());

    let geosite_db_ref = router_handle.geosite_db().unwrap();

    // Test domain lookups
    assert!(geosite_db_ref.match_domain("youtube.com", "streaming"));
    assert!(geosite_db_ref.match_domain("music.youtube.com", "streaming"));
    assert!(geosite_db_ref.match_domain("cloudflarecdn.com", "cdn"));
}

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_geosite_manager_multiple_databases() {
    // Create first database
    let mut temp_file1 = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file1, "google:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file1, "google:suffix:.google.com").expect("Failed to write to temp file");
    temp_file1.flush().expect("Failed to flush temp file");

    let geosite_db1 =
        GeoSiteDb::load_from_file(temp_file1.path()).expect("Failed to load GeoSite database 1");

    // Create second database
    let mut temp_file2 = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file2, "social:exact:facebook.com").expect("Failed to write to temp file");
    writeln!(temp_file2, "social:exact:twitter.com").expect("Failed to write to temp file");
    temp_file2.flush().expect("Failed to flush temp file");

    let geosite_db2 =
        GeoSiteDb::load_from_file(temp_file2.path()).expect("Failed to load GeoSite database 2");

    // Create GeoSite manager with multiple databases
    let mut manager = GeoSiteManager::new();
    manager.set_primary(Arc::new(geosite_db1));
    manager.add_fallback(Arc::new(geosite_db2));

    // Test lookups from primary database
    assert!(manager.match_domain("google.com", "google"));
    assert!(manager.match_domain("mail.google.com", "google"));

    // Test lookups from fallback database
    assert!(manager.match_domain("facebook.com", "social"));
    assert!(manager.match_domain("twitter.com", "social"));

    // Test non-matches
    assert!(!manager.match_domain("yahoo.com", "google"));
    assert!(!manager.match_domain("linkedin.com", "social"));

    // Test category lookup
    let categories = manager.lookup_categories("google.com");
    assert!(categories.contains(&"google".to_string()));
}

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_geosite_database_stats() {
    // Create a temporary GeoSite database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "google:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "google:suffix:.googleapis.com").expect("Failed to write to temp file");
    writeln!(temp_file, "ads:keyword:ads").expect("Failed to write to temp file");
    writeln!(temp_file, "social:exact:facebook.com").expect("Failed to write to temp file");
    writeln!(temp_file, "social:exact:twitter.com").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoSite database
    let geosite_db =
        GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

    // Get database statistics
    let stats = geosite_db.stats();

    // Verify statistics
    assert_eq!(stats.total_categories, 3);
    assert_eq!(stats.total_rules, 5);
    assert!(stats.database_size > 0);
    assert_eq!(stats.cache_size, 0); // No lookups performed yet
}

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_geosite_available_categories() {
    // Create a temporary GeoSite database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "google:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "ads:keyword:ads").expect("Failed to write to temp file");
    writeln!(temp_file, "social:exact:facebook.com").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoSite database
    let geosite_db =
        GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

    // Get available categories
    let categories = geosite_db.available_categories();

    // Verify available categories
    assert_eq!(categories.len(), 3);
    assert!(categories.contains(&"google".to_string()));
    assert!(categories.contains(&"ads".to_string()));
    assert!(categories.contains(&"social".to_string()));
}

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_geosite_category_matching() {
    // Create a temporary GeoSite database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "google:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "google:suffix:.googleapis.com").expect("Failed to write to temp file");
    writeln!(temp_file, "ads:keyword:ads").expect("Failed to write to temp file");
    writeln!(temp_file, "social:exact:facebook.com").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoSite database
    let geosite_db =
        GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

    // Test category matching
    assert!(geosite_db.match_domain("google.com", "google"));
    assert!(!geosite_db.match_domain("google.com", "ads"));
    assert!(!geosite_db.match_domain("google.com", "social"));

    assert!(geosite_db.match_domain("maps.googleapis.com", "google"));
    assert!(!geosite_db.match_domain("maps.googleapis.com", "ads"));

    assert!(geosite_db.match_domain("googleads.com", "ads"));
    assert!(!geosite_db.match_domain("googleads.com", "google"));

    assert!(geosite_db.match_domain("facebook.com", "social"));
    assert!(!geosite_db.match_domain("facebook.com", "google"));

    // Test case insensitive matching
    assert!(geosite_db.match_domain("GOOGLE.COM", "google"));
    assert!(geosite_db.match_domain("google.com", "GOOGLE"));
}

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_geosite_lookup_categories_multiple_matches() {
    // Create a temporary GeoSite database file with overlapping rules
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "google:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "search:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "tech:suffix:.google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "ads:keyword:ads").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoSite database
    let geosite_db =
        GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

    // Test domain that matches multiple categories
    let categories = geosite_db.lookup_categories("google.com");
    assert!(categories.len() >= 2);
    assert!(categories.contains(&"google".to_string()));
    assert!(categories.contains(&"search".to_string()));

    // Test suffix match
    let categories = geosite_db.lookup_categories("maps.google.com");
    assert!(categories.contains(&"tech".to_string()));

    // Test keyword match
    let categories = geosite_db.lookup_categories("googleads.com");
    assert!(categories.contains(&"ads".to_string()));
}

#[test]
#[ignore] // Requires protobuf format GeoSite database file
fn test_enhanced_geosite_lookup_integration() {
    // Create a temporary GeoSite database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "google:exact:google.com").expect("Failed to write to temp file");
    writeln!(temp_file, "ads:keyword:ads").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoSite database
    let geosite_db =
        GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

    // Create RouterHandle with GeoSite database
    let router_handle = RouterHandle::from_env().with_geosite_db(Arc::new(geosite_db));

    // Create a mock RouterIndex with GeoSite rules
    let router_index = sb_core::router::RouterIndex {
        exact: std::collections::HashMap::new(),
        suffix: vec![],
        suffix_map: std::collections::HashMap::new(),
        port_rules: std::collections::HashMap::new(),
        port_ranges: vec![],
        transport_tcp: None,
        transport_udp: None,
        cidr4: vec![],
        cidr6: vec![],
        cidr4_buckets: vec![Vec::new(); 33],
        cidr6_buckets: vec![Vec::new(); 129],
        geoip_rules: vec![],
        geosite_rules: vec![
            ("google".to_string(), "proxy"),
            ("ads".to_string(), "reject"),
        ],
        wifi_ssid_rules: vec![],
        wifi_bssid_rules: vec![],
        rule_set_rules: vec![],
        process_rules: vec![],
        process_path_rules: vec![],
        protocol_rules: vec![],
        network_rules: vec![],
        source_rules: vec![],
        dest_rules: vec![],
        user_agent_rules: vec![],
        #[cfg(feature = "router_keyword")]
        keyword_rules: vec![],
        #[cfg(feature = "router_keyword")]
        keyword_idx: None,
        rules: vec![],
        default: "direct",
        gen: 0,
        checksum: [0; 32],
    };

    // Test enhanced GeoSite lookup
    let result = router_handle.enhanced_geosite_lookup("google.com", &router_index);
    assert_eq!(result, Some("proxy"));

    let result = router_handle.enhanced_geosite_lookup("googleads.com", &router_index);
    assert_eq!(result, Some("reject"));

    let result = router_handle.enhanced_geosite_lookup("example.com", &router_index);
    assert_eq!(result, None);
}
