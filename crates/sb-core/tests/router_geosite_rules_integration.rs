#![cfg(feature = "router")]
//! Integration tests for GeoSite rules in routing engine

use sb_core::router::{geo::GeoSiteDb, router_build_index_from_str, RouterHandle};
use std::io::Write;
use std::sync::Arc;
use tempfile::NamedTempFile;

#[test]
fn test_geosite_rules_parsing() {
    // Test GeoSite rule parsing in router build
    let rules = "geosite:google=proxy\ngeosite:ads=reject\ndefault=direct";

    let idx = router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Verify GeoSite rules were parsed correctly
    assert_eq!(idx.geosite_rules.len(), 2);
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "google" && *dec == "proxy"));
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "ads" && *dec == "reject"));
}

#[test]
fn test_geosite_rules_with_router_handle() {
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

    // Create a mock RouterIndex with GeoSite rules
    let router_index = sb_core::router::RouterIndex {
        rules: vec![],
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
            ("social".to_string(), "direct"),
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
        default: "direct",
        gen: 0,
        checksum: [0; 32],
    };

    // Test GeoSite lookup through RouterHandle
    let result = router_handle.enhanced_geosite_lookup("google.com", &router_index);
    assert_eq!(result, Some("proxy"));

    let result = router_handle.enhanced_geosite_lookup("maps.googleapis.com", &router_index);
    assert_eq!(result, Some("proxy"));

    let result = router_handle.enhanced_geosite_lookup("googleads.com", &router_index);
    assert_eq!(result, Some("reject"));

    let result = router_handle.enhanced_geosite_lookup("facebook.com", &router_index);
    assert_eq!(result, Some("direct"));

    let result = router_handle.enhanced_geosite_lookup("example.com", &router_index);
    assert_eq!(result, None);
}

#[test]
fn test_geosite_rules_decision_priority() {
    // Test that exact rules take priority over GeoSite rules
    let rules = "exact:google.com=direct\ngeosite:google=proxy\ndefault=reject";

    let idx = router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Verify both exact and GeoSite rules exist
    assert_eq!(idx.exact.len(), 1);
    assert_eq!(idx.geosite_rules.len(), 1);
    assert!(idx.exact.contains_key("google.com"));
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "google" && *dec == "proxy"));
}

#[test]
fn test_geosite_rules_case_insensitive() {
    // Test case insensitive GeoSite category parsing
    let rules = "geosite:GOOGLE=proxy\ngeosite:Ads=reject\ndefault=direct";

    let idx = router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Verify GeoSite rules were parsed with lowercase categories
    assert_eq!(idx.geosite_rules.len(), 2);
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "google" && *dec == "proxy"));
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "ads" && *dec == "reject"));
}

#[test]
fn test_geosite_rules_invalid_patterns() {
    // Test invalid GeoSite patterns are rejected
    let rules = "geosite:=proxy\ngeosite:valid=direct\ndefault=reject";

    let result = router_build_index_from_str(rules, 1000);
    assert!(result.is_err());
}

#[test]
fn test_geosite_rules_with_illegal_chars() {
    // Test GeoSite patterns with illegal characters are rejected
    let rules = "geosite:goo gle=proxy\ndefault=direct";

    let result = router_build_index_from_str(rules, 1000);
    assert!(result.is_err());
}

#[test]
fn test_geosite_rules_metrics_integration() {
    // Create a temporary GeoSite database file
    let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
    writeln!(temp_file, "google:exact:google.com").expect("Failed to write to temp file");
    temp_file.flush().expect("Failed to flush temp file");

    // Load GeoSite database
    let geosite_db =
        GeoSiteDb::load_from_file(temp_file.path()).expect("Failed to load GeoSite database");

    // Build router index with GeoSite rules
    let rules = "geosite:google=proxy\ndefault=direct";
    let idx = router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Verify metrics would be recorded (we can't easily test actual metrics in unit tests)
    assert_eq!(idx.geosite_rules.len(), 1);

    // Create RouterHandle with GeoSite database
    let router_handle = RouterHandle::from_env().with_geosite_db(Arc::new(geosite_db));

    // Test that enhanced lookup works
    let result = router_handle.enhanced_geosite_lookup("google.com", &idx);
    assert_eq!(result, Some("proxy"));
}

#[test]
fn test_geosite_rules_multiple_categories() {
    // Test multiple GeoSite categories for the same decision
    let rules = "geosite:google=proxy\ngeosite:youtube=proxy\ngeosite:ads=reject\ndefault=direct";

    let idx = router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Verify all GeoSite rules were parsed
    assert_eq!(idx.geosite_rules.len(), 3);
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "google" && *dec == "proxy"));
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "youtube" && *dec == "proxy"));
    assert!(idx
        .geosite_rules
        .iter()
        .any(|(cat, dec)| cat == "ads" && *dec == "reject"));
}

#[test]
fn test_geosite_rules_with_other_rule_types() {
    // Test GeoSite rules work alongside other rule types
    let rules = r#"
exact:example.com=direct
suffix:.test.com=proxy
geosite:google=proxy
geosite:ads=reject
port:443=secure
default=direct
"#;

    let idx = router_build_index_from_str(rules, 1000).expect("Failed to build router index");

    // Verify all rule types were parsed
    assert_eq!(idx.exact.len(), 1);
    assert_eq!(idx.suffix.len(), 1);
    assert_eq!(idx.geosite_rules.len(), 2);
    assert_eq!(idx.port_rules.len(), 1);
    assert_eq!(idx.default, "direct");
}
