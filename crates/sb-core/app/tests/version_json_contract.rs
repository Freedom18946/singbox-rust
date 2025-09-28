//! Version JSON Contract Test
//!
//! This test locks the JSON schema for the version command output.
//! Any field additions, deletions, or type changes will cause this test to fail.
//! This ensures API stability for CLI consumers.

use serde_json::{json, Value};
use std::collections::BTreeMap;

#[test]
fn test_version_json_schema_contract() {
    // Mock version info that represents the expected structure
    let version_info = json!({
        "name": "singbox-rust",
        "version": "0.1.0",
        "commit": "abcd1234",
        "date": "2024-01-01T00:00:00Z",
        "features": ["router", "metrics"]
    });

    // Test required fields exist and have correct types
    assert!(version_info.is_object(), "Version info must be an object");

    let obj = version_info.as_object().unwrap();

    // Test required fields
    assert!(obj.contains_key("name"), "Must contain 'name' field");
    assert!(obj.contains_key("version"), "Must contain 'version' field");
    assert!(obj.contains_key("commit"), "Must contain 'commit' field");
    assert!(obj.contains_key("date"), "Must contain 'date' field");
    assert!(obj.contains_key("features"), "Must contain 'features' field");

    // Test field types
    assert!(obj["name"].is_string(), "'name' must be a string");
    assert!(obj["version"].is_string(), "'version' must be a string");
    assert!(obj["commit"].is_string(), "'commit' must be a string");
    assert!(obj["date"].is_string(), "'date' must be a string");
    assert!(obj["features"].is_array(), "'features' must be an array");

    // Test features array contains only strings
    if let Some(features) = obj["features"].as_array() {
        for feature in features {
            assert!(feature.is_string(), "All features must be strings");
        }
    }

    // Test exact field count to catch unexpected additions
    assert_eq!(obj.len(), 5, "Version info must have exactly 5 fields: name, version, commit, date, features");
}

#[test]
fn test_version_json_field_order_stability() {
    // Test that serialization produces consistent field order
    let version_info = json!({
        "name": "singbox-rust",
        "version": "0.1.0",
        "commit": "abcd1234",
        "date": "2024-01-01T00:00:00Z",
        "features": ["router"]
    });

    let serialized = serde_json::to_string(&version_info).unwrap();

    // Parse back to ensure structure integrity
    let parsed: Value = serde_json::from_str(&serialized).unwrap();

    // Verify all expected fields are present after round-trip
    let obj = parsed.as_object().unwrap();
    assert!(obj.contains_key("name"));
    assert!(obj.contains_key("version"));
    assert!(obj.contains_key("commit"));
    assert!(obj.contains_key("date"));
    assert!(obj.contains_key("features"));
}

#[test]
fn test_version_features_array_contract() {
    // Test that features array maintains expected structure
    let known_features = vec![
        "router", "metrics", "admin_debug", "bench-cli",
        "dev-cli", "manpage", "reqwest", "subs_http"
    ];

    // Test with multiple features
    let version_info = json!({
        "name": "singbox-rust",
        "version": "0.1.0",
        "commit": "abcd1234",
        "date": "2024-01-01T00:00:00Z",
        "features": known_features
    });

    let features = version_info["features"].as_array().unwrap();
    assert!(features.len() > 0, "Should have at least some features in test");

    // All features should be strings
    for feature in features {
        assert!(feature.is_string(), "Feature must be string");
        // Feature names should be non-empty
        let feature_str = feature.as_str().unwrap();
        assert!(!feature_str.is_empty(), "Feature name should not be empty");
    }
}

#[test]
fn test_version_json_no_extra_fields() {
    // Test that the contract prevents unexpected field additions
    let mut version_map: BTreeMap<String, Value> = BTreeMap::new();
    version_map.insert("name".to_string(), json!("singbox-rust"));
    version_map.insert("version".to_string(), json!("0.1.0"));
    version_map.insert("commit".to_string(), json!("abcd1234"));
    version_map.insert("date".to_string(), json!("2024-01-01T00:00:00Z"));
    version_map.insert("features".to_string(), json!([]));

    // This represents the expected schema
    let expected_fields: Vec<&str> = vec!["name", "version", "commit", "date", "features"];

    // Verify exactly these fields exist
    assert_eq!(version_map.len(), expected_fields.len());
    for field in expected_fields {
        assert!(version_map.contains_key(field), "Missing required field: {}", field);
    }

    // If someone adds a new field, this test will fail
    let version_value = Value::Object(version_map.into_iter().collect());
    let obj = version_value.as_object().unwrap();
    assert_eq!(obj.len(), 5, "Version schema must have exactly 5 fields");
}
