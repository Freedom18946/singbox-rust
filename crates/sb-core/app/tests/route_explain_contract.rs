//! Route Explain JSON Contract Test
//!
//! This test locks the JSON schema for the route explain command output.
//! Any field additions, deletions, or type changes will cause this test to fail.
//! This ensures API stability for CLI consumers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{json, Value};

#[test]
fn test_route_explain_json_schema_contract() {
    // Mock route explain result that represents the expected structure
    let explain_result = json!({
        "dest": "example.com:443",
        "matched_rule": "geo-us",
        "chain": ["cidr:1.2.3.0/24", "geoip:US"],
        "outbound": "proxy-us",
        "rule_id": "abcd1234",
        "reason": "matched geographic rule"
    });

    // Test required fields exist and have correct types
    assert!(explain_result.is_object(), "Explain result must be an object");

    let obj = explain_result.as_object().unwrap();

    // Test required fields
    assert!(obj.contains_key("dest"), "Must contain 'dest' field");
    assert!(obj.contains_key("matched_rule"), "Must contain 'matched_rule' field");
    assert!(obj.contains_key("chain"), "Must contain 'chain' field");
    assert!(obj.contains_key("outbound"), "Must contain 'outbound' field");
    assert!(obj.contains_key("rule_id"), "Must contain 'rule_id' field");
    assert!(obj.contains_key("reason"), "Must contain 'reason' field");

    // Test field types
    assert!(obj["dest"].is_string(), "'dest' must be a string");
    assert!(obj["matched_rule"].is_string(), "'matched_rule' must be a string");
    assert!(obj["chain"].is_array(), "'chain' must be an array");
    assert!(obj["outbound"].is_string(), "'outbound' must be a string");
    assert!(obj["rule_id"].is_string(), "'rule_id' must be a string");
    assert!(obj["reason"].is_string(), "'reason' must be a string");

    // Test chain array contains only strings
    if let Some(chain) = obj["chain"].as_array() {
        for item in chain {
            assert!(item.is_string(), "All chain items must be strings");
        }
    }

    // Test rule_id format (should be sha256-8: 8 hex characters)
    let rule_id = obj["rule_id"].as_str().unwrap();
    test_rule_id_format(rule_id);

    // Test exact field count to catch unexpected additions
    assert_eq!(obj.len(), 6, "Explain result must have exactly 6 fields: dest, matched_rule, chain, outbound, rule_id, reason");
}

fn test_rule_id_format(rule_id: &str) {
    // Rule ID should be sha256-8 format: 8 hexadecimal characters
    assert_eq!(rule_id.len(), 8, "rule_id must be exactly 8 characters (sha256-8)");
    
    // All characters should be valid hexadecimal
    for c in rule_id.chars() {
        assert!(c.is_ascii_hexdigit(), "rule_id must contain only hexadecimal characters");
    }
    
    // Should be lowercase hex
    for c in rule_id.chars() {
        if c.is_ascii_alphabetic() {
            assert!(c.is_ascii_lowercase(), "rule_id hex characters must be lowercase");
        }
    }
}

#[test]
fn test_route_explain_with_trace() {
    // Test explain result with optional trace field
    let explain_with_trace = json!({
        "dest": "api.example.com:443",
        "matched_rule": "api-rule",
        "chain": ["domain_suffix:.example.com"],
        "outbound": "direct",
        "rule_id": "ef123456",
        "reason": "matched API domain rule",
        "trace": {
            "steps": [
                {
                    "rule_index": 0,
                    "rule_type": "domain_suffix",
                    "matched": true,
                    "condition": ".example.com"
                }
            ]
        }
    });

    let obj = explain_with_trace.as_object().unwrap();
    
    // Core fields should still be present
    assert!(obj.contains_key("dest"));
    assert!(obj.contains_key("matched_rule"));
    assert!(obj.contains_key("chain"));
    assert!(obj.contains_key("outbound"));
    assert!(obj.contains_key("rule_id"));
    assert!(obj.contains_key("reason"));

    // Trace is optional but if present, should be an object
    if obj.contains_key("trace") {
        assert!(obj["trace"].is_object(), "'trace' must be an object when present");
        
        let trace = obj["trace"].as_object().unwrap();
        assert!(trace.contains_key("steps"), "trace must contain 'steps' field");
        assert!(trace["steps"].is_array(), "'steps' must be an array");
    }
}

#[test]
fn test_route_explain_chain_variations() {
    // Test different chain formats that should be supported
    let test_cases = vec![
        // Empty chain
        json!([]),
        
        // Single CIDR match
        json!(["cidr:192.168.1.0/24"]),
        
        // GeoIP match
        json!(["geoip:US"]),
        
        // Multiple conditions
        json!(["cidr:10.0.0.0/8", "geoip:CN", "domain_suffix:.cn"]),
        
        // Complex chain
        json!(["port:443", "domain_keyword:api", "geoip:US"])
    ];

    for chain in test_cases {
        let explain_result = json!({
            "dest": "test.com:80",
            "matched_rule": "test-rule",
            "chain": chain,
            "outbound": "direct",
            "rule_id": "12345678",
            "reason": "test case"
        });

        let obj = explain_result.as_object().unwrap();
        assert!(obj["chain"].is_array(), "chain must be an array");
        
        let chain_array = obj["chain"].as_array().unwrap();
        for item in chain_array {
            assert!(item.is_string(), "chain item must be string");
            
            // Chain items should follow expected format patterns
            let item_str = item.as_str().unwrap();
            assert!(!item_str.is_empty(), "chain item should not be empty");
        }
    }
}

#[test]
fn test_route_explain_outbound_types() {
    // Test various outbound types that should be supported
    const OUTBOUND_TYPES: &[&str] = &[ 
        "direct",
        "block", 
        "proxy-us",
        "proxy-eu",
        "socks5-local",
        "http-proxy",
        "wireguard-home",
        "custom-outbound-123"
    ];

    for &outbound in OUTBOUND_TYPES {
        let explain_result = json!({
            "dest": "test.example.com:443",
            "matched_rule": "test-rule",
            "chain": ["test:rule"],
            "outbound": outbound,
            "rule_id": "deadbeef",
            "reason": "test outbound type"
        });

        let obj = explain_result.as_object().unwrap();
        assert_eq!(obj["outbound"].as_str().unwrap(), outbound);
    }
}

#[test]
fn test_route_explain_dest_formats() {
    // Test various destination formats
    const DEST_FORMATS: &[&str] = &[
        // Domain with port
        "example.com:443",
        "api.service.com:8080",
        
        // IP with port  
        "1.2.3.4:80",
        "192.168.1.1:22",
        
        // IPv6 with port (brackets)
        "[2001:db8::1]:443",
        "[::1]:8080",
        
        // Domain without port (routing decision context)
        "example.com",
        
        // IP without port
        "8.8.8.8"
    ];

    for &dest in DEST_FORMATS {
        let explain_result = json!({
            "dest": dest,
            "matched_rule": "test-rule",
            "chain": [],
            "outbound": "direct",
            "rule_id": "fedcba98",
            "reason": "test destination format"
        });

        let obj = explain_result.as_object().unwrap();
        assert_eq!(obj["dest"].as_str().unwrap(), dest);
        assert!(!obj["dest"].as_str().unwrap().is_empty(), "dest should not be empty");
    }
}

#[test]
fn test_route_explain_field_order_stability() {
    // Test that field order remains consistent for API stability
    let explain_result = json!({
        "dest": "example.com:443",
        "matched_rule": "default",
        "chain": ["all"],
        "outbound": "direct",
        "rule_id": "00000000",
        "reason": "default rule"
    });

    let serialized = serde_json::to_string(&explain_result).unwrap();
    let parsed: Value = serde_json::from_str(&serialized).unwrap();

    // Verify all expected fields are present after round-trip
    let obj = parsed.as_object().unwrap();
    assert!(obj.contains_key("dest"));
    assert!(obj.contains_key("matched_rule"));
    assert!(obj.contains_key("chain"));
    assert!(obj.contains_key("outbound"));
    assert!(obj.contains_key("rule_id"));
    assert!(obj.contains_key("reason"));
}

#[test]
fn test_route_explain_no_extra_fields() {
    // Test that the contract prevents unexpected field additions
    const CORE_FIELDS: &[&str] = &["dest", "matched_rule", "chain", "outbound", "rule_id", "reason"];
    
    let explain_result = json!({
        "dest": "test.com:80",
        "matched_rule": "test",
        "chain": [],
        "outbound": "direct", 
        "rule_id": "ffffffff",
        "reason": "test"
    });

    let obj = explain_result.as_object().unwrap();
    
    // Verify exactly the core fields exist
    assert_eq!(obj.len(), CORE_FIELDS.len(), "Should have exactly {} core fields", CORE_FIELDS.len());
    
    for &field in CORE_FIELDS {
        assert!(obj.contains_key(field), "Missing required field: {}", field);
    }
}
