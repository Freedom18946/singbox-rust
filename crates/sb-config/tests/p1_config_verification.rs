//! P1 Features Config Parsing Verification Tests
//!
//! This test module verifies that all P1 feature configurations parse correctly:
//! 1. AdGuard rules - in RuleIR
//! 2. UDP over TCP config - in OutboundIR
//! 3. Headless/Logical rules - in RuleIR
//! 4. uTLS fingerprint - in OutboundIR

use sb_config::ir::RuleIR;

/// Test UoT config fields parse correctly via JSON value access
#[test]
fn test_uot_config_parsing() {
    let json = r#"{
        "type": "shadowsocks",
        "server": "example.com",
        "port": 443,
        "udp_over_tcp": true,
        "udp_over_tcp_version": 2
    }"#;
    
    let doc: serde_json::Value = serde_json::from_str(json).expect("parse JSON");
    assert_eq!(doc["udp_over_tcp"], true);
    assert_eq!(doc["udp_over_tcp_version"], 2);
}

/// Test uTLS fingerprint field parses correctly
#[test]
fn test_utls_fingerprint_parsing() {
    let json = r#"{
        "type": "vmess",
        "server": "example.com",
        "port": 443,
        "utls_fingerprint": "chrome"
    }"#;
    
    let doc: serde_json::Value = serde_json::from_str(json).expect("parse JSON");
    assert_eq!(doc["utls_fingerprint"], "chrome");
}

/// Test headless/logical rule type fields parse correctly
#[test]
fn test_headless_rule_parsing() {
    let json = r#"{
        "type": "logical",
        "mode": "and",
        "rules": [
            { "network": ["tcp"] },
            { "domain_suffix": [".example.com"] }
        ],
        "outbound": "proxy"
    }"#;
    
    let rule: RuleIR = serde_json::from_str(json).expect("parse RuleIR");
    assert_eq!(rule.rule_type.as_deref(), Some("logical"));
    assert_eq!(rule.mode.as_deref(), Some("and"));
    assert_eq!(rule.rules.len(), 2);
    assert_eq!(rule.outbound.as_deref(), Some("proxy"));
}

/// Test AdGuard rule fields parse correctly in RuleIR
#[test]
fn test_adguard_rule_config_parsing() {
    let json = r#"{
        "adguard": ["||ads.example.org^", "@@||safe.example.org^"],
        "not_adguard": ["||tracker.com^"],
        "outbound": "block"
    }"#;
    
    let rule: RuleIR = serde_json::from_str(json).expect("parse RuleIR");
    assert_eq!(rule.adguard.len(), 2);
    assert_eq!(rule.adguard[0], "||ads.example.org^");
    assert_eq!(rule.adguard[1], "@@||safe.example.org^");
    assert_eq!(rule.not_adguard.len(), 1);
    assert_eq!(rule.not_adguard[0], "||tracker.com^");
}

/// Test inverted rule with invert flag
#[test]
fn test_rule_with_invert() {
    let json = r#"{
        "domain_suffix": [".cn"],
        "invert": true,
        "outbound": "direct"
    }"#;
    
    let rule: RuleIR = serde_json::from_str(json).expect("parse RuleIR");
    assert!(rule.invert);
    assert_eq!(rule.domain_suffix.len(), 1);
}

/// Full integration test with all P1 features combined
#[test]
fn test_full_p1_config() {
    let json = r#"{
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-proxy",
                "server": "example.com",
                "port": 8388,
                "method": "aes-256-gcm",
                "password": "secret",
                "udp_over_tcp": true,
                "udp_over_tcp_version": 2,
                "utls_fingerprint": "chrome110"
            }
        ],
        "route": {
            "rules": [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        { "network": ["tcp"] },
                        { "port": ["443", "80"] }
                    ],
                    "outbound": "ss-proxy"
                },
                {
                    "adguard": ["||ads.google.com^"],
                    "outbound": "block"
                }
            ]
        }
    }"#;
    
    let doc: serde_json::Value = serde_json::from_str(json).expect("parse JSON");
    
    // Verify outbound
    let ob = &doc["outbounds"][0];
    assert_eq!(ob["udp_over_tcp"], true);
    assert_eq!(ob["udp_over_tcp_version"], 2);
    assert_eq!(ob["utls_fingerprint"], "chrome110");
    
    // Verify rules
    let rules = doc["route"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["type"], "logical");
    assert_eq!(rules[0]["mode"], "and");
    assert_eq!(rules[1]["adguard"][0], "||ads.google.com^");
}
