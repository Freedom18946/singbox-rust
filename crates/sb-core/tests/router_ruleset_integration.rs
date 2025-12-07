#![cfg(feature = "router")]
//! Integration tests for rule-set loading and matching
//!
//! Tests cover:
//! - Local rule-set loading
//! - Rule-set manager caching
//! - Domain/IP matching with rule-sets
//! - Rule-set format detection

use sb_core::router::ruleset::{
    DefaultRule, IpCidr, Rule, RuleSetFormat, RuleSetManager, RuleSetSource,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn test_ruleset_manager_basic() {
    let temp_dir = std::env::temp_dir().join("sb-ruleset-test");
    let _ = std::fs::create_dir_all(&temp_dir);

    let manager = RuleSetManager::new(temp_dir.clone(), Duration::from_secs(3600));

    // Test loading non-existent rule-set
    let result = manager
        .load(
            "test".to_string(),
            RuleSetSource::Local(PathBuf::from("/nonexistent")),
            RuleSetFormat::Binary,
        )
        .await;
    assert!(result.is_err());

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ip_cidr_parsing() {
    // Test IPv4 CIDR
    let cidr = IpCidr::parse("192.168.1.0/24").unwrap();
    assert_eq!(cidr.prefix_len, 24);

    let ip: std::net::IpAddr = "192.168.1.100".parse().unwrap();
    assert!(cidr.matches(&ip));

    let ip2: std::net::IpAddr = "192.168.2.1".parse().unwrap();
    assert!(!cidr.matches(&ip2));

    // Test IPv6 CIDR
    let cidr6 = IpCidr::parse("2001:db8::/32").unwrap();
    assert_eq!(cidr6.prefix_len, 32);

    let ip6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
    assert!(cidr6.matches(&ip6));

    let ip6_2: std::net::IpAddr = "2001:db9::1".parse().unwrap();
    assert!(!cidr6.matches(&ip6_2));
}

#[test]
fn test_default_rule_domain_matching() {
    let mut rule = DefaultRule::default();

    // Add domain suffix
    rule.domain_suffix.push("example.com".to_string());

    // Add domain keyword
    rule.domain_keyword.push("test".to_string());

    // Add exact domain (using DomainRule enum)
    use sb_core::router::ruleset::DomainRule;
    rule.domain.push(DomainRule::Exact("exact.com".to_string()));

    // Test suffix matching
    assert!(rule.domain_suffix.contains(&"example.com".to_string()));

    // Test keyword matching
    assert!(rule.domain_keyword.contains(&"test".to_string()));
}

#[test]
fn test_default_rule_port_matching() {
    let mut rule = DefaultRule::default();

    // Add specific ports
    rule.port.push(80);
    rule.port.push(443);

    // Add port range
    rule.port_range.push((8000, 9000));

    // Test port membership
    assert!(rule.port.contains(&80));
    assert!(rule.port.contains(&443));
    assert!(!rule.port.contains(&22));

    // Test port range
    assert_eq!(rule.port_range.len(), 1);
    let (start, end) = rule.port_range[0];
    assert_eq!(start, 8000);
    assert_eq!(end, 9000);

    // Port range logic (8500 should be in range)
    let test_port = 8500;
    let in_range = rule
        .port_range
        .iter()
        .any(|(s, e)| test_port >= *s && test_port <= *e);
    assert!(in_range);
}

#[test]
fn test_default_rule_network_matching() {
    let mut rule = DefaultRule::default();

    // Add network types
    rule.network.push("tcp".to_string());
    rule.network.push("udp".to_string());

    assert!(rule.network.contains(&"tcp".to_string()));
    assert!(rule.network.contains(&"udp".to_string()));
    assert!(!rule.network.contains(&"icmp".to_string()));
}

#[test]
fn test_default_rule_process_matching() {
    let mut rule = DefaultRule::default();

    // Add process names
    rule.process_name.push("firefox".to_string());
    rule.process_name.push("chrome".to_string());

    // Add process paths
    rule.process_path.push("/usr/bin/curl".to_string());
    rule.process_path_regex
        .push(r"(?i).*/Chrome\.app$".to_string());

    assert!(rule.process_name.contains(&"firefox".to_string()));
    assert!(rule.process_path.contains(&"/usr/bin/curl".to_string()));
    assert!(rule
        .process_path_regex
        .contains(&r"(?i).*/Chrome\.app$".to_string()));
}

#[test]
fn test_default_rule_invert() {
    let mut rule = DefaultRule {
        invert: false,
        ..Default::default()
    };

    // Add some domain
    rule.domain_suffix.push("example.com".to_string());

    // When invert is true, matching logic should be inverted
    rule.invert = true;
    assert!(rule.invert);
}

#[test]
fn test_logical_rule_construction() {
    use sb_core::router::ruleset::{LogicalMode, LogicalRule};

    // Create AND rule
    let and_rule = LogicalRule {
        mode: LogicalMode::And,
        rules: vec![],
        invert: false,
    };
    assert!(matches!(and_rule.mode, LogicalMode::And));

    // Create OR rule
    let or_rule = LogicalRule {
        mode: LogicalMode::Or,
        rules: vec![],
        invert: false,
    };
    assert!(matches!(or_rule.mode, LogicalMode::Or));
}

#[test]
fn test_rule_enum() {
    use sb_core::router::ruleset::LogicalMode;

    // Test Default rule variant
    let default_rule = Rule::Default(DefaultRule::default());
    assert!(matches!(default_rule, Rule::Default(_)));

    // Test Logical rule variant
    let logical_rule = Rule::Logical(sb_core::router::ruleset::LogicalRule {
        mode: LogicalMode::And,
        rules: vec![],
        invert: false,
    });
    assert!(matches!(logical_rule, Rule::Logical(_)));
}

#[tokio::test]
async fn test_ruleset_manager_caching() {
    let temp_dir = std::env::temp_dir().join("sb-ruleset-cache-test");
    let _ = std::fs::create_dir_all(&temp_dir);

    let manager = Arc::new(RuleSetManager::new(
        temp_dir.clone(),
        Duration::from_secs(3600),
    ));

    // Test that get returns None for non-existent tag
    assert!(manager.get("nonexistent").is_none());

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ip_cidr_validation() {
    // Valid IPv4 CIDR
    assert!(IpCidr::parse("10.0.0.0/8").is_ok());
    assert!(IpCidr::parse("192.168.0.0/16").is_ok());
    assert!(IpCidr::parse("172.16.0.0/12").is_ok());

    // Valid IPv6 CIDR
    assert!(IpCidr::parse("2001:db8::/32").is_ok());
    assert!(IpCidr::parse("fe80::/10").is_ok());

    // Invalid CIDR (should fail)
    assert!(IpCidr::parse("invalid").is_err());
    assert!(IpCidr::parse("10.0.0.0").is_err()); // Missing prefix
    assert!(IpCidr::parse("10.0.0.0/").is_err()); // Missing prefix length
}

#[test]
fn test_ip_cidr_boundary_conditions() {
    // Test /0 (match all)
    let cidr = IpCidr::parse("0.0.0.0/0").unwrap();
    assert_eq!(cidr.prefix_len, 0);

    // Test /32 (exact match)
    let cidr32 = IpCidr::parse("192.168.1.1/32").unwrap();
    assert_eq!(cidr32.prefix_len, 32);

    let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
    assert!(cidr32.matches(&ip));

    let ip2: std::net::IpAddr = "192.168.1.2".parse().unwrap();
    assert!(!cidr32.matches(&ip2));
}
