// crates/sb-core/tests/prop_net_coverage.rs
#![cfg(feature = "check-net")]
use ipnet::{IpNet, Ipv4Net};
use proptest::prelude::*;
use serde_json::json;

// Property test: /16 network should cover all /24 subnets within it
proptest! {
    #[test]
    fn cidr_contains_basic(octet in 0u8..=254) {
        let parent = format!("10.{}.0.0/16", octet);
        let child = format!("10.{}.1.0/24", octet);
        let parent_net: IpNet = parent.parse().unwrap();
        let child_net: IpNet = child.parse().unwrap();

        let covers = match (parent_net, child_net) {
            (IpNet::V4(p), IpNet::V4(c)) => {
                p.contains(&c.network()) && p.prefix_len() <= c.prefix_len()
            },
            _ => false,
        };
        prop_assert!(covers, "{} should contain {}", parent, child);
    }
}

// Property test: Different /24 networks should not contain each other
proptest! {
    #[test]
    fn cidr_disjoint_networks(octet1 in 0u8..=254, octet2 in 0u8..=254) {
        prop_assume!(octet1 != octet2);
        let net1 = format!("10.{}.0.0/24", octet1);
        let net2 = format!("10.{}.0.0/24", octet2);
        let n1: IpNet = net1.parse().unwrap();
        let n2: IpNet = net2.parse().unwrap();

        let overlaps = match (n1, n2) {
            (IpNet::V4(a), IpNet::V4(b)) => {
                a.contains(&b.network()) || b.contains(&a.network())
            },
            _ => false,
        };
        prop_assert!(!overlaps, "Different /24 networks {} and {} should not overlap", net1, net2);
    }
}

// Property test: Domain suffix matching
#[test]
fn domain_suffix_coverage() {
    // Test that *.example.com covers a.b.example.com
    let broader = vec!["*.example.com".to_string()];
    let narrower = vec!["a.b.example.com".to_string()];

    // Create domain patterns similar to check.rs
    let norm_broader = normalize_domains(&broader);
    let norm_narrower = normalize_domains(&narrower);

    assert!(domain_contains_patterns(&norm_broader, &norm_narrower));
}

#[test]
fn domain_exact_matching() {
    // Test that exact domain matches itself
    let domains1 = vec!["example.com".to_string()];
    let domains2 = vec!["example.com".to_string()];

    let norm1 = normalize_domains(&domains1);
    let norm2 = normalize_domains(&domains2);

    assert!(domain_contains_patterns(&norm1, &norm2));
}

#[test]
fn domain_no_false_positives() {
    // Test that example.com does not cover other.com
    let domains1 = vec!["example.com".to_string()];
    let domains2 = vec!["other.com".to_string()];

    let norm1 = normalize_domains(&domains1);
    let norm2 = normalize_domains(&domains2);

    assert!(!domain_contains_patterns(&norm1, &norm2));
}

// Helper functions that mirror check.rs logic
#[derive(Default, Clone)]
struct DomainPattern {
    exact: Vec<String>,  // "a.b.c"
    suffix: Vec<String>, // "example.com" for "*.example.com"
}

fn normalize_domains(domains: &[String]) -> DomainPattern {
    let mut pattern = DomainPattern::default();
    for domain in domains {
        if let Some(rest) = domain.strip_prefix("*.") {
            pattern.suffix.push(rest.to_ascii_lowercase());
        } else {
            pattern.exact.push(domain.to_ascii_lowercase());
        }
    }
    pattern
}

fn domain_contains_patterns(a: &DomainPattern, b: &DomainPattern) -> bool {
    // a 是否覆盖 b：任一 b.exact 被 a.exact 命中或被 a.suffix 覆盖；b.suffix 被 a.suffix 的更短或相等后缀覆盖
    for ex in &b.exact {
        if a.exact.iter().any(|x| x == ex) {
            continue;
        }
        if !a
            .suffix
            .iter()
            .any(|suf| ex.ends_with(&format!(".{}", suf)) || ex == suf)
        {
            return false;
        }
    }
    for suf_b in &b.suffix {
        if a.suffix
            .iter()
            .any(|suf_a| suf_b == suf_a || suf_b.ends_with(&format!(".{}", suf_a)))
        {
            continue;
        }
        return false;
    }
    true
}

// IPv6 coverage tests
proptest! {
    #[test]
    fn ipv6_coverage_basic(prefix in 16u8..=64) {
        prop_assume!(prefix < 64);
        let parent = format!("2001:db8::/{}",  prefix);
        let child = format!("2001:db8::/{}",  prefix + 8);

        let parent_net: IpNet = parent.parse().unwrap();
        let child_net: IpNet = child.parse().unwrap();

        let covers = match (parent_net, child_net) {
            (IpNet::V6(p), IpNet::V6(c)) => {
                p.contains(&c.network()) && p.prefix_len() <= c.prefix_len()
            },
            _ => false,
        };
        prop_assert!(covers, "IPv6 {} should contain {}", parent, child);
    }
}

// Complex rules property test
#[test]
fn complex_rule_specificity() {
    // Rule with domain + CIDR should be more specific than domain-only rule
    let rule_specific = json!({
        "when": {
            "domain": ["api.example.com"],
            "cidr": ["192.168.1.0/24"]
        }
    });

    let rule_general = json!({
        "when": {
            "domain": ["*.example.com"]
        }
    });

    let specific_shape = extract_when_shape(&rule_specific["when"]);
    let general_shape = extract_when_shape(&rule_general["when"]);

    // The general rule should be broader than the specific rule
    assert!(is_rule_broader(&general_shape, &specific_shape));
    assert!(!is_rule_broader(&specific_shape, &general_shape));
}

// Helper to extract rule shape for testing
#[derive(Default, Clone)]
struct TestWhenShape {
    any: bool,
    proto_all: bool,
    proto_set: std::collections::BTreeSet<String>,
    domains: DomainPattern,
    has_domain: bool,
    has_cidr: bool,
}

fn extract_when_shape(when: &serde_json::Value) -> TestWhenShape {
    let mut shape = TestWhenShape::default();

    if !when.is_object() || when.as_object().unwrap().is_empty() {
        shape.any = true;
        return shape;
    }

    if let Some(proto_array) = when.get("proto").and_then(|p| p.as_array()) {
        for proto in proto_array {
            if let Some(proto_str) = proto.as_str() {
                shape.proto_set.insert(proto_str.to_string());
            }
        }
    }
    shape.proto_all = shape.proto_set.contains("tcp") && shape.proto_set.contains("udp");

    if let Some(domain_array) = when.get("domain").and_then(|d| d.as_array()) {
        let domain_strings: Vec<String> = domain_array
            .iter()
            .filter_map(|d| d.as_str().map(|s| s.to_string()))
            .collect();
        shape.domains = normalize_domains(&domain_strings);
        shape.has_domain = !shape.domains.exact.is_empty() || !shape.domains.suffix.is_empty();
    }

    if let Some(_cidr_array) = when.get("cidr").and_then(|c| c.as_array()) {
        shape.has_cidr = true;
    }

    shape
}

fn is_rule_broader(a: &TestWhenShape, b: &TestWhenShape) -> bool {
    if a.any {
        return true;
    }

    // Check protocol coverage
    if a.proto_all {
        // a covers all protocols
    } else if !b.proto_set.is_subset(&a.proto_set) {
        return false;
    }

    // Check domain coverage
    if !a.has_domain && b.has_domain {
        return false;
    }
    if b.has_domain && !domain_contains_patterns(&a.domains, &b.domains) {
        return false;
    }

    // Check CIDR coverage (simplified for test)
    if !a.has_cidr && b.has_cidr {
        return false;
    }

    true
}

// Test that validates rule ordering produces correct specificity
#[test]
fn rule_ordering_correctness() {
    let rules = vec![
        json!({"when": {}, "to": "direct"}), // any
        json!({"when": {"domain": ["*.example.com"]}, "to": "proxy:1"}), // domain wildcard
        json!({"when": {"domain": ["api.example.com"]}, "to": "proxy:2"}), // specific domain
        json!({"when": {"domain": ["api.example.com"], "cidr": ["192.168.1.0/24"]}, "to": "proxy:3"}), // domain + cidr
    ];

    let mut shapes: Vec<(usize, TestWhenShape)> = rules
        .iter()
        .enumerate()
        .map(|(i, rule)| (i, extract_when_shape(&rule["when"])))
        .collect();

    // Sort by specificity (more specific first)
    shapes.sort_by(|a, b| {
        let a_specificity = rule_specificity_score(&a.1);
        let b_specificity = rule_specificity_score(&b.1);
        b_specificity.cmp(&a_specificity).then(a.0.cmp(&b.0))
    });

    // Verify that more specific rules come first
    assert_eq!(shapes[0].0, 3); // domain + cidr most specific
    assert_eq!(shapes[1].0, 2); // specific domain next
    assert_eq!(shapes[2].0, 1); // wildcard domain
    assert_eq!(shapes[3].0, 0); // any rule least specific
}

fn rule_specificity_score(shape: &TestWhenShape) -> u32 {
    if shape.any {
        return 0;
    }

    let mut score = 0;

    // Domain specificity
    score += shape.domains.exact.len() as u32 * 10;
    score += shape.domains.suffix.len() as u32 * 5;

    // CIDR specificity
    if shape.has_cidr {
        score += 10;
    }

    // Protocol specificity
    if !shape.proto_all {
        score += shape.proto_set.len() as u32;
    }

    score
}
