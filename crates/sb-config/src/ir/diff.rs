//! Configuration difference detection for hot reload.
//!
//! Computes changes between old and new ConfigIR to enable
//! minimal disruption during hot reload operations.

use super::{ConfigIR, InboundIR, OutboundIR, RuleIR};
#[cfg(test)]
use crate::ir::RouteIR;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents changes in a collection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Change {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// Complete diff between two configurations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Diff {
    pub inbounds: Change,
    pub outbounds: Change,
    pub rules: Change,
}

/// Generate a diff between two configurations
pub fn diff(old: &ConfigIR, new: &ConfigIR) -> Diff {
    Diff {
        inbounds: diff_inbounds(&old.inbounds, &new.inbounds),
        outbounds: diff_outbounds(&old.outbounds, &new.outbounds),
        rules: diff_rules(&old.route.rules, &new.route.rules),
    }
}

/// Compute inbound differences based on listen address:port combination
fn diff_inbounds(old: &[InboundIR], new: &[InboundIR]) -> Change {
    let old_keys: HashSet<String> = old
        .iter()
        .map(|ib| format!("{}:{}", ib.listen, ib.port))
        .collect();

    let new_keys: HashSet<String> = new
        .iter()
        .map(|ib| format!("{}:{}", ib.listen, ib.port))
        .collect();

    let added: Vec<String> = new_keys.difference(&old_keys).cloned().collect();
    let removed: Vec<String> = old_keys.difference(&new_keys).cloned().collect();

    Change { added, removed }
}

/// Compute outbound differences based on name (if present) or server:port combination
fn diff_outbounds(old: &[OutboundIR], new: &[OutboundIR]) -> Change {
    let old_keys: HashSet<String> = old.iter().map(outbound_key).collect();
    let new_keys: HashSet<String> = new.iter().map(outbound_key).collect();

    let added: Vec<String> = new_keys.difference(&old_keys).cloned().collect();
    let removed: Vec<String> = old_keys.difference(&new_keys).cloned().collect();

    Change { added, removed }
}

/// Generate a unique key for an outbound
fn outbound_key(ob: &OutboundIR) -> String {
    if let Some(name) = &ob.name {
        return name.clone();
    }

    match (&ob.server, ob.port) {
        (Some(server), Some(port)) => format!("{}:{}:{}", ob.ty_str(), server, port),
        (Some(server), None) => format!("{}:{}", ob.ty_str(), server),
        (None, Some(port)) => format!("{}:*:{}", ob.ty_str(), port),
        (None, None) => ob.ty_str().to_string(),
    }
}

/// Compute rule differences based on rule content hash
fn diff_rules(old: &[RuleIR], new: &[RuleIR]) -> Change {
    let old_hashes: HashMap<String, usize> = old
        .iter()
        .enumerate()
        .map(|(i, rule)| (rule_hash(rule), i))
        .collect();

    let new_hashes: HashMap<String, usize> = new
        .iter()
        .enumerate()
        .map(|(i, rule)| (rule_hash(rule), i))
        .collect();

    let old_keys: HashSet<String> = old_hashes.keys().cloned().collect();
    let new_keys: HashSet<String> = new_hashes.keys().cloned().collect();

    let added: Vec<String> = new_keys
        .difference(&old_keys)
        .map(|hash| {
            let idx = new_hashes[hash];
            format!("rule-{}", idx)
        })
        .collect();

    let removed: Vec<String> = old_keys
        .difference(&new_keys)
        .map(|hash| {
            let idx = old_hashes[hash];
            format!("rule-{}", idx)
        })
        .collect();

    Change { added, removed }
}

/// Generate a stable hash for a rule (simple content-based)
fn rule_hash(rule: &RuleIR) -> String {
    // Create a stable string representation for hashing
    let mut components = Vec::new();

    // Positive conditions
    if !rule.domain.is_empty() {
        components.push(format!("domain:{}", rule.domain.join(",")));
    }
    if !rule.geosite.is_empty() {
        components.push(format!("geosite:{}", rule.geosite.join(",")));
    }
    if !rule.geoip.is_empty() {
        components.push(format!("geoip:{}", rule.geoip.join(",")));
    }
    if !rule.ipcidr.is_empty() {
        components.push(format!("ipcidr:{}", rule.ipcidr.join(",")));
    }
    if !rule.port.is_empty() {
        components.push(format!("port:{}", rule.port.join(",")));
    }
    if !rule.process.is_empty() {
        components.push(format!("process:{}", rule.process.join(",")));
    }
    if !rule.network.is_empty() {
        components.push(format!("network:{}", rule.network.join(",")));
    }
    if !rule.protocol.is_empty() {
        components.push(format!("protocol:{}", rule.protocol.join(",")));
    }
    if !rule.source.is_empty() {
        components.push(format!("source:{}", rule.source.join(",")));
    }
    if !rule.dest.is_empty() {
        components.push(format!("dest:{}", rule.dest.join(",")));
    }
    if !rule.user_agent.is_empty() {
        components.push(format!("user_agent:{}", rule.user_agent.join(",")));
    }

    // Negative conditions
    if !rule.not_domain.is_empty() {
        components.push(format!("not_domain:{}", rule.not_domain.join(",")));
    }
    if !rule.not_geosite.is_empty() {
        components.push(format!("not_geosite:{}", rule.not_geosite.join(",")));
    }
    if !rule.not_geoip.is_empty() {
        components.push(format!("not_geoip:{}", rule.not_geoip.join(",")));
    }
    if !rule.not_ipcidr.is_empty() {
        components.push(format!("not_ipcidr:{}", rule.not_ipcidr.join(",")));
    }
    if !rule.not_port.is_empty() {
        components.push(format!("not_port:{}", rule.not_port.join(",")));
    }
    if !rule.not_process.is_empty() {
        components.push(format!("not_process:{}", rule.not_process.join(",")));
    }
    if !rule.not_network.is_empty() {
        components.push(format!("not_network:{}", rule.not_network.join(",")));
    }
    if !rule.not_protocol.is_empty() {
        components.push(format!("not_protocol:{}", rule.not_protocol.join(",")));
    }

    // Outbound
    if let Some(outbound) = &rule.outbound {
        components.push(format!("outbound:{}", outbound));
    }

    // Sort for stable ordering
    components.sort();

    // Create a simple hash using the first 8 characters of a content-based string
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let content = components.join("|");
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:08x}", hasher.finish() & 0xffffffff)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{InboundType, OutboundType};

    #[test]
    fn test_inbound_diff() {
        let old = vec![InboundIR {
            ty: InboundType::Http,
            listen: "127.0.0.1".to_string(),
            port: 8080,
            sniff: false,
            udp: false,
            basic_auth: None,
        }];

        let new = vec![InboundIR {
            ty: InboundType::Http,
            listen: "127.0.0.1".to_string(),
            port: 8081,
            sniff: false,
            udp: false,
            basic_auth: None,
        }];

        let diff = diff_inbounds(&old, &new);
        assert_eq!(diff.added, vec!["127.0.0.1:8081"]);
        assert_eq!(diff.removed, vec!["127.0.0.1:8080"]);
    }

    #[test]
    fn test_outbound_diff_with_names() {
        let old = vec![OutboundIR {
            ty: OutboundType::Http,
            name: Some("proxy1".to_string()),
            server: Some("example.com".to_string()),
            port: Some(8080),
            ..Default::default()
        }];

        let new = vec![OutboundIR {
            ty: OutboundType::Http,
            name: Some("proxy2".to_string()),
            server: Some("example.com".to_string()),
            port: Some(8080),
            ..Default::default()
        }];

        let diff = diff_outbounds(&old, &new);
        assert_eq!(diff.added, vec!["proxy2"]);
        assert_eq!(diff.removed, vec!["proxy1"]);
    }

    #[test]
    fn test_rule_diff() {
        let old = vec![RuleIR {
            domain: vec!["example.com".to_string()],
            outbound: Some("proxy".to_string()),
            ..Default::default()
        }];

        let new = vec![RuleIR {
            domain: vec!["test.com".to_string()],
            outbound: Some("proxy".to_string()),
            ..Default::default()
        }];

        let diff = diff_rules(&old, &new);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.removed.len(), 1);
        assert!(diff.added[0].starts_with("rule-"));
        assert!(diff.removed[0].starts_with("rule-"));
    }

    #[test]
    fn test_rule_hash_stability() {
        let rule = RuleIR {
            domain: vec!["example.com".to_string(), "test.com".to_string()],
            port: vec!["80".to_string()],
            outbound: Some("proxy".to_string()),
            ..Default::default()
        };

        let hash1 = rule_hash(&rule);
        let hash2 = rule_hash(&rule);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_complete_diff() {
        let old = ConfigIR {
            inbounds: vec![InboundIR {
                ty: InboundType::Http,
                listen: "127.0.0.1".to_string(),
                port: 8080,
                sniff: false,
                udp: false,
                basic_auth: None,
            }],
            outbounds: vec![OutboundIR {
                ty: OutboundType::Direct,
                name: Some("direct".to_string()),
                ..Default::default()
            }],
            route: RouteIR {
                rules: vec![RuleIR {
                    domain: vec!["example.com".to_string()],
                    outbound: Some("direct".to_string()),
                    ..Default::default()
                }],
                default: Some("direct".to_string()),
            },
        };

        let new = ConfigIR {
            inbounds: vec![InboundIR {
                ty: InboundType::Http,
                listen: "127.0.0.1".to_string(),
                port: 8081,
                sniff: false,
                udp: false,
                basic_auth: None,
            }],
            outbounds: vec![OutboundIR {
                ty: OutboundType::Http,
                name: Some("proxy".to_string()),
                server: Some("example.com".to_string()),
                port: Some(8080),
                ..Default::default()
            }],
            route: RouteIR {
                rules: vec![RuleIR {
                    domain: vec!["test.com".to_string()],
                    outbound: Some("proxy".to_string()),
                    ..Default::default()
                }],
                default: Some("proxy".to_string()),
            },
        };

        let diff_result = diff(&old, &new);

        assert_eq!(diff_result.inbounds.added, vec!["127.0.0.1:8081"]);
        assert_eq!(diff_result.inbounds.removed, vec!["127.0.0.1:8080"]);
        assert_eq!(diff_result.outbounds.added, vec!["proxy"]);
        assert_eq!(diff_result.outbounds.removed, vec!["direct"]);
        assert_eq!(diff_result.rules.added.len(), 1);
        assert_eq!(diff_result.rules.removed.len(), 1);
    }
}
