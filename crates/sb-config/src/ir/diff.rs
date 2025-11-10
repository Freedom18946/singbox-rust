//! Configuration difference detection for hot reload.
//!
//! Computes changes between old and new ConfigIR to enable
//! minimal disruption during hot reload operations.

use super::{ConfigIR, InboundIR, OutboundIR, RuleIR};
#[cfg(test)]
use crate::ir::RouteIR;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Represents changes in a collection.
///
/// Used to track additions and removals during configuration diff operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Change {
    /// Names/identifiers of newly added items.
    pub added: Vec<String>,
    /// Names/identifiers of removed items.
    pub removed: Vec<String>,
}

/// Complete diff between two configurations.
///
/// Provides granular change tracking for inbounds, outbounds, and routing rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Diff {
    /// Changes to inbound listeners.
    pub inbounds: Change,
    /// Changes to outbound proxies.
    pub outbounds: Change,
    /// Changes to routing rules.
    pub rules: Change,
}

/// Generate a diff between two configurations.
///
/// # Examples
/// ```ignore
/// let old_config = ConfigIR { /* ... */ };
/// let new_config = ConfigIR { /* ... */ };
/// let diff = diff(&old_config, &new_config);
/// println!("Added inbounds: {:?}", diff.inbounds.added);
/// ```
#[must_use]
pub fn diff(old: &ConfigIR, new: &ConfigIR) -> Diff {
    Diff {
        inbounds: diff_inbounds(&old.inbounds, &new.inbounds),
        outbounds: diff_outbounds(&old.outbounds, &new.outbounds),
        rules: diff_rules(&old.route.rules, &new.route.rules),
    }
}

/// Compute inbound differences based on `listen:port` combination.
///
/// Treats each unique `address:port` as a distinct inbound.
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

/// Compute outbound differences based on name (if present) or `server:port` combination.
///
/// Prioritizes named outbounds, falls back to generated keys for unnamed ones.
fn diff_outbounds(old: &[OutboundIR], new: &[OutboundIR]) -> Change {
    let old_keys: HashSet<String> = old.iter().map(outbound_key).collect();
    let new_keys: HashSet<String> = new.iter().map(outbound_key).collect();

    let added: Vec<String> = new_keys.difference(&old_keys).cloned().collect();
    let removed: Vec<String> = old_keys.difference(&new_keys).cloned().collect();

    Change { added, removed }
}

/// Generate a unique key for an outbound.
///
/// Prioritizes the `name` field if present, otherwise generates a key
/// from type, server, and port.
fn outbound_key(ob: &OutboundIR) -> String {
    if let Some(name) = &ob.name {
        return name.clone();
    }

    let ty_str = ob.ty_str();
    match (&ob.server, ob.port) {
        (Some(server), Some(port)) => format!("{ty_str}:{server}:{port}"),
        (Some(server), None) => format!("{ty_str}:{server}"),
        (None, Some(port)) => format!("{ty_str}:*:{port}"),
        (None, None) => ty_str.to_owned(),
    }
}

/// Compute rule differences based on rule content hash.
///
/// Rules are identified by their content (not index), enabling
/// detection of semantic changes rather than just positional shifts.
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

/// Generate a stable hash for a rule (simple content-based).
///
/// Uses a non-cryptographic hash ([`DefaultHasher`]) for performance.
/// Hash collisions are theoretically possible but unlikely in practice
/// given typical rule set sizes.
///
/// # Stability
/// The hash is stable across calls for the same rule content,
/// with components sorted alphabetically before hashing.
fn rule_hash(rule: &RuleIR) -> String {
    /// Helper macro to add non-empty field to components.
    macro_rules! add_field {
        ($components:expr, $field:expr, $name:literal) => {
            if !$field.is_empty() {
                $components.push(format!("{}:{}", $name, $field.join(",")));
            }
        };
    }

    let mut components = Vec::new();

    // Positive conditions
    add_field!(components, rule.domain, "domain");
    add_field!(components, rule.geosite, "geosite");
    add_field!(components, rule.geoip, "geoip");
    add_field!(components, rule.ipcidr, "ipcidr");
    add_field!(components, rule.port, "port");
    add_field!(components, rule.process, "process");
    add_field!(components, rule.network, "network");
    add_field!(components, rule.protocol, "protocol");
    add_field!(components, rule.source, "source");
    add_field!(components, rule.dest, "dest");
    add_field!(components, rule.user_agent, "user_agent");

    // Negative conditions
    add_field!(components, rule.not_domain, "not_domain");
    add_field!(components, rule.not_geosite, "not_geosite");
    add_field!(components, rule.not_geoip, "not_geoip");
    add_field!(components, rule.not_ipcidr, "not_ipcidr");
    add_field!(components, rule.not_port, "not_port");
    add_field!(components, rule.not_process, "not_process");
    add_field!(components, rule.not_network, "not_network");
    add_field!(components, rule.not_protocol, "not_protocol");

    // Outbound
    if let Some(outbound) = &rule.outbound {
        components.push(format!("outbound:{outbound}"));
    }

    // Sort for stable ordering
    components.sort();

    // Create a simple hash using the first 8 hex digits of a content-based string
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let content = components.join("|");
    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    format!("{:08x}", hasher.finish() & 0xffff_ffff)
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
            override_host: None,
            override_port: None,
            method: None,
            password: None,
            users_shadowsocks: None,
            network: None,
            uuid: None,
            alter_id: None,
            users_vmess: None,
            flow: None,
            users_vless: None,
            users_trojan: None,
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            grpc_service: None,
            tls_enabled: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_server_name: None,
            tls_alpn: None,
            multiplex: None,
        }];

        let new = vec![InboundIR {
            ty: InboundType::Http,
            listen: "127.0.0.1".to_string(),
            port: 8081,
            sniff: false,
            udp: false,
            basic_auth: None,
            override_host: None,
            override_port: None,
            method: None,
            password: None,
            users_shadowsocks: None,
            network: None,
            uuid: None,
            alter_id: None,
            users_vmess: None,
            flow: None,
            users_vless: None,
            users_trojan: None,
            transport: None,
            ws_path: None,
            ws_host: None,
            h2_path: None,
            h2_host: None,
            grpc_service: None,
            tls_enabled: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_cert_pem: None,
            tls_key_pem: None,
            tls_server_name: None,
            tls_alpn: None,
            multiplex: None,
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
                override_host: None,
                override_port: None,
                method: None,
                password: None,
                users_shadowsocks: None,
                network: None,
                uuid: None,
                alter_id: None,
                users_vmess: None,
                flow: None,
                users_vless: None,
                users_trojan: None,
                transport: None,
                ws_path: None,
                ws_host: None,
                h2_path: None,
                h2_host: None,
                grpc_service: None,
                tls_enabled: None,
                tls_cert_path: None,
                tls_key_path: None,
                tls_cert_pem: None,
                tls_key_pem: None,
                tls_server_name: None,
                tls_alpn: None,
                multiplex: None,
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
            log: None,
            ntp: None,
            certificate: None,
            dns: None,
        };

        let new = ConfigIR {
            inbounds: vec![InboundIR {
                ty: InboundType::Http,
                listen: "127.0.0.1".to_string(),
                port: 8081,
                sniff: false,
                udp: false,
                override_host: None,
                override_port: None,
                basic_auth: None,
                method: None,
                password: None,
                users_shadowsocks: None,
                network: None,
                uuid: None,
                alter_id: None,
                users_vmess: None,
                flow: None,
                users_vless: None,
                users_trojan: None,
                transport: None,
                ws_path: None,
                ws_host: None,
                h2_path: None,
                h2_host: None,
                grpc_service: None,
                tls_enabled: None,
                tls_cert_path: None,
                tls_key_path: None,
                tls_cert_pem: None,
                tls_key_pem: None,
                tls_server_name: None,
                tls_alpn: None,
                multiplex: None,
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
            log: None,
            ntp: None,
            certificate: None,
            dns: None,
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
