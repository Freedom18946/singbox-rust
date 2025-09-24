//! Enhanced type definitions for Schema v2 strong typing infrastructure
//!
//! This module provides strongly-typed structs with `deny_unknown_fields` for
//! runtime validation of configuration schemas, specifically for route.when
//! and dns configuration sections.

#![cfg(feature = "schema-v2")]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Domain pattern matching configuration with exact and suffix matching
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DomainPattern {
    /// Exact domain matches
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exact: Vec<String>,

    /// Suffix domain matches (without leading dot)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suffix: Vec<String>,
}

impl Default for DomainPattern {
    fn default() -> Self {
        Self {
            exact: Vec::new(),
            suffix: Vec::new(),
        }
    }
}

/// Enhanced when clause with strong typing for Schema v2
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WhenV2 {
    /// Protocol constraints (tcp, udp, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proto: Vec<String>,

    /// Domain matching patterns
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainPattern>,

    /// Negated domain matching patterns (set difference semantics)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_domain: Option<DomainPattern>,

    /// CIDR network constraints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidr: Vec<String>,

    /// Negated CIDR network constraints (set difference semantics)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_cidr: Vec<String>,

    /// Negated protocol constraints
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_proto: Option<Vec<String>>,

    /// Port constraints
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<Vec<u16>>,

    /// Port range constraints (start-end inclusive)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<Vec<String>>,

    /// Source IP constraints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_ip: Vec<String>,

    /// Inbound tag constraints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbound: Vec<String>,
}

impl Default for WhenV2 {
    fn default() -> Self {
        Self {
            proto: Vec::new(),
            domain: None,
            not_domain: None,
            cidr: Vec::new(),
            not_cidr: Vec::new(),
            not_proto: None,
            port: None,
            port_range: None,
            source_ip: Vec::new(),
            inbound: Vec::new(),
        }
    }
}

/// Enhanced route rule with strong typing for Schema v2
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteRuleV2 {
    /// When clause with strong typing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<WhenV2>,

    /// Target outbound name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,

    /// Rule priority (higher values take precedence)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,

    /// Rule description for documentation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Enhanced route configuration with strong typing for Schema v2
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteV2 {
    /// Routing rules with strong typing
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RouteRuleV2>,

    /// Default outbound for unmatched traffic
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,

    /// Auto-detect destination override
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_detect_interface: Option<bool>,

    /// Override destination address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_address: Option<String>,

    /// Override destination port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_port: Option<u16>,
}

impl Default for RouteV2 {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default: None,
            auto_detect_interface: None,
            override_address: None,
            override_port: None,
        }
    }
}

/// Enhanced DNS configuration with strong typing for Schema v2
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsV2 {
    /// DNS resolution mode (system, manual, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// DNS server addresses
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,

    /// Enable DNS caching
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<bool>,

    /// DNS cache TTL in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl: Option<u32>,

    /// DNS query timeout in milliseconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,

    /// Enable DNS over HTTPS
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh: Option<bool>,

    /// DNS over HTTPS URL
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_url: Option<String>,

    /// Enable DNS over TLS
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dot: Option<bool>,

    /// Fallback to system resolver on failure
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<bool>,
}

impl Default for DnsV2 {
    fn default() -> Self {
        Self {
            mode: None,
            servers: Vec::new(),
            cache: None,
            cache_ttl: None,
            timeout: None,
            doh: None,
            doh_url: None,
            dot: None,
            fallback: None,
        }
    }
}

/// Enhanced inbound configuration with strong typing for Schema v2
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboundV2 {
    /// Inbound type (http, socks5, etc.)
    #[serde(rename = "type")]
    pub kind: String,

    /// Listen address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    /// Listen port
    pub port: u16,

    /// Inbound tag for routing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    /// Enable SNIFF for protocol detection
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniff: Option<bool>,

    /// Authentication settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<serde_json::Value>,
}

/// Enhanced outbound configuration with strong typing for Schema v2
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutboundV2 {
    /// Outbound name/tag
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Outbound type (direct, socks5, http, etc.)
    #[serde(rename = "type")]
    pub kind: String,

    /// Server address
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    /// Server port
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Load balancing weight
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u8>,

    /// Authentication settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<serde_json::Value>,

    /// TLS settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<serde_json::Value>,

    /// Transport settings
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<serde_json::Value>,
}

/// Top-level configuration with strong typing for Schema v2
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigV2 {
    /// API version for schema compatibility
    #[serde(
        rename = "apiVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub api_version: Option<String>,

    /// Configuration kind/type
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    /// Inbound configurations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<InboundV2>,

    /// Outbound configurations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbounds: Vec<OutboundV2>,

    /// Route configuration with strong typing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteV2>,

    /// DNS configuration with strong typing
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsV2>,

    /// Experimental features
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<serde_json::Value>,

    /// Log configuration
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<serde_json::Value>,
}

impl Default for ConfigV2 {
    fn default() -> Self {
        Self {
            api_version: None,
            kind: None,
            inbounds: Vec::new(),
            outbounds: Vec::new(),
            route: None,
            dns: None,
            experimental: None,
            log: None,
        }
    }
}

/// Generate JSON schema from ConfigV2 type definitions
pub fn schema_v2() -> serde_json::Value {
    use schemars::schema_for;
    let schema = schema_for!(ConfigV2);
    serde_json::to_value(&schema).expect("Failed to serialize schema to JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_domain_pattern_serialization() {
        let pattern = DomainPattern {
            exact: vec!["example.com".to_string()],
            suffix: vec!["google.com".to_string()],
        };

        let json = serde_json::to_value(&pattern).unwrap();
        let expected = json!({
            "exact": ["example.com"],
            "suffix": ["google.com"]
        });

        assert_eq!(json, expected);
    }

    #[test]
    fn test_when_v2_serialization() {
        let when = WhenV2 {
            proto: vec!["tcp".to_string()],
            domain: Some(DomainPattern {
                exact: vec!["example.com".to_string()],
                suffix: vec![],
            }),
            not_domain: None,
            cidr: vec!["192.168.1.0/24".to_string()],
            not_cidr: vec![],
            not_proto: None,
            port: Some(vec![80, 443]),
            port_range: None,
            source_ip: vec![],
            inbound: vec![],
        };

        let json = serde_json::to_value(&when).unwrap();
        assert!(json.get("proto").is_some());
        assert!(json.get("domain").is_some());
        assert!(json.get("cidr").is_some());
        assert!(json.get("port").is_some());
    }

    #[test]
    fn test_config_v2_deny_unknown_fields() {
        let json = json!({
            "inbounds": [],
            "outbounds": [],
            "unknown_field": "should_fail"
        });

        let result: Result<ConfigV2, _> = serde_json::from_value(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown field"));
    }

    #[test]
    fn test_schema_v2_generation() {
        let schema = schema_v2();
        assert!(schema.is_object());

        // Verify schema contains expected properties
        let properties = schema
            .get("properties")
            .expect("Schema should have properties");
        assert!(properties.get("inbounds").is_some());
        assert!(properties.get("outbounds").is_some());
        assert!(properties.get("route").is_some());
        assert!(properties.get("dns").is_some());
    }

    #[test]
    fn test_route_rule_v2_with_negation() {
        let rule = RouteRuleV2 {
            when: Some(WhenV2 {
                proto: vec!["tcp".to_string()],
                domain: Some(DomainPattern {
                    exact: vec!["example.com".to_string()],
                    suffix: vec![],
                }),
                not_domain: Some(DomainPattern {
                    exact: vec!["blocked.com".to_string()],
                    suffix: vec![],
                }),
                cidr: vec!["10.0.0.0/8".to_string()],
                not_cidr: vec!["10.0.1.0/24".to_string()],
                not_proto: Some(vec!["udp".to_string()]),
                port: None,
                port_range: None,
                source_ip: vec![],
                inbound: vec![],
            }),
            to: Some("proxy".to_string()),
            priority: Some(100),
            description: Some("Test rule with negation".to_string()),
        };

        let json = serde_json::to_value(&rule).unwrap();
        let when = json.get("when").unwrap();
        assert!(when.get("not_domain").is_some());
        assert!(when.get("not_cidr").is_some());
        assert!(when.get("not_proto").is_some());
    }
}
