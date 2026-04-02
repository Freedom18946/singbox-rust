//! Legacy router rules text emission for the bootstrap/runtime adapter path.
//!
//! This module intentionally stays in `app` as a runtime concern:
//! it translates `ConfigIR.route.rules` into the legacy string protocol
//! consumed by `router_build_index_from_str()`.

#[cfg(feature = "router")]
use sb_config::ir::{ConfigIR, RuleIR};

/// Convert `ConfigIR` route rules into legacy router rules text.
#[cfg(feature = "router")]
#[allow(dead_code)]
#[must_use]
pub fn ir_to_router_rules_text(config: &ConfigIR) -> String {
    let mut rules = Vec::new();

    for rule in &config.route.rules {
        let outbound = rule_outbound(rule);

        for domain in &rule.domain {
            rules.push(format!("exact:{domain}={outbound}"));
        }
        for geosite in &rule.geosite {
            rules.push(format!("geosite:{geosite}={outbound}"));
        }
        for geoip in &rule.geoip {
            rules.push(format!("geoip:{geoip}={outbound}"));
        }
        for ipcidr in &rule.ipcidr {
            let rule_type = if ipcidr.contains(':') {
                "cidr6"
            } else {
                "cidr4"
            };
            rules.push(format!("{rule_type}:{ipcidr}={outbound}"));
        }
        for port in &rule.port {
            if port.contains('-') {
                rules.push(format!("portrange:{port}={outbound}"));
            } else {
                rules.push(format!("port:{port}={outbound}"));
            }
        }
        for process in &rule.process_name {
            rules.push(format!("process:{process}={outbound}"));
        }
        for network in &rule.network {
            rules.push(format!("transport:{network}={outbound}"));
        }
        for protocol in &rule.protocol {
            rules.push(format!("protocol:{protocol}={outbound}"));
        }
        // alpn/user-agent/source/dest can be added later when routed
    }

    if let Some(default) = &config.route.default {
        rules.push(format!("default={default}"));
    } else {
        rules.push("default=unresolved".to_string());
    }

    rules.join("\n")
}

#[cfg(feature = "router")]
#[allow(dead_code)]
fn rule_outbound(rule: &RuleIR) -> &str {
    rule.outbound.as_deref().unwrap_or("unresolved")
}

#[cfg(all(test, feature = "router"))]
mod tests {
    use super::*;

    fn render(config: ConfigIR) -> Vec<String> {
        ir_to_router_rules_text(&config)
            .lines()
            .map(std::string::ToString::to_string)
            .collect()
    }

    #[test]
    fn emits_expected_legacy_router_rule_tokens() {
        let mut config = ConfigIR::default();
        config.route.rules.push(RuleIR {
            domain: vec!["example.com".into()],
            geosite: vec!["geosite-cn".into()],
            geoip: vec!["geoip-private".into()],
            ipcidr: vec!["10.0.0.0/8".into(), "2001:db8::/32".into()],
            port: vec!["53".into(), "8000-8010".into()],
            process_name: vec!["curl".into()],
            network: vec!["tcp".into()],
            protocol: vec!["http".into()],
            outbound: Some("proxy-a".into()),
            ..Default::default()
        });
        config.route.default = Some("final-out".into());

        assert_eq!(
            render(config),
            vec![
                "exact:example.com=proxy-a".to_string(),
                "geosite:geosite-cn=proxy-a".to_string(),
                "geoip:geoip-private=proxy-a".to_string(),
                "cidr4:10.0.0.0/8=proxy-a".to_string(),
                "cidr6:2001:db8::/32=proxy-a".to_string(),
                "port:53=proxy-a".to_string(),
                "portrange:8000-8010=proxy-a".to_string(),
                "process:curl=proxy-a".to_string(),
                "transport:tcp=proxy-a".to_string(),
                "protocol:http=proxy-a".to_string(),
                "default=final-out".to_string(),
            ]
        );
    }

    #[test]
    fn missing_rule_outbound_falls_back_to_unresolved() {
        let mut config = ConfigIR::default();
        config.route.rules.push(RuleIR {
            domain: vec!["missing-outbound.example".into()],
            ..Default::default()
        });

        assert_eq!(
            render(config),
            vec![
                "exact:missing-outbound.example=unresolved".to_string(),
                "default=unresolved".to_string(),
            ]
        );
    }

    #[test]
    fn missing_route_default_emits_unresolved_default() {
        let mut config = ConfigIR::default();
        config.route.rules.push(RuleIR {
            domain: vec!["example.com".into()],
            outbound: Some("proxy-a".into()),
            ..Default::default()
        });

        let lines = render(config);
        assert_eq!(lines.last().map(String::as_str), Some("default=unresolved"));
    }

    #[test]
    fn route_default_emits_configured_default_line() {
        let mut config = ConfigIR::default();
        config.route.default = Some("proxy-b".into());

        assert_eq!(render(config), vec!["default=proxy-b".to_string()]);
    }

    #[test]
    fn emitted_text_is_consumable_by_router_index_builder() {
        let mut config = ConfigIR::default();
        config.route.rules.push(RuleIR {
            domain: vec!["example.com".into()],
            outbound: Some("proxy-a".into()),
            ..Default::default()
        });
        config.route.default = Some("proxy-a".into());

        let text = ir_to_router_rules_text(&config);
        let index = sb_core::router::router_build_index_from_str(&text, 64);
        assert!(
            index.is_ok(),
            "generated text should remain router-consumable"
        );
    }

    #[test]
    fn wp30ak_pin_router_text_owner_is_router_text_rs() {
        let source = include_str!("router_text.rs");
        let bootstrap = include_str!("bootstrap.rs");

        assert!(source.contains("pub(crate) fn ir_to_router_rules_text"));
        assert!(!bootstrap.contains("fn ir_to_router_rules_text("));
    }

    #[test]
    fn wp30ak_pin_bootstrap_delegates_router_text_owner() {
        let bootstrap = include_str!("bootstrap.rs");

        assert!(bootstrap
            .contains("crate::bootstrap_runtime::router_helpers::build_router_index_from_config("));
        assert!(bootstrap.contains("crate::bootstrap_runtime::router_helpers::parse_env_usize("));
    }
}
