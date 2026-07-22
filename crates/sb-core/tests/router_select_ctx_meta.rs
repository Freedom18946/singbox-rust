use sb_config::ir::{ConfigIR, RuleAction, RuleIR};
use sb_core::outbound::RouteTarget;
use sb_core::router::rules::{CompositeRule, Decision, RouteCtx as RuleRouteCtx};
use sb_core::router::{
    router_build_index_from_str, DnsResolve, DnsResult, RouteCtx, RouterHandle, Transport,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

#[test]
fn select_ctx_and_record_with_meta_labels() {
    let rules = r#"
exact:api.example.com=proxy
suffix:example.com=direct
cidr4:10.0.0.0/8=proxy
default=unresolved
"#;
    let idx = router_build_index_from_str(rules, 8192).expect("build index");
    let handle = RouterHandle::from_index(idx);

    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        host: Some("api.example.com"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("exact"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "proxy"));

    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        host: Some("www.example.com"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("suffix"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "direct"));

    let ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        ip: Some(ip),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("ip"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "proxy"));

    let (target, rule) = handle.select_ctx_and_record_with_meta(RouteCtx {
        host: Some("no-match.example"),
        ..Default::default()
    });
    assert_eq!(rule.as_deref(), Some("final"));
    assert!(matches!(target, RouteTarget::Named(ref t) if t == "unresolved"));
}

#[test]
fn decide_with_meta_carries_udp_route_action_options() {
    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("direct".to_string());
    cfg.route.rules.push(RuleIR {
        action: RuleAction::RouteOptions,
        domain_suffix: vec!["example.test".to_string()],
        network: vec!["udp".to_string()],
        outbound: Some("direct".to_string()),
        override_address: Some("1.1.1.1".to_string()),
        override_port: Some(8443),
        network_strategy: Some("prefer_ipv4".to_string()),
        fallback_network_type: Some(vec!["wifi".to_string()]),
        fallback_delay: Some("250ms".to_string()),
        udp_disable_domain_unmapping: Some(true),
        udp_connect: Some(true),
        udp_timeout: Some("45s".to_string()),
        tls_fragment: Some(true),
        tls_fragment_fallback_delay: Some("50ms".to_string()),
        ..Default::default()
    });

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx);
    let meta = handle.decide_with_meta(&RouteCtx {
        host: Some("api.example.test"),
        port: Some(53),
        transport: Transport::Udp,
        network: "udp",
        ..Default::default()
    });

    assert_eq!(meta.rule.as_deref(), Some("final"));
    assert!(matches!(
        meta.decision,
        sb_core::router::rules::Decision::Direct
    ));
    assert!(meta.route_options.udp_disable_domain_unmapping);
    assert!(meta.route_options.udp_connect);
    assert_eq!(
        meta.route_options.udp_timeout,
        Some(Duration::from_secs(45))
    );
    assert_eq!(
        meta.route_options.override_address.as_deref(),
        Some("1.1.1.1")
    );
    assert_eq!(meta.route_options.override_port, Some(8443));
    assert_eq!(
        meta.route_options.network_strategy.as_deref(),
        Some("prefer_ipv4")
    );
    assert_eq!(
        meta.route_options.fallback_network_type,
        Some(vec!["wifi".to_string()])
    );
    assert_eq!(
        meta.route_options.fallback_delay,
        Some(Duration::from_millis(250))
    );
    assert!(meta.route_options.tls_fragment);
    assert_eq!(
        meta.route_options.tls_fragment_fallback_delay,
        Some(Duration::from_millis(50))
    );
}

#[test]
fn decide_matches_go_11313_interface_and_preferred_by_fields() {
    let mut interface_address = BTreeMap::new();
    interface_address.insert("en0".to_string(), vec!["192.0.2.0/24".to_string()]);
    let mut network_interface_address = BTreeMap::new();
    network_interface_address.insert("wifi".to_string(), vec!["192.0.2.0/24".to_string()]);

    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("unresolved".to_string());
    cfg.route.rules.push(RuleIR {
        action: RuleAction::Bypass,
        outbound: Some("direct".to_string()),
        inbound: vec!["mixed-in".to_string()],
        auth_user: vec!["alice".to_string()],
        process_path_regex: vec!["^/usr/bin/curl$".to_string()],
        source_ip_is_private: Some(true),
        port_range: vec!["8000-9000".to_string()],
        source_port_range: vec!["2000-3000".to_string()],
        preferred_by: vec!["selector-a".to_string()],
        interface_address,
        network_interface_address,
        default_interface_address: vec!["203.0.113.1".to_string()],
        ..Default::default()
    });

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx);
    let matched = handle.decide(&RouteCtx {
        host: Some("api.example.test"),
        port: Some(8443),
        source_port: Some(2500),
        source_ip: Some("10.1.2.3".parse::<IpAddr>().unwrap()),
        process_path: Some("/usr/bin/curl"),
        inbound_tag: Some("mixed-in"),
        auth_user: Some("alice"),
        preferred_by: Some("selector-a"),
        interface_name: Some("en0"),
        interface_address: Some("192.0.2.55".parse::<IpAddr>().unwrap()),
        network_type: Some("wifi"),
        default_interface_address: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
        ..Default::default()
    });
    assert!(matches!(matched, Decision::Direct));

    let missed = handle.decide(&RouteCtx {
        host: Some("api.example.test"),
        port: Some(8443),
        source_port: Some(2500),
        source_ip: Some("10.1.2.3".parse::<IpAddr>().unwrap()),
        process_path: Some("/usr/bin/curl"),
        inbound_tag: Some("mixed-in"),
        auth_user: Some("alice"),
        preferred_by: Some("selector-b"),
        interface_name: Some("en0"),
        interface_address: Some("192.0.2.55".parse::<IpAddr>().unwrap()),
        network_type: Some("wifi"),
        default_interface_address: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
        ..Default::default()
    });
    assert!(matches!(missed, Decision::Proxy(Some(ref tag)) if tag == "unresolved"));
}

#[test]
fn empty_bypass_continues_to_later_rule() {
    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("block".to_string());
    cfg.route.rules = vec![
        RuleIR {
            action: RuleAction::Bypass,
            port: vec!["18897".to_string()],
            ..Default::default()
        },
        RuleIR {
            action: RuleAction::Route,
            outbound: Some("direct".to_string()),
            port: vec!["18897".to_string()],
            ..Default::default()
        },
    ];

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx);
    let meta = handle.decide_with_meta(&RouteCtx {
        port: Some(18897),
        ..Default::default()
    });
    assert_eq!(meta.decision, Decision::Direct);
    assert_eq!(meta.rule.as_deref(), Some("rule#1"));
}

#[test]
fn direct_action_continues_to_later_rule_like_go_11313() {
    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("block".to_string());
    cfg.route.rules = vec![
        RuleIR {
            action: RuleAction::Direct,
            port: vec!["18897".to_string()],
            ..Default::default()
        },
        RuleIR {
            action: RuleAction::Reject,
            port: vec!["18897".to_string()],
            ..Default::default()
        },
    ];

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx);
    let meta = handle.decide_with_meta(&RouteCtx {
        port: Some(18897),
        ..Default::default()
    });
    assert_eq!(meta.decision, Decision::Reject);
    assert_eq!(meta.rule.as_deref(), Some("rule#1"));
}

#[test]
fn resolved_meta_preserves_inbound_sniff_before_route_rules() {
    let mut cfg = ConfigIR::default();
    cfg.route.rules.push(RuleIR {
        action: RuleAction::Reject,
        port: vec!["18897".to_string()],
        ..Default::default()
    });

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx);
    let meta = handle.decide_with_meta(&RouteCtx {
        port: Some(18897),
        inbound_sniff: true,
        inbound_sniff_override: true,
        ..Default::default()
    });
    assert_eq!(
        meta.decision,
        Decision::Sniff {
            override_destination: true
        }
    );
    assert_eq!(meta.rule.as_deref(), Some("sniff"));

    let routed = handle.decide_with_meta(&RouteCtx {
        port: Some(18897),
        protocol: Some("tls"),
        inbound_sniff: true,
        inbound_sniff_override: true,
        ..Default::default()
    });
    assert_eq!(routed.decision, Decision::Reject);
    assert_eq!(routed.rule.as_deref(), Some("rule#0"));
}

#[test]
fn route_options_accumulate_and_mutate_later_port_match() {
    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("block".to_string());
    cfg.route.rules = vec![
        RuleIR {
            action: RuleAction::RouteOptions,
            port: vec!["18897".to_string()],
            override_port: Some(18898),
            ..Default::default()
        },
        RuleIR {
            action: RuleAction::Route,
            outbound: Some("direct".to_string()),
            port: vec!["18898".to_string()],
            ..Default::default()
        },
    ];

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx);
    let meta = handle.decide_with_meta(&RouteCtx {
        port: Some(18897),
        ..Default::default()
    });
    assert_eq!(meta.decision, Decision::Direct);
    assert_eq!(meta.rule.as_deref(), Some("rule#1"));
    assert_eq!(meta.route_options.override_port, Some(18898));
}

#[test]
fn route_options_override_domain_mutates_later_domain_match() {
    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("block".to_string());
    cfg.route.rules = vec![
        RuleIR {
            action: RuleAction::RouteOptions,
            port: vec!["18897".to_string()],
            override_address: Some("rewritten.test".to_string()),
            ..Default::default()
        },
        RuleIR {
            action: RuleAction::Route,
            outbound: Some("direct".to_string()),
            domain: vec!["rewritten.test".to_string()],
            ..Default::default()
        },
    ];

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx);
    let meta = handle.decide_with_meta(&RouteCtx {
        host: Some("original.test"),
        port: Some(18897),
        ..Default::default()
    });
    assert_eq!(meta.decision, Decision::Direct);
    assert_eq!(meta.rule.as_deref(), Some("rule#1"));
    assert_eq!(
        meta.route_options.override_address.as_deref(),
        Some("rewritten.test")
    );
}

struct LoopbackResolver(&'static str);

impl DnsResolve for LoopbackResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        _timeout_ms: u64,
    ) -> Pin<Box<dyn Future<Output = DnsResult> + Send + 'a>> {
        assert_eq!(host, self.0);
        Box::pin(async { DnsResult::Ok(vec!["127.0.0.1".parse().unwrap()]) })
    }
}

#[tokio::test]
async fn resolve_action_continues_with_resolved_destination_ips() {
    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("block".to_string());
    cfg.route.rules = vec![
        RuleIR {
            action: RuleAction::Resolve,
            domain: vec!["localhost".to_string()],
            ..Default::default()
        },
        RuleIR {
            action: RuleAction::Route,
            outbound: Some("direct".to_string()),
            ipcidr: vec!["127.0.0.0/8".to_string()],
            ..Default::default()
        },
    ];

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx)
        .with_resolver(std::sync::Arc::new(LoopbackResolver("localhost")));
    let meta = handle
        .decide_with_meta_resolved(&RouteCtx {
            host: Some("localhost"),
            port: Some(18897),
            ..Default::default()
        })
        .await
        .expect("resolve and route");

    assert_eq!(meta.decision, Decision::Direct);
    assert_eq!(meta.rule.as_deref(), Some("rule#1"));
    assert_eq!(
        meta.resolved_ips,
        vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn route_options_domain_override_survives_resolve_resume() {
    let mut cfg = ConfigIR::default();
    cfg.route.final_outbound = Some("block".to_string());
    cfg.route.rules = vec![
        RuleIR {
            action: RuleAction::RouteOptions,
            domain: vec!["original.test".to_string()],
            override_address: Some("rewritten.test".to_string()),
            ..Default::default()
        },
        RuleIR {
            action: RuleAction::Resolve,
            domain: vec!["rewritten.test".to_string()],
            ..Default::default()
        },
        RuleIR {
            action: RuleAction::Route,
            outbound: Some("direct".to_string()),
            ipcidr: vec!["127.0.0.0/8".to_string()],
            ..Default::default()
        },
    ];

    let idx = sb_core::router::builder::build_index_from_ir(&cfg).expect("build router");
    let handle = RouterHandle::from_index(idx)
        .with_resolver(std::sync::Arc::new(LoopbackResolver("rewritten.test")));
    let meta = handle
        .decide_with_meta_resolved(&RouteCtx {
            host: Some("original.test"),
            port: Some(18897),
            ..Default::default()
        })
        .await
        .expect("override, resolve, and route");

    assert_eq!(meta.decision, Decision::Direct);
    assert_eq!(meta.rule.as_deref(), Some("rule#2"));
    assert_eq!(
        meta.route_options.override_address.as_deref(),
        Some("rewritten.test")
    );
    assert_eq!(
        meta.resolved_ips,
        vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn composite_rule_set_ipcidr_source_mode_uses_source_rule_sets() {
    let rule = RuleIR {
        action: RuleAction::Route,
        outbound: Some("proxy-src".to_string()),
        rule_set_ipcidr: vec!["src-private".to_string()],
        rule_set_ip_cidr_match_source: Some(true),
        ..Default::default()
    };
    let compiled = CompositeRule::try_from(&rule).expect("compile");

    assert!(compiled.matches(&RuleRouteCtx {
        source_ip_rule_sets: vec!["src-private".to_string()],
        ..Default::default()
    }));
    assert!(!compiled.matches(&RuleRouteCtx {
        ip_rule_sets: vec!["src-private".to_string()],
        ..Default::default()
    }));
}

#[test]
fn reject_action_method_drop_maps_to_reject_drop() {
    let drop_rule = RuleIR {
        action: RuleAction::Reject,
        method: Some("drop".to_string()),
        ..Default::default()
    };
    let compiled = CompositeRule::try_from(&drop_rule).expect("compile");
    assert_eq!(compiled.decision, Decision::RejectDrop);

    let reply_rule = RuleIR {
        action: RuleAction::Reject,
        method: Some("reply".to_string()),
        ..Default::default()
    };
    let compiled = CompositeRule::try_from(&reply_rule).expect("compile");
    assert_eq!(compiled.decision, Decision::Reject);

    let invalid_rule = RuleIR {
        action: RuleAction::Reject,
        method: Some("drop".to_string()),
        no_drop: Some(true),
        ..Default::default()
    };
    assert!(CompositeRule::try_from(&invalid_rule).is_err());
}
