#![cfg(feature = "router")]

use sb_config::ir::{ConfigIR, RuleAction, RuleIR};
use sb_core::outbound::RouteTarget;
use sb_core::router::{router_build_index_from_str, RouteCtx, RouterHandle, Transport};
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
    cfg.route.rules.push(RuleIR {
        action: RuleAction::RouteOptions,
        domain_suffix: vec!["example.test".to_string()],
        network: vec!["udp".to_string()],
        outbound: Some("direct".to_string()),
        udp_disable_domain_unmapping: Some(true),
        udp_connect: Some(true),
        udp_timeout: Some("45s".to_string()),
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

    assert_eq!(meta.rule.as_deref(), Some("rule#0"));
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
}
