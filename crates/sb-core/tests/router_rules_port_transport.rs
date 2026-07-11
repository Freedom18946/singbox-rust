#![cfg(feature = "router")]
#![allow(clippy::await_holding_lock)]
use sb_core::router::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

fn handle(rules: &str) -> RouterHandle {
    RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules.into(),
        udp_enabled: true,
        udp_rules: Some(rules.into()),
        ..RouterRuntimeOptions::default()
    }))
}

#[test]
fn http_port_rule_applies_when_host_not_matched() {
    let rules = r#"
    port:443=proxy
    default=unresolved
    "#;
    assert_eq!(handle(rules).decide_http("no.match:443"), "proxy");
}

#[test]
fn http_transport_tcp_as_fallback() {
    let rules = r#"
    transport:tcp=reject
    default=unresolved
    "#;
    assert_eq!(handle(rules).decide_http("no.match"), "reject");
}

#[tokio::test]
async fn udp_transport_udp_as_fallback() {
    let rules = r#"
    transport:udp=proxy
    default=unresolved
    "#;
    let h = handle(rules);
    let d = h.decide_udp_async("no.match").await;
    assert_eq!(d, "proxy");
}
