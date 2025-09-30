use sb_core::router::router_build_index_from_str;
use sb_core::router::{decide_http, RouterHandle};
use std::sync::Arc;

#[test]
fn http_port_rule_applies_when_host_not_matched() {
    let rules = r#"
    port:443=proxy
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    // host 无匹配，端口 443 命中 -> proxy
    let decision = decide_http("no.match:443");
    assert_eq!(decision.target, "proxy");
}

#[test]
fn http_transport_tcp_as_fallback() {
    let rules = r#"
    transport:tcp=reject
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    let decision = decide_http("no.match");
    assert_eq!(decision.target, "reject");
}

#[tokio::test]
async fn udp_transport_udp_as_fallback() {
    let rules = r#"
    transport:udp=proxy
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);
    let h = RouterHandle::from_env();
    let d = h.decide_udp_async("no.match").await;
    assert_eq!(d, "proxy");
}
