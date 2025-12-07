#![cfg(feature = "router")]
use sb_core::router::decide_http;

#[test]
fn http_port_range_matches_first_wins() {
    let rules = r#"
    portrange:1000-2000=proxy
    portrange:1500-1600=reject
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules);

    // 1500 命中首条 portrange -> proxy
    let decision = decide_http("no.match:1500");
    assert_eq!(decision.target, "proxy");
    // 边界值 1000/2000
    let decision = decide_http("no.match:1000");
    assert_eq!(decision.target, "proxy");
    let decision = decide_http("no.match:2000");
    assert_eq!(decision.target, "proxy");
    // 区间外 -> 默认
    let decision = decide_http("no.match:2020");
    assert_eq!(decision.target, "direct");
}
