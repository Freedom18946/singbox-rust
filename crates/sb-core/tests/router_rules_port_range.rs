#![cfg(feature = "router")]
use sb_core::router::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

#[test]
fn http_port_range_matches_first_wins() {
    let rules = r#"
    portrange:1000-2000=proxy
    portrange:1500-1600=reject
    default=unresolved
    "#;
    let h = RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules.into(),
        ..RouterRuntimeOptions::default()
    }));

    // 1500 命中首条 portrange -> proxy
    assert_eq!(h.decide_http("no.match:1500"), "proxy");
    // 边界值 1000/2000
    assert_eq!(h.decide_http("no.match:1000"), "proxy");
    assert_eq!(h.decide_http("no.match:2000"), "proxy");
    // 区间外 -> 默认
    assert_eq!(h.decide_http("no.match:2020"), "unresolved");
}
