#![cfg(feature = "router")]
use sb_core::router::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

#[test]
fn http_portset_first_wins_and_valid() {
    let rules = r#"
    portset:80,443,8443=proxy
    port:443=reject   # 已被 portset 初始化时占位，first-wins -> 不生效
    default=unresolved
    "#;
    let h = RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules.into(),
        ..RouterRuntimeOptions::default()
    }));
    // 80、443、8443 都应命中 proxy
    for p in [80u16, 443u16, 8443u16] {
        let t = format!("no.match:{}", p);
        assert_eq!(h.decide_http(&t), "proxy");
    }
    // 81 不在集合 -> default
    assert_eq!(h.decide_http("no.match:81"), "unresolved");
}
