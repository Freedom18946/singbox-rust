use sb_core::router::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

#[tokio::test]
async fn udp_cache_key_does_not_pollute_http_path() {
    let rules = r#"
    transport:tcp=reject
    transport:udp=proxy
    default=unresolved
    "#;
    let h = RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules.into(),
        decision_cache: true,
        decision_cache_capacity: 16,
        ..RouterRuntimeOptions::default()
    }));
    // 首先 UDP 决策，缓存 key=udp|host
    let u = h.decide_udp_async("no.match").await;
    assert_eq!(u, "proxy");
    // HTTP 决策不使用该缓存（且是 tcp 兜底）
    assert_eq!(h.decide_http("no.match"), "reject");
}
