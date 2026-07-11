use sb_core::router::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

#[tokio::test]
async fn decision_cache_isolated_between_option_snapshots() {
    // 初始规则：suffix .test -> direct；默认 unresolved
    let rules1 = r#"
    suffix:.test=direct
    default=unresolved
    "#;
    let h1 = RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules1.into(),
        decision_cache: true,
        decision_cache_capacity: 16,
        ..RouterRuntimeOptions::default()
    }));
    let d1 = h1.decide_udp_async("a.test").await;
    assert_eq!(d1, "direct");

    // 模拟热切换到新索引：.test -> proxy，并将 generation +1
    let rules2 = r#"
    suffix:.test=proxy
    default=unresolved
    "#;
    let h2 = RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        rules_inline: rules2.into(),
        decision_cache: true,
        decision_cache_capacity: 16,
        ..RouterRuntimeOptions::default()
    }));
    let d2 = h2.decide_udp_async("a.test").await;
    assert_eq!(d2, "proxy");
}
