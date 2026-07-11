use sb_core::router::engine::RouterHandle;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::sync::Arc;

/// 预算严格化：预算非常小（0ms）时，只在"未定→默认"计 degrade，
/// exact 命中不应被预算回退覆盖（Never break userspace）
#[tokio::test]
async fn budget_never_overrides_determined_decision() {
    let h = RouterHandle::from_options(Arc::new(RouterRuntimeOptions {
        udp_enabled: true,
        udp_rules: Some("exact:hit.example.com=proxy".into()),
        decide_budget_ms: 0,
        ..Default::default()
    }));
    // 命中 exact，应返回 proxy，不应因为预算为 0 而回滚为 default
    let d = h.decide_udp_async("hit.example.com").await;
    assert_eq!(d, "proxy");
}
