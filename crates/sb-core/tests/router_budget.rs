#![cfg(feature = "router")]
use sb_core::router::engine::RouterHandle;
use std::env;

/// 预算严格化：预算非常小（0ms）时，只在"未定→默认"计 degrade，
/// exact 命中不应被预算回退覆盖（Never break userspace）
#[tokio::test]
async fn budget_never_overrides_determined_decision() {
    env::set_var("SB_ROUTER_UDP", "1");
    env::set_var("SB_ROUTER_RULES", "exact:hit.example.com=proxy");
    env::set_var("SB_ROUTER_DECIDE_BUDGET_MS", "0");
    let h = RouterHandle::from_env();
    // 命中 exact，应返回 proxy，不应因为预算为 0 而回滚为 default
    let d = h.decide_udp_async("hit.example.com").await;
    assert_eq!(d, "proxy");
}
