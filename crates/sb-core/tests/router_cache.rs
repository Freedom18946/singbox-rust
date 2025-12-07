#![cfg(feature = "router")]
use sb_core::router::{router_build_index_from_str, shared_index, RouterHandle};
use std::sync::Arc;

#[tokio::test]
async fn decision_cache_invalidate_on_generation_change() {
    // 开启缓存
    std::env::set_var("SB_ROUTER_DECISION_CACHE", "1");
    std::env::set_var("SB_ROUTER_DECISION_CACHE_CAP", "16");
    // 初始规则：suffix .test -> direct；默认 direct
    let rules1 = r#"
    suffix:.test=direct
    default=direct
    "#;
    std::env::set_var("SB_ROUTER_RULES", rules1);
    // 构建索引并创建 RouterHandle（触发 shared_index 初始化）
    let _ = router_build_index_from_str(rules1, 8192).expect("build rules1");
    let h = RouterHandle::from_env();
    let d1 = h.decide_udp_async("a.test").await;
    assert_eq!(d1, "direct");

    // 模拟热切换到新索引：.test -> proxy，并将 generation +1
    let rules2 = r#"
    suffix:.test=proxy
    default=direct
    "#;
    let new_idx = router_build_index_from_str(rules2, 8192).expect("build rules2");
    let shared = shared_index();
    {
        let mut w = shared.write().unwrap();
        let mut idx = (*new_idx).clone();
        idx.gen = w.gen.saturating_add(1);
        *w = Arc::new(idx);
    }
    // 再次决策，应返回 proxy（若缓存未失效会错误返回 direct）
    let d2 = h.decide_udp_async("a.test").await;
    assert_eq!(d2, "proxy");
}
