#[cfg(feature = "router_cache_lru_demo")]
#[test]
fn cache_wire_snapshot_min() {
    use sb_core::router::cache_wire::demo_lru::LruDecision;
    use sb_core::router::{register_router_decision_cache_adapter, register_router_hot_adapter};
    let lru = Box::leak(Box::new(LruDecision::new(8)));
    lru.put("a", 1);
    lru.get("a");
    lru.get("x");
    register_router_decision_cache_adapter(lru);
    register_router_hot_adapter(lru);
    let j = sb_core::router::router_cache_summary();
    assert!(j.contains("\"disabled\":false") || j.contains("\"size\""));
}
