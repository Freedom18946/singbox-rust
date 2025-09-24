#[cfg(all(feature = "router_cache_lru_demo", feature = "cache_stats_hot"))]
#[test]
fn cache_hot_has_items() {
    use sb_core::router::cache_wire::demo_lru::LruDecision;
    use sb_core::router::register_router_hot_adapter;
    let lru = Box::leak(Box::new(LruDecision::new(4)));
    lru.put("a", 1);
    lru.put("b", 2);
    register_router_hot_adapter(lru);
    let js = sb_core::router::cache_hot::hot_json(8);
    println!("Hot JSON output: {}", js);
    assert!(js.contains("limit"));
    assert!(js.contains("items"));
    assert!(js.contains("count"));
}
