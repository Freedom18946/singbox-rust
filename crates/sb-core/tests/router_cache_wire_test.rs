#![cfg(feature = "router")]
//! R135: Tests for router cache wire functionality (R132)

#[cfg(feature = "router_cache_lru_demo")]
#[test]
fn test_lru_demo_cache() {
    use sb_core::router::cache_wire::demo_lru::LruDecision;
    use sb_core::router::cache_wire::DecisionCacheSource;

    let cache = LruDecision::new(10);

    // Test basic functionality
    assert_eq!(cache.size(), 0);
    assert_eq!(cache.capacity(), 10);
    assert_eq!(cache.hits(), 0);
    assert_eq!(cache.misses(), 0);

    // Test put/get
    cache.put("test1", 42);
    assert_eq!(cache.size(), 1);

    let result = cache.get("test1");
    assert_eq!(result, Some(42));
    assert_eq!(cache.hits(), 1);
    assert_eq!(cache.misses(), 0);

    // Test miss
    let result = cache.get("nonexistent");
    assert_eq!(result, None);
    assert_eq!(cache.hits(), 1);
    assert_eq!(cache.misses(), 1);

    // Test topn
    cache.put("test2", 100);
    cache.put("test3", 200);
    let top = cache.topn(2);
    assert_eq!(top.len(), 2);
}

#[cfg(feature = "router_cache_wire")]
#[test]
fn test_cache_stats_provider() {
    use sb_core::router::cache_stats;
    use sb_core::router::cache_wire::demo_lru::LruDecision;
    use sb_core::router::cache_wire::register_router_decision_cache_adapter;
    use std::sync::LazyLock;

    static CACHE: LazyLock<LruDecision> = LazyLock::new(|| LruDecision::new(5));

    // Register the cache adapter
    register_router_decision_cache_adapter(&*CACHE);

    // Test that stats are properly provided
    let stats = cache_stats::snapshot();
    assert!(stats.is_some());
    let stats = stats.unwrap();
    assert!(stats.enabled);
    assert_eq!(stats.capacity, 5);
}
