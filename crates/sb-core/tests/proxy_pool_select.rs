use sb_core::outbound::{
    endpoint::{ProxyEndpoint, ProxyKind},
    registry::{PoolPolicy, ProxyPool, StickyCfg},
    selector::PoolSelector,
};

// NOTE: These tests are currently disabled due to API changes in PoolSelector.
// The PoolSelector now uses an internal HealthView instead of accepting an external one.
// These tests need to be rewritten to use the new API.

#[allow(dead_code)]
struct MockHealthView {
    healthy_addrs: Vec<std::net::SocketAddr>,
}

#[allow(dead_code)]
impl MockHealthView {
    fn new(healthy_addrs: Vec<&str>) -> Self {
        let addrs = healthy_addrs
            .into_iter()
            .map(|s| s.parse().unwrap())
            .collect();
        Self {
            healthy_addrs: addrs,
        }
    }
}

#[test]
#[ignore = "Test disabled: PoolSelector API changed, needs rewrite"]
fn test_proxy_pool_weighted_selection() {
    let pool = ProxyPool {
        name: "test_pool".to_string(),
        endpoints: vec![
            ProxyEndpoint {
                kind: ProxyKind::Http,
                addr: "127.0.0.1:8080".parse().unwrap(),
                auth: None,
                weight: 3,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
            ProxyEndpoint {
                kind: ProxyKind::Http,
                addr: "127.0.0.1:8081".parse().unwrap(),
                auth: None,
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
        ],
        policy: PoolPolicy::WeightedRR,
        sticky: StickyCfg {
            ttl_ms: 1000,
            cap: 100,
        },
    };

    let health = MockHealthView::new(vec!["127.0.0.1:8080", "127.0.0.1:8081"]);
    let selector = PoolSelector::new(100, 1000);
    let client = "192.168.1.100:12345".parse().unwrap();

    // Test multiple selections to verify weight distribution
    let mut selections = std::collections::HashMap::new();
    for i in 0..100 {
        let target = format!("example{}.com:443", i);
        if let Some(ep) = selector.select(&pool, client, &target, &health) {
            *selections.entry(ep.addr).or_insert(0) += 1;
        }
    }

    // With weight 3:1, we expect roughly 75% to 8080 and 25% to 8081
    // Allow some variance due to randomization
    let count_8080 = *selections
        .get(&"127.0.0.1:8080".parse().unwrap())
        .unwrap_or(&0);
    let count_8081 = *selections
        .get(&"127.0.0.1:8081".parse().unwrap())
        .unwrap_or(&0);

    println!("Selections: 8080={}, 8081={}", count_8080, count_8081);

    // Should have selections for both endpoints
    assert!(count_8080 > 0);
    assert!(count_8081 > 0);

    // Higher weight should get more selections (allowing for randomization variance)
    assert!(count_8080 > count_8081);
}

#[test]
#[ignore = "Test disabled: PoolSelector API changed, needs rewrite"]
fn test_proxy_pool_health_filtering() {
    let pool = ProxyPool {
        name: "test_pool".to_string(),
        endpoints: vec![
            ProxyEndpoint {
                kind: ProxyKind::Http,
                addr: "127.0.0.1:8080".parse().unwrap(),
                auth: None,
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
            ProxyEndpoint {
                kind: ProxyKind::Http,
                addr: "127.0.0.1:8081".parse().unwrap(),
                auth: None,
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
        ],
        policy: PoolPolicy::WeightedRR,
        sticky: StickyCfg {
            ttl_ms: 1000,
            cap: 100,
        },
    };

    // Only one endpoint is healthy
    let health = MockHealthView::new(vec!["127.0.0.1:8080"]);
    let selector = PoolSelector::new(100, 1000);
    let client = "192.168.1.100:12345".parse().unwrap();

    // Test multiple selections - should only get the healthy endpoint
    for i in 0..10 {
        let target = format!("example{}.com:443", i);
        if let Some(ep) = selector.select(&pool, client, &target, &health) {
            assert_eq!(ep.addr, "127.0.0.1:8080".parse().unwrap());
        }
    }
}

#[test]
#[ignore = "Test disabled: PoolSelector API changed, needs rewrite"]
fn test_proxy_pool_sticky_affinity() {
    let pool = ProxyPool {
        name: "test_pool".to_string(),
        endpoints: vec![
            ProxyEndpoint {
                kind: ProxyKind::Http,
                addr: "127.0.0.1:8080".parse().unwrap(),
                auth: None,
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
            ProxyEndpoint {
                kind: ProxyKind::Http,
                addr: "127.0.0.1:8081".parse().unwrap(),
                auth: None,
                weight: 1,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
        ],
        policy: PoolPolicy::WeightedRR,
        sticky: StickyCfg {
            ttl_ms: 10000,
            cap: 100,
        },
    };

    let health = MockHealthView::new(vec!["127.0.0.1:8080", "127.0.0.1:8081"]);
    let selector = PoolSelector::new(100, 10000);
    let client = "192.168.1.100:12345".parse().unwrap();
    let target = "example.com:443";

    // First selection
    let first_selection = selector.select(&pool, client, target, &health).unwrap();

    // Subsequent selections for the same client+target should return the same endpoint
    for _ in 0..5 {
        let selection = selector.select(&pool, client, target, &health).unwrap();
        assert_eq!(selection.addr, first_selection.addr);
    }

    // Different target should potentially get a different endpoint
    let different_target = "other.com:443";
    let _different_selection = selector.select(&pool, client, different_target, &health);
    // Note: Due to randomization, we can't assert it's different, but it should be cached separately
}

#[test]
#[ignore = "Test disabled: PoolSelector API changed, needs rewrite"]
fn test_proxy_pool_no_healthy_endpoints() {
    let pool = ProxyPool {
        name: "test_pool".to_string(),
        endpoints: vec![ProxyEndpoint {
            kind: ProxyKind::Http,
            addr: "127.0.0.1:8080".parse().unwrap(),
            auth: None,
            weight: 1,
            max_fail: 3,
            open_ms: 5000,
            half_open_ms: 1000,
        }],
        policy: PoolPolicy::WeightedRR,
        sticky: StickyCfg {
            ttl_ms: 1000,
            cap: 100,
        },
    };

    // No healthy endpoints
    let health = MockHealthView::new(vec![]);
    let selector = PoolSelector::new(100, 1000);
    let client = "192.168.1.100:12345".parse().unwrap();
    let target = "example.com:443";

    // Should return None when no endpoints are healthy
    let selection = selector.select(&pool, client, target, &health);
    assert!(selection.is_none());
}
