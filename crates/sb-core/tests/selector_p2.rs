use sb_core::outbound::{
    endpoint::{ProxyEndpoint, ProxyKind},
    registry::{PoolPolicy, ProxyPool, StickyCfg},
    selector::{HealthView, PoolSelector},
};
use std::net::SocketAddr;
use std::sync::Arc;

struct MockHealthView;

impl HealthView for MockHealthView {
    fn is_selectable(&self, _ep: &ProxyEndpoint) -> bool {
        true // All endpoints are healthy for testing
    }
}

fn demo_pool() -> ProxyPool {
    let endpoints = vec![
        ProxyEndpoint {
            kind: ProxyKind::Socks5,
            addr: "127.0.0.1:8080".parse().unwrap(),
            auth: None,
            weight: 8,
            max_fail: 3,
            open_ms: 5000,
            half_open_ms: 1000,
        },
        ProxyEndpoint {
            kind: ProxyKind::Socks5,
            addr: "127.0.0.1:8081".parse().unwrap(),
            auth: None,
            weight: 8,
            max_fail: 3,
            open_ms: 5000,
            half_open_ms: 1000,
        },
    ];

    ProxyPool {
        name: "demo".to_string(),
        endpoints,
        policy: PoolPolicy::WeightedRRWithLatencyBias,
        sticky: StickyCfg {
            ttl_ms: 10000,
            cap: 1000,
        },
    }
}

#[test]
fn test_rtt_bias_affects_selection() {
    // Set environment variables to enable RTT bias
    std::env::set_var("SB_SELECT_RTT_BIAS", "1");
    std::env::set_var("SB_SELECT_RTT_ALPHA", "1.0");
    std::env::set_var("SB_SELECT_RTT_NORM_MS", "100");

    let pool = demo_pool();
    let selector = PoolSelector::new(1000, 10000);
    let health = MockHealthView;
    let client: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Simulate RTT observations - make endpoint 1 slower than endpoint 0
    for _ in 0..10 {
        selector.on_observation("demo", 0, 30, true); // Fast endpoint
        selector.on_observation("demo", 1, 300, true); // Slow endpoint
    }

    // Count selections over many iterations
    let mut count_0 = 0;
    let mut count_1 = 0;

    for i in 0..10_000 {
        let target = format!("target-{}", i);
        if let Some(ep) = selector.select(&pool, client, &target, &health) {
            if ep.addr.port() == 8080 {
                count_0 += 1;
            } else if ep.addr.port() == 8081 {
                count_1 += 1;
            }
        }
    }

    // The faster endpoint should be selected more often when RTT bias is enabled
    assert!(
        count_0 > count_1,
        "Fast endpoint (count_0={}) should be selected more than slow endpoint (count_1={})",
        count_0,
        count_1
    );

    // Clean up environment variables
    std::env::remove_var("SB_SELECT_RTT_BIAS");
    std::env::remove_var("SB_SELECT_RTT_ALPHA");
    std::env::remove_var("SB_SELECT_RTT_NORM_MS");
}

#[test]
fn test_half_open_circuit_breaker() {
    // Clean environment first
    std::env::remove_var("SB_SELECT_RTT_BIAS");
    std::env::remove_var("SB_SELECT_HALF_OPEN");
    std::env::remove_var("SB_SELECT_FAIL_OPEN_THRESHOLD");
    std::env::remove_var("SB_SELECT_HALF_OPEN_TOKENS");

    // Set environment variables to enable half-open circuit breaker
    std::env::set_var("SB_SELECT_HALF_OPEN", "1");
    std::env::set_var("SB_SELECT_FAIL_OPEN_THRESHOLD", "2");
    std::env::set_var("SB_SELECT_HALF_OPEN_TOKENS", "2");

    let pool = demo_pool();
    let selector = PoolSelector::new(1000, 10000);
    let health = MockHealthView;
    let client: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Make endpoint 1 fail enough times to trigger circuit breaker
    selector.on_observation("demo", 1, 100, false); // failure
    selector.on_observation("demo", 1, 100, false); // failure - should trigger circuit breaker

    // Count selections - endpoint 1 should be rarely selected due to circuit breaker
    let mut count_0 = 0;
    let mut count_1 = 0;

    for i in 0..2000 {
        let target = format!("target-circuit-{}", i);
        if let Some(ep) = selector.select(&pool, client, &target, &health) {
            if ep.addr.port() == 8080 {
                count_0 += 1;
            } else if ep.addr.port() == 8081 {
                count_1 += 1;
            }
        }
    }

    // Endpoint 1 should be rarely selected while circuit breaker is active
    assert!(count_1 < 100,
        "Failed endpoint should rarely be selected while circuit breaker is active: count_1={}, count_0={}",
        count_1, count_0);

    // Now provide successful observations to endpoint 1 to help it recover
    for _ in 0..5 {
        selector.on_observation("demo", 1, 50, true); // success
    }

    // Count selections again - endpoint 1 should start recovering
    let mut count_1_recovery = 0;

    for i in 0..2000 {
        let target = format!("target-recovery-{}", i);
        if let Some(ep) = selector.select(&pool, client, &target, &health) {
            if ep.addr.port() == 8081 {
                count_1_recovery += 1;
            }
        }
    }

    // After successful observations, endpoint 1 should get more traffic
    assert!(
        count_1_recovery >= 10,
        "Endpoint should recover some traffic after successful observations: count_1_recovery={}",
        count_1_recovery
    );

    // Clean up environment variables
    std::env::remove_var("SB_SELECT_HALF_OPEN");
    std::env::remove_var("SB_SELECT_FAIL_OPEN_THRESHOLD");
    std::env::remove_var("SB_SELECT_HALF_OPEN_TOKENS");
}

#[test]
fn test_p2_disabled_by_default() {
    // Ensure no P2 environment variables are set
    std::env::remove_var("SB_SELECT_RTT_BIAS");
    std::env::remove_var("SB_SELECT_HALF_OPEN");

    let pool = demo_pool();
    let selector = PoolSelector::new(1000, 10000);
    let health = MockHealthView;
    let client: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // Provide RTT observations (these should be ignored when P2 is disabled)
    for _ in 0..10 {
        selector.on_observation("demo", 0, 30, true); // Fast
        selector.on_observation("demo", 1, 300, true); // Slow
    }

    // Count selections
    let mut count_0 = 0;
    let mut count_1 = 0;

    for i in 0..1000 {
        let target = format!("target-default-{}", i);
        if let Some(ep) = selector.select(&pool, client, &target, &health) {
            if ep.addr.port() == 8080 {
                count_0 += 1;
            } else if ep.addr.port() == 8081 {
                count_1 += 1;
            }
        }
    }

    // Without P2 enabled, selections should be roughly balanced (both endpoints have same weight)
    let ratio = count_0 as f64 / (count_0 + count_1) as f64;
    assert!(
        ratio > 0.3 && ratio < 0.7,
        "Without P2, selection should be roughly balanced. Ratio: {:.2} (count_0={}, count_1={})",
        ratio,
        count_0,
        count_1
    );
}

#[test]
fn default_weighted_rr_respects_weights_ratio() {
    // Ensure P2 disabled
    std::env::remove_var("SB_SELECT_RTT_BIAS");
    std::env::remove_var("SB_SELECT_HALF_OPEN");

    // Pool with asymmetric weights 8:4 = 2:1
    let pool = ProxyPool {
        name: "ratio".into(),
        endpoints: vec![
            ProxyEndpoint {
                kind: ProxyKind::Socks5,
                addr: "127.0.0.1:8080".parse().unwrap(),
                auth: None,
                weight: 8,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
            ProxyEndpoint {
                kind: ProxyKind::Socks5,
                addr: "127.0.0.1:8081".parse().unwrap(),
                auth: None,
                weight: 4,
                max_fail: 3,
                open_ms: 5000,
                half_open_ms: 1000,
            },
        ],
        policy: PoolPolicy::WeightedRRWithLatencyBias,
        sticky: StickyCfg {
            ttl_ms: 10000,
            cap: 1000,
        },
    };

    let selector = PoolSelector::new(1000, 10000);
    let health = MockHealthView;
    let client: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let mut a = 0u64;
    let mut b = 0u64;
    for i in 0..12_000u64 {
        let target = format!("ratio-{}", 900_000 + i);
        if let Some((idx, _ep)) = selector.select_with_index(&pool, client, &target, &health) {
            if idx == 0 {
                a += 1;
            } else if idx == 1 {
                b += 1;
            }
        }
    }
    let ratio = (a as f64) / (b.max(1) as f64);
    assert!(
        ratio > 1.8 && ratio < 2.2,
        "ratio ~ 2:1 expected, got {ratio} (a={a} b={b})"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn success_feedback_increases_share() {
    // Enable RTT bias
    std::env::set_var("SB_SELECT_RTT_BIAS", "1");
    std::env::set_var("SB_SELECT_RTT_ALPHA", "0.8");
    std::env::set_var("SB_SELECT_RTT_HALF_LIFE_MS", "1");
    std::env::set_var("SB_SELECT_RTT_NORM_MS", "100");

    let pool = demo_pool();
    let selector = PoolSelector::new(1000, 10000);
    let health = MockHealthView;
    let client: SocketAddr = "127.0.0.1:22334".parse().unwrap();

    // Seed with equal samples
    for _ in 0..5 {
        selector.on_observation("demo", 0, 100, true);
        selector.on_observation("demo", 1, 100, true);
    }
    // Make 0 faster + successful; 1 slower + sometimes failing
    for _ in 0..20 {
        selector.on_observation("demo", 0, 40, true);
        selector.on_observation("demo", 1, 200, false);
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }

    let mut cnt0 = 0;
    let mut cnt1 = 0;
    for i in 0..5000u64 {
        let target = format!("target-{}", 100_000 + i);
        if let Some((idx, _ep)) = selector.select_with_index(&pool, client, &target, &health) {
            if idx == 0 {
                cnt0 += 1;
            } else if idx == 1 {
                cnt1 += 1;
            }
        }
    }
    assert!(
        cnt0 > cnt1,
        "endpoint 0 should receive more selections after positive feedback: a={cnt0} b={cnt1}"
    );

    std::env::remove_var("SB_SELECT_RTT_BIAS");
    std::env::remove_var("SB_SELECT_RTT_ALPHA");
}

#[test]
fn failures_push_endpoint_share_down() {
    // Enable RTT bias so observations influence selection
    std::env::set_var("SB_SELECT_RTT_BIAS", "1");
    std::env::set_var("SB_SELECT_RTT_ALPHA", "0.6");

    let pool = demo_pool();
    let selector = PoolSelector::new(1000, 10000);

    // Simulate observations: endpoint 0 stable fast, endpoint 1 slow and failing
    for _ in 0..16 {
        selector.on_observation("demo", 0, 60, true);
        selector.on_observation("demo", 1, 250, false);
    }

    let health = MockHealthView;
    let client: SocketAddr = "127.0.0.1:34567".parse().unwrap();
    let mut a: u64 = 0;
    let mut b: u64 = 0;
    for i in 0..6000u64 {
        let target = format!("t-{}", 500_000 + i);
        if let Some((idx, _ep)) = selector.select_with_index(&pool, client, &target, &health) {
            if idx == 0 {
                a += 1;
            } else if idx == 1 {
                b += 1;
            }
        }
    }
    assert!(a > b, "failed+slow endpoint must lose share: a={a} b={b}");
}
