//! PoolSelector behavior coverage (CAL-19, package09).
//!
//! History: this file — together with the now-removed `selector_p2.rs` and
//! `selector_smoke.rs` stubs — was disabled for ~7.5 months behind an always-false
//! `cfg` plus per-test `#[ignore]` markers citing a selector API drift, after the
//! selector moved from an external health-view API to an internal `HealthView`.
//! These tests are rewritten against the current `PoolSelector` API
//! (`sb_core::outbound::selector`), which selects the healthy endpoint with the
//! lowest observed RTT. The `selector` module has no feature gate, so this runs on
//! the default feature set.
//!
//! Scope note: the current `PoolSelector::select` ignores weight and sticky affinity
//! (it delegates to `select_healthy_endpoint`: healthy filter + minimum `avg_rtt_ms`).
//! The former weighted-selection and sticky-affinity tests are therefore intentionally
//! NOT reinstated — that behavior is not implemented — and are recorded as de-scoped in
//! the package09 evidence.

use sb_core::outbound::selector::PoolSelector;
use std::net::SocketAddr;

fn peer() -> SocketAddr {
    "127.0.0.1:12345".parse().expect("valid peer addr")
}

/// `add_pool` parses `http://IP:PORT` endpoints (via `ProxyEndpoint::parse`) and they
/// start healthy, so a freshly populated pool both reports healthy and selects an endpoint.
/// The explicit endpoint-count assertion guards against silent parse drops:
/// `add_endpoint_from_string` skips anything `ProxyEndpoint::parse` cannot handle (it only
/// accepts `http://IP:PORT` / `socks5://IP:PORT`).
#[test]
fn populated_pool_selects_and_reports_healthy() {
    let mut sel = PoolSelector::new("sel".to_string(), "main".to_string());
    sel.add_pool(
        "main".to_string(),
        vec![
            "http://127.0.0.1:8080".to_string(),
            "http://127.0.0.1:8081".to_string(),
        ],
    );

    let pool = sel.get_pool("main").expect("pool exists");
    assert_eq!(
        pool.endpoints.len(),
        2,
        "both http://IP:PORT endpoints must parse and load (no silent drop)"
    );
    assert!(sel.has_healthy_endpoints("main"));
    assert!(sel.select("main", peer(), "example.com:443", &()).is_some());
}

/// An endpoint marked unhealthy via a failed observation is filtered out; selection
/// returns one of the remaining healthy endpoints.
#[test]
fn select_filters_unhealthy_endpoint() {
    let mut sel = PoolSelector::new("sel".to_string(), "main".to_string());
    sel.add_pool(
        "main".to_string(),
        vec![
            "http://127.0.0.1:8080".to_string(), // index 0
            "http://127.0.0.1:8081".to_string(), // index 1
        ],
    );
    // Mark index 0 unhealthy (failed observation); index 1 stays healthy with an RTT.
    sel.record_observation("main", 0, 0, false);
    sel.record_observation("main", 1, 30, true);

    let chosen = sel
        .select("main", peer(), "example.com:443", &())
        .expect("a healthy endpoint remains");
    assert_eq!(
        chosen.addr.port(),
        8081,
        "the unhealthy index-0 endpoint must be filtered out"
    );
}

/// Among healthy endpoints, selection prefers the one with the lowest observed RTT.
#[test]
fn select_prefers_lowest_latency() {
    let mut sel = PoolSelector::new("sel".to_string(), "main".to_string());
    sel.add_pool(
        "main".to_string(),
        vec![
            "http://127.0.0.1:8080".to_string(), // index 0 -> slow
            "http://127.0.0.1:8081".to_string(), // index 1 -> fast
        ],
    );
    sel.record_observation("main", 0, 200, true); // 200ms
    sel.record_observation("main", 1, 40, true); // 40ms

    let chosen = sel
        .select("main", peer(), "example.com:443", &())
        .expect("a healthy endpoint exists");
    assert_eq!(
        chosen.addr.port(),
        8081,
        "the lower-RTT endpoint (40ms) must be preferred over 200ms"
    );
}

/// When every endpoint is unhealthy, selection yields `None` and the pool reports
/// no healthy endpoints.
#[test]
fn no_healthy_endpoints_selects_none() {
    let mut sel = PoolSelector::new("sel".to_string(), "main".to_string());
    sel.add_pool(
        "main".to_string(),
        vec![
            "http://127.0.0.1:8080".to_string(),
            "http://127.0.0.1:8081".to_string(),
        ],
    );
    sel.record_observation("main", 0, 0, false);
    sel.record_observation("main", 1, 0, false);

    assert!(!sel.has_healthy_endpoints("main"));
    assert!(sel.select("main", peer(), "example.com:443", &()).is_none());
}

/// Basic pool bookkeeping: known pools are listed; an unknown pool reports no health and
/// selects nothing (no panic).
#[test]
fn pool_bookkeeping_and_unknown_pool() {
    let mut sel = PoolSelector::new("sel".to_string(), "main".to_string());
    sel.add_pool(
        "main".to_string(),
        vec!["http://127.0.0.1:8080".to_string()],
    );

    assert!(
        sel.pool_names().iter().any(|n| n.as_str() == "main"),
        "the added pool must be listed by pool_names()"
    );

    assert!(!sel.has_healthy_endpoints("does-not-exist"));
    assert!(sel
        .select("does-not-exist", peer(), "example.com:443", &())
        .is_none());
}
