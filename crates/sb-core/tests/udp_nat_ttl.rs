//! UDP NAT TTL eviction tests with real time delays
//!
//! These tests verify TTL-based eviction behavior using real time delays.
//! We use short TTL values (10-50ms) to keep tests fast while ensuring
//! proper time-based expiration logic.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use sb_core::net::udp_nat_core::UdpNat;

fn test_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
}

#[tokio::test]
async fn test_ttl_eviction_deterministic() {
    // Use a relaxed TTL to avoid timing flake on loaded test runners
    let mut nat = UdpNat::new(100, Duration::from_millis(200)); // 200ms TTL

    // Create initial mapping
    let src = test_addr(1234);
    let dst = test_addr(5678);
    let mapped_addr = nat.create_mapping(src, dst).unwrap();
    assert_eq!(nat.session_count(), 1);

    // Verify session exists
    assert!(nat.lookup_session(&mapped_addr).is_some());

    // Wait less than TTL (50ms)
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Session should still exist
    assert_eq!(nat.session_count(), 1);
    assert!(nat.lookup_session(&mapped_addr).is_some());
    let evicted_before = nat.evict_expired();
    assert_eq!(evicted_before, 0);

    // Wait past TTL (another 200ms = 250ms total > 200ms TTL)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now evict expired sessions
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 1);
    assert_eq!(nat.session_count(), 0);
    assert!(nat.lookup_session(&mapped_addr).is_none());
}

#[tokio::test]
async fn test_ttl_eviction_with_activity_update() {
    let mut nat = UdpNat::new(100, Duration::from_millis(30)); // 30ms TTL

    // Create mapping
    let src = test_addr(1234);
    let dst = test_addr(5678);
    let mapped_addr = nat.create_mapping(src, dst).unwrap();
    let session = nat.lookup_session(&mapped_addr).unwrap();
    let flow_key = session.flow_key.clone();

    // Wait near TTL expiration (20ms)
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Update activity (this should reset the TTL countdown)
    nat.update_activity(&flow_key);

    // Wait another 20ms (40ms from creation, but only 20ms from last activity)
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Session should still exist because activity was updated
    assert_eq!(nat.session_count(), 1);
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 0); // No eviction yet

    // Wait another 20ms (40ms from last activity, past 30ms TTL)
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Now session should expire
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 1);
    assert_eq!(nat.session_count(), 0);
}

#[tokio::test]
async fn test_batch_ttl_eviction() {
    let mut nat = UdpNat::new(100, Duration::from_millis(40)); // 40ms TTL

    // Create multiple sessions
    let sessions = [
        (test_addr(1001), test_addr(2001)),
        (test_addr(1002), test_addr(2002)),
        (test_addr(1003), test_addr(2003)),
        (test_addr(1004), test_addr(2004)),
        (test_addr(1005), test_addr(2005)),
    ];

    let mut mapped_addrs = Vec::new();
    for (src, dst) in &sessions {
        let mapped = nat.create_mapping(*src, *dst).unwrap();
        mapped_addrs.push(mapped);
    }
    assert_eq!(nat.session_count(), 5);

    // Wait partway through TTL (20ms)
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Update activity for sessions 2 and 4 (indices 1 and 3)
    for i in [1, 3] {
        nat.update_activity_by_addr(&mapped_addrs[i]);
    }

    // Wait for original sessions to expire (another 30ms = 50ms total > 40ms TTL)
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Evict expired sessions
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 3); // Sessions 0, 2, 4 should expire
    assert_eq!(nat.session_count(), 2); // Sessions 1, 3 should remain

    // Verify correct sessions remain
    assert!(nat.lookup_session(&mapped_addrs[1]).is_some());
    assert!(nat.lookup_session(&mapped_addrs[3]).is_some());
    assert!(nat.lookup_session(&mapped_addrs[0]).is_none());
    assert!(nat.lookup_session(&mapped_addrs[2]).is_none());
    assert!(nat.lookup_session(&mapped_addrs[4]).is_none());
}

#[tokio::test]
async fn test_ttl_batch_eviction_limit() {
    let mut nat = UdpNat::new(100, Duration::from_millis(15)); // 15ms TTL

    // Create 10 sessions
    for i in 0..10 {
        let _ = nat
            .create_mapping(test_addr(1000 + i), test_addr(2000 + i))
            .unwrap();
    }
    assert_eq!(nat.session_count(), 10);

    // Wait past TTL (25ms > 15ms)
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Batch evict with limit of 3
    let evicted_count = nat.evict_expired_batch(3);
    assert_eq!(evicted_count, 3);
    assert_eq!(nat.session_count(), 7);

    // Evict remaining
    let evicted_count = nat.evict_expired_batch(10);
    assert_eq!(evicted_count, 7);
    assert_eq!(nat.session_count(), 0);
}
