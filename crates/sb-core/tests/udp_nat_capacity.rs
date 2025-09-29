//! UDP NAT capacity eviction tests
//!
//! Tests capacity-driven eviction using LRU (Least Recently Used) strategy.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::{advance, pause, resume};

use sb_core::net::udp_nat_core::UdpNat;

fn test_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
}

#[tokio::test]
async fn test_capacity_eviction_basic() {
    pause();

    // Create NAT with capacity of 3 sessions
    let mut nat = UdpNat::new(3, Duration::from_secs(300)); // Long TTL to focus on capacity

    // Fill to capacity
    let sessions = [
        (test_addr(1001), test_addr(2001)),
        (test_addr(1002), test_addr(2002)),
        (test_addr(1003), test_addr(2003)),
    ];

    let mut mapped_addrs = Vec::new();
    for (src, dst) in &sessions {
        let mapped = nat.create_mapping(*src, *dst).unwrap();
        mapped_addrs.push(mapped);
        advance(Duration::from_millis(100)).await; // Small time gap to ensure LRU ordering
    }
    assert_eq!(nat.session_count(), 3);

    // Add one more session, should trigger capacity eviction of LRU (first session)
    let (src4, dst4) = (test_addr(1004), test_addr(2004));
    let mapped4 = nat.create_mapping(src4, dst4).unwrap();
    assert_eq!(nat.session_count(), 3); // Still at capacity

    // First session should be evicted (LRU)
    assert!(nat.lookup_session(&mapped_addrs[0]).is_none());
    // Other sessions should still exist
    assert!(nat.lookup_session(&mapped_addrs[1]).is_some());
    assert!(nat.lookup_session(&mapped_addrs[2]).is_some());
    assert!(nat.lookup_session(&mapped4).is_some());

    resume();
}

#[tokio::test]
async fn test_capacity_eviction_lru_ordering() {
    pause();

    let mut nat = UdpNat::new(3, Duration::from_secs(300));

    // Create sessions with time gaps
    let sessions = [
        (test_addr(1001), test_addr(2001)),
        (test_addr(1002), test_addr(2002)),
        (test_addr(1003), test_addr(2003)),
    ];

    let mut mapped_addrs = Vec::new();
    for (_i, (src, dst)) in sessions.iter().enumerate() {
        let mapped = nat.create_mapping(*src, *dst).unwrap();
        mapped_addrs.push(mapped);
        advance(Duration::from_secs(1)).await; // 1 second gap between each
    }

    // Update activity on the first session to make it more recent
    advance(Duration::from_secs(5)).await;
    nat.update_activity_by_addr(&mapped_addrs[0]);

    // Now ordering should be: session 2 (oldest), session 3, session 1 (newest)

    // Add another session to trigger eviction
    let (src4, dst4) = (test_addr(1004), test_addr(2004));
    let _mapped4 = nat.create_mapping(src4, dst4).unwrap();

    // Session 2 should be evicted (it's now the LRU)
    assert!(nat.lookup_session(&mapped_addrs[1]).is_none());
    // Sessions 1 and 3 should remain
    assert!(nat.lookup_session(&mapped_addrs[0]).is_some());
    assert!(nat.lookup_session(&mapped_addrs[2]).is_some());

    resume();
}

#[tokio::test]
async fn test_capacity_eviction_multiple_waves() {
    pause();

    let mut nat = UdpNat::new(2, Duration::from_secs(300)); // Very small capacity

    // Create sessions in waves
    let mut all_mapped = Vec::new();

    // Wave 1: Fill to capacity
    for i in 0..2 {
        let mapped = nat
            .create_mapping(test_addr(1000 + i), test_addr(2000 + i))
            .unwrap();
        all_mapped.push(mapped);
        advance(Duration::from_millis(100)).await;
    }
    assert_eq!(nat.session_count(), 2);

    // Wave 2: Add more sessions, triggering evictions
    for i in 2..5 {
        let mapped = nat
            .create_mapping(test_addr(1000 + i), test_addr(2000 + i))
            .unwrap();
        all_mapped.push(mapped);
        assert_eq!(nat.session_count(), 2); // Should stay at capacity
        advance(Duration::from_millis(100)).await;
    }

    // Only the last 2 sessions should exist
    assert!(nat.lookup_session(&all_mapped[0]).is_none()); // Evicted
    assert!(nat.lookup_session(&all_mapped[1]).is_none()); // Evicted
    assert!(nat.lookup_session(&all_mapped[2]).is_none()); // Evicted
    assert!(nat.lookup_session(&all_mapped[3]).is_some()); // Exists
    assert!(nat.lookup_session(&all_mapped[4]).is_some()); // Exists

    resume();
}

#[tokio::test]
async fn test_capacity_zero_fails_gracefully() {
    let mut nat = UdpNat::new(0, Duration::from_secs(300));

    // Attempting to create a mapping with zero capacity should fail
    let result = nat.create_mapping(test_addr(1000), test_addr(2000));
    assert!(result.is_err());
    assert_eq!(nat.session_count(), 0);
}

#[tokio::test]
async fn test_capacity_with_duplicate_flows() {
    pause();

    let mut nat = UdpNat::new(2, Duration::from_secs(300));

    let src = test_addr(1000);
    let dst = test_addr(2000);

    // Create initial mapping
    let mapped1 = nat.create_mapping(src, dst).unwrap();
    assert_eq!(nat.session_count(), 1);

    // Create duplicate mapping (should reuse existing session)
    let mapped2 = nat.create_mapping(src, dst).unwrap();
    assert_eq!(mapped1, mapped2); // Same mapped address
    assert_eq!(nat.session_count(), 1); // No new session created

    // Fill remaining capacity
    let _mapped3 = nat
        .create_mapping(test_addr(1001), test_addr(2001))
        .unwrap();
    assert_eq!(nat.session_count(), 2);

    // Try to add one more unique session
    let _mapped4 = nat
        .create_mapping(test_addr(1002), test_addr(2002))
        .unwrap();
    assert_eq!(nat.session_count(), 2); // At capacity, should evict LRU

    resume();
}

#[tokio::test]
async fn test_mixed_ttl_and_capacity_eviction() {
    pause();

    let mut nat = UdpNat::new(3, Duration::from_secs(10)); // Short TTL and small capacity

    // Create sessions
    for i in 0..3 {
        let _ = nat
            .create_mapping(test_addr(1000 + i), test_addr(2000 + i))
            .unwrap();
        advance(Duration::from_millis(500)).await;
    }
    assert_eq!(nat.session_count(), 3);

    // Wait for some sessions to expire
    advance(Duration::from_secs(8)).await;

    // Update activity on one session to keep it alive
    let session = nat.active_sessions().next().unwrap();
    let flow_key = session.flow_key.clone();
    nat.update_activity(&flow_key);

    // Advance past TTL for older sessions
    advance(Duration::from_secs(5)).await;

    // Add new session, which should trigger both TTL cleanup and potentially capacity eviction
    let _new_mapped = nat
        .create_mapping(test_addr(1010), test_addr(2010))
        .unwrap();

    // Should have cleaned up expired sessions first, then added new one
    assert!(nat.session_count() <= 3);

    resume();
}
