//! UDP NAT TTL eviction tests with deterministic time control
//!
//! These tests use tokio::time::pause/advance to control time deterministically
//! and test TTL-based eviction behavior without relying on real-time delays.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::time::{advance, pause, resume};

use sb_core::net::udp_nat_core::UdpNat;

fn test_addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), port)
}

#[tokio::test]
async fn test_ttl_eviction_deterministic() {
    // Pause time at the start of test
    pause();

    let mut nat = UdpNat::new(100, Duration::from_secs(60)); // 60 second TTL

    // Create initial mapping
    let src = test_addr(1234);
    let dst = test_addr(5678);
    let mapped_addr = nat.create_mapping(src, dst).unwrap();
    assert_eq!(nat.session_count(), 1);

    // Verify session exists
    assert!(nat.lookup_session(&mapped_addr).is_some());

    // Advance time to just before TTL expiration (59 seconds)
    advance(Duration::from_secs(59)).await;

    // Session should still exist
    assert_eq!(nat.session_count(), 1);
    assert!(nat.lookup_session(&mapped_addr).is_some());

    // Advance time past TTL (62 seconds total)
    advance(Duration::from_secs(3)).await;

    // Now evict expired sessions
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 1);
    assert_eq!(nat.session_count(), 0);
    assert!(nat.lookup_session(&mapped_addr).is_none());

    // Resume time for cleanup
    resume();
}

#[tokio::test]
async fn test_ttl_eviction_with_activity_update() {
    pause();

    let mut nat = UdpNat::new(100, Duration::from_secs(30)); // 30 second TTL

    // Create mapping
    let src = test_addr(1234);
    let dst = test_addr(5678);
    let mapped_addr = nat.create_mapping(src, dst).unwrap();
    let session = nat.lookup_session(&mapped_addr).unwrap();
    let flow_key = session.flow_key.clone();

    // Advance time to near TTL expiration (25 seconds)
    advance(Duration::from_secs(25)).await;

    // Update activity (this should reset the TTL countdown)
    nat.update_activity(&flow_key);

    // Advance another 25 seconds (50 seconds total from creation, but only 25 from last activity)
    advance(Duration::from_secs(25)).await;

    // Session should still exist because activity was updated
    assert_eq!(nat.session_count(), 1);
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 0); // No eviction yet

    // Advance another 10 seconds (35 seconds from last activity, past 30s TTL)
    advance(Duration::from_secs(10)).await;

    // Now session should expire
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 1);
    assert_eq!(nat.session_count(), 0);

    resume();
}

#[tokio::test]
async fn test_batch_ttl_eviction() {
    pause();

    let mut nat = UdpNat::new(100, Duration::from_secs(45)); // 45 second TTL

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

    // Update activity for some sessions partway through
    advance(Duration::from_secs(20)).await;

    // Update activity for sessions 2 and 4 (indices 1 and 3)
    for i in [1, 3] {
        nat.update_activity_by_addr(&mapped_addrs[i]);
    }

    // Advance to TTL expiration for original sessions (50 seconds total)
    advance(Duration::from_secs(30)).await;

    // Evict expired sessions
    let evicted_count = nat.evict_expired();
    assert_eq!(evicted_count, 3); // Sessions 1, 3, 5 should expire
    assert_eq!(nat.session_count(), 2); // Sessions 2, 4 should remain

    // Verify correct sessions remain
    assert!(nat.lookup_session(&mapped_addrs[1]).is_some());
    assert!(nat.lookup_session(&mapped_addrs[3]).is_some());
    assert!(nat.lookup_session(&mapped_addrs[0]).is_none());
    assert!(nat.lookup_session(&mapped_addrs[2]).is_none());
    assert!(nat.lookup_session(&mapped_addrs[4]).is_none());

    resume();
}

#[tokio::test]
async fn test_ttl_batch_eviction_limit() {
    pause();

    let mut nat = UdpNat::new(100, Duration::from_secs(15)); // 15 second TTL

    // Create 10 sessions
    for i in 0..10 {
        let _ = nat
            .create_mapping(test_addr(1000 + i), test_addr(2000 + i))
            .unwrap();
    }
    assert_eq!(nat.session_count(), 10);

    // Advance time past TTL
    advance(Duration::from_secs(20)).await;

    // Batch evict with limit of 3
    let evicted_count = nat.evict_expired_batch(3);
    assert_eq!(evicted_count, 3);
    assert_eq!(nat.session_count(), 7);

    // Evict remaining
    let evicted_count = nat.evict_expired_batch(10);
    assert_eq!(evicted_count, 7);
    assert_eq!(nat.session_count(), 0);

    resume();
}
