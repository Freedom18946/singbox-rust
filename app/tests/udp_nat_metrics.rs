use sb_core::udp_nat_instrument::{UdpNatTable, UpstreamFail};
use sb_metrics::registry::global as M;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;

#[test]
fn nat_metrics_update() {
    let t = UdpNatTable::new(4);
    let s: SocketAddr = "127.0.0.1:10001".parse().unwrap();
    let u: SocketAddr = "8.8.8.8:53".parse().unwrap();
    t.insert(s, u, Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(2));
    t.evict_expired();
    assert!(M().udp_evict_total.snapshot().len() >= 1);
    t.upstream_fail(UpstreamFail::Timeout);
}

#[tokio::test]
async fn concurrent_eviction_metrics() {
    // Test concurrent eviction and assert metrics changes
    let table = Arc::new(UdpNatTable::new(50));
    let barrier = Arc::new(Barrier::new(4));

    let initial_evictions = M().udp_evict_total.snapshot().len();

    // Spawn multiple tasks that create sessions and trigger evictions
    let mut handles = vec![];

    for worker_id in 0..4 {
        let table = Arc::clone(&table);
        let barrier = Arc::clone(&barrier);

        let handle = tokio::spawn(async move {
            barrier.wait().await;

            // Each worker creates sessions with very short TTL
            for i in 0..15 {
                let src: SocketAddr = format!("192.168.{}.{}:1000", worker_id, i).parse().unwrap();
                let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
                table.insert(src, dst, Duration::from_millis(5));
            }

            // Wait for TTL expiration
            tokio::time::sleep(Duration::from_millis(10)).await;

            // Trigger eviction
            table.evict_expired();
        });

        handles.push(handle);
    }

    // Wait for all workers to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Assert that eviction metrics increased
    let final_evictions = M().udp_evict_total.snapshot().len();
    assert!(
        final_evictions > initial_evictions,
        "Eviction metrics should have increased"
    );

    // Verify table is cleaned up
    assert_eq!(table.active_count(), 0, "All sessions should be evicted");
}

#[tokio::test]
async fn ttl_expiration_metrics() {
    // Test TTL expiration tracking and metrics recording
    let table = UdpNatTable::new(20);

    let initial_ttl_recordings = M().udp_ttl_histogram.snapshot().count();

    // Create sessions with different TTLs
    let sessions = vec![
        ("127.0.0.1:1001", Duration::from_millis(10)),
        ("127.0.0.1:1002", Duration::from_millis(20)),
        ("127.0.0.1:1003", Duration::from_millis(30)),
        ("127.0.0.1:1004", Duration::from_millis(40)),
        ("127.0.0.1:1005", Duration::from_millis(50)),
    ];

    for (addr_str, ttl) in sessions {
        let src: SocketAddr = addr_str.parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:53".parse().unwrap();
        table.insert(src, dst, ttl);
    }

    assert_eq!(table.active_count(), 5, "All sessions should be active");

    // Wait for first batch to expire (10ms)
    tokio::time::sleep(Duration::from_millis(15)).await;
    let expired_count_1 = table.evict_expired();
    assert!(expired_count_1 >= 1, "At least one session should expire");

    // Wait for second batch to expire (20ms total)
    tokio::time::sleep(Duration::from_millis(10)).await;
    let expired_count_2 = table.evict_expired();

    // Wait for remaining sessions to expire
    tokio::time::sleep(Duration::from_millis(40)).await;
    let expired_count_3 = table.evict_expired();

    let total_expired = expired_count_1 + expired_count_2 + expired_count_3;
    assert_eq!(total_expired, 5, "All 5 sessions should be expired");

    // Verify TTL metrics were recorded
    let final_ttl_recordings = M().udp_ttl_histogram.snapshot().count();
    assert!(
        final_ttl_recordings > initial_ttl_recordings,
        "TTL metrics should be recorded for expired sessions"
    );

    // Verify table is empty
    assert_eq!(
        table.active_count(),
        0,
        "Table should be empty after all expirations"
    );
}
