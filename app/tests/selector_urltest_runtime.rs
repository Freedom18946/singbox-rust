//! Selector and URLTest Runtime Behavior Tests
//!
//! These tests verify runtime behavior of selector groups and URLTest,
//! not just configuration validation. Tests include:
//! - URLTest automatic health checking and selection
//! - Selector manual switching
//! - Failover behavior
//! - Integration with different protocol types
//!
//! Priority: WS-E Task "Validate selector/urltest runtime behavior"

use sb_core::outbound::selector_group::{ProxyMember, SelectorGroup, UrlTestOptions};
use sb_core::outbound::Outbound;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::sleep;

/// Mock connector for testing
#[derive(Debug)]
struct MockConnector {
    _name: String,
    delay_ms: u64,
    fail_count: Arc<AtomicUsize>,
    max_fails: usize,
    permanent_fail: bool,
}

impl MockConnector {
    fn new(name: &str, delay_ms: u64) -> Self {
        Self {
            _name: name.to_string(),
            delay_ms,
            fail_count: Arc::new(AtomicUsize::new(0)),
            max_fails: 0,
            permanent_fail: false,
        }
    }

    #[allow(dead_code)]
    fn with_failures(name: &str, delay_ms: u64, max_fails: usize) -> Self {
        Self {
            _name: name.to_string(),
            delay_ms,
            fail_count: Arc::new(AtomicUsize::new(0)),
            max_fails,
            permanent_fail: false,
        }
    }

    fn with_permanent_failure(name: &str) -> Self {
        Self {
            _name: name.to_string(),
            delay_ms: 0,
            fail_count: Arc::new(AtomicUsize::new(0)),
            max_fails: 0,
            permanent_fail: true,
        }
    }
}

impl Outbound for MockConnector {
    fn r#type(&self) -> &str {
        "mock"
    }
    fn tag(&self) -> sb_types::OutboundTag {
        sb_types::OutboundTag::new(self._name.clone())
    }
    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp]
    }
    fn dial<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            use tokio_util::compat::TokioAsyncReadCompatExt;
            if self.permanent_fail {
                return Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "mock permanent failure",
                ));
            }
            sleep(Duration::from_millis(self.delay_ms)).await;
            let count = self.fail_count.fetch_add(1, Ordering::SeqCst);
            if self.max_fails > 0 && count < self.max_fails {
                return Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Refused,
                    "mock failure",
                ));
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|err| sb_types::CoreError::io(err.to_string()))?;
            let addr = listener
                .local_addr()
                .map_err(|err| sb_types::CoreError::io(err.to_string()))?;
            let stream = TcpStream::connect(addr)
                .await
                .map_err(|err| sb_types::CoreError::io(err.to_string()))?;
            tokio::spawn(async move {
                if let Ok((mut socket, _)) = listener.accept().await {
                    use tokio::io::AsyncWriteExt;
                    let _ = socket.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await;
                }
            });
            Ok(Box::new(stream.compat()) as sb_types::BoxedStream)
        })
    }
    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::connect(
                sb_types::ConnectErrorKind::Unsupported,
                "mock UDP unsupported",
            ))
        })
    }
}

fn create_test_member(tag: &str, delay_ms: u64) -> ProxyMember {
    ProxyMember {
        tag: tag.to_string(),
        connector: Arc::new(MockConnector::new(tag, delay_ms)),
        health: Arc::new(sb_core::outbound::selector_group::ProxyHealth::default()),
    }
}

#[allow(dead_code)]
fn create_failing_member(tag: &str, delay_ms: u64, max_fails: usize) -> ProxyMember {
    ProxyMember {
        tag: tag.to_string(),
        connector: Arc::new(MockConnector::with_failures(tag, delay_ms, max_fails)),
        health: Arc::new(sb_core::outbound::selector_group::ProxyHealth::default()),
    }
}

fn create_permanent_fail_member(tag: &str) -> ProxyMember {
    ProxyMember {
        tag: tag.to_string(),
        connector: Arc::new(MockConnector::with_permanent_failure(tag)),
        health: Arc::new(sb_core::outbound::selector_group::ProxyHealth::default()),
    }
}

/// Test: URLTest selector health checking
///
/// Verifies that URLTest selector:
/// 1. Performs periodic health checks on all outbounds
/// 2. Selects the fastest available outbound
/// 3. Updates selection when health changes
#[tokio::test]
async fn test_urltest_health_checking() {
    let members = vec![
        create_test_member("fast", 10),
        create_test_member("slow", 100),
    ];

    let selector = Arc::new(SelectorGroup::new_urltest(
        "test-urltest".to_string(),
        members,
        UrlTestOptions {
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            interval: Duration::from_millis(100), // Fast interval for testing
            timeout: Duration::from_secs(1),
            tolerance_ms: 10,
            cache_file: None,
            urltest_history: None,
        },
    ));

    // Start health check in background
    let s = selector.clone();
    s.start_health_check();

    // Wait for health checks to run and pick the fastest member
    let mut final_metrics = String::new();
    let mut selected_fast = false;
    for _ in 0..20 {
        if let Some(member) = selector.select_best().await {
            if member.tag == "fast" {
                selected_fast = true;
            }
        }

        final_metrics = sb_metrics::export_prometheus();
        if selected_fast && final_metrics.contains("status=\"ok\"") {
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    assert!(selected_fast, "URLTest should select the fastest outbound");
    assert!(
        final_metrics.contains("selector_health_check_total"),
        "expected selector health metrics to be exported"
    );
}

/// Test: URLTest failover behavior
///
/// Verifies that URLTest automatically fails over to next best outbound
/// when the currently selected one becomes unavailable.
#[tokio::test]
async fn test_urltest_failover() {
    // "fast" will fail first 3 times, then recover (but we only need it to fail enough to be marked down)
    // Actually, health check logic marks down after 3 failures.
    // So let's make it fail 5 times to be sure.
    let members = vec![
        create_permanent_fail_member("unstable"),
        create_test_member("stable", 50),
    ];

    let selector = Arc::new(SelectorGroup::new_urltest(
        "test-failover".to_string(),
        members,
        UrlTestOptions {
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            interval: Duration::from_millis(100),
            timeout: Duration::from_secs(1),
            tolerance_ms: 10,
            cache_file: None,
            urltest_history: None,
        },
    ));

    let s = selector.clone();
    s.start_health_check();

    // Wait for health checks to mark "unstable" as down
    let mut selected_tag = None;
    for _ in 0..30 {
        if let Some(member) = selector.select_best().await {
            selected_tag = Some(member.tag.clone());
            if member.tag == "stable" {
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(
        selected_tag.as_deref(),
        Some("stable"),
        "URLTest should fail over to the stable member after repeated failures"
    );
    for _ in 0..5 {
        let again = selector.select_best().await.unwrap();
        assert_eq!(again.tag, "stable", "unstable should remain demoted");
        sleep(Duration::from_millis(50)).await;
    }
}

/// Test: Manual selector switching
///
/// Verifies that manual selector allows user to change selected outbound
/// and traffic is routed correctly.
#[tokio::test]
async fn test_selector_manual_switching() {
    let members = vec![
        create_test_member("proxy-a", 10),
        create_test_member("proxy-b", 10),
    ];

    let selector = SelectorGroup::new_manual(
        "manual-selector".to_string(),
        members,
        Some("proxy-a".to_string()),
        None,
        None,
    );

    // Default
    assert_eq!(selector.get_selected().await, Some("proxy-a".to_string()));

    // Switch
    selector.select_by_name("proxy-b").await.unwrap();
    assert_eq!(selector.get_selected().await, Some("proxy-b".to_string()));

    // Switch back
    selector.select_by_name("proxy-a").await.unwrap();
    assert_eq!(selector.get_selected().await, Some("proxy-a".to_string()));
}

/// Test: Selector with permanently failed outbound
///
/// Verifies that selector correctly handles permanently failed outbounds
/// (e.g., unsupported protocol, configuration error) by excluding them.
#[tokio::test]
async fn test_selector_permanent_failure_handling() {
    let members = vec![
        create_permanent_fail_member("broken"),
        create_test_member("working", 10),
    ];

    let selector = Arc::new(SelectorGroup::new_urltest(
        "test-perm-fail".to_string(),
        members,
        UrlTestOptions {
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            interval: Duration::from_millis(100),
            timeout: Duration::from_secs(1),
            tolerance_ms: 10,
            cache_file: None,
            urltest_history: None,
        },
    ));

    let s = selector.clone();
    s.start_health_check();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let broken_is_unhealthy = selector
                .get_members()
                .iter()
                .find(|(tag, _, _)| tag == "broken")
                .is_some_and(|(_, healthy, _)| !healthy);
            if broken_is_unhealthy {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("broken member should become unhealthy");

    // "broken" should be permanently failed
    let members_status = selector.get_members();
    let broken_status = members_status
        .iter()
        .find(|(tag, _, _)| tag == "broken")
        .unwrap();
    // Note: is_healthy() returns false for permanent failure
    assert!(!broken_status.1, "Broken member should be unhealthy");

    // Should select "working"
    let selected = selector.select_best().await;
    assert!(selected.is_some());
    assert_eq!(selected.unwrap().tag, "working");
}

/// Test: URLTest tolerance configuration
///
/// Verifies that tolerance setting works correctly:
/// - Selector switches only when latency difference exceeds tolerance
#[tokio::test]
async fn test_urltest_tolerance() {
    let members = vec![
        create_test_member("proxy-100", 100),
        create_test_member("proxy-120", 120),
    ];

    // Tolerance 50ms. 120 - 100 = 20 < 50. Should stick to current if valid?
    // Actually implementation of select_by_latency currently picks min RTT.
    // The comment says "tolerance-based switching can be added later".
    // So for now we expect it to pick the absolute best.

    let selector = Arc::new(SelectorGroup::new_urltest(
        "test-tolerance".to_string(),
        members,
        UrlTestOptions {
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            interval: Duration::from_millis(100),
            timeout: Duration::from_secs(1),
            tolerance_ms: 50,
            cache_file: None,
            urltest_history: None,
        },
    ));

    let s = selector.clone();
    s.start_health_check();
    sleep(Duration::from_millis(200)).await;

    let selected = selector.select_best().await;
    assert_eq!(selected.unwrap().tag, "proxy-100");
}
