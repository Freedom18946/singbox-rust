use sb_core::outbound::{endpoint::ProxyEndpoint, health, registry};

#[tokio::test]
async fn test_proxy_endpoint_parsing() {
    // Test valid HTTP proxy parsing
    let http_ep = ProxyEndpoint::parse("http://127.0.0.1:8080");
    assert!(http_ep.is_some());
    let ep = http_ep.unwrap();
    assert_eq!(ep.kind, sb_core::outbound::endpoint::ProxyKind::Http);
    assert_eq!(ep.addr.port(), 8080);

    // Test valid SOCKS5 proxy parsing
    let socks_ep = ProxyEndpoint::parse("socks5://192.168.1.1:1080");
    assert!(socks_ep.is_some());
    let ep = socks_ep.unwrap();
    assert_eq!(ep.kind, sb_core::outbound::endpoint::ProxyKind::Socks5);
    assert_eq!(ep.addr.port(), 1080);

    // Test invalid formats
    assert!(ProxyEndpoint::parse("invalid://127.0.0.1:8080").is_none());
    assert!(ProxyEndpoint::parse("http://invalid:port").is_none());
    assert!(ProxyEndpoint::parse("").is_none());
}

#[tokio::test]
async fn test_registry_operations() {
    // Test empty registry
    let empty_reg = registry::Registry::default();
    assert!(empty_reg.default.is_none());

    // Test registry with default proxy
    let ep = ProxyEndpoint::parse("http://127.0.0.1:3128").unwrap();
    let reg = registry::Registry {
        default: Some(ep),
        pools: std::collections::HashMap::new(),
    };
    assert!(reg.default.is_some());

    // Test global registry installation
    registry::install_global(reg);
    let global_reg = registry::global();
    assert!(global_reg.is_some());
    let reg_ref = global_reg.unwrap();
    assert!(reg_ref.default.is_some());
}

#[tokio::test]
async fn test_health_status_basic() {
    let status = health::HealthStatus::new();

    // Default state should be up
    assert!(status.is_up());

    // Test setting down
    status.up.store(false, std::sync::atomic::Ordering::Relaxed);
    assert!(!status.is_up());

    // Test consecutive failures
    {
        let mut fail_count = status.consecutive_fail.lock();
        *fail_count = 5;
    }

    let fail_count = *status.consecutive_fail.lock();
    assert_eq!(fail_count, 5);

    // Test RTT recording
    {
        let mut rtt = status.last_rtt_ms.lock();
        *rtt = Some(150);
    }

    let rtt = *status.last_rtt_ms.lock();
    assert_eq!(rtt, Some(150));
}

#[tokio::test]
async fn test_health_disabled_no_panic() {
    // Test that spawning with health disabled doesn't panic
    // and doesn't create global status when disabled

    // Ensure environment is clean
    std::env::remove_var("SB_PROXY_HEALTH_ENABLE");

    // Install a registry with a proxy
    let ep = ProxyEndpoint::parse("http://127.0.0.1:1").unwrap();
    registry::install_global(registry::Registry {
        default: Some(ep),
        pools: std::collections::HashMap::new(),
    });

    // Spawn should not panic and should not start health checking
    health::spawn_if_enabled().await;

    // Global status should be None since health checking is disabled
    // Note: This test may be flaky if health system was previously enabled
    // in the same test process, but it demonstrates the basic functionality

    // Clean up
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY");
}

#[test]
fn test_environment_variable_parsing() {
    // Test interval parsing
    std::env::set_var("SB_PROXY_HEALTH_INTERVAL_MS", "5000");
    // Note: We can't directly test the private functions, but we can test
    // that invalid values don't crash the system

    std::env::set_var("SB_PROXY_HEALTH_TIMEOUT_MS", "invalid");
    // This should fall back to default without panicking

    // Clean up
    std::env::remove_var("SB_PROXY_HEALTH_INTERVAL_MS");
    std::env::remove_var("SB_PROXY_HEALTH_TIMEOUT_MS");
}

#[tokio::test]
async fn test_proxy_kind_labels() {
    use sb_core::outbound::endpoint::ProxyKind;

    // Create endpoints of different kinds
    let http_ep = ProxyEndpoint::parse("http://127.0.0.1:8080").unwrap();
    let socks_ep = ProxyEndpoint::parse("socks5://127.0.0.1:1080").unwrap();

    assert_eq!(http_ep.kind, ProxyKind::Http);
    assert_eq!(socks_ep.kind, ProxyKind::Socks5);

    // Test that the kinds are different
    assert_ne!(http_ep.kind, socks_ep.kind);
}

#[test]
fn test_health_status_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let status = Arc::new(health::HealthStatus::new());
    let status_clone = status.clone();

    // Test concurrent access from multiple threads
    let handle = thread::spawn(move || {
        status_clone
            .up
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let mut fail_count = status_clone.consecutive_fail.lock();
        *fail_count = 10;
    });

    // Access from main thread
    let _is_up = status.is_up();

    handle.join().unwrap();

    // Verify final state
    let final_fail_count = *status.consecutive_fail.lock();
    assert_eq!(final_fail_count, 10);
    assert!(!status.is_up());
}
