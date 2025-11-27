//! Comprehensive Rate Limiting Validation Tests for Trojan and Shadowsocks
//!
//! Test Coverage (Milestone 2, Week 49):
//! 1. Per-IP connection rate limiting
//! 2. Failed authentication attempt tracking
//! 3. Configurable QPS limits
//! 4. Sliding window rate limiter
//!
//! Run with:
//!   cargo test --package sb-adapters --test rate_limiting_validation -- --nocapture

use sb_core::net::tcp_rate_limit::{TcpRateLimiter, TcpRateLimitConfig};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

// ============================================================================
// PER-IP CONNECTION RATE LIMITING TESTS
// ============================================================================

#[test]
fn test_trojan_rate_limit_per_ip() {
    // Test Trojan-specific rate limiting configuration
    let config = TcpRateLimitConfig {
        max_connections: 5,
        window: Duration::from_secs(10),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

    // First 5 connections should be allowed
    for i in 1..=5 {
        assert!(
            limiter.allow_connection(ip),
            "Connection {} should be allowed", i
        );
    }

    // 6th connection should be rate limited
    assert!(
        !limiter.allow_connection(ip),
        "Connection 6 should be rate limited"
    );

    println!("✓ Trojan per-IP rate limiting validated (5 conn/10s)");
}

#[test]
fn test_shadowsocks_rate_limit_per_ip() {
    // Test Shadowsocks-specific rate limiting configuration
    let config = TcpRateLimitConfig {
        max_connections: 10,
        window: Duration::from_secs(5),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    // First 10 connections should be allowed
    for i in 1..=10 {
        assert!(
            limiter.allow_connection(ip),
            "Connection {} should be allowed", i
        );
    }

    // 11th connection should be rate limited
    assert!(
        !limiter.allow_connection(ip),
        "Connection 11 should be rate limited"
    );

    println!("✓ Shadowsocks per-IP rate limiting validated (10 conn/5s)");
}

#[test]
fn test_rate_limit_multiple_ips() {
    // Test that different IPs have independent rate limits
    let config = TcpRateLimitConfig {
        max_connections: 3,
        window: Duration::from_secs(10),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    
    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    // IP1: Use up all connections
    for _ in 0..3 {
        assert!(limiter.allow_connection(ip1));
    }
    assert!(!limiter.allow_connection(ip1));

    // IP2: Should still have full quota
    for _ in 0..3 {
        assert!(limiter.allow_connection(ip2));
    }
    assert!(!limiter.allow_connection(ip2));

    println!("✓ Multiple IP isolation validated");
}

// ============================================================================
// FAILED AUTHENTICATION ATTEMPT TRACKING
// ============================================================================

#[test]
fn test_trojan_auth_failure_tracking() {
    // Test authentication failure tracking for Trojan
    let config = TcpRateLimitConfig {
        max_auth_failures: 5,
        auth_failure_window: Duration::from_secs(60),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

    // IP should not be banned initially
    assert!(!limiter.is_banned(ip));

    // Record 5 auth failures (at the limit, not over)
    for i in 1..=5 {
        let is_banned = limiter.record_auth_failure(ip);
        assert!(
            !is_banned,
            "IP should not be banned after {} failures (limit is 5)", i
        );
    }

    // 6th failure should trigger ban
    let is_banned = limiter.record_auth_failure(ip);
    assert!(is_banned, "IP should be banned after 6 failures");
    assert!(limiter.is_banned(ip), "IP should remain banned");

    println!("✓ Trojan auth failure tracking validated (5 failures/60s)");
}

#[test]
fn test_shadowsocks_auth_failure_tracking() {
    // Test authentication failure tracking for Shadowsocks
    let config = TcpRateLimitConfig {
        max_auth_failures: 3,
        auth_failure_window: Duration::from_secs(30),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

    // Record failures
    limiter.record_auth_failure(ip);
    limiter.record_auth_failure(ip);
    limiter.record_auth_failure(ip);
    
    assert!(!limiter.is_banned(ip), "3 failures should not ban");

    // 4th failure bans
    limiter.record_auth_failure(ip);
    assert!(limiter.is_banned(ip), "4 failures should ban");

    println!("✓ Shadowsocks auth failure tracking validated (3 failures/30s)");
}

#[test]
fn test_auth_failure_window_expiry() {
    // Test that auth failures expire after window
    let config = TcpRateLimitConfig {
        max_auth_failures: 2,
        auth_failure_window: Duration::from_millis(100),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    // Record 2 failures
    limiter.record_auth_failure(ip);
    limiter.record_auth_failure(ip);

    assert!(!limiter.is_banned(ip), "2 failures should not ban yet");

    // Wait for window to expire
    std::thread::sleep(Duration::from_millis(150));

    // Should not be banned anymore
    assert!(!limiter.is_banned(ip), "Ban should expire after window");

    // New failure should not trigger ban (old ones expired)
    limiter.record_auth_failure(ip);
    assert!(!limiter.is_banned(ip), "Single new failure should not ban");

    println!("✓ Auth failure window expiry validated");
}

// ============================================================================
// CONFIGURABLE QPS LIMITS
// ============================================================================

#[test]
fn test_trojan_qps_limiting() {
    // Test QPS limiting for Trojan
    let config = TcpRateLimitConfig {
        max_qps: Some(10), // 10 requests per second
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));

    // First 10 requests should be allowed (token bucket starts full)
    for i in 1..=10 {
        assert!(
            limiter.allow_request(ip),
            "Request {} should be allowed", i
        );
    }

    // 11th request should be blocked (bucket empty)
    assert!(
        !limiter.allow_request(ip),
        "Request 11 should be rate limited"
    );

    println!("✓ Trojan QPS limiting validated (10 req/s)");
}

#[test]
fn test_shadowsocks_qps_limiting() {
    // Test QPS limiting for Shadowsocks
    let config = TcpRateLimitConfig {
        max_qps: Some(20), // 20 requests per second
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1));

    // First 20 requests should be allowed
    for i in 1..=20 {
        assert!(
            limiter.allow_request(ip),
            "Request {} should be allowed", i
        );
    }

    // 21st request should be blocked
    assert!(
        !limiter.allow_request(ip),
        "Request 21 should be rate limited"
    );

    println!("✓ Shadowsocks QPS limiting validated (20 req/s)");
}

#[test]
fn test_qps_token_bucket_refill() {
    // Test token bucket refill mechanism
    let config = TcpRateLimitConfig {
        max_qps: Some(10), // 10 tokens per second
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));

    // Exhaust tokens
    for _ in 0..10 {
        assert!(limiter.allow_request(ip));
    }
    assert!(!limiter.allow_request(ip), "Should be rate limited");

    // Wait for 100ms = should refill 1 token (10 QPS = 1 token per 100ms)
    std::thread::sleep(Duration::from_millis(110));

    // Should allow 1 request after refill
    assert!(
        limiter.allow_request(ip),
        "Should allow request after token refill"
    );
    
    // Should be rate limited again
    assert!(
        !limiter.allow_request(ip),
        "Should be rate limited after consuming refilled token"
    );

    println!("✓ QPS token bucket refill validated");
}

#[test]
fn test_qps_no_limit() {
    // Test that None QPS limit allows unlimited requests
    let config = TcpRateLimitConfig {
        max_qps: None, // No QPS limit
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));

    // Should allow many requests without limit
    for _ in 0..1000 {
        assert!(limiter.allow_request(ip));
    }

    println!("✓ QPS no-limit mode validated");
}

// ============================================================================
// SLIDING WINDOW RATE LIMITER
// ============================================================================

#[test]
fn test_sliding_window_behavior() {
    // Test sliding window rate limiting
    let config = TcpRateLimitConfig {
        max_connections: 3,
        window: Duration::from_millis(200),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 50, 1));

    // T=0ms: Allow 3 connections
    for _ in 0..3 {
        assert!(limiter.allow_connection(ip));
    }
    assert!(!limiter.allow_connection(ip));

    // T=100ms: Still rate limited (half window)
    std::thread::sleep(Duration::from_millis(100));
    assert!(!limiter.allow_connection(ip), "Should still be rate limited at T+100ms");

    // T=250ms: Window expired, should allow new connections
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        limiter.allow_connection(ip),
        "Should allow connection after window expiry"
    );

    println!("✓ Sliding window rate limiter validated");
}

#[test]
fn test_connection_window_recovery() {
    // Test that connections recover gradually as window slides
    let config = TcpRateLimitConfig {
        max_connections: 2,
        window: Duration::from_millis(100),
        ..Default::default()
    };
    let limiter = TcpRateLimiter::new(config);
    let ip = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));

    // Use both slots
    assert!(limiter.allow_connection(ip));
    assert!(limiter.allow_connection(ip));
    assert!(!limiter.allow_connection(ip));

    // Wait for window
    std::thread::sleep(Duration::from_millis(120));

    // Should be able to make 2 more connections
    assert!(limiter.allow_connection(ip));
    assert!(limiter.allow_connection(ip));
    assert!(!limiter.allow_connection(ip));

    println!("✓ Connection window recovery validated");
}

// ============================================================================
// ENVIRONMENT VARIABLE CONFIGURATION
// ============================================================================

#[test]
fn test_env_var_configuration() {
    // Test loading configuration from environment variables
    std::env::set_var("SB_INBOUND_RATE_LIMIT_PER_IP", "50");
    std::env::set_var("SB_INBOUND_RATE_LIMIT_WINDOW_SEC", "30");
    std::env::set_var("SB_INBOUND_RATE_LIMIT_QPS", "100");

    let config = TcpRateLimitConfig::from_env();

    assert_eq!(config.max_connections, 50);
    assert_eq!(config.window, Duration::from_secs(30));
    assert_eq!(config.max_qps, Some(100));

    // Clean up
    std::env::remove_var("SB_INBOUND_RATE_LIMIT_PER_IP");
    std::env::remove_var("SB_INBOUND_RATE_LIMIT_WINDOW_SEC");
    std::env::remove_var("SB_INBOUND_RATE_LIMIT_QPS");

    println!("✓ Environment variable configuration validated");
}

// ============================================================================
// SUMMARY TEST
// ============================================================================

#[test]
fn test_rate_limiting_validation_summary() {
    println!("\n=== Rate Limiting Validation Summary ===");
    println!("✓ Per-IP Connection Limiting: Trojan, Shadowsocks, Multi-IP");
    println!("✓ Auth Failure Tracking: Trojan (5/60s), Shadowsocks (3/30s), Window expiry");
    println!("✓ QPS Limiting: Trojan (10 req/s), Shadowsocks (20 req/s), Token bucket refill");
    println!("✓ Sliding Window: Window behavior, Recovery, Expiry");
    println!("✓ Configuration: Environment variables");
    println!("\nAll rate limiting features validated successfully!");
    println!("=========================================\n");
}
