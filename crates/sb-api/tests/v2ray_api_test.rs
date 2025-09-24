//! Integration tests for V2Ray API

use sb_api::{types::ApiConfig, v2ray::SimpleV2RayApiServer};
use std::net::SocketAddr;

/// Test V2Ray API server creation and basic functionality
#[tokio::test]
async fn test_v2ray_api_server_creation() {
    let config = ApiConfig {
        listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = SimpleV2RayApiServer::new(config).unwrap();
    let stats = server.get_all_stats().await;

    // Should have initial stats
    assert!(!stats.is_empty());
    assert!(stats.contains_key("inbound>>>api>>>traffic>>>uplink"));
    assert!(stats.contains_key("inbound>>>api>>>traffic>>>downlink"));
    assert!(stats.contains_key("outbound>>>direct>>>traffic>>>uplink"));
    assert!(stats.contains_key("outbound>>>direct>>>traffic>>>downlink"));
}

/// Test V2Ray API stats operations
#[tokio::test]
async fn test_v2ray_api_stats_operations() {
    let config = ApiConfig {
        listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = SimpleV2RayApiServer::new(config).unwrap();

    // Test getting stats for an existing counter
    let request = sb_api::v2ray::simple::SimpleStatsRequest {
        name: "inbound>>>api>>>traffic>>>uplink".to_string(),
        reset: false,
    };

    let response = server.get_stats(request).await.unwrap();
    assert_eq!(response.stat.name, "inbound>>>api>>>traffic>>>uplink");
    assert_eq!(response.stat.value, 0);

    // Test updating traffic stats
    server
        .update_traffic("inbound>>>api>>>traffic>>>uplink", 2048)
        .await;

    let request = sb_api::v2ray::simple::SimpleStatsRequest {
        name: "inbound>>>api>>>traffic>>>uplink".to_string(),
        reset: false,
    };

    let response = server.get_stats(request).await.unwrap();
    assert_eq!(response.stat.value, 2048);

    // Test getting stats for a non-existent counter
    let request = sb_api::v2ray::simple::SimpleStatsRequest {
        name: "non_existent_counter".to_string(),
        reset: false,
    };

    let response = server.get_stats(request).await.unwrap();
    assert_eq!(response.stat.name, "non_existent_counter");
    assert_eq!(response.stat.value, 0);
}

/// Test V2Ray API query stats functionality
#[tokio::test]
async fn test_v2ray_api_query_stats() {
    let config = ApiConfig {
        listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = SimpleV2RayApiServer::new(config).unwrap();

    // Update some stats first
    server
        .update_traffic("inbound>>>api>>>traffic>>>uplink", 1024)
        .await;
    server
        .update_traffic("outbound>>>direct>>>traffic>>>downlink", 4096)
        .await;

    // Test querying all stats (empty pattern)
    let request = sb_api::v2ray::simple::SimpleQueryStatsRequest {
        pattern: "".to_string(),
        reset: false,
    };

    let response = server.query_stats(request).await.unwrap();
    assert!(response.stats.len() >= 4);

    // Verify that our updated stats are included
    let uplink_stat = response
        .stats
        .iter()
        .find(|s| s.name == "inbound>>>api>>>traffic>>>uplink")
        .unwrap();
    assert_eq!(uplink_stat.value, 1024);

    let downlink_stat = response
        .stats
        .iter()
        .find(|s| s.name == "outbound>>>direct>>>traffic>>>downlink")
        .unwrap();
    assert_eq!(downlink_stat.value, 4096);

    // Test querying with pattern matching
    let request = sb_api::v2ray::simple::SimpleQueryStatsRequest {
        pattern: "inbound".to_string(),
        reset: false,
    };

    let response = server.query_stats(request).await.unwrap();
    assert!(response.stats.len() >= 1);

    // All returned stats should contain "inbound" in the name
    for stat in &response.stats {
        assert!(
            stat.name.contains("inbound"),
            "Stat '{}' should contain 'inbound'",
            stat.name
        );
    }

    // Test querying with specific pattern
    let request = sb_api::v2ray::simple::SimpleQueryStatsRequest {
        pattern: "outbound>>>direct".to_string(),
        reset: false,
    };

    let response = server.query_stats(request).await.unwrap();
    assert!(response.stats.len() >= 2); // Should match both uplink and downlink

    for stat in &response.stats {
        assert!(
            stat.name.contains("outbound>>>direct"),
            "Stat '{}' should contain 'outbound>>>direct'",
            stat.name
        );
    }
}

/// Test V2Ray API stats subscription
#[tokio::test]
async fn test_v2ray_api_stats_subscription() {
    let config = ApiConfig {
        listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = SimpleV2RayApiServer::new(config).unwrap();
    let mut rx = server.subscribe_stats();

    // Update stats and verify broadcast
    server.update_traffic("test_counter_broadcast", 512).await;

    let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;

    assert!(received.is_ok(), "Should receive stats update");
    let stat = received.unwrap().unwrap();
    assert_eq!(stat.name, "test_counter_broadcast");
    assert_eq!(stat.value, 512);

    // Test multiple updates
    server.update_traffic("test_counter_broadcast", 256).await;

    let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;

    assert!(received.is_ok(), "Should receive second stats update");
    let stat = received.unwrap().unwrap();
    assert_eq!(stat.name, "test_counter_broadcast");
    assert_eq!(stat.value, 768); // 512 + 256
}

/// Test V2Ray API server startup
#[tokio::test]
async fn test_v2ray_api_server_startup() {
    let config = ApiConfig {
        listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 100, // Fast interval for testing
        log_buffer_size: 100,
    };

    let server = SimpleV2RayApiServer::new(config).unwrap();

    // Start server (this should complete without blocking)
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), server.start()).await;

    assert!(result.is_ok(), "Server should start successfully");
    assert!(result.unwrap().is_ok(), "Server start should return Ok");

    // Wait a bit for the background task to update stats
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Verify that the background task is updating stats
    let stats = server.get_all_stats().await;
    let downlink_value = stats
        .get("inbound>>>api>>>traffic>>>downlink")
        .copied()
        .unwrap_or(0);

    // The background task should have updated this value
    assert!(
        downlink_value > 0,
        "Background task should have updated stats"
    );
}

/// Test V2Ray API error handling
#[tokio::test]
async fn test_v2ray_api_error_handling() {
    let config = ApiConfig {
        listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = SimpleV2RayApiServer::new(config).unwrap();

    // Test with various counter names to ensure robustness
    let test_cases = vec![
        "",
        "very_long_counter_name_that_exceeds_normal_length_but_should_still_work",
        "counter with spaces",
        "counter/with/slashes",
        "counter>>>with>>>arrows",
        "counter.with.dots",
        "пириӄы",    // Unicode characters
        "🚀counter", // Emoji characters
    ];

    for counter_name in test_cases {
        // Test getting stats
        let request = sb_api::v2ray::simple::SimpleStatsRequest {
            name: counter_name.to_string(),
            reset: false,
        };

        let result = server.get_stats(request).await;
        assert!(
            result.is_ok(),
            "Getting stats should not fail for counter '{}'",
            counter_name
        );

        // Test updating stats
        let result = server.update_traffic(counter_name, 100).await;
        // update_traffic doesn't return a result, but it shouldn't panic

        // Verify the update worked
        let request = sb_api::v2ray::simple::SimpleStatsRequest {
            name: counter_name.to_string(),
            reset: false,
        };

        let response = server.get_stats(request).await.unwrap();
        assert_eq!(
            response.stat.value, 100,
            "Stats should be updated for counter '{}'",
            counter_name
        );
    }
}
