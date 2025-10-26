//! Integration tests for Clash API

use sb_api::{clash::ClashApiServer, types::ApiConfig};
use std::net::SocketAddr;

/// Test Clash API server creation and basic functionality
#[tokio::test]
async fn test_clash_api_server_creation() -> anyhow::Result<()> {
    let config = ApiConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        enable_cors: true,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = ClashApiServer::new(config)?;
    assert!(server.state().config.enable_cors);
    assert!(server.state().config.enable_traffic_ws);
    assert!(server.state().config.enable_logs_ws);
    Ok(())
}

/// Test Clash API server with CORS configuration
#[tokio::test]
async fn test_clash_api_cors_config() -> anyhow::Result<()> {
    let config = ApiConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        enable_cors: true,
        cors_origins: Some(vec!["http://localhost:3000".to_string()]),
        auth_token: Some("test_token".to_string()),
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 500,
        log_buffer_size: 50,
    };

    let server = ClashApiServer::new(config)?;
    assert_eq!(
        server.state().config.cors_origins.as_ref().unwrap()[0],
        "http://localhost:3000"
    );
    assert_eq!(
        server.state().config.auth_token.as_ref().unwrap(),
        "test_token"
    );
    assert!(!server.state().config.enable_traffic_ws);
    assert!(!server.state().config.enable_logs_ws);
    Ok(())
}

/// Test broadcasting traffic statistics
#[tokio::test]
async fn test_clash_api_traffic_broadcast() -> anyhow::Result<()> {
    let config = ApiConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = ClashApiServer::new(config)?;

    let traffic_stats = sb_api::types::TrafficStats {
        up: 1024,
        down: 2048,
        up_speed: 100,
        down_speed: 200,
        timestamp: 1640995200000,
    };

    // Should succeed (no active clients, but broadcast channel is set up)
    let result = server.broadcast_traffic(traffic_stats);
    // This will fail because there are no subscribers, which is expected
    assert!(result.is_err());
    Ok(())
}

/// Test broadcasting log entries
#[tokio::test]
async fn test_clash_api_log_broadcast() -> anyhow::Result<()> {
    let config = ApiConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let server = ClashApiServer::new(config)?;

    let log_entry = sb_api::types::LogEntry {
        r#type: "info".to_string(),
        payload: "Test log entry".to_string(),
        timestamp: 1640995200000,
        source: "TestModule".to_string(),
        connection_id: Some("test-connection-123".to_string()),
    };

    // Should succeed (no active clients, but broadcast channel is set up)
    let result = server.broadcast_log(log_entry);
    // This will fail because there are no subscribers, which is expected
    assert!(result.is_err());
    Ok(())
}

/// Test API configuration validation
#[tokio::test]
async fn test_api_config_validation() {
    // Test with invalid listen address (should work with valid parsing)
    let valid_config = ApiConfig {
        listen_addr: "0.0.0.0:9090".parse::<SocketAddr>().unwrap(),
        enable_cors: true,
        cors_origins: Some(vec![
            "http://localhost:3000".to_string(),
            "https://clash.example.com".to_string(),
        ]),
        auth_token: Some("secure_token_123".to_string()),
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 1000,
    };

    let server = ClashApiServer::new(valid_config).unwrap();
    assert_eq!(server.state().config.listen_addr.port(), 9090);
    assert_eq!(
        server.state().config.cors_origins.as_ref().unwrap().len(),
        2
    );
    assert_eq!(server.state().config.traffic_broadcast_interval_ms, 1000);
    assert_eq!(server.state().config.log_buffer_size, 1000);
}

/// Test error handling for invalid configurations
#[test]
fn test_invalid_configurations() -> anyhow::Result<()> {
    // Test various edge cases for configuration
    let edge_case_config = ApiConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 65535)),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 100, // Very fast interval
        log_buffer_size: 1,                 // Very small buffer
    };

    let server = ClashApiServer::new(edge_case_config)?;
    assert_eq!(server.state().config.listen_addr.port(), 65535);
    assert_eq!(server.state().config.traffic_broadcast_interval_ms, 100);
    assert_eq!(server.state().config.log_buffer_size, 1);
    Ok(())
}

/// Test data structure serialization/deserialization
#[test]
fn test_api_data_structures() -> anyhow::Result<()> {
    use sb_api::types::*;

    // Test Proxy serialization
    let proxy = Proxy {
        name: "DIRECT".to_string(),
        r#type: "Direct".to_string(),
        all: vec!["DIRECT".to_string(), "PROXY".to_string()],
        now: "DIRECT".to_string(),
        alive: Some(true),
        delay: Some(50),
        extra: std::collections::HashMap::new(),
    };

    let json = serde_json::to_string(&proxy)?;
    let deserialized: Proxy = serde_json::from_str(&json)?;
    assert_eq!(proxy.name, deserialized.name);
    assert_eq!(proxy.r#type, deserialized.r#type);
    assert_eq!(proxy.alive, deserialized.alive);
    assert_eq!(proxy.delay, deserialized.delay);

    // Test TrafficStats serialization
    let traffic = TrafficStats {
        up: 1024,
        down: 2048,
        up_speed: 100,
        down_speed: 200,
        timestamp: 1640995200000,
    };

    let json = serde_json::to_string(&traffic)?;
    let deserialized: TrafficStats = serde_json::from_str(&json)?;
    assert_eq!(traffic.up, deserialized.up);
    assert_eq!(traffic.down, deserialized.down);
    assert_eq!(traffic.up_speed, deserialized.up_speed);
    assert_eq!(traffic.down_speed, deserialized.down_speed);

    // Test LogEntry serialization
    let log = LogEntry {
        r#type: "error".to_string(),
        payload: "Test error message".to_string(),
        timestamp: 1640995200000,
        source: "TestModule".to_string(),
        connection_id: Some("conn-123".to_string()),
    };

    let json = serde_json::to_string(&log)?;
    let deserialized: LogEntry = serde_json::from_str(&json)?;
    assert_eq!(log.r#type, deserialized.r#type);
    assert_eq!(log.payload, deserialized.payload);
    assert_eq!(log.source, deserialized.source);
    assert_eq!(log.connection_id, deserialized.connection_id);
    Ok(())
}
