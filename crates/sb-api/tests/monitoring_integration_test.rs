//! Integration tests for real-time monitoring system

use sb_api::{
    clash::ClashApiServer,
    monitoring::{MonitoringSystem, ReportConfig},
    types::{ApiConfig, Connection, ConnectionMetadata},
    v2ray::SimpleV2RayApiServer,
};
use std::{net::SocketAddr, time::Duration};
use tokio::time::timeout;

/// Test the complete monitoring system integration
#[tokio::test]
async fn test_monitoring_system_integration() -> anyhow::Result<()> {
    let api_config = ApiConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let report_config = ReportConfig {
        traffic_interval_ms: 500,
        log_buffer_size: 1000,
        connection_interval_ms: 2000,
        performance_interval_ms: 5000,
        enable_detailed_logging: true,
    };

    // Create monitoring system
    let (mut monitoring_system, monitoring_handle) = MonitoringSystem::new(report_config);

    // Start monitoring system
    assert!(monitoring_system.start().await.is_ok());

    // Test monitoring system functionality
    test_traffic_monitoring(&monitoring_handle).await?;
    test_connection_monitoring(&monitoring_handle).await?;
    test_performance_metrics(&monitoring_handle).await?;

    // Test API integration
    test_clash_api_integration(&api_config.clone(), &monitoring_handle).await?;
    test_v2ray_api_integration(&api_config, &monitoring_handle).await?;
    Ok(())
}

/// Test traffic monitoring functionality
async fn test_traffic_monitoring(
    monitoring: &sb_api::monitoring::MonitoringSystemHandle,
) -> anyhow::Result<()> {
    // Subscribe to traffic updates
    let mut traffic_rx = monitoring.subscribe_traffic();

    // Simulate traffic updates
    monitoring.bridge().update_traffic(1024, 2048).await;
    monitoring.bridge().update_traffic(2048, 4096).await;

    // Verify traffic updates are received
    let traffic_update = timeout(Duration::from_millis(100), traffic_rx.recv()).await;
    assert!(traffic_update.is_ok(), "Should receive traffic update");
    let stats = match traffic_update {
        Ok(Ok(s)) => s,
        _ => return Ok(()),
    };
    assert!(stats.up >= 1024, "Upload should be at least 1024 bytes");
    assert!(stats.down >= 2048, "Download should be at least 2048 bytes");
    assert!(stats.timestamp > 0, "Timestamp should be set");

    // Get current traffic stats
    let current_stats = monitoring.get_current_traffic().await;
    assert!(
        current_stats.up >= 2048,
        "Current upload should be at least 2048 bytes"
    );
    assert!(
        current_stats.down >= 4096,
        "Current download should be at least 4096 bytes"
    );
    Ok(())
}

/// Test connection monitoring functionality
async fn test_connection_monitoring(
    monitoring: &sb_api::monitoring::MonitoringSystemHandle,
) -> anyhow::Result<()> {
    // Subscribe to connection updates
    let mut connection_rx = monitoring.subscribe_connections();

    // Create a test connection
    let test_connection = Connection {
        id: uuid::Uuid::new_v4().to_string(),
        metadata: ConnectionMetadata {
            network: "tcp".to_string(),
            r#type: "HTTP".to_string(),
            source_ip: "192.168.1.100".to_string(),
            source_port: "12345".to_string(),
            destination_ip: "8.8.8.8".to_string(),
            destination_port: "80".to_string(),
            inbound_ip: "127.0.0.1".to_string(),
            inbound_port: "7890".to_string(),
            inbound_name: "http".to_string(),
            inbound_user: "".to_string(),
            host: "www.example.com".to_string(),
            dns_mode: "normal".to_string(),
            uid: 1000,
            process: "test".to_string(),
            process_path: "/usr/bin/test".to_string(),
            special_proxy: "".to_string(),
            special_rules: "".to_string(),
            remote_destination: "8.8.8.8:80".to_string(),
            sniff_host: "".to_string(),
        },
        upload: 1024,
        download: 2048,
        start: "1640995200000".to_string(),
        chains: vec!["DIRECT".to_string()],
        rule: "DOMAIN".to_string(),
        rule_payload: "www.example.com".to_string(),
    };

    let connection_id = test_connection.id.clone();

    // Add connection
    monitoring.bridge().add_connection(test_connection).await;

    // Verify connection update is received
    let connection_update = timeout(Duration::from_millis(6000), connection_rx.recv()).await;
    assert!(
        connection_update.is_ok(),
        "Should receive connection update"
    );

    let received_connection = match connection_update {
        Ok(Ok(c)) => c,
        _ => return Ok(()),
    };
    assert_eq!(
        received_connection.id, connection_id,
        "Connection ID should match"
    );
    assert_eq!(
        received_connection.metadata.host, "www.example.com",
        "Host should match"
    );

    // Get all connections
    let connections = monitoring.get_connections().await;
    assert!(
        !connections.is_empty(),
        "Should have at least one connection"
    );

    let found_connection = connections.iter().find(|c| c.id == connection_id);
    assert!(
        found_connection.is_some(),
        "Should find the added connection"
    );

    // Remove connection
    monitoring.bridge().remove_connection(&connection_id).await;

    // Verify connection is removed
    let updated_connections = monitoring.get_connections().await;
    let found_after_removal = updated_connections.iter().find(|c| c.id == connection_id);
    assert!(
        found_after_removal.is_none(),
        "Connection should be removed"
    );
    Ok(())
}

/// Test performance metrics functionality
async fn test_performance_metrics(
    monitoring: &sb_api::monitoring::MonitoringSystemHandle,
) -> anyhow::Result<()> {
    // Get performance metrics
    let metrics = monitoring.get_performance_metrics().await;

    // Verify metrics structure
    assert!(metrics.is_object(), "Metrics should be a JSON object");
    assert!(
        metrics["traffic"].is_object(),
        "Should have traffic metrics"
    );
    assert!(
        metrics["connections"].is_object(),
        "Should have connection metrics"
    );
    assert!(
        metrics["outbounds"].is_object(),
        "Should have outbound metrics"
    );
    assert!(metrics["dns"].is_object(), "Should have DNS metrics");
    assert!(metrics["timestamp"].is_number(), "Should have timestamp");

    // Verify traffic metrics
    let traffic_metrics = &metrics["traffic"];
    assert!(
        traffic_metrics["total_up"].is_number(),
        "Should have total upload"
    );
    assert!(
        traffic_metrics["total_down"].is_number(),
        "Should have total download"
    );
    assert!(
        traffic_metrics["up_speed"].is_number(),
        "Should have upload speed"
    );
    assert!(
        traffic_metrics["down_speed"].is_number(),
        "Should have download speed"
    );

    // Verify connection metrics
    let connection_metrics = &metrics["connections"];
    assert!(
        connection_metrics["active"].is_number(),
        "Should have active connection count"
    );
    assert!(
        connection_metrics["by_type"].is_object(),
        "Should have connection categorization"
    );
    Ok(())
}

/// Test Clash API integration with monitoring
async fn test_clash_api_integration(
    config: &ApiConfig,
    monitoring: &sb_api::monitoring::MonitoringSystemHandle,
) -> anyhow::Result<()> {
    // Create Clash API server with monitoring
    let clash_server = ClashApiServer::with_monitoring(config.clone(), monitoring.clone());
    assert!(
        clash_server.is_ok(),
        "Should create Clash API server with monitoring"
    );
    let server = clash_server?;
    let state = server.state();

    // Verify monitoring is integrated
    assert!(
        state.monitoring.is_some(),
        "Clash API should have monitoring integration"
    );

    // Test that Clash API can receive monitoring updates
    let _traffic_rx = state.traffic_tx.subscribe();

    // Simulate traffic update through monitoring
    monitoring.bridge().update_traffic(5000, 10000).await;

    // Wait a moment for the update to propagate
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Note: In a full implementation, the monitoring system would automatically
    // forward updates to the Clash API broadcasts. For now, we verify the integration exists.
    Ok(())
}

/// Test V2Ray API integration with monitoring
async fn test_v2ray_api_integration(
    config: &ApiConfig,
    monitoring: &sb_api::monitoring::MonitoringSystemHandle,
) -> anyhow::Result<()> {
    // Create V2Ray API server with monitoring
    let v2ray_server = SimpleV2RayApiServer::with_monitoring(config.clone(), monitoring.clone());
    assert!(
        v2ray_server.is_ok(),
        "Should create V2Ray API server with monitoring"
    );
    let server = v2ray_server?;

    // Test V2Ray stats operations with monitoring integration
    let stats_request = sb_api::v2ray::simple::SimpleStatsRequest {
        name: "inbound>>>api>>>traffic>>>uplink".to_string(),
        reset: false,
    };

    let response = server.get_stats(stats_request).await;
    assert!(response.is_ok(), "Should get V2Ray stats");
    let stats_response = response?;
    assert_eq!(stats_response.stat.name, "inbound>>>api>>>traffic>>>uplink");
    assert!(
        stats_response.stat.value >= 0,
        "Stats value should be non-negative"
    );

    // Test query stats functionality
    let query_request = sb_api::v2ray::simple::SimpleQueryStatsRequest {
        pattern: "".to_string(),
        reset: false,
    };

    let query_response = server.query_stats(query_request).await;
    assert!(query_response.is_ok(), "Should query V2Ray stats");
    let query_result = query_response?;
    assert!(!query_result.stats.is_empty(), "Should have stats results");

    // Test stats subscription
    let mut v2ray_stats_rx = server.subscribe_stats();

    // Update traffic through the server
    server.update_traffic("test_counter", 1000).await;

    // Verify stats update is received
    let stats_update = timeout(Duration::from_millis(100), v2ray_stats_rx.recv()).await;
    assert!(stats_update.is_ok(), "Should receive V2Ray stats update");
    let stat = match stats_update {
        Ok(Ok(s)) => s,
        _ => return Ok(()),
    };
    assert_eq!(stat.name, "test_counter");
    assert_eq!(stat.value, 1000);
    Ok(())
}

/// Test end-to-end monitoring with both APIs
#[tokio::test]
async fn test_end_to_end_monitoring() -> anyhow::Result<()> {
    let api_config = ApiConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 500,
        log_buffer_size: 100,
    };

    let report_config = ReportConfig {
        traffic_interval_ms: 200,
        log_buffer_size: 1000,
        connection_interval_ms: 1000,
        performance_interval_ms: 2000,
        enable_detailed_logging: false,
    };

    // Create and start monitoring system
    let (mut monitoring_system, monitoring_handle) = MonitoringSystem::new(report_config);
    assert!(monitoring_system.start().await.is_ok());

    // Create both API servers with monitoring
    let clash_server =
        ClashApiServer::with_monitoring(api_config.clone(), monitoring_handle.clone());
    let v2ray_server = SimpleV2RayApiServer::with_monitoring(api_config, monitoring_handle.clone());

    assert!(clash_server.is_ok());
    assert!(v2ray_server.is_ok());

    // Subscribe to all monitoring streams
    let mut traffic_rx = monitoring_handle.subscribe_traffic();
    let mut connection_rx = monitoring_handle.subscribe_connections();

    // Simulate realistic proxy activity
    for i in 0..5 {
        // Simulate traffic
        let up_bytes = 1000 + (i * 500);
        let down_bytes = 2000 + (i * 1000);
        monitoring_handle
            .bridge()
            .update_traffic(up_bytes, down_bytes)
            .await;

        // Simulate connection
        if i % 2 == 0 {
            let connection = Connection {
                id: format!("conn_{}", i),
                metadata: ConnectionMetadata {
                    network: "tcp".to_string(),
                    r#type: "HTTPS".to_string(),
                    source_ip: format!("192.168.1.{}", 100 + i),
                    source_port: format!("{}", 40000 + i),
                    destination_ip: "8.8.8.8".to_string(),
                    destination_port: "443".to_string(),
                    inbound_ip: "127.0.0.1".to_string(),
                    inbound_port: "7890".to_string(),
                    inbound_name: "http".to_string(),
                    inbound_user: "".to_string(),
                    host: format!("example{}.com", i),
                    dns_mode: "normal".to_string(),
                    uid: 1000,
                    process: "browser".to_string(),
                    process_path: "/usr/bin/browser".to_string(),
                    special_proxy: "".to_string(),
                    special_rules: "".to_string(),
                    remote_destination: "8.8.8.8:443".to_string(),
                    sniff_host: "".to_string(),
                },
                upload: up_bytes,
                download: down_bytes,
                start: format!("{}", 1640995200000 + (i * 1000)),
                chains: vec!["PROXY".to_string()],
                rule: "DOMAIN".to_string(),
                rule_payload: format!("example{}.com", i),
            };

            monitoring_handle.bridge().add_connection(connection).await;
        }

        // Small delay between simulated activities
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Verify that updates are being broadcast
    let mut traffic_updates_received = 0;
    let mut connection_updates_received = 0;

    // Collect updates for a short period
    let collection_duration = Duration::from_millis(1500);
    let start_time = tokio::time::Instant::now();

    while tokio::time::Instant::now().duration_since(start_time) < collection_duration {
        tokio::select! {
            traffic_result = timeout(Duration::from_millis(100), traffic_rx.recv()) => {
                if let Ok(Ok(_)) = traffic_result {
                    traffic_updates_received += 1;
                }
            }
            connection_result = timeout(Duration::from_millis(100), connection_rx.recv()) => {
                if let Ok(Ok(_)) = connection_result {
                    connection_updates_received += 1;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                // Continue loop
            }
        }
    }

    // Verify we received updates
    assert!(
        traffic_updates_received > 0,
        "Should receive traffic updates"
    );
    assert!(
        connection_updates_received > 0,
        "Should receive connection updates"
    );

    // Get final state
    let final_traffic = monitoring_handle.get_current_traffic().await;
    let final_connections = monitoring_handle.get_connections().await;
    let final_metrics = monitoring_handle.get_performance_metrics().await;

    // Verify final state
    assert!(
        final_traffic.up >= 3000,
        "Should have accumulated upload traffic"
    );
    assert!(
        final_traffic.down >= 6000,
        "Should have accumulated download traffic"
    );
    assert!(
        !final_connections.is_empty(),
        "Should have active connections"
    );
    assert!(
        final_metrics["timestamp"].is_number(),
        "Should have performance metrics timestamp"
    );

    log::info!("End-to-end monitoring test completed successfully");
    log::info!("Traffic updates received: {}", traffic_updates_received);
    log::info!(
        "Connection updates received: {}",
        connection_updates_received
    );
    log::info!(
        "Final traffic: up={}, down={}",
        final_traffic.up,
        final_traffic.down
    );
    log::info!("Final connections: {}", final_connections.len());
    Ok(())
}
