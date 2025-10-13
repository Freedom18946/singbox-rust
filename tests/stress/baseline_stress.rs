//! Baseline Stress Tests
//!
//! These tests establish baseline performance and resource usage
//! for direct TCP connections without any protocol overhead.
//!
//! Run with: cargo test --test stress_tests --release -- baseline --ignored

use super::stress::*;
use std::time::Duration;

#[tokio::test]
#[ignore] // Run explicitly with --ignored flag
async fn stress_baseline_short_duration() {
    println!("\n🧪 Baseline Stress Test - Short Duration (60s)");

    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");

    let config = StressTestConfig {
        duration: Duration::from_secs(60),
        connection_rate: 50,
        concurrent_limit: 100,
        payload_size: 1024,
        enable_monitoring: true,
    };

    let metrics = run_stress_test(addr, config).await;
    metrics.print_summary();

    // Assertions
    let total = metrics
        .total_connections
        .load(std::sync::atomic::Ordering::Relaxed);
    let success = metrics
        .successful_connections
        .load(std::sync::atomic::Ordering::Relaxed);

    assert!(total > 0, "No connections attempted");
    assert!(
        success as f64 / total as f64 > 0.95,
        "Success rate below 95%"
    );
}

#[tokio::test]
#[ignore] // Run explicitly with --ignored flag
async fn stress_baseline_high_connection_rate() {
    println!("\n🧪 Baseline Stress Test - High Connection Rate");

    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");

    let config = StressTestConfig {
        duration: Duration::from_secs(30),
        connection_rate: 200, // High rate
        concurrent_limit: 500,
        payload_size: 512,
        enable_monitoring: true,
    };

    let metrics = run_stress_test(addr, config).await;
    metrics.print_summary();

    let total = metrics
        .total_connections
        .load(std::sync::atomic::Ordering::Relaxed);
    let success = metrics
        .successful_connections
        .load(std::sync::atomic::Ordering::Relaxed);

    assert!(total > 1000, "Expected at least 1000 connection attempts");
    assert!(
        success as f64 / total as f64 > 0.90,
        "Success rate below 90% under high load"
    );
}

#[tokio::test]
#[ignore] // Run explicitly with --ignored flag
async fn stress_baseline_large_data_transfer() {
    println!("\n🧪 Baseline Stress Test - Large Data Transfer");

    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");

    let config = StressTestConfig {
        duration: Duration::from_secs(60),
        connection_rate: 10,
        concurrent_limit: 50,
        payload_size: 1024 * 1024, // 1 MB per connection
        enable_monitoring: true,
    };

    let metrics = run_stress_test(addr, config).await;
    metrics.print_summary();

    let bytes_sent = metrics
        .bytes_sent
        .load(std::sync::atomic::Ordering::Relaxed);
    let bytes_received = metrics
        .bytes_received
        .load(std::sync::atomic::Ordering::Relaxed);

    assert!(
        bytes_sent > 100 * 1024 * 1024,
        "Expected at least 100 MB sent"
    );
    assert_eq!(
        bytes_sent, bytes_received,
        "Sent and received bytes should match"
    );
}

#[tokio::test]
#[ignore] // Run explicitly with --ignored flag
async fn stress_baseline_resource_monitoring() {
    println!("\n🧪 Baseline Stress Test - Resource Monitoring");

    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");

    // Start resource monitoring
    let monitor_handle = tokio::spawn(async {
        monitor_resources(Duration::from_secs(120), Duration::from_secs(5)).await
    });

    // Run stress test
    let config = StressTestConfig {
        duration: Duration::from_secs(120),
        connection_rate: 30,
        concurrent_limit: 100,
        payload_size: 2048,
        enable_monitoring: true,
    };

    let metrics = run_stress_test(addr, config).await;
    metrics.print_summary();

    // Get monitoring results
    let resource_report = monitor_handle.await.expect("Monitor task failed");
    resource_report.print_summary();

    // Check for leaks
    assert!(
        !resource_report.detect_fd_leak(),
        "File descriptor leak detected!"
    );
    assert!(
        !resource_report.detect_memory_leak(),
        "Memory leak detected!"
    );
}

#[tokio::test]
#[ignore] // Run explicitly with --ignored flag for 24-hour test
async fn stress_baseline_24_hour_endurance() {
    println!("\n🧪 Baseline Stress Test - 24 Hour Endurance");
    println!("⚠️  This test will run for 24 hours!");

    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");

    // Start resource monitoring with 1-minute intervals
    let monitor_handle = tokio::spawn(async {
        monitor_resources(Duration::from_secs(24 * 60 * 60), Duration::from_secs(60)).await
    });

    // Run stress test for 24 hours
    let config = StressTestConfig {
        duration: Duration::from_secs(24 * 60 * 60), // 24 hours
        connection_rate: 10,                         // Moderate rate for long duration
        concurrent_limit: 50,
        payload_size: 4096,
        enable_monitoring: true,
    };

    let start = std::time::Instant::now();
    let metrics = run_stress_test(addr, config).await;
    let elapsed = start.elapsed();

    println!("\n24-Hour Test Completed!");
    println!(
        "Actual Duration: {:.2} hours",
        elapsed.as_secs_f64() / 3600.0
    );

    metrics.print_summary();

    // Get monitoring results
    let resource_report = monitor_handle.await.expect("Monitor task failed");
    resource_report.print_summary();

    // Strict checks for 24-hour test
    let total = metrics
        .total_connections
        .load(std::sync::atomic::Ordering::Relaxed);
    let success = metrics
        .successful_connections
        .load(std::sync::atomic::Ordering::Relaxed);

    assert!(
        total > 100_000,
        "Expected at least 100k connections over 24 hours"
    );
    assert!(
        success as f64 / total as f64 > 0.99,
        "Success rate below 99% in endurance test"
    );
    assert!(
        !resource_report.detect_fd_leak(),
        "File descriptor leak detected in 24h test!"
    );
    assert!(
        !resource_report.detect_memory_leak(),
        "Memory leak detected in 24h test!"
    );
}
