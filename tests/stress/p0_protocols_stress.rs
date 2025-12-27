//! P0 Protocol Stress Tests
//!
//! Comprehensive stress tests for all P0 protocols:
//! - REALITY TLS
//! - ECH
//! - Hysteria v1/v2
//! - SSH
//! - TUIC
//!
//! Run with: cargo test --test stress_tests --release -- p0 --ignored

use crate::stress::*;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;

// ============================================================================
// REALITY TLS Stress Tests
// ============================================================================

#[cfg(feature = "tls_reality")]
mod reality_stress {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn stress_reality_24_hour_endurance() {
        println!("\n🧪 REALITY TLS - 24 Hour Endurance Test");
        println!("⚠️  This test will run for 24 hours!");

        let addr = match env::var("SB_REALITY_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_REALITY_STRESS_ADDR not set; skipping");
                return;
            }
        };

        let config = StressTestConfig {
            duration: Duration::from_secs(24 * 60 * 60),
            connection_rate: 10,
            concurrent_limit: 200,
            payload_size: 4096,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_reality_high_connection_rate() {
        println!("\n🧪 REALITY TLS - High Connection Rate");

        let addr = match env::var("SB_REALITY_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_REALITY_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 100,
            concurrent_limit: 500,
            payload_size: 512,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_reality_large_data_transfer() {
        println!("\n🧪 REALITY TLS - Large Data Transfer");

        let addr = match env::var("SB_REALITY_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_REALITY_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(120),
            connection_rate: 5,
            concurrent_limit: 50,
            payload_size: 1024 * 1024,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }
}

// ============================================================================
// ECH Stress Tests
// ============================================================================

#[cfg(feature = "tls_ech")]
mod ech_stress {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn stress_ech_24_hour_endurance() {
        println!("\n🧪 ECH - 24 Hour Endurance Test");
        println!("⚠️  This test will run for 24 hours!");

        let addr = match env::var("SB_ECH_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_ECH_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(24 * 60 * 60),
            connection_rate: 10,
            concurrent_limit: 200,
            payload_size: 4096,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_ech_high_connection_rate() {
        println!("\n🧪 ECH - High Connection Rate");

        let addr = match env::var("SB_ECH_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_ECH_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 100,
            concurrent_limit: 500,
            payload_size: 512,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }
}

// ============================================================================
// Hysteria v1 Stress Tests
// ============================================================================

#[cfg(feature = "adapter-hysteria")]
mod hysteria_v1_stress {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn stress_hysteria_v1_24_hour_endurance() {
        println!("\n🧪 Hysteria v1 - 24 Hour Endurance Test");
        println!("⚠️  This test will run for 24 hours!");

        let addr = match env::var("SB_HYSTERIA1_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_HYSTERIA1_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(24 * 60 * 60),
            connection_rate: 10,
            concurrent_limit: 200,
            payload_size: 4096,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_hysteria_v1_udp_relay() {
        println!("\n🧪 Hysteria v1 - UDP Relay Stress Test");

        let addr = match env::var("SB_HYSTERIA1_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_HYSTERIA1_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 50,
            concurrent_limit: 200,
            payload_size: 1024,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_hysteria_v1_high_throughput() {
        println!("\n🧪 Hysteria v1 - High Throughput Test");

        let addr = match env::var("SB_HYSTERIA1_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_HYSTERIA1_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(120),
            connection_rate: 5,
            concurrent_limit: 100,
            payload_size: 1024 * 1024,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }
}

// ============================================================================
// Hysteria v2 Stress Tests
// ============================================================================

#[cfg(feature = "adapter-hysteria2")]
mod hysteria_v2_stress {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn stress_hysteria_v2_24_hour_endurance() {
        println!("\n🧪 Hysteria v2 - 24 Hour Endurance Test");
        println!("⚠️  This test will run for 24 hours!");

        let addr = match env::var("SB_HYSTERIA2_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_HYSTERIA2_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(24 * 60 * 60),
            connection_rate: 10,
            concurrent_limit: 200,
            payload_size: 4096,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_hysteria_v2_udp_over_stream() {
        println!("\n🧪 Hysteria v2 - UDP Over Stream Stress Test");

        let addr = match env::var("SB_HYSTERIA2_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_HYSTERIA2_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 50,
            concurrent_limit: 200,
            payload_size: 1024,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_hysteria_v2_with_obfuscation() {
        println!("\n🧪 Hysteria v2 - Salamander Obfuscation Stress Test");

        let addr = match env::var("SB_HYSTERIA2_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_HYSTERIA2_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 20,
            concurrent_limit: 100,
            payload_size: 2048,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }
}

// ============================================================================
// SSH Stress Tests
// ============================================================================

#[cfg(feature = "adapter-ssh")]
mod ssh_stress {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn stress_ssh_24_hour_endurance() {
        println!("\n🧪 SSH - 24 Hour Endurance Test");
        println!("⚠️  This test will run for 24 hours!");

        let addr = match env::var("SB_SSH_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_SSH_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(24 * 60 * 60),
            connection_rate: 10,
            concurrent_limit: 200,
            payload_size: 4096,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_ssh_connection_pooling() {
        println!("\n🧪 SSH - Connection Pooling Stress Test");

        let addr = match env::var("SB_SSH_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_SSH_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 50,
            concurrent_limit: 200,
            payload_size: 1024,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_ssh_high_connection_rate() {
        println!("\n🧪 SSH - High Connection Rate");

        let addr = match env::var("SB_SSH_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_SSH_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 100,
            concurrent_limit: 500,
            payload_size: 512,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }
}

// ============================================================================
// TUIC Stress Tests
// ============================================================================

#[cfg(feature = "adapter-tuic")]
mod tuic_stress {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn stress_tuic_24_hour_endurance() {
        println!("\n🧪 TUIC - 24 Hour Endurance Test");
        println!("⚠️  This test will run for 24 hours!");

        let addr = match env::var("SB_TUIC_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_TUIC_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(24 * 60 * 60),
            connection_rate: 10,
            concurrent_limit: 200,
            payload_size: 4096,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_tuic_udp_over_stream() {
        println!("\n🧪 TUIC - UDP Over Stream Stress Test");

        let addr = match env::var("SB_TUIC_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_TUIC_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 50,
            concurrent_limit: 200,
            payload_size: 1024,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }

    #[tokio::test]
    #[ignore]
    async fn stress_tuic_high_throughput() {
        println!("\n🧪 TUIC - High Throughput Test");

        let addr = match env::var("SB_TUIC_STRESS_ADDR")
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            Some(addr) => addr,
            None => {
                eprintln!("SB_TUIC_STRESS_ADDR not set; skipping");
                return;
            }
        };
        let config = StressTestConfig {
            duration: Duration::from_secs(120),
            connection_rate: 5,
            concurrent_limit: 100,
            payload_size: 1024 * 1024,
            enable_monitoring: true,
        };
        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();
    }
}

// ============================================================================
// Combined Protocol Stress Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn stress_all_protocols_sequential() {
    println!("\n🧪 All P0 Protocols - Sequential Stress Test");
    println!("This test runs stress tests for all protocols sequentially");

    // Run baseline first
    println!("\n--- Baseline TCP ---");
    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");
    let config = StressTestConfig {
        duration: Duration::from_secs(300), // 5 minutes per protocol
        connection_rate: 20,
        concurrent_limit: 100,
        payload_size: 4096,
        enable_monitoring: true,
    };
    let baseline_metrics = run_stress_test(addr, config.clone()).await;
    baseline_metrics.print_summary();

    let protocols = [
        ("REALITY", "SB_REALITY_STRESS_ADDR"),
        ("ECH", "SB_ECH_STRESS_ADDR"),
        ("HYSTERIA1", "SB_HYSTERIA1_STRESS_ADDR"),
        ("HYSTERIA2", "SB_HYSTERIA2_STRESS_ADDR"),
        ("SSH", "SB_SSH_STRESS_ADDR"),
        ("TUIC", "SB_TUIC_STRESS_ADDR"),
    ];

    for (name, var) in protocols {
        if let Some(addr) = env::var(var)
            .ok()
            .and_then(|v| v.parse::<SocketAddr>().ok())
        {
            println!("\n--- {} ---", name);
            let metrics = run_stress_test(addr, config.clone()).await;
            metrics.print_summary();
        } else {
            println!("\n--- {} ---", name);
            println!("Skipping {}; set {} to run", name, var);
        }
    }
}

#[tokio::test]
#[ignore]
async fn stress_memory_leak_detection() {
    println!("\n🧪 Memory Leak Detection - All Protocols");

    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");

    // Run multiple iterations to detect memory leaks
    for iteration in 1..=5 {
        println!("\n--- Iteration {} ---", iteration);

        let monitor_handle = tokio::spawn(async {
            monitor_resources(Duration::from_secs(60), Duration::from_secs(5)).await
        });

        let config = StressTestConfig {
            duration: Duration::from_secs(60),
            connection_rate: 50,
            concurrent_limit: 100,
            payload_size: 2048,
            enable_monitoring: true,
        };

        let metrics = run_stress_test(addr, config).await;
        metrics.print_summary();

        let resource_report = monitor_handle.await.expect("Monitor task failed");
        resource_report.print_summary();

        assert!(
            !resource_report.detect_fd_leak(),
            "File descriptor leak detected in iteration {}",
            iteration
        );
        assert!(
            !resource_report.detect_memory_leak(),
            "Memory leak detected in iteration {}",
            iteration
        );
    }

    println!("\n✅ No memory leaks detected across 5 iterations");
}

#[tokio::test]
#[ignore]
async fn stress_file_descriptor_leak_detection() {
    println!("\n🧪 File Descriptor Leak Detection");

    let addr = start_echo_server()
        .await
        .expect("Failed to start echo server");

    // Monitor FDs specifically
    let monitor_handle = tokio::spawn(async {
        monitor_resources(Duration::from_secs(180), Duration::from_secs(2)).await
    });

    // Run test with many short-lived connections
    let config = StressTestConfig {
        duration: Duration::from_secs(180),
        connection_rate: 100, // High rate to stress FD management
        concurrent_limit: 200,
        payload_size: 512,
        enable_monitoring: true,
    };

    let metrics = run_stress_test(addr, config).await;
    metrics.print_summary();

    let resource_report = monitor_handle.await.expect("Monitor task failed");
    resource_report.print_summary();

    assert!(
        !resource_report.detect_fd_leak(),
        "File descriptor leak detected!"
    );
}
