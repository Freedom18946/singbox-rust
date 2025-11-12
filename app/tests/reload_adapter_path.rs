//! Adapter Path Hot Reload Tests
//!
//! Tests that verify adapter reconstruction during hot reload:
//! - Inbound adapters are properly stopped and restarted
//! - Outbound adapters are correctly reconfigured
//! - Adapter registry handles feature-gated protocols during reload
//! - Selector groups update their members after reload
//!
//! These tests ensure the adapter path (not scaffold) correctly
//! handles configuration changes without requiring a full restart.

#![cfg(all(feature = "net_e2e", feature = "adapters"))]

use anyhow::Result;
use serde_json::json;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

/// Test reload with HTTP inbound adapter reconfiguration
///
/// Verifies that HTTP inbound adapter can be reconfigured during reload.
#[tokio::test]
async fn test_reload_http_inbound_adapter() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial: HTTP inbound on port 20001
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20001
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    // Start application
    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--admin-listen")
        .arg("127.0.0.1:20090")
        .arg("--admin-token")
        .arg("test-token")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    sleep(Duration::from_millis(500)).await;

    // Verify initial port
    assert!(
        test_port_connectivity(20001).await,
        "Initial HTTP inbound should be accessible"
    );

    // Reload: Change port to 20002
    let reload_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in-new",
            "listen": "127.0.0.1",
            "port": 20002
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    send_reload_request(&reload_config, "test-token", 20090).await?;
    sleep(Duration::from_millis(300)).await;

    // Verify port switched
    assert!(
        test_port_connectivity(20002).await,
        "New HTTP inbound should be accessible after reload"
    );
    assert!(
        !test_port_connectivity(20001).await,
        "Old HTTP inbound should be stopped"
    );

    child.kill().await?;
    Ok(())
}

/// Test reload with SOCKS inbound adapter replacement
///
/// Verifies that SOCKS inbound adapter can replace HTTP inbound during reload.
#[tokio::test]
async fn test_reload_socks_inbound_adapter() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial: HTTP inbound
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20011
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--admin-listen")
        .arg("127.0.0.1:20091")
        .arg("--admin-token")
        .arg("test-token")
        .spawn()?;

    sleep(Duration::from_millis(500)).await;

    // Reload: Replace with SOCKS inbound
    let reload_config = json!({
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 20012
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    send_reload_request(&reload_config, "test-token", 20091).await?;
    sleep(Duration::from_millis(300)).await;

    // Verify SOCKS inbound is active
    assert!(
        test_port_connectivity(20012).await,
        "SOCKS inbound should be accessible after reload"
    );

    child.kill().await?;
    Ok(())
}

/// Test reload with Shadowsocks outbound adapter reconfiguration
///
/// Verifies that encrypted protocol outbound adapters can be reconfigured.
#[tokio::test]
async fn test_reload_shadowsocks_outbound_adapter() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial: Direct outbound
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20021
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--admin-listen")
        .arg("127.0.0.1:20092")
        .arg("--admin-token")
        .arg("test-token")
        .spawn()?;

    sleep(Duration::from_millis(500)).await;

    // Reload: Add Shadowsocks outbound
    let reload_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20021
        }],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-out",
                "server": "127.0.0.1",
                "port": 8388,
                "method": "aes-256-gcm",
                "password": "test-password"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "ss-out"
        }
    });

    let response = send_reload_request(&reload_config, "test-token", 20092).await?;

    // Verify reload succeeded
    assert_eq!(response["ok"], true, "Reload should succeed");
    assert!(
        response["changed"]["outbounds"]["added"].is_array(),
        "Outbounds should be added"
    );

    child.kill().await?;
    Ok(())
}

/// Test reload with selector group member changes
///
/// Verifies that selector groups update their members during reload.
#[tokio::test]
async fn test_reload_selector_members() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial: Selector with one member
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20031
        }],
        "outbounds": [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["direct"]
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "default": "proxy"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--admin-listen")
        .arg("127.0.0.1:20093")
        .arg("--admin-token")
        .arg("test-token")
        .spawn()?;

    sleep(Duration::from_millis(500)).await;

    // Reload: Add more members to selector
    let reload_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20031
        }],
        "outbounds": [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["http-out", "socks-out", "direct"]
            },
            {
                "type": "http",
                "tag": "http-out",
                "server": "127.0.0.1",
                "port": 8080
            },
            {
                "type": "socks",
                "tag": "socks-out",
                "server": "127.0.0.1",
                "port": 1080
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "default": "proxy"
        }
    });

    let response = send_reload_request(&reload_config, "test-token", 20093).await?;

    // Verify reload succeeded
    assert_eq!(response["ok"], true, "Reload should succeed");

    child.kill().await?;
    Ok(())
}

/// Test reload preserves adapter state idempotency
///
/// Verifies that reloading with the same config is idempotent.
#[tokio::test]
async fn test_reload_adapter_idempotency() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    let config = json!({
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "port": 20041
        }],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "ss-out",
                "server": "127.0.0.1",
                "port": 8388,
                "method": "aes-256-gcm",
                "password": "test-password"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "default": "ss-out"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--admin-listen")
        .arg("127.0.0.1:20094")
        .arg("--admin-token")
        .arg("test-token")
        .spawn()?;

    sleep(Duration::from_millis(500)).await;

    // First reload with same config
    let response1 = send_reload_request(&config, "test-token", 20094).await?;
    assert_eq!(response1["ok"], true);

    // Second reload with same config
    let response2 = send_reload_request(&config, "test-token", 20094).await?;
    assert_eq!(response2["ok"], true);

    // Port should still be accessible
    assert!(
        test_port_connectivity(20041).await,
        "Inbound should remain accessible after idempotent reloads"
    );

    child.kill().await?;
    Ok(())
}

/// Test reload with feature-gated adapters
///
/// Verifies that adapters respect feature gates during reload.
#[tokio::test]
async fn test_reload_feature_gated_adapters() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial: Basic adapters
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20051
        }],
        "outbounds": [{
            "type": "direct",
            "tag": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--admin-listen")
        .arg("127.0.0.1:20095")
        .arg("--admin-token")
        .arg("test-token")
        .spawn()?;

    sleep(Duration::from_millis(500)).await;

    // Reload: Add adapters that may be feature-gated
    let reload_config = json!({
        "inbounds": [{
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": 20051
        }],
        "outbounds": [
            // VMess - feature-gated
            {
                "type": "vmess",
                "tag": "vmess-out",
                "server": "127.0.0.1",
                "port": 10000,
                "uuid": "2dd61d93-75d8-4da4-ac0e-6aece7eac365"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "default": "direct"
        }
    });

    let response = send_reload_request(&reload_config, "test-token", 20095).await?;

    // Reload should succeed (adapters feature enabled in this test)
    assert_eq!(
        response["ok"], true,
        "Reload with feature-gated adapters should succeed when features enabled"
    );

    child.kill().await?;
    Ok(())
}

// Helper functions

async fn test_port_connectivity(port: u16) -> bool {
    timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await
    .is_ok()
}

async fn send_reload_request(
    config: &serde_json::Value,
    token: &str,
    admin_port: u16,
) -> Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let reload_body = json!({
        "config": config
    });

    let response = client
        .post(format!("http://127.0.0.1:{}/reload", admin_port))
        .header("Authorization", format!("Bearer {}", token))
        .json(&reload_body)
        .send()
        .await?;

    let result = response.json::<serde_json::Value>().await?;
    Ok(result)
}
