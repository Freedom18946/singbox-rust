#![allow(clippy::len_zero)]
//! Rule switching reload integration test
//!
//! Tests hot reload functionality for routing rule changes,
//! verifying route decision changes through Admin API.

use serde_json::json;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Test rule switching via reload
#[tokio::test]
async fn test_rule_switch_reload() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial configuration with direct outbound as default
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19120
        }],
        "outbounds": [
            {
                "type": "direct",
                "name": "direct"
            },
            {
                "type": "http",
                "name": "proxy",
                "server": "127.0.0.1",
                "port": 19181
            }
        ],
        "route": {
            "rules": [{
                "domain": ["example.com"],
                "outbound": "direct"
            }],
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    // Start the application
    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .arg("--admin-listen")
        .arg("127.0.0.1:19193")
        .arg("--admin-token")
        .arg("rule-test-token")
        .arg("--grace")
        .arg("1500")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Wait for startup
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test initial route decision
    let initial_route = query_route_decision("example.com:80", "rule-test-token", 19193).await?;
    assert_eq!(
        initial_route["outbound"], "direct",
        "Initial route should use direct outbound"
    );

    // New configuration with selector outbound and different rules
    let new_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19120
        }],
        "outbounds": [
            {
                "type": "direct",
                "name": "direct"
            },
            {
                "type": "http",
                "name": "proxy",
                "server": "127.0.0.1",
                "port": 19181
            },
            {
                "type": "selector",
                "name": "auto",
                "members": ["proxy", "direct"]
            }
        ],
        "route": {
            "rules": [
                {
                    "domain": ["example.com"],
                    "outbound": "proxy"
                },
                {
                    "domain": ["test.com"],
                    "outbound": "direct"
                }
            ],
            "default": "auto"
        }
    });

    let reload_request = json!({
        "config": new_config
    });

    // Send reload request
    let reload_response = send_reload_request(&reload_request, "rule-test-token", 19193).await?;

    // Verify reload was successful
    assert_eq!(reload_response["event"], "reload");
    assert_eq!(reload_response["ok"], true);

    // Verify rule changes are reported
    let rules_changed = &reload_response["changed"]["rules"];
    assert!(
        rules_changed["added"].as_array().unwrap().len() > 0,
        "Should report added rules"
    );
    assert!(
        rules_changed["removed"].as_array().unwrap().len() > 0,
        "Should report removed rules"
    );

    // Verify outbound changes
    let outbounds_changed = &reload_response["changed"]["outbounds"];
    assert!(
        outbounds_changed["added"]
            .as_array()
            .unwrap()
            .contains(&json!("auto")),
        "Should add auto selector"
    );

    // Wait for reload to take effect
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Test route decision after reload
    let new_route_example =
        query_route_decision("example.com:80", "rule-test-token", 19193).await?;
    assert_eq!(
        new_route_example["outbound"], "proxy",
        "example.com should now use proxy outbound"
    );

    let new_route_test = query_route_decision("test.com:80", "rule-test-token", 19193).await?;
    assert_eq!(
        new_route_test["outbound"], "direct",
        "test.com should use direct outbound"
    );

    let new_route_default =
        query_route_decision("unknown.com:80", "rule-test-token", 19193).await?;
    assert_eq!(
        new_route_default["outbound"], "auto",
        "Unknown domains should use auto selector"
    );

    // Cleanup
    child.kill().await?;
    let _ = child.wait().await;

    Ok(())
}

/// Test complex rule modifications
#[tokio::test]
async fn test_complex_rule_modifications() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial configuration with multiple rules
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19121
        }],
        "outbounds": [
            {
                "type": "direct",
                "name": "direct"
            },
            {
                "type": "block",
                "name": "block"
            },
            {
                "type": "http",
                "name": "proxy1",
                "server": "proxy1.example.com",
                "port": 8080
            }
        ],
        "route": {
            "rules": [
                {
                    "domain": ["ads.example.com", "tracker.com"],
                    "outbound": "block"
                },
                {
                    "geoip": ["CN"],
                    "outbound": "direct"
                },
                {
                    "port": ["443"],
                    "protocol": ["tls"],
                    "outbound": "proxy1"
                }
            ],
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    // Start the application
    let mut child = Command::new("target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .arg("--admin-listen")
        .arg("127.0.0.1:19194")
        .arg("--admin-token")
        .arg("complex-rule-token")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Wait for startup
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test initial route decisions
    let blocked_route =
        query_route_decision("ads.example.com:80", "complex-rule-token", 19194).await?;
    assert_eq!(blocked_route["outbound"], "block", "Ads should be blocked");

    let _https_route =
        query_route_decision("secure.example.com:443", "complex-rule-token", 19194).await?;
    // Note: This might be "proxy1" if port matching works, or "direct" as fallback

    // Modified configuration with updated rules
    let modified_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19121
        }],
        "outbounds": [
            {
                "type": "direct",
                "name": "direct"
            },
            {
                "type": "block",
                "name": "block"
            },
            {
                "type": "http",
                "name": "proxy2",
                "server": "proxy2.example.com",
                "port": 8080
            }
        ],
        "route": {
            "rules": [
                {
                    "domain": ["ads.example.com", "malware.com"],
                    "outbound": "block"
                },
                {
                    "domain": ["secure.example.com"],
                    "outbound": "proxy2"
                },
                {
                    "geoip": ["US"],
                    "outbound": "proxy2"
                }
            ],
            "default": "direct"
        }
    });

    let reload_request = json!({
        "config": modified_config
    });

    // Send reload request
    let reload_response = send_reload_request(&reload_request, "complex-rule-token", 19194).await?;

    // Verify reload was successful
    assert_eq!(reload_response["event"], "reload");
    assert_eq!(reload_response["ok"], true);

    // Verify changes are properly reported
    let outbounds_changed = &reload_response["changed"]["outbounds"];
    assert!(
        outbounds_changed["added"]
            .as_array()
            .unwrap()
            .contains(&json!("proxy2")),
        "Should add proxy2"
    );
    assert!(
        outbounds_changed["removed"]
            .as_array()
            .unwrap()
            .contains(&json!("proxy1")),
        "Should remove proxy1"
    );

    // Wait for changes to take effect
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Test updated route decisions
    let secure_route =
        query_route_decision("secure.example.com:80", "complex-rule-token", 19194).await?;
    assert_eq!(
        secure_route["outbound"], "proxy2",
        "secure.example.com should now use proxy2"
    );

    let blocked_route_after =
        query_route_decision("ads.example.com:80", "complex-rule-token", 19194).await?;
    assert_eq!(
        blocked_route_after["outbound"], "block",
        "Ads should still be blocked"
    );

    let malware_route = query_route_decision("malware.com:80", "complex-rule-token", 19194).await?;
    assert_eq!(
        malware_route["outbound"], "block",
        "Malware domain should be blocked"
    );

    // Cleanup
    child.kill().await?;
    let _ = child.wait().await;

    Ok(())
}

/// Query route decision via Admin API
async fn query_route_decision(
    dest: &str,
    token: &str,
    port: u16,
) -> anyhow::Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/explain", port);

    let request_body = json!({
        "dest": dest,
        "network": "tcp",
        "protocol": "http"
    });

    let response = timeout(
        Duration::from_secs(5),
        client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Admin-Token", token)
            .json(&request_body)
            .send(),
    )
    .await??;

    let response_text = response.text().await?;
    let json_response: serde_json::Value = serde_json::from_str(&response_text)?;
    Ok(json_response)
}

/// Send reload request
async fn send_reload_request(
    request: &serde_json::Value,
    token: &str,
    port: u16,
) -> anyhow::Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/reload", port);

    let response = timeout(
        Duration::from_secs(5),
        client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Admin-Token", token)
            .json(request)
            .send(),
    )
    .await??;

    let response_text = response.text().await?;
    let json_response: serde_json::Value = serde_json::from_str(&response_text)?;
    Ok(json_response)
}
