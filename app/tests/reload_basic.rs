//! Basic reload integration test
//!
//! Tests hot reload functionality via Admin API endpoint,
//! including port switching and connectivity verification.

use serde_json::json;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Test basic reload functionality with port switching
#[tokio::test]
async fn test_basic_reload() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Initial configuration with port 19110
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19110
        }],
        "outbounds": [{
            "type": "http",
            "name": "upstream",
            "server": "127.0.0.1",
            "port": 19181
        }],
        "route": {
            "default": "upstream"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    // Start the application
    let mut child = Command::new("../target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .arg("--admin-listen")
        .arg("127.0.0.1:19190")
        .arg("--admin-token")
        .arg("test-token")
        .arg("--grace")
        .arg("1500")
        .env("ADMIN_LISTEN", "127.0.0.1:19190")
        .env("ADMIN_TOKEN", "test-token")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let stderr = child.stderr.take().expect("failed to capture stderr");
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        while let Ok(n) = reader.read_line(&mut line).await {
            if n == 0 {
                break;
            }
            print!("SERVER STDERR: {}", line);
            line.clear();
        }
    });

    // Wait for startup
    tokio::time::sleep(Duration::from_millis(2000)).await;

    if let Ok(Some(status)) = child.try_wait() {
        println!("Server exited prematurely with status: {}", status);
    }

    // Test initial connectivity to port 19110
    let initial_connectivity = test_port_connectivity(19110).await;
    assert!(
        initial_connectivity,
        "Initial port 19110 should be accessible"
    );

    // Prepare reload configuration with port 19111
    let reload_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19111
        }],
        "outbounds": [{
            "type": "http",
            "name": "upstream",
            "server": "127.0.0.1",
            "port": 19181
        }],
        "route": {
            "default": "upstream"
        }
    });

    let reload_request = json!({
        "config": reload_config
    });

    // Send reload request
    let reload_response = send_reload_request(&reload_request, "test-token").await?;

    // Verify reload response structure
    assert_eq!(reload_response["event"], "reload");
    assert_eq!(reload_response["ok"], true);
    assert!(reload_response["changed"]["inbounds"]["added"]
        .as_array()
        .unwrap()
        .contains(&json!("127.0.0.1:19111")));
    assert!(reload_response["changed"]["inbounds"]["removed"]
        .as_array()
        .unwrap()
        .contains(&json!("127.0.0.1:19110")));
    assert!(reload_response["fingerprint"].is_string());
    assert!(reload_response["t"].is_number());

    // Wait for reload to take effect
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Test new port connectivity
    let new_connectivity = test_port_connectivity(19111).await;
    assert!(
        new_connectivity,
        "New port 19111 should be accessible after reload"
    );

    // Test old port is no longer accessible
    let old_connectivity = test_port_connectivity(19110).await;
    assert!(
        !old_connectivity,
        "Old port 19110 should no longer be accessible"
    );

    // Cleanup
    child.kill().await?;
    let _ = child.wait().await;

    Ok(())
}

/// Test reload with invalid configuration
#[tokio::test]
async fn test_reload_invalid_config() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    // Valid initial configuration
    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19112
        }],
        "outbounds": [{
            "type": "direct",
            "name": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&initial_config)?)?;

    // Start the application
    let mut child = Command::new("../target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .arg("--admin-listen")
        .arg("127.0.0.1:19191")
        .arg("--admin-token")
        .arg("test-token-2")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Wait for startup
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Invalid configuration (missing required fields)
    let invalid_config = json!({
        "inbounds": [{
            "type": "invalid_type",
            "listen": "127.0.0.1"
            // missing port
        }]
    });

    let reload_request = json!({
        "config": invalid_config
    });

    // Send reload request with invalid config
    let reload_response =
        send_reload_request_to_port(&reload_request, "test-token-2", 19191).await?;

    // Verify error response
    assert_eq!(reload_response["event"], "reload");
    assert_eq!(reload_response["ok"], false);
    assert!(reload_response["error"]["code"]
        .as_str()
        .unwrap()
        .contains("invalid_config"));
    assert!(reload_response["error"]["message"].is_string());

    // Verify original port is still accessible
    let connectivity = test_port_connectivity(19112).await;
    assert!(
        connectivity,
        "Original port should still be accessible after failed reload"
    );

    // Cleanup
    child.kill().await?;
    let _ = child.wait().await;

    Ok(())
}

/// Test reload without authentication token
#[tokio::test]
async fn test_reload_unauthorized() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    let config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": 19113
        }],
        "outbounds": [{
            "type": "direct",
            "name": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });

    std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)?;

    // Start the application with token
    let mut child = Command::new("../target/debug/run")
        .arg("-c")
        .arg(&config_path)
        .arg("--format")
        .arg("json")
        .arg("--admin-listen")
        .arg("127.0.0.1:19192")
        .arg("--admin-token")
        .arg("secret-token")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Wait for startup
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let reload_request = json!({
        "config": config
    });

    // Send reload request without token
    let result = send_reload_request_to_port(&reload_request, "", 19192).await;

    // Should receive 403 Forbidden
    assert!(result.is_err() || result.unwrap()["error"]["code"] == "unauthorized");

    // Cleanup
    child.kill().await?;
    let _ = child.wait().await;

    Ok(())
}

/// Send reload request to default admin port (19190)
async fn send_reload_request(
    request: &serde_json::Value,
    token: &str,
) -> anyhow::Result<serde_json::Value> {
    send_reload_request_to_port(request, token, 19190).await
}

/// Send reload request to specific port
async fn send_reload_request_to_port(
    request: &serde_json::Value,
    token: &str,
    port: u16,
) -> anyhow::Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/reload", port);

    let mut req_builder = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(request);

    if !token.is_empty() {
        req_builder = req_builder.header("X-Admin-Token", token);
    }

    let response = timeout(Duration::from_secs(5), req_builder.send()).await??;
    let response_text = response.text().await?;

    let json_response: serde_json::Value = serde_json::from_str(&response_text)?;
    Ok(json_response)
}

/// Test if a port is accessible (simple TCP connection test)
async fn test_port_connectivity(port: u16) -> bool {
    timeout(Duration::from_millis(100), async {
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await
    })
    .await
    .is_ok_and(|result| result.is_ok())
}

// Helper modules for test dependencies
#[cfg(test)]
mod test_deps {
    // This would include any necessary test utilities
    // For the basic implementation, we'll use simple connectivity tests
}
