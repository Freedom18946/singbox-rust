//! SIGHUP restart integration test
//!
//! Ensures SIGHUP triggers a config check + full restart and that
//! listeners are replaced accordingly.

#![cfg(all(unix, feature = "router", feature = "adapters"))]

use anyhow::Result;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::{sleep, timeout};

mod common;
use common::workspace::workspace_bin;
async fn port_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

async fn wait_for_port(port: u16, expected_open: bool, max_wait: Duration) -> bool {
    let deadline = Instant::now() + max_wait;
    loop {
        if port_open(port).await == expected_open {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
#[ignore = "requires app binary with router+adapters: cargo build -p app --features router,adapters && cargo test --features router,adapters --test reload_sighup_restart -- --ignored"]
async fn test_sighup_restart_switches_ports() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let config_path = temp_dir.path().join("config.json");

    let initial_port = 19210;
    let next_port = 19211;

    let initial_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": initial_port
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

    let app_bin = workspace_bin("app");
    let mut child = Command::new(app_bin)
        .arg("run")
        .arg("--config")
        .arg(&config_path)
        .arg("--no-banner")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line).await {
                if n == 0 {
                    break;
                }
                eprint!("RUN STDERR: {}", line);
                line.clear();
            }
        });
    }

    assert!(
        wait_for_port(initial_port, true, Duration::from_secs(5)).await,
        "initial port should open"
    );

    let reload_config = json!({
        "inbounds": [{
            "type": "http",
            "listen": "127.0.0.1",
            "port": next_port
        }],
        "outbounds": [{
            "type": "direct",
            "name": "direct"
        }],
        "route": {
            "default": "direct"
        }
    });
    std::fs::write(&config_path, serde_json::to_string_pretty(&reload_config)?)?;

    let pid = child.id().expect("run pid");
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status()
        .await?;
    assert!(status.success(), "failed to send SIGHUP");

    assert!(
        wait_for_port(next_port, true, Duration::from_secs(5)).await,
        "restarted port should open"
    );
    assert!(
        wait_for_port(initial_port, false, Duration::from_secs(5)).await,
        "previous port should close after restart"
    );
    assert!(
        child.try_wait()?.is_none(),
        "process should still be running after SIGHUP restart"
    );

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await?;
    assert!(status.success(), "failed to send SIGTERM");

    let status = timeout(Duration::from_secs(5), child.wait()).await??;
    assert!(status.success(), "run should exit cleanly after SIGTERM");
    Ok(())
}
