//! Hot reload stability test (L16.2.2)
//!
//! Starts the Rust kernel, sends 100 SIGHUP signals, and verifies:
//! - process stays alive
//! - /healthz returns 200 continuously
//! - FD count does not leak abnormally
//! - RSS growth remains under threshold

#![cfg(feature = "long_tests")]
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use chrono::Utc;
use serde_json::json;

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if start.elapsed() > timeout {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return None,
        }
    }
}

fn detect_default_binary() -> String {
    for candidate in ["target/debug/run", "../target/debug/run"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "target/debug/run".to_string()
}

fn detect_default_config() -> String {
    for candidate in [
        "labs/interop-lab/configs/bench_rust.json",
        "../labs/interop-lab/configs/bench_rust.json",
        "examples/e2e/minimal.yaml",
        "../examples/e2e/minimal.yaml",
    ] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "labs/interop-lab/configs/bench_rust.json".to_string()
}

fn detect_stability_report_dir() -> PathBuf {
    if std::path::Path::new("../reports").exists() {
        PathBuf::from("../reports/stability")
    } else {
        PathBuf::from("reports/stability")
    }
}

fn get_fd_count(pid: u32) -> usize {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("lsof")
            .args(["-p", &pid.to_string()])
            .output()
            .ok();
        output
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .count()
                    .saturating_sub(1)
            })
            .unwrap_or(0)
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir(format!("/proc/{}/fd", pid))
            .map(|entries| entries.count())
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        0
    }
}

fn get_rss_kb(pid: u32) -> i64 {
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok();
        out.and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<i64>().ok())
            .unwrap_or(0)
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{}/status", pid))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|line| line.starts_with("VmRSS:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|n| n.parse::<i64>().ok())
            })
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        0
    }
}

fn http_status(addr: &str, path: &str) -> Option<u16> {
    let mut stream = std::net::TcpStream::connect(addr).ok()?;
    stream
        .write_all(
            format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                path, addr
            )
            .as_bytes(),
        )
        .ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().next()?;
    line.split_whitespace().nth(1)?.parse::<u16>().ok()
}

fn wait_for_health(addr: &str, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if http_status(addr, "/healthz") == Some(200) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

#[test]
fn hot_reload_100x_stability() {
    let binary = std::env::var("SINGBOX_BINARY").unwrap_or_else(|_| detect_default_binary());
    if !std::path::Path::new(&binary).exists() {
        eprintln!("Skipping hot_reload test: binary not found at {}", binary);
        return;
    }

    let config = std::env::var("SINGBOX_CONFIG").unwrap_or_else(|_| detect_default_config());
    let admin_addr =
        std::env::var("SINGBOX_HEALTH_ADDR").unwrap_or_else(|_| "127.0.0.1:19090".to_string());

    let mut child = Command::new(&binary)
        .args(["--config", &config, "--admin-listen", &admin_addr])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start singbox process");

    let pid = child.id();
    assert!(
        wait_for_health(&admin_addr, Duration::from_secs(10)),
        "health endpoint not ready at {}",
        admin_addr
    );
    assert!(
        child.try_wait().ok().flatten().is_none(),
        "Process exited prematurely before SIGHUP loop"
    );

    let initial_fds = get_fd_count(pid);
    let initial_rss_kb = get_rss_kb(pid);
    let mut health_checks_ok = 0usize;

    for i in 0..100 {
        let kill_status = Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .expect("failed to execute kill command");
        assert!(
            kill_status.success(),
            "Failed to send SIGHUP #{} to pid {}",
            i + 1,
            pid
        );

        std::thread::sleep(Duration::from_millis(250));
        assert!(
            child.try_wait().ok().flatten().is_none(),
            "Process died after SIGHUP #{}",
            i + 1
        );
        if http_status(&admin_addr, "/healthz") == Some(200) {
            health_checks_ok += 1;
        } else {
            panic!("healthz check failed after SIGHUP #{}", i + 1);
        }
    }

    let final_fds = get_fd_count(pid);
    let final_rss_kb = get_rss_kb(pid);

    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();

    let exit = wait_with_timeout(&mut child, Duration::from_secs(10));
    if exit.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }

    let fd_threshold = initial_fds + 50;
    assert!(
        final_fds <= fd_threshold,
        "FD leak detected: initial={}, final={} (limit={})",
        initial_fds,
        final_fds,
        fd_threshold
    );

    let rss_limit_kb = ((initial_rss_kb as f64) * 1.10) as i64;
    assert!(
        final_rss_kb <= rss_limit_kb || initial_rss_kb == 0,
        "RSS growth over threshold: initial={}KB final={}KB limit={}KB",
        initial_rss_kb,
        final_rss_kb,
        rss_limit_kb
    );

    let report = json!({
        "test": "hot_reload_100x_stability",
        "timestamp": Utc::now().to_rfc3339(),
        "result": "pass",
        "iterations": 100,
        "binary": binary,
        "config": config,
        "admin_addr": admin_addr,
        "initial_fds": initial_fds,
        "final_fds": final_fds,
        "fd_delta": final_fds as i64 - initial_fds as i64,
        "initial_rss_kb": initial_rss_kb,
        "final_rss_kb": final_rss_kb,
        "rss_delta_kb": final_rss_kb - initial_rss_kb,
        "threshold_check": {
            "health_checks_passed": health_checks_ok,
            "health_checks_expected": 100,
            "fd_limit_delta": 50,
            "rss_growth_limit_pct": 10
        }
    });

    let report_dir = detect_stability_report_dir();
    let _ = std::fs::create_dir_all(&report_dir);
    let report_path = report_dir.join("hot_reload_100x.json");
    if let Ok(json_str) = serde_json::to_string_pretty(&report) {
        let _ = std::fs::write(&report_path, json_str);
        println!("Report written to: {}", report_path.display());
    }
}
