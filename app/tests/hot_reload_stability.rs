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
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
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

fn read_timeout_secs() -> u64 {
    std::env::var("SINGBOX_HEALTH_READY_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
}

fn detect_default_binary() -> String {
    for env_key in ["CARGO_BIN_EXE_run", "CARGO_BIN_EXE_app"] {
        if let Ok(path) = std::env::var(env_key) {
            if std::path::Path::new(&path).exists() {
                return path;
            }
        }
    }
    for candidate in ["target/debug/run", "../target/debug/run"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "target/debug/run".to_string()
}

fn detect_default_config() -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH")
        .as_millis();
    let path = std::env::temp_dir().join(format!(
        "singbox_hot_reload_long_test_{}_{}.json",
        std::process::id(),
        nonce
    ));
    std::fs::write(&path, "{}\n").expect("Failed to write temp long-test config");
    path.to_string_lossy().into_owned()
}

fn detect_stability_report_dir() -> PathBuf {
    if std::path::Path::new("../reports").exists() {
        PathBuf::from("../reports/stability")
    } else {
        PathBuf::from("reports/stability")
    }
}

fn reserve_local_admin_addr() -> String {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to reserve local ephemeral admin port");
    let addr = listener
        .local_addr()
        .expect("Failed to query reserved local admin address");
    format!("127.0.0.1:{}", addr.port())
}

fn wait_port_available(addr: &str, timeout: Duration) -> bool {
    let parsed: SocketAddr = match addr.parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        match TcpListener::bind(parsed) {
            Ok(listener) => {
                drop(listener);
                return true;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    false
}

fn port_holder_diagnostics(addr: &str) -> String {
    let port = match addr.rsplit(':').next() {
        Some(p) => p.to_string(),
        None => return String::new(),
    };
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
            .output();
        if let Ok(out) = output {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ss")
            .args(["-ltnp", &format!("sport = :{port}")])
            .output();
        if let Ok(out) = output {
            return String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
    }
    String::new()
}

fn trim_tail(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn collect_child_logs(child: &mut Child) -> (String, String) {
    let mut stdout_buf = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.read_to_string(&mut stdout_buf);
    }

    let mut stderr_buf = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr_buf);
    }

    (trim_tail(&stdout_buf, 60), trim_tail(&stderr_buf, 60))
}

fn terminate_child(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    if wait_with_timeout(child, Duration::from_secs(8)).is_none() {
        let _ = child.kill();
        let _ = child.wait();
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
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
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

fn wait_for_health(addr: &str, timeout: Duration, poll_interval: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if http_status(addr, "/healthz") == Some(200) {
            return true;
        }
        std::thread::sleep(poll_interval);
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
    let admin_addr = std::env::var("SINGBOX_HEALTH_ADDR").unwrap_or_else(|_| reserve_local_admin_addr());
    let health_timeout = Duration::from_secs(read_timeout_secs());
    let preflight_timeout = Duration::from_secs(8);

    assert!(
        wait_port_available(&admin_addr, preflight_timeout),
        "Admin port busy before start at {}. holder:\n{}",
        admin_addr,
        port_holder_diagnostics(&admin_addr)
    );

    let mut child = Command::new(&binary)
        .args(["--config", &config, "--admin-listen", &admin_addr])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start singbox process");

    let pid = child.id();
    if !wait_for_health(&admin_addr, health_timeout, Duration::from_millis(250)) {
        terminate_child(&mut child);
        let (stdout_tail, stderr_tail) = collect_child_logs(&mut child);
        panic!(
            "health endpoint not ready at {} within {:?}\nstdout_tail:\n{}\nstderr_tail:\n{}\nport_holder:\n{}",
            admin_addr,
            health_timeout,
            stdout_tail,
            stderr_tail,
            port_holder_diagnostics(&admin_addr)
        );
    }
    if let Ok(Some(status)) = child.try_wait() {
        let (stdout_tail, stderr_tail) = collect_child_logs(&mut child);
        panic!(
            "Process exited prematurely before SIGHUP loop: {:?}\nstdout_tail:\n{}\nstderr_tail:\n{}",
            status, stdout_tail, stderr_tail
        );
    }

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
        if let Ok(Some(status)) = child.try_wait() {
            let (stdout_tail, stderr_tail) = collect_child_logs(&mut child);
            panic!(
                "Process died after SIGHUP #{}: {:?}\nstdout_tail:\n{}\nstderr_tail:\n{}",
                i + 1,
                status,
                stdout_tail,
                stderr_tail
            );
        }
        if http_status(&admin_addr, "/healthz") == Some(200) {
            health_checks_ok += 1;
        } else {
            terminate_child(&mut child);
            let (stdout_tail, stderr_tail) = collect_child_logs(&mut child);
            panic!(
                "healthz check failed after SIGHUP #{} at {}\nstdout_tail:\n{}\nstderr_tail:\n{}",
                i + 1,
                admin_addr,
                stdout_tail,
                stderr_tail
            );
        }
    }

    let final_fds = get_fd_count(pid);
    let final_rss_kb = get_rss_kb(pid);

    terminate_child(&mut child);

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
