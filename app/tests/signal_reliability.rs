//! Signal handling reliability test (L16.2.3)
//!
//! Validates:
//! - SIGTERM shutdown exits with code 0
//! - 10 rounds start/stop release admin listen port
//! - task monitor active count does not keep increasing
//! - emits `reports/stability/signal_reliability_10x.json`

#![cfg(feature = "long_tests")]
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use chrono::Utc;
use serde_json::{json, Value};

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
        "singbox_signal_long_test_{}_{}.json",
        std::process::id(),
        nonce
    ));
    std::fs::write(
        &path,
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"#,
    )
    .expect("Failed to write temp long-test config");
    path.to_string_lossy().into_owned()
}

fn detect_stability_report_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SINGBOX_STABILITY_REPORT_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    if std::path::Path::new("../reports").exists() {
        PathBuf::from("../reports/stability")
    } else {
        PathBuf::from("reports/stability")
    }
}

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

fn read_iterations() -> usize {
    std::env::var("SINGBOX_SIGNAL_ITERATIONS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(10)
}

fn http_get_json(addr: &str, path: &str) -> Option<Value> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
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
    let body = text.split("\r\n\r\n").nth(1)?;
    serde_json::from_str(body).ok()
}

fn http_status(addr: &str, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;
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
    let status_line = text.lines().next()?;
    status_line.split_whitespace().nth(1)?.parse::<u16>().ok()
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

fn read_active_task_count(addr: &str) -> Option<i64> {
    let value = http_get_json(addr, "/metricsz")?;
    value
        .get("task_monitor")
        .and_then(|v| v.get("count"))
        .and_then(|v| v.as_i64())
}

fn wait_port_released(addr: &str, timeout: Duration) -> bool {
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
            Err(_) => {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    false
}

fn reserve_local_admin_addr() -> String {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to reserve local ephemeral admin port");
    let addr = listener
        .local_addr()
        .expect("Failed to query reserved local admin address");
    format!("127.0.0.1:{}", addr.port())
}

fn resolve_admin_addr(base_port: Option<u16>, round_idx: usize) -> String {
    match base_port {
        Some(base) => format!("127.0.0.1:{}", base.saturating_add(round_idx as u16)),
        None => reserve_local_admin_addr(),
    }
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

fn has_increasing_streak(values: &[i64], streak_len: usize) -> bool {
    if values.len() < streak_len || streak_len < 2 {
        return false;
    }
    let mut streak = 1usize;
    for i in 1..values.len() {
        if values[i] > values[i - 1] {
            streak += 1;
            if streak >= streak_len {
                return true;
            }
        } else {
            streak = 1;
        }
    }
    false
}

#[test]
fn signal_reliability_10x() {
    let binary = std::env::var("SINGBOX_BINARY").unwrap_or_else(|_| detect_default_binary());
    if !std::path::Path::new(&binary).exists() {
        eprintln!("Skipping signal test: binary not found at {}", binary);
        return;
    }

    let config = std::env::var("SINGBOX_CONFIG").unwrap_or_else(|_| detect_default_config());
    let base_port = std::env::var("SINGBOX_SIGNAL_BASE_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok());
    let health_timeout = Duration::from_secs(read_timeout_secs());
    let preflight_timeout = Duration::from_secs(8);

    let iterations = read_iterations();
    let mut rounds = Vec::with_capacity(iterations);
    let mut round_task_counts = Vec::with_capacity(iterations);
    let mut all_exit_zero = true;
    let mut all_ports_released = true;
    let mut all_health_checks_ok = true;

    for i in 0..iterations {
        let round = i + 1;
        let admin_addr = resolve_admin_addr(base_port, i);

        assert!(
            wait_port_available(&admin_addr, preflight_timeout),
            "Round {}: admin port busy before start at {}. holder:\n{}",
            round,
            admin_addr,
            port_holder_diagnostics(&admin_addr)
        );

        let mut child = Command::new(&binary)
            .args(["--config", &config, "--admin-listen", &admin_addr])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("Round {}: failed to start process: {}", round, e));

        let health_ready = wait_for_health(&admin_addr, health_timeout, Duration::from_millis(250));
        if !health_ready {
            terminate_child(&mut child);
            let (stdout_tail, stderr_tail) = collect_child_logs(&mut child);
            panic!(
                "Round {}: /healthz not ready at {} within {:?}\nstdout_tail:\n{}\nstderr_tail:\n{}\nport_holder:\n{}",
                round,
                admin_addr,
                health_timeout,
                stdout_tail,
                stderr_tail,
                port_holder_diagnostics(&admin_addr)
            );
        }
        all_health_checks_ok &= health_ready;

        let mut samples = Vec::new();
        for _ in 0..3 {
            if let Some(c) = read_active_task_count(&admin_addr) {
                samples.push(c);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let sampled_task_count = samples.into_iter().max().unwrap_or(-1);
        if sampled_task_count >= 0 {
            round_task_counts.push(sampled_task_count);
        }

        let _held_conn = TcpStream::connect(&admin_addr).ok();

        let pid = child.id();
        let kill_status = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .expect("failed to execute kill command");
        assert!(
            kill_status.success(),
            "Round {}: failed to send SIGTERM to pid {}",
            round,
            pid
        );

        let (exit_code, exited_in_time, exit_zero) =
            if let Some(status) = wait_with_timeout(&mut child, Duration::from_secs(10)) {
                let code = status.code();
                let ok = status.success() || code == Some(0);
                (code, true, ok)
            } else {
                terminate_child(&mut child);
                (None, false, false)
            };

        if !exit_zero {
            let (stdout_tail, stderr_tail) = collect_child_logs(&mut child);
            panic!(
                "Round {}: process did not exit cleanly after SIGTERM (code={:?}, exited_in_time={})\nstdout_tail:\n{}\nstderr_tail:\n{}",
                round,
                exit_code,
                exited_in_time,
                stdout_tail,
                stderr_tail
            );
        }

        all_exit_zero &= exit_zero;
        let port_released = wait_port_released(&admin_addr, Duration::from_secs(5));
        all_ports_released &= port_released;

        if !port_released {
            panic!(
                "Round {}: admin port not released at {}. holder:\n{}",
                round,
                admin_addr,
                port_holder_diagnostics(&admin_addr)
            );
        }

        rounds.push(json!({
            "round": round,
            "admin_addr": admin_addr,
            "pid": pid,
            "health_ready": health_ready,
            "task_count": sampled_task_count,
            "sigterm_exit_code": exit_code,
            "exited_in_time": exited_in_time,
            "port_released": port_released
        }));
    }

    let max_allowed_task_delta = 2i64;
    let first_task_count = round_task_counts.first().copied().unwrap_or(0);
    let last_task_count = round_task_counts.last().copied().unwrap_or(0);
    let task_delta = last_task_count - first_task_count;
    let has_growth_streak = has_increasing_streak(&round_task_counts, 4);
    let tasks_not_persistently_increasing =
        !round_task_counts.is_empty() && task_delta <= max_allowed_task_delta && !has_growth_streak;
    let overall_pass = all_exit_zero
        && all_ports_released
        && all_health_checks_ok
        && tasks_not_persistently_increasing;

    let report = json!({
        "test": "signal_reliability_10x",
        "timestamp": Utc::now().to_rfc3339(),
        "result": if overall_pass { "pass" } else { "fail" },
        "iterations": iterations,
        "binary": binary,
        "config": config,
        "rounds": rounds,
        "task_count_series": round_task_counts,
        "threshold_check": {
            "sigterm_exit_zero_all_rounds": all_exit_zero,
            "port_released_all_rounds": all_ports_released,
            "health_ready_all_rounds": all_health_checks_ok,
            "active_task_not_persistently_increasing": tasks_not_persistently_increasing,
            "first_task_count": first_task_count,
            "last_task_count": last_task_count,
            "task_delta": task_delta,
            "max_allowed_task_delta": max_allowed_task_delta,
            "increasing_streak_detected": has_growth_streak
        }
    });

    let report_dir = detect_stability_report_dir();
    let _ = std::fs::create_dir_all(&report_dir);
    let report_path = report_dir.join(format!("signal_reliability_{}x.json", iterations));
    let legacy_report_path = report_dir.join("signal_reliability_10x.json");
    if let Ok(json_str) = serde_json::to_string_pretty(&report) {
        let _ = std::fs::write(&report_path, json_str);
        if report_path != legacy_report_path {
            let _ = std::fs::copy(&report_path, &legacy_report_path);
        }
        println!("Report written to: {}", report_path.display());
    }

    assert!(
        all_health_checks_ok,
        "Some rounds failed /healthz readiness"
    );
    assert!(
        all_exit_zero,
        "Some rounds did not exit cleanly after SIGTERM"
    );
    assert!(all_ports_released, "Some rounds did not release admin port");
    assert!(
        tasks_not_persistently_increasing,
        "Active task count kept increasing across rounds: {:?}",
        round_task_counts
    );
}
