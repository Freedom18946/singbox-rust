use assert_cmd::prelude::*;
use std::process::Command;

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_app"));
    cmd
}

#[cfg(not(feature = "reqwest"))]
#[test]
fn bench_io_h2_without_feature_shows_actionable_error_and_exit2() {
    let mut cmd = bin();
    let assert = cmd
        .arg("bench")
        .arg("io")
        .arg("--h2")
        .arg("--url")
        .arg("http://127.0.0.1:1")
        .arg("--json")
        .output()
        .expect("run app bin");
    assert_eq!(assert.status.code(), Some(2), "exit code must be 2");
    let stdout = String::from_utf8_lossy(&assert.stdout);
    // structured json
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json error output");
    assert_eq!(
        v.get("error").and_then(|v| v.as_str()),
        Some("feature_required")
    );
    assert_eq!(v.get("feature").and_then(|v| v.as_str()), Some("reqwest"));
}

#[cfg(feature = "reqwest")]
#[test]
fn bench_io_with_feature_outputs_fixed_schema_json() {
    let mut cmd = bin();
    // local invalid port to avoid external network; requests kept small
    let out = cmd
        .arg("bench")
        .arg("io")
        .arg("--url")
        .arg("http://127.0.0.1:0")
        .arg("--requests")
        .arg("1")
        .arg("--concurrency")
        .arg("1")
        .arg("--json")
        .output()
        .expect("run app bin");
    assert!(out.status.success(), "must succeed with feature");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json shape");
    for key in ["p50", "p90", "p99", "rps", "throughput_bps", "elapsed_ms"] {
        assert!(v.get(key).is_some(), "missing key: {}", key);
    }
}
