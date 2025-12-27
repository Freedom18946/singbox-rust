#![cfg(feature = "dev-cli")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn target_dir_for(features: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    let pid = std::process::id();
    let slug = if features.is_empty() {
        "default".to_string()
    } else {
        features
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    };
    dir.push(format!("sb_app_build_{slug}_{pid}"));
    dir
}

fn bin_path(target_dir: &Path) -> PathBuf {
    let profile = std::env::var("CARGO_PROFILE")
        .ok()
        .or_else(|| std::env::var("PROFILE").ok())
        .unwrap_or_else(|| "debug".into());
    let mut path = target_dir.to_path_buf();
    path.push(profile);
    path.push("app");
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

fn build_app(features: &str) -> PathBuf {
    let target_dir = target_dir_for(features);
    std::fs::create_dir_all(&target_dir).expect("create target dir");
    let bin = bin_path(&target_dir);
    if !bin.exists() {
        let mut cmd = Command::new("cargo");
        cmd.args(["build", "-p", "app", "--bin", "app"]);
        if !features.is_empty() {
            cmd.arg("--features");
            cmd.arg(features);
        }
        cmd.env("CARGO_TARGET_DIR", &target_dir);
        let status = cmd.status().expect("build app");
        assert!(
            status.success(),
            "failed to build app with features: {features}"
        );
    }
    bin
}

#[cfg(all(not(feature = "reqwest"), feature = "bench-cli"))]
#[test]
fn bench_io_h2_without_feature_shows_actionable_error_and_exit2() {
    let bin = build_app("bench-cli");
    let mut cmd = Command::new(bin);
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

#[cfg(all(feature = "reqwest", feature = "bench-cli"))]
#[test]
fn bench_io_with_feature_outputs_fixed_schema_json() {
    let bin = build_app("bench-cli,reqwest");
    let mut cmd = Command::new(bin);
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
