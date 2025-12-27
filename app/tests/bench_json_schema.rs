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

#[cfg(all(feature = "reqwest", feature = "bench-cli"))]
#[test]
fn bench_io_json_schema_fields_exist() {
    let bin = build_app("bench-cli,reqwest");

    // requests=0 avoids real network I/O, still emits stats
    let out = Command::new(bin)
        .args([
            "bench",
            "io",
            "--url",
            "http://127.0.0.1:0",
            "--requests",
            "0",
            "--concurrency",
            "1",
            "--hist-buckets",
            "1,5,10",
            "--json",
        ])
        .output()
        .expect("run app bin");

    assert!(out.status.success(), "bench io must succeed");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for k in [
        "p50",
        "p90",
        "p99",
        "rps",
        "throughput_bps",
        "elapsed_ms",
        "histogram",
    ] {
        assert!(v.get(k).is_some(), "missing key: {k}");
    }
}
