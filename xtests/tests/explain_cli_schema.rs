use assert_cmd::prelude::*;
use serde_json::Value;
use std::process::Command;

/// 契约：docs/SCHEMA.explain.json5
#[test]
fn explain_cli_envelope() {
    // 需要在构建时启用 --features explain
    let out = Command::new("bash")
        .args([
            "-lc",
            "target/debug/sb-route-explain --json --sni www.example.com --port 443 --proto tcp",
        ])
        .output()
        .expect("run");
    assert!(out.status.success(), "sb-route-explain failed");
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.get("decision").is_some(), "missing decision");
    assert!(v.get("trace").is_some(), "missing trace");
}
