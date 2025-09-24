use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn report_includes_file_lists_and_bin_gates() {
    let mut cmd = Command::cargo_bin("report").unwrap();
    let out = cmd.arg("--root").arg(".").output().expect("run report");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false));
    let repo = v.get("repo").expect("repo");
    let metrics = repo.get("metrics").expect("metrics");
    // file list arrays should exist (may be empty)
    assert!(metrics["error_json"]["text_plain_files"].is_array());
    assert!(metrics["error_json"]["json_error_call_files"].is_array());
    assert!(metrics["analyze_dispatch"]["build_single_patch_files"].is_array());
    // bin gates should exist (arrays)
    assert!(metrics["bin_gates"]["minimal_bins"].is_array());
    assert!(metrics["bin_gates"]["router_gated_bins"].is_array());
}