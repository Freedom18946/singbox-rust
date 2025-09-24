use serde_json::Value;
use std::process::Command;

#[test]
fn check_json_shape() {
    let out = Command::new("bash").args(["-lc",
        "SB_CHECK_ANALYZE=1 SB_CHECK_RULEID=1 target/debug/singbox-rust check --json tests/assets/check/bad_conflict.yaml"]).output().expect("run");
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    let arr = v.as_array().expect("array");
    assert!(!arr.is_empty());
    let item = &arr[0];
    assert!(item.get("code").is_some());
    assert!(item.get("ptr").is_some());
    assert!(item.get("rule_id").is_some());
}
