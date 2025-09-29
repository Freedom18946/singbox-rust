use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn version_json_shape_ok() {
    let mut cmd = Command::cargo_bin("version").unwrap();
    let output = cmd.output().expect("run version");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false));
    let data = v.get("data").expect("data");
    assert!(data.get("name").is_some());
    assert!(data.get("version").is_some());
    assert!(data.get("features").is_some());
    assert!(data.get("fingerprint").is_some());
}
