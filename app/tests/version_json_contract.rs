use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn version_json_shape_ok() {
    let mut cmd = Command::cargo_bin("version").unwrap();
    let output = cmd.output().expect("run version");
    assert!(output.status.success());
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(v.get("ok").is_none(), "version bin should emit plain JSON");
    assert!(v.get("name").is_some());
    assert!(v.get("version").is_some());
    assert!(v.get("features").is_some());
    assert!(v.get("fingerprint").is_some());
    assert!(v.get("build_info").is_some());
}
