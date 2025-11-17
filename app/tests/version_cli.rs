use assert_cmd::Command;
use serde_json::Value;

#[test]
fn version_json_shape_and_types() {
    let output = Command::cargo_bin("app")
        .unwrap()
        .args(["version", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: Value = serde_json::from_slice(&output).expect("json");

    // Required keys
    assert!(v
        .get("name")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    assert!(v
        .get("version")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    assert!(v
        .get("commit")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    assert!(v
        .get("date")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    assert!(v.get("features").map(|x| x.is_array()).unwrap_or(false));
}
