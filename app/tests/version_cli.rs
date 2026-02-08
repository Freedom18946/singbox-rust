use serde_json::Value;

#[test]
fn version_json_shape_and_types() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args(["version", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: Value = serde_json::from_slice(&output).expect("json");

    // Required keys (Go-aligned format)
    assert!(v
        .get("version")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    assert!(v
        .get("environment")
        .and_then(|x| x.as_str())
        .map(|s| !s.is_empty())
        .unwrap_or(false));
    assert!(v.get("tags").map(|x| x.is_array()).unwrap_or(false));
}
