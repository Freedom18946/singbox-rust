use serde_json::Value;

#[test]
fn sb_version_json_shape() {
    let out = assert_cmd::cargo::cargo_bin_cmd!("version")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v.get("name").unwrap().as_str().unwrap(), "app");
    assert!(v.get("version").is_some());
    assert!(v.get("features").unwrap().as_array().is_some());
    assert!(v.get("fingerprint").is_some());
}
