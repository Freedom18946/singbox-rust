use serde_json::Value;

const EXPECTED_VERSION_OUTPUT: &str = include_str!("golden/version_output.json");

#[test]
fn version_json_contract() {
    let out = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args(["version", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual_output = String::from_utf8(out.clone()).unwrap();

    // Find the JSON part (after the log line)
    let json_start = actual_output.find('{').unwrap();
    let json_part = &actual_output[json_start..];

    let actual: Value = serde_json::from_str(json_part).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED_VERSION_OUTPUT).unwrap();

    // Check required fields are present and have correct types (Go-aligned format)
    assert!(actual.get("version").unwrap().is_string());
    assert!(actual.get("environment").unwrap().is_string());
    assert!(actual.get("tags").unwrap().is_array());

    // Check that version matches expected value
    assert_eq!(actual.get("version"), expected.get("version"));

    // Check environment contains "rust" and OS/arch info
    let env_str = actual.get("environment").unwrap().as_str().unwrap();
    assert!(env_str.contains("rust"));

    // Check tags array contains strings
    let tags = actual.get("tags").unwrap().as_array().unwrap();
    for tag in tags {
        assert!(tag.is_string());
    }
}

#[test]
fn version_human_format() {
    // Also test that human format works
    let out = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args(["version", "--format", "human"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output = String::from_utf8(out).unwrap();
    assert!(output.contains("sing-box"));
    assert!(output.contains("0.1.0"));
    assert!(output.contains("Environment:"));
}
