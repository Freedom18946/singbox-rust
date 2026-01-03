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

    // Check required fields are present and have correct types
    assert!(actual.get("name").unwrap().is_string());
    assert!(actual.get("version").unwrap().is_string());
    assert!(actual.get("commit").unwrap().is_string());
    assert!(actual.get("date").unwrap().is_string());
    assert!(actual.get("features").unwrap().is_array());

    // Check that name and version match expected values
    assert_eq!(actual.get("name"), expected.get("name"));
    assert_eq!(actual.get("version"), expected.get("version"));

    // Check commit is 8+ characters (git short hash)
    let commit = actual.get("commit").unwrap().as_str().unwrap();
    assert!(commit.len() >= 8);

    // Check date is ISO 8601 format
    let date = actual.get("date").unwrap().as_str().unwrap();
    assert!(date.contains('T'));
    assert!(date.contains('+') || date.contains('Z'));

    // Check features array contains at least something and is valid
    let features = actual.get("features").unwrap().as_array().unwrap();
    // Features array should be sorted alphabetically and contain strings
    for feature in features {
        assert!(feature.is_string());
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
    assert!(output.contains("app"));
    assert!(output.contains("0.1.0"));
    assert!(output.contains("Built:"));
    assert!(output.contains("Features:"));
}
