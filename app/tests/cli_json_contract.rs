use assert_cmd::Command;
use serde_json::Value;
use std::fs;

const GOOD_CONFIG: &str = include_str!("golden/config_good.json");
const BAD_CONFIG: &str = include_str!("golden/config_bad.json");
const EXPECTED_GOOD_OUTPUT: &str = include_str!("golden/check_good_output.json");
const EXPECTED_BAD_OUTPUT: &str = include_str!("golden/check_bad_output.json");

fn write_cfg(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[test]
fn check_good_config_contract() {
    let tmp = write_cfg(GOOD_CONFIG);
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual_output = String::from_utf8(out.clone()).unwrap();
    println!("Good config command output: {}", actual_output);

    // Find the JSON part (after the log line)
    let json_start = actual_output.find('{').unwrap();
    let json_part = &actual_output[json_start..];

    let actual: Value = serde_json::from_str(json_part).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED_GOOD_OUTPUT).unwrap();

    // Check structure matches (ignoring dynamic fields like fingerprint and exact file path)
    assert_eq!(actual.get("ok"), expected.get("ok"));
    assert_eq!(actual.get("issues"), expected.get("issues"));
    assert_eq!(actual.get("summary"), expected.get("summary"));
    // Just check that file path is present and is a string
    assert!(actual.get("file").unwrap().is_string());
}

#[test]
fn check_bad_config_contract() {
    let tmp = write_cfg(BAD_CONFIG);
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
            "--schema-v2-validate",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let actual_output = String::from_utf8(out.clone()).unwrap();
    println!("Bad config command output: {}", actual_output);

    // Find the JSON part (after the log line)
    let json_start = actual_output.find('{').unwrap();
    let json_part = &actual_output[json_start..];

    let actual: Value = serde_json::from_str(json_part).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED_BAD_OUTPUT).unwrap();

    // Check structure matches
    assert_eq!(actual.get("ok"), expected.get("ok"));
    assert_eq!(actual.get("summary"), expected.get("summary"));
    // Just check that file path is present and is a string
    assert!(actual.get("file").unwrap().is_string());

    // Check issues structure (might have slight differences in exact messages)
    let actual_issues = actual.get("issues").unwrap().as_array().unwrap();
    let expected_issues = expected.get("issues").unwrap().as_array().unwrap();
    assert_eq!(actual_issues.len(), expected_issues.len());

    // Verify all expected issue codes are present
    for expected_issue in expected_issues {
        let expected_code = expected_issue.get("code").unwrap().as_str().unwrap();
        let found = actual_issues
            .iter()
            .any(|issue| issue.get("code").unwrap().as_str().unwrap() == expected_code);
        assert!(found, "Expected issue code {} not found", expected_code);
    }
}
