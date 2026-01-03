#![cfg(feature = "dev-cli")]
use predicates::str::contains;
use serde_json::Value;
use std::fs;

fn write_tmp(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[test]
fn minimize_is_degraded_when_negation_present_text() {
    let cfg = r#"{"route":{"rules":[{"domain":["a.com"],"not_domain":["x.com"],"outbound":"direct"}]}}"#;
    let tmp = write_tmp(cfg);
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("app");
    cmd.args([
        "check",
        "-c",
        tmp.path().to_str().unwrap(),
        "--minimize-rules",
    ]);
    cmd.assert().code(1).stderr(contains("MINIMIZE_SKIPPED"));
}

#[test]
fn minimize_is_degraded_when_negation_present_json() {
    let cfg = r#"{"route":{"rules":[{"domain":["a.com"],"not_domain":["x.com"],"outbound":"direct"}]}}"#;
    let tmp = write_tmp(cfg);
    let output = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--minimize-rules",
            "--format",
            "json",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&output).unwrap();
    let issues = v.get("issues").unwrap().as_array().unwrap();
    assert!(issues
        .iter()
        .any(|i| i.get("code").unwrap() == "MinimizeSkippedByNegation"));
    assert!(v.get("fingerprint").is_some());
}
