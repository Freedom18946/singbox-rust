#![cfg(feature = "schema-v2")]
use assert_cmd::Command;
use serde_json::Value;
use std::fs;

fn write_tmp(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[test]
fn schema_v2_unknown_field_has_ptr_and_code() {
    let cfg = r#"
    {"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080,"__unknown__":true}]}
    "#;
    let tmp = write_tmp(cfg);
    let output = Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "json",
        ])
        .assert()
        .failure() // 退出码 2
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&output).unwrap();
    let issues = v.get("issues").unwrap().as_array().unwrap();
    let first = issues.first().unwrap();
    assert_eq!(first.get("kind").unwrap(), "error");
    assert_eq!(first.get("code").unwrap(), "UnknownField");
    assert!(first
        .get("ptr")
        .unwrap()
        .as_str()
        .unwrap()
        .contains("/inbounds/0"));
    assert!(v.get("fingerprint").is_some());
}
