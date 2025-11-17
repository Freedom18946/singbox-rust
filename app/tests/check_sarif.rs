use assert_cmd::Command;
use serde_json::Value;
use std::fs;

#[test]
fn check_sarif_minimal_keys() {
    let bad = r#"{
        "schema_version": 2,
        "inbounds": [ { "type": "http", "listen": "127.0.0.1", "port": "oops" } ],
        "outbounds": [ { "type": "direct" } ],
        "route": { "rules": [ { "outbound": "direct" } ] }
    }"#;
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), bad.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            f.path().to_str().unwrap(),
            "--schema-v2-validate",
            "--format",
            "sarif",
        ])
        .assert()
        .failure() // should be non-zero (code 2)
        .get_output()
        .stdout
        .clone();

    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v.get("version").and_then(|x| x.as_str()), Some("2.1.0"));
    let runs = v
        .get("runs")
        .and_then(|x| x.as_array())
        .expect("runs array");
    assert!(!runs.is_empty());
    let run0 = &runs[0];
    assert!(run0.get("tool").is_some());
    let results = run0
        .get("results")
        .and_then(|x| x.as_array())
        .expect("results array");
    assert!(!results.is_empty());
    let r0 = &results[0];
    assert!(r0.get("ruleId").is_some());
    assert!(r0.get("message").is_some());
    assert!(r0.get("locations").is_some());
}
