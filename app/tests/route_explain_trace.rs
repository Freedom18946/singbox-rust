use assert_cmd::Command;
use serde_json::Value;

#[test]
fn explain_with_trace_opt_in() {
    let out = Command::cargo_bin("route-explain")
        .unwrap()
        .args(["--host", "example.com", "--port", "443", "--proto", "tcp", "--format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("trace").is_some());
    assert_eq!(v.get("matched_rule").unwrap().as_str().unwrap().len(), 8);
}
