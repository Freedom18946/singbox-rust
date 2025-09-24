use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value;
use std::fs;

fn write_cfg(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[test]
fn run_started_event_json_shape() {
    // run 以 --format json 输出固定字段集
    let mut cmd = Command::cargo_bin("run").unwrap();
    cmd.args(["-c", "/dev/null", "--format", "json"])
        .env("PROM_LISTEN", "") // 不启动导出器
        .env("DNS_STUB", "0");
    let out = cmd.assert().success().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v.get("event").unwrap(), "started");
    assert!(v.get("pid").unwrap().as_u64().unwrap() > 0);
    assert!(v.get("fingerprint").is_some());
}

#[test]
fn check_v2_error_shape() {
    // 复用既有校验：注入未知字段
    let cfg =
        r#"{"inbounds":[{"type":"socks","listen":"0.0.0.0","port":1080,"__unknown__":true}]}"#;
    let tmp = write_cfg(cfg);
    let mut cmd = Command::cargo_bin("app").unwrap();
    cmd.args([
        "check",
        "-c",
        tmp.path().to_str().unwrap(),
        "--schema-v2-validate",
        "--format",
        "json",
    ]);
    let out = cmd.assert().failure().get_output().stdout.clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    let issues = v.get("issues").unwrap().as_array().unwrap();
    assert!(!issues.is_empty());
    let i0 = issues.first().unwrap();
    assert_eq!(i0.get("kind").unwrap(), "error");
    assert!(i0.get("code").unwrap().is_string());
    assert!(i0
        .get("ptr")
        .unwrap()
        .as_str()
        .unwrap()
        .starts_with("/inbounds/"));
    assert!(v.get("fingerprint").is_some());
}

#[test]
fn route_explain_shape() {
    let cfg = r#"{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}]}"#;
    let tmp = write_cfg(cfg);
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("dest").is_some());
    assert_eq!(v.get("matched_rule").unwrap().as_str().unwrap().len(), 8);
    assert!(v.get("chain").unwrap().as_array().unwrap().len() >= 1);
    assert!(v.get("outbound").is_some());
}

#[test]
fn version_json_shape() {
    let out = Command::cargo_bin("version")
        .unwrap()
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("name").unwrap().is_string());
    assert!(v.get("version").unwrap().is_string());
    assert!(v.get("features").unwrap().as_array().is_some());
    assert!(v.get("fingerprint").is_some());
}
