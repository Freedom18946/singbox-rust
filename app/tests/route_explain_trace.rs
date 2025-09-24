use assert_cmd::Command;
use serde_json::Value;
use std::fs;

fn write_cfg(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[test]
fn explain_with_trace_opt_in() {
    let cfg = r#"{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}]}"#;
    let tmp = write_cfg(cfg);
    let out = Command::cargo_bin("singbox-rust")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--trace",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert!(v.get("trace").is_some());
    assert_eq!(v.get("matched_rule").unwrap().as_str().unwrap().len(), 8);
}
