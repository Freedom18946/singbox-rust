use assert_cmd::Command;
use serde_json::Value;
use std::fs;

fn write_cfg(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[test]
fn normalize_write_out() {
    let cfg = r#"{
      "inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}],
      "route":{"rules":[{"domain":["EXAMPLE.COM","a.EXAMPLE.com",".b.com."],"port":["80-82","81","443"]}]}
    }"#;
    let tmp = write_cfg(cfg);
    let out = format!("{}.normalized.json", tmp.path().to_str().unwrap());
    let _ = Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
            "--write-normalized",
            "--out",
            &out,
        ])
        .assert()
        .success();
    let raw = fs::read_to_string(&out).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert!(v.get("route").is_some());
}

#[test]
fn minimize_guard_works() {
    let cfg = r#"{"route":{"rules":[{"not_domain":["x.com"],"domain":["A.COM","a.com"]}]}}"#;
    let tmp = write_cfg(cfg);
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--minimize-rules",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: Value = serde_json::from_slice(&out).unwrap();
    let iss = v.get("issues").unwrap().as_array().unwrap();
    assert!(iss
        .iter()
        .any(|i| i.get("code").unwrap() == "MinimizeSkippedByNegation"));
}
