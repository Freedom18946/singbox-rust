#![cfg(feature = "dev-cli")]
use assert_cmd::Command;
use std::fs;

fn write_cfg(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[test]
fn version_json_field_order_locked() {
    let out = Command::cargo_bin("version")
        .unwrap()
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let s = String::from_utf8(out).unwrap();
    // Expect top-level ok then data fields inside
    let ok_pos = s.find("\"ok\"").unwrap();
    let data_pos = s.find("\"data\"").unwrap();
    assert!(ok_pos < data_pos);
    let name_pos = s.find("\"name\"").unwrap();
    let ver_pos = s.find("\"version\"").unwrap();
    let feat_pos = s.find("\"features\"").unwrap();
    let fp_pos = s.find("\"fingerprint\"").unwrap();
    assert!(name_pos < ver_pos && ver_pos < feat_pos && feat_pos < fp_pos);
}

#[test]
fn route_explain_json_field_order_locked() {
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
    let s = String::from_utf8(out).unwrap();
    let dest = s.find("\"dest\"").unwrap();
    let mr = s.find("\"matched_rule\"").unwrap();
    let chain = s.find("\"chain\"").unwrap();
    let ob = s.find("\"outbound\"").unwrap();
    assert!(dest < mr && mr < chain && chain < ob);
}
