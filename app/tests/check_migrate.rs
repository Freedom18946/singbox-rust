#![cfg(feature = "dev-cli")]
use std::fs;

#[test]
fn check_migrate_and_write_normalized_produces_v2() {
    let v1 = r#"{
        "outbounds":[{"type":"direct","name":"direct"}],
        "rules":[{"domain_suffix":["example.com"],"outbound":"direct"}]
    }"#;
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("v1.json");
    fs::write(&cfg, v1).unwrap();
    let out = dir.path().join("out.json");
    assert_cmd::cargo::cargo_bin_cmd!("check")
        .args([
            "--migrate",
            "--write-normalized",
            "--config",
            cfg.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();
    let s = fs::read_to_string(&out).unwrap();
    assert!(s.contains("schema_version"));
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["schema_version"], 2);
    assert!(v.get("route").is_some());
}
