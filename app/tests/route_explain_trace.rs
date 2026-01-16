#![cfg(feature = "explain")]
use serde_json::Value;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn explain_with_trace_opt_in() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            { "type": "socks", "listen": "127.0.0.1:1080" }
        ],
        "outbounds": [
            { "type": "direct", "name": "direct" }
        ],
        "route": {
            "rules": [
                { "domain": ["example.com"], "outbound": "direct" }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = NamedTempFile::new().unwrap();
    fs::write(tmp.path(), cfg.as_bytes()).unwrap();

    let out = assert_cmd::cargo::cargo_bin_cmd!("route-explain")
        .args([
            "-c",
            tmp.path().to_str().unwrap(),
            "--destination",
            "example.com:443",
            "--with-trace",
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
