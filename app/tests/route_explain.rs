#[cfg(feature = "router")]
mod route_explain_tests {
    use assert_cmd::Command;
    use serde_json::Value;
    use std::fs;

    fn write_cfg(content: &str) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        fs::write(f.path(), content.as_bytes()).unwrap();
        f
    }

    // Minimal routeable config
    const CFG: &str = r#"{
        "inbounds": [ { "type": "http", "listen": "127.0.0.1", "port": 18081 } ],
        "outbounds": [ { "type": "direct", "name": "direct" } ],
        "route": { "rules": [ { "domain_suffix": ["example.com"], "outbound": "direct" } ], "default": "direct" }
    }"#;

    #[test]
    fn explain_json_shape() {
        let tmp = write_cfg(CFG);
        let out = Command::cargo_bin("app")
            .unwrap()
            .args([
                "route",
                "-c",
                tmp.path().to_str().unwrap(),
                "--dest",
                "example.com:443",
                "--format",
                "json",
                "--explain",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("dest").and_then(|x| x.as_str()).is_some());
        assert_eq!(v.get("matched_rule").and_then(|x| x.as_str()).unwrap().len(), 8);
        assert!(v.get("chain").and_then(|x| x.as_array()).map(|a| a.len() >= 0).unwrap_or(false));
        assert!(v.get("outbound").and_then(|x| x.as_str()).is_some());
    }

    #[test]
    fn explain_with_trace_includes_trace() {
        let tmp = write_cfg(CFG);
        let out = Command::cargo_bin("app")
            .unwrap()
            .args([
                "route",
                "-c",
                tmp.path().to_str().unwrap(),
                "--dest",
                "example.com:443",
                "--with-trace",
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
        assert!(v.get("trace").is_some());
        assert_eq!(v.get("matched_rule").and_then(|x| x.as_str()).unwrap().len(), 8);
    }
}
