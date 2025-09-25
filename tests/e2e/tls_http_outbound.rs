use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;
use xtests::workspace_bin;

fn write_cfg(content: &str) -> NamedTempFile {
    let f = NamedTempFile::new().expect("tmp");
    fs::write(f.path(), content.as_bytes()).expect("write cfg");
    f
}

fn run(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() { return None; }
    String::from_utf8(out.stdout).ok()
}

fn go_bin() -> Option<String> { std::env::var("GO_SINGBOX_BIN").ok().filter(|s| !s.is_empty()) }

#[test]
fn e2e_check_http_tls_outbound_subset() {
    // Only validate JSON shape; no real network I/O
    let cfg = r#"{
        "inbounds": [{"type":"http","listen":"127.0.0.1:0"}],
        "outbounds": [
            {"type":"http","name":"http1","server":"example.com","port":443,"tls":true}
        ],
        "rules":[{"protocol":["http"],"outbound":"http1"}],
        "default_outbound":"http1"
    }"#;
    let tmp = write_cfg(cfg);

    let rust = workspace_bin("singbox-rust").to_string_lossy().to_string();
    let out_rust = run(&rust, &["check","--config", tmp.path().to_str().unwrap(), "--format","json"]).expect("rust check ok");
    let v_rs: serde_json::Value = serde_json::from_str(&out_rust).unwrap();
    assert!(v_rs.get("ok").is_some());
    assert!(v_rs.get("summary").is_some());

    if let Some(go) = go_bin() {
        if let Some(out_go) = run(&go, &["check","--config", tmp.path().to_str().unwrap(), "--format","json"]) {
            let v_go: serde_json::Value = serde_json::from_str(&out_go).unwrap();
            // Compare a tiny stable subset
            assert_eq!(v_go.get("ok"), v_rs.get("ok"));
        } else {
            eprintln!("[e2e] go check failed; skipping compare");
        }
    }
}

