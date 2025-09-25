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
fn e2e_route_ip_rule_match_subset() {
    let cfg = r#"{
        "inbounds":[{"type":"socks","listen":"127.0.0.1:1080"}],
        "outbounds":[{"type":"direct","name":"direct"}],
        "rules":[{"ip_cidr":["1.1.1.1/32"],"outbound":"direct"}],
        "default_outbound":"direct"
    }"#;
    let tmp = write_cfg(cfg);
    let dest = "1.1.1.1:53";

    let rust_bin = workspace_bin("singbox-rust");
    let rust = rust_bin.to_string_lossy().to_string();
    let out_rust = run(&rust, &["route","-c", tmp.path().to_str().unwrap(),"--dest",dest,"--explain","--format","json"]).expect("rust route ok");

    if let Some(go) = go_bin() {
        if let Some(out_go) = run(&go, &["route","--config", tmp.path().to_str().unwrap(),"--dest",dest,"--explain","--format","json"]) {
            // Compare subset fields equal
            let v_go: serde_json::Value = serde_json::from_str(&out_go).unwrap();
            let v_rs: serde_json::Value = serde_json::from_str(&out_rust).unwrap();
            for k in ["dest","matched_rule","outbound"] { assert_eq!(v_go.get(k), v_rs.get(k), "key {} differs", k); }
        } else {
            eprintln!("[e2e] go route failed; skipping compare");
        }
    } else {
        eprintln!("[e2e] GO_SINGBOX_BIN not set; skipping compare");
    }
}

