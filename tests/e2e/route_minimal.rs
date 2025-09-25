use std::process::Command;
use std::str;
use xtests::workspace_bin;

fn go_bin() -> Option<String> {
    std::env::var("GO_SINGBOX_BIN").ok().filter(|s| !s.is_empty())
}

fn have_go() -> bool { go_bin().is_some() }

fn run_cmd(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    if !out.status.success() { return None; }
    String::from_utf8(out.stdout).ok()
}

fn filter_explain_json(raw: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    // 保持字段顺序（手动组装）
    let mut obj = serde_json::Map::new();
    obj.insert("dest".into(), v.get("dest")?.clone());
    obj.insert("matched_rule".into(), v.get("matched_rule")?.clone());
    obj.insert("chain".into(), v.get("chain")?.clone());
    obj.insert("outbound".into(), v.get("outbound")?.clone());
    Some(serde_json::to_string_pretty(&serde_json::Value::Object(obj)).ok()?)
}

#[test]
fn e2e_route_minimal_subset_compat() {
    if !have_go() {
        eprintln!("[e2e] GO_SINGBOX_BIN not set; skipping (compat)");
        return;
    }

    // minimal config shipped in repo root
    let cfg = "minimal.yaml";
    let dest = "example.com:443";

    let go = go_bin().unwrap();
    let go_out = match run_cmd(
        &go,
        &["route","--config",cfg,"--dest",dest,"--explain","--format","json"],
    ) { Some(s) => s, None => { eprintln!("[e2e] go route failed; skipping"); return; } };

    let rust_bin = workspace_bin("singbox-rust");
    let rust_bin = rust_bin.to_string_lossy().to_string();
    let rust_out = match run_cmd(
        &rust_bin,
        &["route","--config",cfg,"--dest",dest,"--explain","--format","json"],
    ) { Some(s) => s, None => { panic!("rust route failed"); } };

    let go_view = filter_explain_json(&go_out).expect("go subset json");
    let rs_view = filter_explain_json(&rust_out).expect("rust subset json");
    assert_eq!(go_view, rs_view, "subset JSON must match exactly");
}
