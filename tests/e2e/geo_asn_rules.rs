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
    let mut obj = serde_json::Map::new();
    obj.insert("dest".into(), v.get("dest")?.clone());
    obj.insert("matched_rule".into(), v.get("matched_rule")?.clone());
    obj.insert("chain".into(), v.get("chain")?.clone());
    obj.insert("outbound".into(), v.get("outbound")?.clone());
    if let Some(geo) = v.get("geoip") { obj.insert("geoip".into(), geo.clone()); }
    if let Some(asn) = v.get("asn") { obj.insert("asn".into(), asn.clone()); }
    Some(serde_json::to_string_pretty(&serde_json::Value::Object(obj)).ok()?)
}

#[test]
fn e2e_geoip_rules_compat() {
    if !have_go() {
        eprintln!("[e2e] GO_SINGBOX_BIN not set; skipping GeoIP compat");
        return;
    }

    let cfg = "minimal.yaml";
    let dest = "8.8.8.8:53";

    let go = go_bin().unwrap();
    let go_out = match run_cmd(
        &go,
        &["route","--config",cfg,"--dest",dest,"--explain","--format","json"],
    ) { Some(s) => s, None => { eprintln!("[e2e] go GeoIP failed; skipping"); return; } };

    let rust_bin = workspace_bin("singbox-rust");
    let rust_bin = rust_bin.to_string_lossy().to_string();
    let rust_out = match run_cmd(
        &rust_bin,
        &["route","--config",cfg,"--dest",dest,"--explain","--format","json"],
    ) { Some(s) => s, None => { panic!("rust GeoIP failed"); } };

    let go_view = filter_explain_json(&go_out).expect("go GeoIP JSON");
    let rs_view = filter_explain_json(&rust_out).expect("rust GeoIP JSON");
    assert_eq!(go_view, rs_view, "GeoIP JSON must match exactly");
}

#[test]
fn e2e_asn_rules_compat() {
    if !have_go() {
        eprintln!("[e2e] GO_SINGBOX_BIN not set; skipping ASN compat");
        return;
    }

    let cfg = "minimal.yaml";
    let dest = "1.1.1.1:443";

    let go = go_bin().unwrap();
    let go_out = match run_cmd(
        &go,
        &["route","--config",cfg,"--dest",dest,"--explain","--format","json"],
    ) { Some(s) => s, None => { eprintln!("[e2e] go ASN failed; skipping"); return; } };

    let rust_bin = workspace_bin("singbox-rust");
    let rust_bin = rust_bin.to_string_lossy().to_string();
    let rust_out = match run_cmd(
        &rust_bin,
        &["route","--config",cfg,"--dest",dest,"--explain","--format","json"],
    ) { Some(s) => s, None => { panic!("rust ASN failed"); } };

    let go_view = filter_explain_json(&go_out).expect("go ASN JSON");
    let rs_view = filter_explain_json(&rust_out).expect("rust ASN JSON");
    assert_eq!(go_view, rs_view, "ASN JSON must match exactly");
}