// app/tests/cli_smoke.rs
use assert_cmd::prelude::*;
use std::process::Command;

#[test]
fn minimal_help_and_version() {
    // version binary
    let mut cmd = Command::cargo_bin("version").expect("version bin");
    cmd.arg("--help");
    let out = cmd.assert().success();
    // basic check
    out.get_output();

    let mut v = Command::cargo_bin("version").expect("version bin");
    v.assert().success();
}

#[cfg(feature = "router")]
#[test]
fn router_route_explain_smoke() {
    let mut cmd = Command::cargo_bin("route").expect("route bin");
    cmd.arg("--help");
    cmd.assert().success();

    // route-explain exists under router
    let mut explain = Command::cargo_bin("route-explain").expect("route-explain bin");
    explain.args(["--sni", "example.com", "--port", "443", "--json"]);
    explain.assert().success();
}

#[cfg(feature = "observe")]
#[test]
fn metrics_export_probe() {
    // The registry is always present; exporting should succeed
    let text = sb_metrics::registry::export_prometheus();
    assert!(text.contains("sb_build_info") || text.contains("proxy_select_score"));
}
