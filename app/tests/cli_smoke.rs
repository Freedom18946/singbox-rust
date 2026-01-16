// app/tests/cli_smoke.rs
#[test]
fn minimal_help_and_version() {
    // version binary
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("version");
    cmd.arg("--help");
    let out = cmd.assert().success();
    // basic check
    out.get_output();

    let mut v = assert_cmd::cargo::cargo_bin_cmd!("version");
    v.assert().success();
}

#[cfg(all(
    feature = "router",
    feature = "dsl_analyze",
    feature = "dsl_derive",
    feature = "explain"
))]
#[test]
fn router_route_explain_smoke() {
    let cfg_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ok.json");
    let cfg_arg = cfg_path.to_string_lossy();

    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("route");
    cmd.arg("--help");
    cmd.assert().success();

    // route-explain exists under router
    let mut explain = assert_cmd::cargo::cargo_bin_cmd!("route-explain");
    explain.args([
        "--config",
        cfg_arg.as_ref(),
        "--destination",
        "example.com:443",
        "--format",
        "json",
    ]);
    explain.assert().success();
}

#[cfg(feature = "observe")]
#[test]
fn metrics_export_probe() {
    // Seed a metric so the export is non-empty and stable.
    sb_metrics::set_proxy_select_score("probe", 1.0);
    let text = sb_metrics::export_prometheus();
    assert!(text.contains("proxy_select_score"));
}
