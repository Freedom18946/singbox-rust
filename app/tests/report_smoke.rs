#[test]
fn report_json_shape_ok() {
    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("report");
    let out = cmd.output().expect("run report");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert!(v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false));
    let build = v.get("build").expect("build");
    assert!(build.get("git_sha").is_some());
    assert!(build.get("build_ts").is_some());
    let repo = v.get("repo").expect("repo");
    let metrics = repo.get("metrics").expect("metrics");
    assert!(metrics.get("error_json").is_some());
    assert!(metrics.get("analyze_dispatch").is_some());
    assert!(metrics.get("bin_gates").is_some());
}
