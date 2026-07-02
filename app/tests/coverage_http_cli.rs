#![cfg(feature = "rule_coverage")]

#[test]
fn coverage_http_rejects_invalid_listen_address() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("coverage-http")
        .env("SB_COV_ADDR", "not-a-socket-addr")
        .output()
        .expect("run coverage-http");

    assert!(!output.status.success(), "invalid address must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid SB_COV_ADDR"),
        "stderr did not report invalid address: {stderr}"
    );
}
