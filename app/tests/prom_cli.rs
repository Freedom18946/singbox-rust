#[test]
fn prom_scrape_invalid_filter_fails_without_runtime_panic() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args([
            "prom",
            "scrape",
            "--url",
            "http://127.0.0.1:9/",
            "--filter",
            "[",
        ])
        .output()
        .expect("run app prom scrape");

    assert!(!output.status.success(), "invalid filter must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid --filter regex"),
        "stderr did not report invalid filter: {stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "invalid filter must not panic: {stderr}"
    );
}
