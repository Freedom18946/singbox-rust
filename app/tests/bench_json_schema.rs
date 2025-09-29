#[cfg(feature = "reqwest")]
use assert_cmd::Command;
#[cfg(feature = "reqwest")]
use serde_json::Value;

#[cfg(feature = "reqwest")]
#[test]
fn bench_io_json_schema_fields_exist() {
    // requests=0 avoids real network I/O, still emits stats
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "bench",
            "io",
            "--url",
            "http://example.com/",
            "--requests",
            "0",
            "--concurrency",
            "1",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let v: Value = serde_json::from_slice(&out).unwrap();
    for k in [
        "p50",
        "p90",
        "p99",
        "rps",
        "throughput_bps",
        "elapsed_ms",
        "histogram",
    ] {
        assert!(v.get(k).is_some(), "missing key: {k}");
    }
}
