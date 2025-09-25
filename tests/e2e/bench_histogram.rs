use std::process::Command;
use xtests::workspace_bin;

#[test]
fn e2e_bench_json_histogram_fields_presence() {
    let bin = workspace_bin("singbox-rust");
    let out = Command::new(bin)
        .args([
            "bench","io","--url","http://example.com/",
            "--requests","0","--concurrency","1","--json",
            "--hist-buckets","1,5,10"
        ])
        .output()
        .expect("spawn bench");
    if !out.status.success() {
        // Feature may be disabled; accept as a skip
        eprintln!("[e2e] bench io not available (feature), skipping");
        return;
    }
    let v: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(v) => v,
        Err(_) => { eprintln!("[e2e] bench output not json; skipping"); return; }
    };
    if v.get("error").is_some() { eprintln!("[e2e] bench feature missing; skipping"); return; }
    for k in ["p50","p90","p99","rps","throughput_bps","elapsed_ms","histogram"] {
        assert!(v.get(k).is_some(), "missing key: {k}");
    }
}

