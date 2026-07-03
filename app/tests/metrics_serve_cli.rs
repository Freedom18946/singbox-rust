#![cfg(feature = "observe")]

use std::net::TcpListener;
use std::time::Duration;

#[test]
fn metrics_serve_rejects_occupied_listen_addr() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let occupied_addr = listener.local_addr()?;

    let output = assert_cmd::cargo::cargo_bin_cmd!("metrics-serve")
        .env("SB_METRICS_ADDR", occupied_addr.to_string())
        .env("RUST_LOG", "off")
        .timeout(Duration::from_secs(5))
        .output()?;

    assert!(
        !output.status.success(),
        "metrics-serve must fail when its listen address is already in use"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("READY"),
        "metrics-serve must not report READY after bind failure: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("metrics exporter bind failed")
            || stderr.contains("Address already in use"),
        "stderr did not report metrics bind failure: {stderr}"
    );

    Ok(())
}
