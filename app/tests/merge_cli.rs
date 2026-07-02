use std::fs;

#[test]
fn merge_rejects_missing_inline_resource_path() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let config_path = dir.path().join("config.json");
    let output_path = dir.path().join("merged.json");
    let missing_path = dir.path().join("missing-cert.pem");

    fs::write(
        &config_path,
        serde_json::to_string_pretty(&serde_json::json!({
            "outbounds": [
                {
                    "type": "http",
                    "tag": "proxy",
                    "tls": {
                        "certificate_path": missing_path
                    }
                }
            ]
        }))?,
    )?;

    let output = assert_cmd::cargo::cargo_bin_cmd!("merge")
        .arg("-c")
        .arg(&config_path)
        .arg(&output_path)
        .output()?;

    assert!(!output.status.success(), "missing inline path must fail");
    assert!(
        !output_path.exists(),
        "merge should not write output after inline failure"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("read inline resource path"),
        "stderr did not report inline resource read failure: {stderr}"
    );
    Ok(())
}
