#![cfg(feature = "router")]

use serde_json::{json, Value};

fn parse_json_output(output: &[u8]) -> Value {
    let output_str = String::from_utf8_lossy(output);
    let json_start = output_str.find('{').expect("No JSON in output");
    serde_json::from_str(&output_str[json_start..]).expect("Failed to parse JSON")
}

fn write_config_json(contents: &Value) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temp config");
    std::fs::write(
        file.path(),
        serde_json::to_vec(contents).expect("serialize config"),
    )
    .expect("write config");
    file
}

fn explain(config: &tempfile::NamedTempFile, dest: &str) -> Value {
    let out = assert_cmd::cargo::cargo_bin_cmd!("app")
        .args([
            "route",
            "-c",
            config.path().to_str().expect("config path"),
            "--dest",
            dest,
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    parse_json_output(&out)
}

#[test]
fn parity_spec_domain_rules_match_fqdn_before_default() {
    let config = write_config_json(&json!({
        "outbounds": [
            { "type": "direct", "name": "direct" },
            { "type": "block", "name": "block" }
        ],
        "route": {
            "rules": [
                { "domain": ["api.example.com"], "outbound": "block" }
            ],
            "default": "direct"
        }
    }));

    let fqdn_match = explain(&config, "api.example.com:443");
    assert_eq!(fqdn_match["outbound"], "block");
    assert!(
        fqdn_match["matched_rule"].is_string(),
        "matched rule should be recorded for FQDN hits"
    );

    let unmatched = explain(&config, "api.example.net:443");
    assert_eq!(unmatched["outbound"], "direct");
    assert_ne!(
        fqdn_match["matched_rule"], unmatched["matched_rule"],
        "default path should not report the same rule identity as a suffix hit"
    );
}

#[test]
fn parity_spec_ip_cidr_rules_match_addresses_before_default() {
    let config = write_config_json(&json!({
        "outbounds": [
            { "type": "direct", "name": "direct" },
            { "type": "block", "name": "block" }
        ],
        "route": {
            "rules": [
                { "ip_cidr": ["198.18.0.0/15"], "outbound": "block" }
            ],
            "default": "direct"
        }
    }));

    let cidr_match = explain(&config, "198.18.1.10:443");
    assert_eq!(cidr_match["outbound"], "block");
    assert!(
        cidr_match["matched_rule"].is_string(),
        "matched rule should be recorded for CIDR hits"
    );

    let unmatched = explain(&config, "203.0.113.10:443");
    assert_eq!(unmatched["outbound"], "direct");
    assert_ne!(
        cidr_match["matched_rule"], unmatched["matched_rule"],
        "default path should not report the same rule identity as a CIDR hit"
    );
}
