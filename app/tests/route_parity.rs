#![allow(dead_code)]
//! Route explain stability and replay guard tests
//!
//! Ensures route JSON output maintains stable contract:
//! - Fixed field set: dest, matched_rule, chain, outbound
//! - With --with-trace: adds trace field without breaking existing fields
//! - Go/Rust parity: key fields should be structurally equivalent

use assert_cmd::Command;
use serde_json::Value;
use std::fs;

const ROUTE_MIN_CONFIG: &str = include_str!("data/route_min.json");

/// Helper to parse JSON from command output, skipping logging lines
fn parse_json_output(output: &[u8]) -> Value {
    let output_str = String::from_utf8_lossy(output);
    let json_start = output_str.find('{').expect("No JSON in output");
    let json_str = &output_str[json_start..];
    serde_json::from_str(json_str).expect("Failed to parse JSON")
}

fn write_config_json(contents: &serde_json::Value) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temp config");
    std::fs::write(
        file.path(),
        serde_json::to_vec(contents).expect("serialize"),
    )
    .expect("write config");
    file
}

#[cfg(feature = "router")]
#[test]
fn route_explain_stable_fields_without_trace() {
    // Test that route explain output has exactly the expected fields without trace
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), ROUTE_MIN_CONFIG.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);

    // Contract: must have exactly these fields (no trace)
    assert!(result.get("dest").is_some(), "missing 'dest' field");
    assert!(
        result.get("matched_rule").is_some(),
        "missing 'matched_rule' field"
    );
    assert!(result.get("chain").is_some(), "missing 'chain' field");
    assert!(result.get("outbound").is_some(), "missing 'outbound' field");

    // Trace should NOT be present without --with-trace
    assert!(
        result.get("trace").is_none(),
        "trace field should not be present without --with-trace"
    );

    // Verify field types
    assert!(result["dest"].is_string());
    assert!(result["matched_rule"].is_string());
    assert!(result["chain"].is_array());
    assert!(result["outbound"].is_string());
}

#[cfg(feature = "router")]
#[test]
fn route_explain_stable_fields_with_trace() {
    // Test that route explain with --with-trace adds trace without breaking existing fields
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), ROUTE_MIN_CONFIG.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
            "--with-trace",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);

    // Contract: must have all base fields plus trace
    assert!(result.get("dest").is_some(), "missing 'dest' field");
    assert!(
        result.get("matched_rule").is_some(),
        "missing 'matched_rule' field"
    );
    assert!(result.get("chain").is_some(), "missing 'chain' field");
    assert!(result.get("outbound").is_some(), "missing 'outbound' field");
    assert!(
        result.get("trace").is_some(),
        "missing 'trace' field with --with-trace"
    );

    // Verify field types
    assert!(result["dest"].is_string());
    assert!(result["matched_rule"].is_string());
    assert!(result["chain"].is_array());
    assert!(result["outbound"].is_string());
    // Trace can be array or object depending on implementation
    assert!(result["trace"].is_array() || result["trace"].is_object());
}

#[cfg(feature = "router")]
#[test]
fn route_explain_domain_vs_ip_output_differs() {
    let config = serde_json::json!({
        "inbounds": [ { "type": "http", "listen": "127.0.0.1", "port": 18081 } ],
        "outbounds": [
            { "type": "direct", "name": "direct" },
            { "type": "block", "name": "block" }
        ],
        "route": {
            "rules": [
                { "domain_suffix": ["example.com"], "outbound": "block" }
            ],
            "default": "direct"
        }
    });
    let cfg = write_config_json(&config);

    let domain_out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            cfg.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let domain_json = parse_json_output(&domain_out);
    assert_eq!(domain_json["outbound"], "block");

    let ip_out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            cfg.path().to_str().unwrap(),
            "--dest",
            "93.184.216.34:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let ip_json = parse_json_output(&ip_out);
    assert_eq!(ip_json["outbound"], "direct");
    assert_ne!(domain_json["matched_rule"], ip_json["matched_rule"]);
}

#[cfg(feature = "router")]
#[test]
fn route_explain_udp_output_contains_fields() {
    let config = serde_json::json!({
        "inbounds": [ { "type": "http", "listen": "127.0.0.1", "port": 18082 } ],
        "outbounds": [
            { "type": "direct", "name": "tcp-out" },
            { "type": "block", "name": "udp-block" }
        ],
        "route": {
            "rules": [ { "outbound": "tcp-out" } ],
            "default": "tcp-out"
        }
    });
    let cfg = write_config_json(&config);

    let tcp_out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            cfg.path().to_str().unwrap(),
            "--dest",
            "example.com:80",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let tcp_json = parse_json_output(&tcp_out);
    assert_eq!(tcp_json["outbound"], "tcp-out");

    let udp_out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            cfg.path().to_str().unwrap(),
            "--dest",
            "example.com:80",
            "--udp",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let udp_json = parse_json_output(&udp_out);
    assert_eq!(udp_json["dest"], "example.com:80");
    assert!(udp_json["matched_rule"].is_string());
    assert!(udp_json["chain"].is_array());
    assert_eq!(udp_json["outbound"], "tcp-out");
}

#[cfg(feature = "router")]
#[test]
fn route_explain_replay_determinism() {
    // Test that running the same query twice produces identical results (deterministic)
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), ROUTE_MIN_CONFIG.as_bytes()).unwrap();

    let run_query = || {
        Command::cargo_bin("app")
            .unwrap()
            .args([
                "route",
                "-c",
                tmp.path().to_str().unwrap(),
                "--dest",
                "example.com:443",
                "--explain",
                "--format",
                "json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };

    let out1 = run_query();
    let out2 = run_query();

    let result1: Value = serde_json::from_slice(&out1).unwrap();
    let result2: Value = serde_json::from_slice(&out2).unwrap();

    // All fields should be identical across runs
    assert_eq!(result1.get("dest"), result2.get("dest"));
    assert_eq!(result1.get("matched_rule"), result2.get("matched_rule"));
    assert_eq!(result1.get("chain"), result2.get("chain"));
    assert_eq!(result1.get("outbound"), result2.get("outbound"));
}

#[cfg(feature = "router")]
#[test]
fn route_explain_matched_rule_format() {
    // Test that matched_rule has expected format (8-char rule ID)
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), ROUTE_MIN_CONFIG.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);
    let matched_rule = result.get("matched_rule").unwrap().as_str().unwrap();

    // Rule ID should be 8 characters (stable format)
    assert_eq!(matched_rule.len(), 8, "matched_rule should be 8-char ID");
}

#[cfg(feature = "router")]
#[test]
fn route_explain_chain_structure() {
    // Test that chain is a non-empty array with valid entries
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), ROUTE_MIN_CONFIG.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);
    let chain = result.get("chain").unwrap().as_array().unwrap();

    // Chain should have at least one entry
    assert!(!chain.is_empty(), "chain should not be empty");

    // Each entry should be a string
    for entry in chain {
        assert!(entry.is_string(), "chain entry should be string");
    }
}

// ============================================================================
// SECTION: Route Vector Replay Tests (Go/Rust Parity)
// ============================================================================
// These tests replay sample route decisions against known golden configs
// to verify:
// - Correct outbound selection (direct/blackhole/selector/geoip)
// - Stable matched_rule and chain structure
// - Case stability (field names, outbound names)

#[cfg(feature = "router")]
#[test]
fn route_vector_direct_localhost() {
    // Vector: direct.json - localhost should route to DIRECT
    let config = include_str!("data/route_vectors/direct.json");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "localhost:80",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // Parse JSON, skipping any logging lines
    let output_str = String::from_utf8_lossy(&out);
    let json_start = output_str.find('{').expect("No JSON in output");
    let json_str = &output_str[json_start..];
    let result: Value = serde_json::from_str(json_str).unwrap();

    // Verify parity: outbound should be DIRECT (case-sensitive)
    assert_eq!(result["outbound"].as_str().unwrap(), "DIRECT");
    assert_eq!(result["dest"].as_str().unwrap(), "localhost:80");

    // matched_rule should be 8-char hex ID
    let matched_rule = result["matched_rule"].as_str().unwrap();
    assert_eq!(matched_rule.len(), 8);

    // chain should contain DIRECT
    let chain = result["chain"].as_array().unwrap();
    assert!(chain.iter().any(|v| v.as_str() == Some("DIRECT")));
}

#[cfg(feature = "router")]
#[test]
fn route_vector_blackhole_ads() {
    // Vector: blackhole.json - ads.example.com should route to BLOCK
    let config = include_str!("data/route_vectors/blackhole.json");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "ads.example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);

    // Verify parity: outbound should be BLOCK
    assert_eq!(result["outbound"].as_str().unwrap(), "BLOCK");
    assert_eq!(result["dest"].as_str().unwrap(), "ads.example.com:443");
}

#[cfg(feature = "router")]
#[test]
fn route_vector_blackhole_default_fallthrough() {
    // Vector: blackhole.json - non-matching domain should fallthrough to DIRECT
    let config = include_str!("data/route_vectors/blackhole.json");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);

    // Verify parity: should fallthrough to default (DIRECT)
    assert_eq!(result["outbound"].as_str().unwrap(), "DIRECT");
}

#[cfg(feature = "router")]
#[test]
fn route_vector_selector_rule_match() {
    // Vector: selector.json - test selector with tag-based routing
    let config = include_str!("data/route_vectors/selector.json");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config.as_bytes()).unwrap();

    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "api.example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);

    // Verify structure: outbound should be present and non-empty
    let outbound = result["outbound"].as_str().unwrap();
    assert!(!outbound.is_empty(), "outbound should not be empty");

    // matched_rule should be stable 8-char ID
    assert_eq!(result["matched_rule"].as_str().unwrap().len(), 8);
}

#[cfg(feature = "router")]
#[test]
fn route_vector_geoip_cn() {
    // Vector: geoip.json - Chinese IP should route appropriately
    let config = include_str!("data/route_vectors/geoip.json");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config.as_bytes()).unwrap();

    // Test with a known Chinese IP range (example: 1.2.4.0 is CN)
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "1.2.4.8:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);

    // Verify structure: should have valid routing decision
    assert!(result.get("outbound").is_some());
    assert!(result.get("matched_rule").is_some());
    assert!(result.get("chain").is_some());
}

// ============================================================================
// SECTION: Check Command Parity Tests
// ============================================================================
// These tests verify that `app check` command maintains stable exit codes
// and error reporting across Rust/Go implementations

#[test]
fn check_parity_valid_config() {
    // Valid config should exit 0
    let config = include_str!("data/ok.json");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config.as_bytes()).unwrap();

    Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();
}

#[test]
fn check_parity_invalid_config() {
    // Invalid config should exit 1 with error details
    let config = include_str!("data/bad.json");
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config.as_bytes()).unwrap();

    let output = Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
            "--schema-v2-validate",
        ])
        .assert()
        .failure()
        .get_output()
        .stdout
        .clone();

    let result: Value = serde_json::from_slice(&output).unwrap();

    // Check should return issues array with at least one error
    assert!(result.get("issues").is_some());
    let issues = result["issues"].as_array().unwrap();
    let errors: Vec<_> = issues
        .iter()
        .filter(|i| i.get("level").and_then(|l| l.as_str()) == Some("error"))
        .collect();
    assert!(
        !errors.is_empty(),
        "bad config should produce at least one error"
    );

    // Each error should have code and message
    for error in errors {
        assert!(error.get("code").is_some(), "error should have code");
        assert!(error.get("message").is_some(), "error should have message");
    }
}

#[test]
fn check_parity_type_mismatch() {
    // Type mismatch (e.g., port as string) should be caught
    let bad_type_config = r#"{
        "inbounds": [{ "type": "http", "listen": "127.0.0.1", "port": "not_a_number" }],
        "outbounds": [{ "type": "direct", "name": "direct" }]
    }"#;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), bad_type_config.as_bytes()).unwrap();

    Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
            "--schema-v2-validate",
        ])
        .assert()
        .failure();
}

#[test]
fn check_parity_missing_required_field() {
    // Missing required field should be reported
    let missing_field = r#"{
        "inbounds": [{ "type": "http", "listen": "127.0.0.1" }],
        "outbounds": []
    }"#;

    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), missing_field.as_bytes()).unwrap();

    Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
            "--schema-v2-validate",
        ])
        .assert()
        .failure();
}

// ============================================================================
// SECTION: Performance Smoke Tests (Local Validation Only)
// ============================================================================
// These tests are marked #[ignore] and only run manually via:
//   cargo test --features acceptance -- --ignored
// They verify stability under repeated operations without timing.

#[cfg(feature = "router")]
#[test]
#[ignore]
fn perf_smoke_route_explain_1k_iterations() {
    // Smoke test: Run route explain 1000 times to verify stability
    // Does NOT measure timing, only validates no panics/leaks/crashes
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), ROUTE_MIN_CONFIG.as_bytes()).unwrap();

    println!("[perf_smoke] Running 1000 route explain iterations...");

    for i in 0..1000 {
        let out = Command::cargo_bin("app")
            .unwrap()
            .args([
                "route",
                "-c",
                tmp.path().to_str().unwrap(),
                "--dest",
                &format!("example{}.com:443", i % 10), // Vary destination
                "--explain",
                "--format",
                "json",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let result: Value = parse_json_output(&out);

        // Verify output structure is stable across all iterations
        assert!(result.get("dest").is_some());
        assert!(result.get("matched_rule").is_some());
        assert!(result.get("chain").is_some());
        assert!(result.get("outbound").is_some());

        if (i + 1) % 100 == 0 {
            println!("  ... {} iterations completed", i + 1);
        }
    }

    println!("[perf_smoke] ✓ 1000 iterations completed successfully");
}

#[test]
#[ignore]
fn perf_smoke_check_large_config() {
    // Smoke test: Check a large config (~1-5MB with repeated rules)
    // Verifies no OOM, no timeout (uses default TEST_TIMEOUT_SECS)

    println!("[perf_smoke] Generating large config with 1000 rules...");

    // Generate a config with 1000 domain rules
    let mut config = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "http", "listen": "127.0.0.1", "port": 18081 }],
        "outbounds": [
            { "type": "direct", "name": "DIRECT" },
            { "type": "block", "name": "BLOCK" }
        ],
        "route": {
            "rules": [],
            "default": "DIRECT"
        }
    });

    // Add 1000 rules with varying patterns
    for i in 0..1000 {
        config["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "domain": [format!("domain{}.example.com", i)],
                "outbound": if i % 2 == 0 { "DIRECT" } else { "BLOCK" }
            }));
    }

    let config_str = serde_json::to_string_pretty(&config).unwrap();
    println!("[perf_smoke] Config size: {} bytes", config_str.len());

    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config_str.as_bytes()).unwrap();

    println!("[perf_smoke] Running check on large config...");

    // Should complete without OOM or timeout
    Command::cargo_bin("app")
        .unwrap()
        .args([
            "check",
            "-c",
            tmp.path().to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    println!("[perf_smoke] ✓ Large config check completed successfully");
}

#[cfg(feature = "router")]
#[test]
#[ignore]
fn perf_smoke_route_explain_large_ruleset() {
    // Smoke test: Route explain with large ruleset (similar to check_large_config)
    println!("[perf_smoke] Testing route explain with 1000-rule config...");

    let mut config = serde_json::json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "http", "listen": "127.0.0.1", "port": 18081 }],
        "outbounds": [
            { "type": "direct", "name": "DIRECT" },
            { "type": "block", "name": "BLOCK" }
        ],
        "route": {
            "rules": [],
            "default": "DIRECT"
        }
    });

    for i in 0..1000 {
        config["route"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "domain": [format!("rule{}.test.com", i)],
                "outbound": "BLOCK"
            }));
    }

    let config_str = serde_json::to_string(&config).unwrap();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), config_str.as_bytes()).unwrap();

    // Test route explain against non-matching domain (exercises full rule scan)
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let result: Value = parse_json_output(&out);

    // Should fallthrough to default after checking all 1000 rules
    assert_eq!(result["outbound"].as_str().unwrap(), "DIRECT");

    println!("[perf_smoke] ✓ Route explain with 1000 rules completed");
}
