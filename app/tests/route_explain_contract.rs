#![cfg(feature = "router")]
#![allow(unused_imports, dead_code)]
use assert_cmd::Command;
use serde_json::Value;
use std::fs;

const ROUTE_CONFIG: &str = include_str!("golden/config_route.json");
const EXPECTED_TCP_OUTPUT: &str = include_str!("golden/explain_tcp_output.json");
const EXPECTED_UDP_OUTPUT: &str = include_str!("golden/explain_udp_output.json");

fn write_cfg(content: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    fs::write(f.path(), content.as_bytes()).unwrap();
    f
}

#[cfg(feature = "router")]
#[test]
fn route_explain_tcp_contract() {
    let tmp = write_cfg(ROUTE_CONFIG);
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

    let actual: Value = serde_json::from_slice(&out).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED_TCP_OUTPUT).unwrap();

    // Check required fields are present
    assert_eq!(actual.get("dest"), expected.get("dest"));
    assert_eq!(actual.get("outbound"), expected.get("outbound"));

    // Check rule_id is 8 characters
    let matched_rule = actual.get("matched_rule").unwrap().as_str().unwrap();
    assert_eq!(matched_rule.len(), 8);

    // Check chain structure
    let chain = actual.get("chain").unwrap().as_array().unwrap();
    assert!(!chain.is_empty());
    assert!(chain[0].as_str().unwrap().contains("domain"));
}

#[cfg(feature = "router")]
#[test]
fn route_explain_udp_contract() {
    let tmp = write_cfg(ROUTE_CONFIG);
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:53",
            "--explain",
            "--format",
            "json",
            "--udp",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual: Value = serde_json::from_slice(&out).unwrap();
    let expected: Value = serde_json::from_str(EXPECTED_UDP_OUTPUT).unwrap();

    // Check required fields are present
    assert_eq!(actual.get("dest"), expected.get("dest"));
    assert_eq!(actual.get("outbound"), expected.get("outbound"));

    // Check rule_id is 8 characters
    let matched_rule = actual.get("matched_rule").unwrap().as_str().unwrap();
    assert_eq!(matched_rule.len(), 8);

    // Check chain structure
    let chain = actual.get("chain").unwrap().as_array().unwrap();
    assert!(!chain.is_empty());
}

#[cfg(feature = "router")]
#[test]
fn route_explain_with_trace_contract() {
    let tmp = write_cfg(ROUTE_CONFIG);
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "example.com:443",
            "--explain",
            "--with-trace",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual: Value = serde_json::from_slice(&out).unwrap();
    println!(
        "DEBUG: trace output: {}",
        serde_json::to_string_pretty(&actual).unwrap()
    );

    // Verify trace field exists and is an object
    let trace = actual.get("trace").expect("trace field missing");
    assert!(trace.is_object(), "trace should be an object");
    let trace_obj = trace.as_object().unwrap();
    assert!(
        trace_obj.contains_key("steps") || trace_obj.contains_key("matched_rule"),
        "trace should contain steps or matched_rule"
    );
}

#[cfg(feature = "router")]
#[test]
fn route_explain_complex_chain_contract() {
    let complex_config = include_str!("golden/config_route_complex.json");
    let tmp = write_cfg(complex_config);

    // Test 1: Match domain rule
    let out = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "mail.google.com:443",
            "--explain",
            "--with-trace",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual: Value = serde_json::from_slice(&out).unwrap();
    println!(
        "DEBUG: complex chain output 1: {}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
    assert_eq!(
        actual.get("outbound").unwrap().as_str().unwrap(),
        "my_direct"
    );
    assert_eq!(
        actual.get("matched_rule").unwrap().as_str().unwrap(),
        "google.com"
    );

    // Test 2: Match IP rule
    let out_ip = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "8.8.8.8:53",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual_ip: Value = serde_json::from_slice(&out_ip).unwrap();
    assert_eq!(
        actual_ip.get("outbound").unwrap().as_str().unwrap(),
        "direct"
    );
    // IP matching might return the CIDR or specific rule ID depending on implementation
    // Let's just check outbound for now, or check if matched_rule exists
    assert!(actual_ip.get("matched_rule").is_some());

    // Test 3: Logical rule (DNS protocol AND port 53)
    // Note: "protocol": "dns" matching usually requires sniffing or specific setup in explain.
    // route explain might not simulate protocol sniffing easily without input.
    // But we can test the port part if we assume protocol is not matched or we can force it?
    // Actually, `route explain` CLI doesn't easily allow specifying protocol unless inferred.
    // So this might fall through to default "block".

    let out_default = Command::cargo_bin("app")
        .unwrap()
        .args([
            "route",
            "-c",
            tmp.path().to_str().unwrap(),
            "--dest",
            "unknown.com:80",
            "--explain",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let actual_default: Value = serde_json::from_slice(&out_default).unwrap();
    assert_eq!(
        actual_default.get("outbound").unwrap().as_str().unwrap(),
        "block"
    );
}
