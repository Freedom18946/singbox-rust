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
    assert!(chain.len() >= 1);
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
    assert!(chain.len() >= 1);
}
