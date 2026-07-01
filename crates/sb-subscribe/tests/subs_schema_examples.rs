#![cfg(feature = "subs_schema")]

use jsonschema::JSONSchema;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn repo_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../..");
    for part in parts {
        path.push(part);
    }
    path
}

fn read_json(parts: &[&str]) -> Value {
    let path = repo_path(parts);
    let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("failed to read {}: {err}", path.display());
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        panic!("failed to parse {}: {err}", path.display());
    })
}

fn assert_valid(compiled: &JSONSchema, value: &Value, label: &str) {
    if let Err(errors) = compiled.validate(value) {
        let messages = errors.map(|err| err.to_string()).collect::<Vec<_>>();
        panic!("{label} should validate: {}", messages.join("; "));
    }
}

#[test]
fn exported_subscription_schema_accepts_sample_and_rejects_bad_fixture() {
    let schema = read_json(&["examples", "schemas", "subs.schema.json"]);
    let compiled = JSONSchema::compile(&schema).expect("subscription schema compiles");

    let sample = read_json(&["examples", "misc", "subs.nodes.sample.json"]);
    assert_valid(&compiled, &sample, "subs.nodes.sample.json");

    let bad = read_json(&["examples", "misc", "subs.bad.json"]);
    let nodes = bad
        .as_array()
        .expect("subs.bad.json remains a node-list array");
    for node in nodes {
        let tag = node
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or("<missing-tag>");
        let wrapped = Value::Array(vec![node.clone()]);
        assert!(
            compiled.validate(&wrapped).is_err(),
            "{tag} should remain invalid against subs.schema.json"
        );
    }
}
