use serde_json::Value;

/// Returns the v2 JSON schema for configuration validation
pub fn schema_v2() -> Value {
    let schema_text = include_str!("validator/v2_schema.json");
    serde_json::from_str(schema_text).expect("v2_schema.json should be valid JSON")
}
