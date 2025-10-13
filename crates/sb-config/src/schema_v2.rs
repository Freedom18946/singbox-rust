use anyhow::{Context, Result};
use serde_json::Value;

/// Returns the v2 JSON schema for configuration validation
///
/// # Errors
///
/// Returns an error if the embedded schema JSON cannot be parsed.
/// This should never happen in practice since the schema is validated at compile time.
pub fn schema_v2() -> Result<Value> {
    let schema_text = include_str!("validator/v2_schema.json");
    serde_json::from_str(schema_text).context("Failed to parse embedded v2_schema.json")
}
