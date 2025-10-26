//! JSON normalization utilities.
//!
//! Provides functions to canonicalize JSON by sorting object keys recursively,
//! useful for deterministic comparisons and testing.

use anyhow::Context;
use serde_json::{Map, Value};
use std::{fs, path::Path};

/// Recursively normalize a JSON value by sorting object keys.
///
/// - Objects: Keys are sorted alphabetically, values are recursively normalized
/// - Arrays: Order is preserved, elements are recursively normalized
/// - Scalars: Returned as-is
///
/// # Examples
/// ```
/// use serde_json::json;
/// use sb_config::json_norm::normalize_value;
///
/// let input = json!({"z": 1, "a": 2});
/// let output = normalize_value(input);
/// // Object keys are now sorted: {"a": 2, "z": 1}
/// ```
#[must_use]
pub fn normalize_value(v: Value) -> Value {
    match v {
        Value::Object(mut m) => {
            let mut nm = Map::new();
            let mut keys: Vec<_> = m.keys().cloned().collect();
            keys.sort_unstable();
            for k in keys {
                if let Some(vv) = m.remove(&k) {
                    nm.insert(k, normalize_value(vv));
                }
            }
            Value::Object(nm)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(normalize_value).collect()),
        x => x,
    }
}

/// Read a JSON file, normalize it, and return the pretty-printed string.
///
/// # Errors
/// Returns an error if:
/// - File cannot be read
/// - Content is not valid JSON
/// - Serialization fails
///
/// # Examples
/// ```no_run
/// use sb_config::json_norm::normalize_file_to_string;
///
/// let normalized = normalize_file_to_string("config.json")?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn normalize_file_to_string(path: impl AsRef<Path>) -> anyhow::Result<String> {
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed to read file: {}", path.as_ref().display()))?;
    let v: Value = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse JSON: {}", path.as_ref().display()))?;
    let nv = normalize_value(v);
    Ok(serde_json::to_string_pretty(&nv)?)
}
