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

/// Normalize JSON for fingerprinting: sort keys, drop comments, preserve arrays.
///
/// - Objects: Keys are sorted alphabetically, comment keys (`//` or `#` prefix) are dropped
/// - Arrays: Order is preserved (rule ordering matters), elements are recursively normalized
/// - Scalars: Returned as-is
///
/// This produces a canonical representation for stable fingerprinting.
#[must_use]
pub fn normalize_value_for_fingerprint(v: Value) -> Value {
    match v {
        Value::Object(mut m) => {
            let mut nm = Map::new();
            // Filter out comment keys and sort remaining
            let mut keys: Vec<_> = m
                .keys()
                .filter(|k| !k.starts_with("//") && !k.starts_with('#'))
                .cloned()
                .collect();
            keys.sort_unstable();
            for k in keys {
                if let Some(vv) = m.remove(&k) {
                    nm.insert(k, normalize_value_for_fingerprint(vv));
                }
            }
            Value::Object(nm)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .map(normalize_value_for_fingerprint)
                .collect(),
        ),
        x => x,
    }
}

/// Compute stable fingerprint of JSON value: canonical normalization + SHA256.
/// Returns first 8 hex characters of the SHA256 hash.
///
/// This is the canonical fingerprinting function used across all reloads and outputs.
#[must_use]
pub fn fingerprint_hex8(v: &Value) -> String {
    use sha2::{Digest, Sha256};

    let normalized = normalize_value_for_fingerprint(v.clone());
    let bytes = serde_json::to_vec(&normalized).unwrap_or_default();
    let hash = Sha256::digest(&bytes);
    let hex_full = format!("{:x}", hash);
    hex_full[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fingerprint_hex8_length() {
        let v = json!({"foo": "bar"});
        let fp = fingerprint_hex8(&v);
        assert_eq!(fp.len(), 8, "fingerprint should be 8 hex chars");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "should be hex");
    }

    #[test]
    fn test_fingerprint_key_order_independent() {
        // Same content, different key order -> same fingerprint
        let v1 = json!({"z": 1, "a": 2, "m": 3});
        let v2 = json!({"a": 2, "m": 3, "z": 1});
        assert_eq!(fingerprint_hex8(&v1), fingerprint_hex8(&v2));
    }

    #[test]
    fn test_fingerprint_ignores_comments() {
        let with_comment = json!({"foo": "bar", "//note": "ignored", "#todo": "also"});
        let without_comment = json!({"foo": "bar"});
        assert_eq!(
            fingerprint_hex8(&with_comment),
            fingerprint_hex8(&without_comment)
        );
    }

    #[test]
    fn test_fingerprint_preserves_array_order() {
        // Array order matters - different order = different fingerprint
        let v1 = json!({"items": [1, 2, 3]});
        let v2 = json!({"items": [3, 2, 1]});
        assert_ne!(fingerprint_hex8(&v1), fingerprint_hex8(&v2));
    }
}
