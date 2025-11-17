//! Minimal shared contract for admin/CLI JSON envelopes.
//!
//! This crate defines a standardized JSON response format used across
//! singbox-rust admin APIs and CLI tools, ensuring consistent error
//! handling and data serialization.
//!
//! # Examples
//!
//! ```
//! use sb_admin_contract::{ResponseEnvelope, ErrorKind};
//!
//! // Success response
//! let ok_resp = ResponseEnvelope::ok("data".to_string())
//!     .with_request_id("req-123");
//! assert!(ok_resp.ok);
//!
//! // Error response
//! let err_resp: ResponseEnvelope<()> = ResponseEnvelope::err(
//!     ErrorKind::NotFound,
//!     "Resource not found"
//! );
//! assert!(!err_resp.ok);
//! ```
//!
//! MSRV = 1.90

#![deny(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic, clippy::nursery)]

use serde::{ser::Serializer, Deserialize, Serialize};

/// Recursively removes all `null` values from a JSON value.
///
/// This function traverses objects and arrays, filtering out:
/// - Object keys with `null` values
/// - Recursively processing nested structures
///
/// # Performance
/// Uses single-pass iteration with in-place mutation for efficiency.
fn strip_nulls(mut v: serde_json::Value) -> serde_json::Value {
    match &mut v {
        serde_json::Value::Object(map) => {
            // Remove null entries in-place
            map.retain(|_, val| !val.is_null());
            // Recursively process remaining values
            for val in map.values_mut() {
                *val = strip_nulls(std::mem::take(val));
            }
            serde_json::Value::Object(std::mem::take(map))
        }
        serde_json::Value::Array(arr) => {
            let new = std::mem::take(arr).into_iter().map(strip_nulls).collect();
            serde_json::Value::Array(new)
        }
        _ => v,
    }
}

/// Custom serializer that skips `null` values in nested JSON structures.
///
/// Used by `ResponseEnvelope` to ensure clean JSON output without
/// unnecessary `null` fields in the `data` payload.
///
/// Note: Takes `&Option<T>` instead of `Option<&T>` to match serde's
/// generated code expectations (cannot be changed without manual Serialize impl).
#[allow(clippy::ref_option)]
fn serialize_data_skip_none<T, S>(data: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    match data {
        None => serializer.serialize_none(),
        Some(value) => {
            let json = serde_json::to_value(value).map_err(serde::ser::Error::custom)?;
            let filtered = strip_nulls(json);
            serializer.serialize_some(&filtered)
        }
    }
}

/// Standard JSON response envelope for admin APIs and CLI output.
///
/// Provides a consistent structure for success/failure responses with
/// optional metadata (request ID, error details).
///
/// # Fields
/// - `ok`: `true` for success, `false` for errors
/// - `data`: Optional payload (only present when `ok == true`)
/// - `error`: Optional error details (only present when `ok == false`)
/// - `request_id`: Optional request tracking ID
///
/// # Examples
/// ```
/// use sb_admin_contract::ResponseEnvelope;
///
/// let resp = ResponseEnvelope::ok(vec![1, 2, 3])
///     .with_request_id("abc-123");
/// assert_eq!(resp.request_id, Some("abc-123".to_string()));
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(bound(
    serialize = "T: serde::Serialize",
    deserialize = "T: serde::de::DeserializeOwned"
))]
pub struct ResponseEnvelope<T> {
    /// Indicates success (`true`) or failure (`false`).
    pub ok: bool,
    /// Response data (only present on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(serialize_with = "serialize_data_skip_none")]
    pub data: Option<T>,
    /// Error details (only present on failure).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    /// Optional request tracking identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl<T> ResponseEnvelope<T> {
    /// Creates a successful response with the given data.
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::ResponseEnvelope;
    ///
    /// let resp = ResponseEnvelope::ok("success");
    /// assert!(resp.ok);
    /// assert_eq!(resp.data, Some("success"));
    /// ```
    #[must_use]
    pub const fn ok(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
            request_id: None,
        }
    }

    /// Creates an error response with the specified kind and message.
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::{ResponseEnvelope, ErrorKind};
    ///
    /// let resp: ResponseEnvelope<()> = ResponseEnvelope::err(
    ///     ErrorKind::NotFound,
    ///     "User not found"
    /// );
    /// assert!(!resp.ok);
    /// assert!(resp.error.is_some());
    /// ```
    #[must_use]
    pub fn err(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(ErrorBody {
                kind,
                msg: msg.into(),
                ptr: None,
                hint: None,
            }),
            request_id: None,
        }
    }

    /// Attaches a request ID to this response.
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::ResponseEnvelope;
    ///
    /// let resp = ResponseEnvelope::ok(42)
    ///     .with_request_id("req-999");
    /// assert_eq!(resp.request_id, Some("req-999".to_string()));
    /// ```
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// Returns this envelope as a `Result`, moving the payload on success
    /// or the error body on failure. This is useful for chaining with `?`.
    ///
    /// # Examples
    /// ```
    /// use sb_admin_contract::{ResponseEnvelope, ErrorKind};
    ///
    /// let ok = ResponseEnvelope::ok(1).as_result();
    /// assert_eq!(ok, Ok(1));
    ///
    /// let err: ResponseEnvelope<()> = ResponseEnvelope::err(ErrorKind::Internal, "boom");
    /// assert!(err.as_result().is_err());
    /// ```
    /// # Errors
    /// Returns `Err(ErrorBody)` when `ok == false` or when `ok == true` but
    /// the envelope unexpectedly lacks `data` (defensive fallback).
    pub fn as_result(self) -> Result<T, ErrorBody> {
        if self.ok {
            // `ok` envelopes must not carry `error`.
            // Move the payload out, defaulting to a unit error if malformed (defensive).
            self.data.ok_or_else(|| ErrorBody {
                kind: ErrorKind::Internal,
                msg: "missing data in ok response".to_string(),
                ptr: None,
                hint: Some("this is a bug; please report".to_string()),
            })
        } else {
            // Error envelopes must carry `error`; provide a fallback if absent.
            Err(self.error.unwrap_or_else(|| ErrorBody {
                kind: ErrorKind::Internal,
                msg: "missing error in error response".to_string(),
                ptr: None,
                hint: Some("this is a bug; please report".to_string()),
            }))
        }
    }

    /// Attach a JSON pointer (RFC6901) to the error, if present.
    /// No-op for successful envelopes.
    #[must_use]
    pub fn with_error_ptr(mut self, ptr: impl Into<String>) -> Self {
        if let Some(err) = &mut self.error {
            err.ptr = Some(ptr.into());
        }
        self
    }

    /// Attach a human-readable hint to the error, if present.
    /// No-op for successful envelopes.
    #[must_use]
    pub fn with_error_hint(mut self, hint: impl Into<String>) -> Self {
        if let Some(err) = &mut self.error {
            err.hint = Some(hint.into());
        }
        self
    }
}

/// Detailed error information for failed responses.
///
/// # Fields
/// - `kind`: Categorizes the error type
/// - `msg`: Human-readable error message
/// - `ptr`: Optional JSON pointer to the problematic field (RFC 6901)
/// - `hint`: Optional suggestion for resolving the error
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    /// The category of error.
    pub kind: ErrorKind,
    /// A human-readable error message.
    pub msg: String,
    /// Optional JSON pointer (RFC 6901) to the problematic field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    /// Optional hint for resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// Categorizes different types of errors.
///
/// Marked `#[non_exhaustive]` to allow adding new variants without
/// breaking compatibility.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
#[non_exhaustive]
pub enum ErrorKind {
    /// Resource not found.
    NotFound,
    /// Resource conflict (e.g., duplicate).
    Conflict,
    /// Invalid state transition.
    State,
    /// Authentication/authorization failure.
    Auth,
    /// Rate limit exceeded.
    RateLimit,
    /// I/O error.
    Io,
    /// Decoding/parsing error.
    Decode,
    /// Operation timeout.
    Timeout,
    /// Internal server error.
    Internal,
    /// Custom error type.
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ok() -> Result<(), Box<dyn std::error::Error>> {
        let env =
            ResponseEnvelope::ok(serde_json::json!({"hello": "world"})).with_request_id("r-1");
        let s = serde_json::to_string(&env)?;
        let de: ResponseEnvelope<serde_json::Value> = serde_json::from_str(&s)?;
        assert!(de.ok);
        assert_eq!(de.request_id.as_deref(), Some("r-1"));
        Ok(())
    }

    #[test]
    fn roundtrip_err() -> Result<(), Box<dyn std::error::Error>> {
        let env: ResponseEnvelope<()> =
            ResponseEnvelope::err(ErrorKind::NotFound, "Resource missing");
        let s = serde_json::to_string(&env)?;
        let de: ResponseEnvelope<()> = serde_json::from_str(&s)?;
        assert!(!de.ok);
        assert!(de.data.is_none());
        assert_eq!(
            de.error.as_ref().map(|e| e.msg.as_str()),
            Some("Resource missing")
        );
        Ok(())
    }

    #[test]
    fn strip_nulls_removes_null_values() {
        let input = serde_json::json!({
            "a": 1,
            "b": null,
            "c": {
                "d": null,
                "e": "value"
            },
            "f": [1, null, 3]
        });
        let output = strip_nulls(input);
        assert_eq!(
            output,
            serde_json::json!({
                "a": 1,
                "c": {
                    "e": "value"
                },
                "f": [1, null, 3]  // Array nulls are preserved
            })
        );
    }

    #[test]
    fn serialize_skips_nested_nulls() -> Result<(), Box<dyn std::error::Error>> {
        #[derive(Serialize, Deserialize)]
        struct Data {
            field1: Option<String>,
            field2: String,
        }
        let data = Data {
            field1: None,
            field2: "value".to_string(),
        };
        let env = ResponseEnvelope::ok(data);
        let s = serde_json::to_string(&env)?;
        // Verify nested nulls are stripped
        assert!(!s.contains("field1"));
        assert!(s.contains("field2"));
        Ok(())
    }

    #[test]
    fn error_kinds_serialize_correctly() -> Result<(), Box<dyn std::error::Error>> {
        let kinds = vec![
            ErrorKind::NotFound,
            ErrorKind::Conflict,
            ErrorKind::Auth,
            ErrorKind::Other("custom".to_string()),
        ];
        for kind in kinds {
            let env: ResponseEnvelope<()> = ResponseEnvelope::err(kind, "test");
            let s = serde_json::to_string(&env)?;
            let _: ResponseEnvelope<()> = serde_json::from_str(&s)?;
        }
        Ok(())
    }
}
