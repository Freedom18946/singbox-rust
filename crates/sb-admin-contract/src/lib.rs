//! Minimal shared contract for admin/CLI JSON envelopes.
//! MSRV = 1.90

#![deny(warnings)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![warn(clippy::pedantic, clippy::nursery)]

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResponseEnvelope<T> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl<T> ResponseEnvelope<T> {
    pub const fn ok(data: T) -> Self {
        Self { ok: true, data: Some(data), error: None, request_id: None }
    }
    pub fn err(kind: ErrorKind, msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(ErrorBody { kind, msg: msg.into(), ptr: None, hint: None }),
            request_id: None,
        }
    }
    #[must_use]
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    pub kind: ErrorKind,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum ErrorKind {
    NotFound,
    Conflict,
    State,
    Auth,
    RateLimit,
    Io,
    Decode,
    Timeout,
    Internal,
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_ok() {
        let env = ResponseEnvelope::ok(serde_json::json!({"hello":"world"})).with_request_id("r-1");
        let s = serde_json::to_string(&env).unwrap();
        let de: ResponseEnvelope<serde_json::Value> = serde_json::from_str(&s).unwrap();
        assert!(de.ok);
        assert_eq!(de.request_id.as_deref(), Some("r-1"));
    }
}