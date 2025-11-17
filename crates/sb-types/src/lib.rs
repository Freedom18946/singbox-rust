//! sb-types: cross-crate stable contracts (error codes, shared enums/structs).
//! This crate defines small, stable data types shared across the workspace.
//!
//! Design notes:
//! - Keep enums string-serializable for human-friendly logs and wire formats.
//! - Avoid breaking changes (e.g., variant renames) to preserve compatibility.
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Stable issue codes used by config validation / CLI / network diagnostics.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum IssueCode {
    // ----- CLI / General -----
    CliInvalidArg,
    CliIoFail,
    // ----- Validation / Schema -----
    UnknownField,
    MissingRequired,
    TypeMismatch,
    RangeExceeded,
    InvalidEnum,
    Conflict,
    // Legacy compatibility
    InvalidType,
    OutOfRange,
    DuplicateTag,
    SchemaInvalid,
    SchemaMissingField,
    SchemaTypeMismatch,
    SchemaRangeInvalid,
    // ----- CLI tools -----
    MinimizeSkippedByNegation,
    // ----- TLS -----
    TlsHandshakeTimeout,
    TlsHandshakeProtocol,
    TlsCertInvalid,
    // ----- Network / Transport -----
    NetTimeout,
    NetRefused,
    NetProto,
    NetCert,
    NetOther,
    // ----- Upstream/Network -----
    UpstreamTimeout,
    UpstreamIcmp,
    UpstreamRefused,
    UpstreamOther,
}

impl IssueCode {
    /// Returns the canonical string representation of the issue code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        use IssueCode::*;
        match self {
            CliInvalidArg => "CliInvalidArg",
            CliIoFail => "CliIoFail",
            UnknownField => "UnknownField",
            MissingRequired => "MissingRequired",
            TypeMismatch => "TypeMismatch",
            RangeExceeded => "RangeExceeded",
            InvalidEnum => "InvalidEnum",
            Conflict => "Conflict",
            InvalidType => "InvalidType",
            OutOfRange => "OutOfRange",
            DuplicateTag => "DuplicateTag",
            SchemaInvalid => "SchemaInvalid",
            SchemaMissingField => "SchemaMissingField",
            SchemaTypeMismatch => "SchemaTypeMismatch",
            SchemaRangeInvalid => "SchemaRangeInvalid",
            MinimizeSkippedByNegation => "MinimizeSkippedByNegation",
            TlsHandshakeTimeout => "TlsHandshakeTimeout",
            TlsHandshakeProtocol => "TlsHandshakeProtocol",
            TlsCertInvalid => "TlsCertInvalid",
            NetTimeout => "NetTimeout",
            NetRefused => "NetRefused",
            NetProto => "NetProto",
            NetCert => "NetCert",
            NetOther => "NetOther",
            UpstreamTimeout => "UpstreamTimeout",
            UpstreamIcmp => "UpstreamIcmp",
            UpstreamRefused => "UpstreamRefused",
            UpstreamOther => "UpstreamOther",
        }
    }
}

impl Display for IssueCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for IssueCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Common error payload shape used across crates (optional helper).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IssuePayload {
    /// Error kind/category (e.g., "schema", "cli", "network").
    pub kind: String,
    /// Stable machine-readable code.
    pub code: IssueCode,
    /// Optional RFC6901 JSON Pointer pointing to the offending location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ptr: Option<String>,
    /// Human-readable message.
    pub msg: String,
    /// Optional remediation hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Optional build/runtime fingerprint for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

impl IssuePayload {
    /// Construct a new payload with the required fields.
    #[inline]
    pub fn new(kind: impl Into<String>, code: IssueCode, msg: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            code,
            ptr: None,
            msg: msg.into(),
            hint: None,
            fingerprint: None,
        }
    }

    /// Attach a JSON pointer.
    #[inline]
    pub fn with_ptr(mut self, ptr: impl Into<String>) -> Self {
        self.ptr = Some(ptr.into());
        self
    }

    /// Attach a hint message.
    #[inline]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Attach a fingerprint string.
    #[inline]
    pub fn with_fingerprint(mut self, fp: impl Into<String>) -> Self {
        self.fingerprint = Some(fp.into());
        self
    }
}

impl Display for IssuePayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Compact single-line format for logs.
        match (&self.ptr, &self.hint) {
            (Some(ptr), Some(hint)) => write!(
                f,
                "[{kind}] {code}: {msg} (at {ptr}; hint: {hint})",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
            (Some(ptr), None) => write!(
                f,
                "[{kind}] {code}: {msg} (at {ptr})",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
            (None, Some(hint)) => write!(
                f,
                "[{kind}] {code}: {msg} (hint: {hint})",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
            (None, None) => write!(
                f,
                "[{kind}] {code}: {msg}",
                kind = self.kind,
                code = self.code,
                msg = self.msg
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issuecode_serialization() {
        let res = serde_json::to_string(&IssueCode::SchemaInvalid);
        match res {
            Ok(j) => assert_eq!(j, "\"SchemaInvalid\""),
            Err(e) => panic!("serialization failed: {e}"),
        }
    }
}
