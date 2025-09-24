//! sb-types: cross-crate stable contracts (error codes, shared enums/structs).
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
    pub fn as_str(&self) -> &'static str {
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

/// Common error payload shape used across crates (optional helper).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuePayload {
    pub kind: String,
    pub code: IssueCode,
    pub ptr: Option<String>,
    pub msg: String,
    pub hint: Option<String>,
    pub fingerprint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issuecode_serialization() {
        let j = serde_json::to_string(&IssueCode::SchemaInvalid).unwrap();
        assert_eq!(j, r#""SCHEMA_INVALID""#);
    }
}
