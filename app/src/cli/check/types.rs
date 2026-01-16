use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueKind {
    Error,
    Warning,
}

// Use the shared, stable IssueCode from sb-types to enforce cross-crate consistency
pub use sb_types::IssueCode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckIssue {
    #[serde(rename = "level")]
    pub kind: IssueKind,
    /// RFC6901 JSON Pointer
    pub ptr: String,
    #[serde(rename = "message")]
    pub msg: String,
    pub code: IssueCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Optional stable rule id (sha8) when `SB_CHECK_RULEID=1` and ptr points to `/route/rules/N`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<usize>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReport {
    pub ok: bool,
    pub file: String,
    pub issues: Vec<CheckIssue>,
    pub summary: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical: Option<Value>,
}

/// Helper function to create a warning issue
pub fn push_warn(
    issues: &mut Vec<CheckIssue>,
    code: IssueCode,
    ptr: &str,
    msg: &str,
    hint: Option<&str>,
) {
    issues.push(CheckIssue {
        kind: IssueKind::Warning,
        ptr: ptr.to_string(),
        msg: msg.to_string(),
        code,
        hint: hint.map(std::string::ToString::to_string),
        rule_id: None,
        key: None,
        members: None,
        tos: None,
        risk: None,
    });
}

/// Helper function to create an error issue
pub fn push_err(
    issues: &mut Vec<CheckIssue>,
    code: IssueCode,
    ptr: &str,
    msg: &str,
    hint: Option<&str>,
) {
    issues.push(CheckIssue {
        kind: IssueKind::Error,
        ptr: ptr.to_string(),
        msg: msg.to_string(),
        code,
        hint: hint.map(std::string::ToString::to_string),
        rule_id: None,
        key: None,
        members: None,
        tos: None,
        risk: None,
    });
}
