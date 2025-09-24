use std::{fmt, io, time::Duration};
use thiserror::Error;

#[cfg(feature = "error-v2")]
use serde::{Deserialize, Serialize};

pub type Result<T, E = Error> = std::result::Result<T, E>;
pub type SbResult<T> = std::result::Result<T, SbError>;

/// Legacy error type for backward compatibility
#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("timeout after {0:?}")]
    Timeout(Duration),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("protocol: {0}")]
    Protocol(&'static str),

    #[error("unreachable")]
    Unreachable,

    #[error("refused")]
    Refused,

    #[error("canceled")]
    Canceled,

    #[error("internal: {0}")]
    Internal(&'static str),
}

/// Schema v2 error system with structured error reporting
#[derive(Debug, Clone, PartialEq)]
pub enum SbError {
    Config {
        code: IssueCode,
        ptr: String,
        msg: String,
        hint: Option<String>,
    },
    Network {
        class: ErrorClass,
        msg: String,
    },
    Timeout {
        operation: String,
        timeout_ms: u64,
    },
    Capacity {
        what: String,
        limit: usize,
    },
}

/// Issue codes for configuration validation errors
pub use sb_types::IssueCode;

/// Error classification for network and protocol errors
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorClass {
    Connection,
    Protocol,
    Authentication,
    Configuration,
    Resource,
}

/// Structured error report for Schema v2 validation
#[derive(Debug)]
#[cfg_attr(feature = "error-v2", derive(Serialize))]
pub struct ErrorReport {
    pub issues: Vec<Issue>,
    pub fingerprint: String,
}

/// Individual issue in error report
#[derive(Debug)]
#[cfg_attr(feature = "error-v2", derive(Serialize))]
pub struct Issue {
    pub kind: String,
    pub code: String,
    pub ptr: String,
    pub msg: String,
    pub hint: Option<String>,
}

impl fmt::Display for SbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SbError::Config {
                code,
                ptr,
                msg,
                hint,
            } => {
                write!(f, "Config error [{:?}] at {}: {}", code, ptr, msg)?;
                if let Some(h) = hint {
                    write!(f, " (hint: {})", h)?;
                }
                Ok(())
            }
            SbError::Network { class, msg } => {
                write!(f, "Network error [{:?}]: {}", class, msg)
            }
            SbError::Timeout {
                operation,
                timeout_ms,
            } => {
                write!(f, "Timeout in {} after {}ms", operation, timeout_ms)
            }
            SbError::Capacity { what, limit } => {
                write!(f, "Capacity exceeded for {}: limit {}", what, limit)
            }
        }
    }
}

impl std::error::Error for SbError {}

impl SbError {
    /// Create a configuration error
    pub fn config(code: IssueCode, ptr: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Config {
            code,
            ptr: ptr.into(),
            msg: msg.into(),
            hint: None,
        }
    }

    /// Add a hint to a configuration error
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        if let Self::Config {
            hint: ref mut h, ..
        } = self
        {
            *h = Some(hint.into());
        }
        self
    }

    /// Create a network error
    pub fn network(class: ErrorClass, msg: impl Into<String>) -> Self {
        Self::Network {
            class,
            msg: msg.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout(operation: impl Into<String>, timeout_ms: u64) -> Self {
        Self::Timeout {
            operation: operation.into(),
            timeout_ms,
        }
    }

    /// Create a capacity error
    pub fn capacity(what: impl Into<String>, limit: usize) -> Self {
        Self::Capacity {
            what: what.into(),
            limit,
        }
    }
}

impl From<Issue> for SbError {
    fn from(issue: Issue) -> Self {
        let code = match issue.code.as_str() {
            "UnknownField" => IssueCode::UnknownField,
            "InvalidType" => IssueCode::InvalidType,
            "OutOfRange" => IssueCode::OutOfRange,
            "MissingRequired" => IssueCode::MissingRequired,
            "DuplicateTag" => IssueCode::DuplicateTag,
            _ => IssueCode::UnknownField,
        };

        SbError::Config {
            code,
            ptr: issue.ptr,
            msg: issue.msg,
            hint: issue.hint,
        }
    }
}

impl From<SbError> for Issue {
    fn from(error: SbError) -> Self {
        match error {
            SbError::Config {
                code,
                ptr,
                msg,
                hint,
            } => Issue {
                kind: "config".to_string(),
                code: format!("{:?}", code),
                ptr,
                msg,
                hint,
            },
            SbError::Network { class, msg } => Issue {
                kind: "network".to_string(),
                code: format!("{:?}", class),
                ptr: "".to_string(),
                msg,
                hint: None,
            },
            SbError::Timeout {
                operation,
                timeout_ms,
            } => Issue {
                kind: "timeout".to_string(),
                code: "Timeout".to_string(),
                ptr: "".to_string(),
                msg: format!("Timeout in {} after {}ms", operation, timeout_ms),
                hint: None,
            },
            SbError::Capacity { what, limit } => Issue {
                kind: "capacity".to_string(),
                code: "CapacityExceeded".to_string(),
                ptr: "".to_string(),
                msg: format!("Capacity exceeded for {}: limit {}", what, limit),
                hint: None,
            },
        }
    }
}

impl ErrorReport {
    /// Create error report from a list of errors
    pub fn from_errors(errors: Vec<SbError>) -> Self {
        let issues: Vec<Issue> = errors.into_iter().map(Issue::from).collect();
        let fingerprint = Self::calculate_fingerprint(&issues);

        Self {
            issues,
            fingerprint,
        }
    }

    /// Calculate SHA256 fingerprint of error patterns
    fn calculate_fingerprint(issues: &[Issue]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        for issue in issues {
            hasher.update(&issue.code);
            hasher.update(&issue.ptr);
        }

        format!("sha256:{:x}", hasher.finalize())
    }

    /// Create a single-issue error report
    pub fn single(error: SbError) -> Self {
        Self::from_errors(vec![error])
    }
}
