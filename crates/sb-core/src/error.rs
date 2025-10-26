//! Error types for singbox-rust core.
//!
//! This module provides two error systems:
//! - [`Error`]: Legacy error type for backward compatibility
//! - [`SbError`]: Modern structured error system (Schema v2) with detailed classification
//!
//! ## Error Reporting
//! [`ErrorReport`] provides aggregated error collection with fingerprinting for
//! configuration validation and diagnostics.

use std::{error::Error as StdError, fmt, io, time::Duration};
use thiserror::Error;

#[cfg(feature = "error-v2")]
use serde::Serialize;

pub type Result<T, E = Error> = std::result::Result<T, E>;
pub type SbResult<T> = std::result::Result<T, SbError>;

/// Legacy error type for backward compatibility.
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
#[derive(Debug)]
pub enum SbError {
    /// I/O error wrapper
    Io(#[allow(dead_code)] io::Error),
    /// DNS-related error (NXDOMAIN, SERVFAIL, malformed, etc.)
    Dns {
        message: String,
    },
    /// Input parse error
    Parse {
        message: String,
    },
    /// Timeout with operation and duration
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
    /// Address related error
    Addr {
        message: String,
    },
    /// Operation was canceled
    Canceled {
        operation: String,
    },
    /// Poisoned synchronization primitive encountered
    Poison {
        message: String,
    },
    /// Generic error wrapper with optional source
    Other {
        message: String,
        #[allow(dead_code)]
        source: Option<Box<dyn StdError + Send + Sync>>,
    },
}

/// Issue codes for configuration validation errors
pub use sb_types::IssueCode;

/// Error classification for network and protocol errors
#[derive(Debug, Clone, PartialEq, Eq)]
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
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Dns { message } => write!(f, "DNS error: {message}"),
            Self::Parse { message } => write!(f, "Parse error: {message}"),
            Self::Config {
                code,
                ptr,
                msg,
                hint,
            } => {
                write!(f, "Config error [{code:?}] at {ptr}: {msg}")?;
                if let Some(h) = hint {
                    write!(f, " (hint: {h})")?;
                }
                Ok(())
            }
            Self::Network { class, msg } => {
                write!(f, "Network error [{class:?}]: {msg}")
            }
            Self::Timeout {
                operation,
                timeout_ms,
            } => {
                write!(f, "Timeout in {operation} after {timeout_ms}ms")
            }
            Self::Capacity { what, limit } => {
                write!(f, "Capacity exceeded for {what}: limit {limit}")
            }
            Self::Addr { message } => write!(f, "Address error: {message}"),
            Self::Canceled { operation } => write!(f, "Canceled: {operation}"),
            Self::Poison { message } => write!(f, "Poison error: {message}"),
            Self::Other { message, .. } => write!(f, "Other error: {message}"),
        }
    }
}

impl std::error::Error for SbError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Other {
                source: Some(src), ..
            } => Some(src.as_ref()),
            _ => None,
        }
    }
}

impl SbError {
    /// Create an I/O error wrapper
    pub const fn io(e: io::Error) -> Self {
        Self::Io(e)
    }
    /// Create a parse error
    ///
    /// Example
    /// ```
    /// use sb_core::error::SbError;
    /// let e = SbError::parse("bad token");
    /// assert_eq!(e.kind(), "Parse");
    /// ```
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse {
            message: msg.into(),
        }
    }
    /// Create a DNS error
    pub fn dns(msg: impl Into<String>) -> Self {
        Self::Dns {
            message: msg.into(),
        }
    }
    /// Create an address error
    pub fn addr(msg: impl Into<String>) -> Self {
        Self::Addr {
            message: msg.into(),
        }
    }
    /// Create a canceled error
    pub fn canceled(operation: impl Into<String>) -> Self {
        Self::Canceled {
            operation: operation.into(),
        }
    }
    /// Create a poison error
    pub fn poison(msg: impl Into<String>) -> Self {
        Self::Poison {
            message: msg.into(),
        }
    }
    /// Create a generic other error with optional source
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other {
            message: msg.into(),
            source: None,
        }
    }
    /// Stable error kind for matching in tests and callers
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) => "Io",
            Self::Dns { .. } => "Dns",
            Self::Parse { .. } => "Parse",
            Self::Config { .. } => "Config",
            Self::Network { .. } => "Network",
            Self::Timeout { .. } => "Timeout",
            Self::Capacity { .. } => "Capacity",
            Self::Addr { .. } => "Addr",
            Self::Canceled { .. } => "Canceled",
            Self::Poison { .. } => "Poison",
            Self::Other { .. } => "Other",
        }
    }
}

impl From<io::Error> for SbError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<anyhow::Error> for SbError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other {
            message: e.to_string(),
            source: Some(e.into()),
        }
    }
}

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

        Self::Config {
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
            SbError::Io(e) => Self {
                kind: "io".to_string(),
                code: format!("{:?}", e.kind()),
                ptr: String::new(),
                msg: e.to_string(),
                hint: None,
            },
            SbError::Dns { message } => Self {
                kind: "dns".to_string(),
                code: "Dns".to_string(),
                ptr: String::new(),
                msg: message,
                hint: None,
            },
            SbError::Parse { message } => Self {
                kind: "parse".to_string(),
                code: "Parse".to_string(),
                ptr: String::new(),
                msg: message,
                hint: None,
            },
            SbError::Config {
                code,
                ptr,
                msg,
                hint,
            } => Self {
                kind: "config".to_string(),
                code: format!("{code:?}"),
                ptr,
                msg,
                hint,
            },
            SbError::Network { class, msg } => Self {
                kind: "network".to_string(),
                code: format!("{class:?}"),
                ptr: String::new(),
                msg,
                hint: None,
            },
            SbError::Timeout {
                operation,
                timeout_ms,
            } => Self {
                kind: "timeout".to_string(),
                code: "Timeout".to_string(),
                ptr: String::new(),
                msg: format!("Timeout in {operation} after {timeout_ms}ms"),
                hint: None,
            },
            SbError::Capacity { what, limit } => Self {
                kind: "capacity".to_string(),
                code: "CapacityExceeded".to_string(),
                ptr: String::new(),
                msg: format!("Capacity exceeded for {what}: limit {limit}"),
                hint: None,
            },
            SbError::Addr { message } => Self {
                kind: "addr".to_string(),
                code: "Addr".to_string(),
                ptr: String::new(),
                msg: message,
                hint: None,
            },
            SbError::Canceled { operation } => Self {
                kind: "canceled".to_string(),
                code: "Canceled".to_string(),
                ptr: String::new(),
                msg: format!("Operation canceled: {operation}"),
                hint: None,
            },
            SbError::Poison { message } => Self {
                kind: "poison".to_string(),
                code: "Poison".to_string(),
                ptr: String::new(),
                msg: message,
                hint: None,
            },
            SbError::Other { message, .. } => Self {
                kind: "other".to_string(),
                code: "Other".to_string(),
                ptr: String::new(),
                msg: message,
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
