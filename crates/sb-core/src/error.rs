use std::{error::Error as StdError, fmt, io, time::Duration};
use thiserror::Error;

#[cfg(feature = "error-v2")]
use serde::Serialize;

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
#[derive(Debug)]
pub enum SbError {
    /// I/O error wrapper
    Io(#[allow(dead_code)] io::Error),
    /// DNS-related error (NXDOMAIN, SERVFAIL, malformed, etc.)
    Dns { message: String },
    /// Input parse error
    Parse { message: String },
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
    Addr { message: String },
    /// Operation was canceled
    Canceled { operation: String },
    /// Poisoned synchronization primitive encountered
    Poison { message: String },
    /// Generic error wrapper with optional source
    Other { message: String, #[allow(dead_code)] source: Option<Box<dyn StdError + Send + Sync>> },
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
            SbError::Io(e) => write!(f, "io: {}", e),
            SbError::Dns { message } => write!(f, "DNS error: {}", message),
            SbError::Parse { message } => write!(f, "Parse error: {}", message),
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
            SbError::Addr { message } => write!(f, "Address error: {}", message),
            SbError::Canceled { operation } => write!(f, "Canceled: {}", operation),
            SbError::Poison { message } => write!(f, "Poison error: {}", message),
            SbError::Other { message, .. } => write!(f, "Other error: {}", message),
        }
    }
}

impl std::error::Error for SbError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            SbError::Io(e) => Some(e),
            SbError::Other { source: Some(src), .. } => Some(src.as_ref()),
            _ => None,
        }
    }
}

impl SbError {
    /// Create an I/O error wrapper
    pub fn io(e: io::Error) -> Self { Self::Io(e) }
    /// Create a parse error
    ///
    /// Example
    /// ```
    /// use sb_core::error::SbError;
    /// let e = SbError::parse("bad token");
    /// assert_eq!(e.kind(), "Parse");
    /// ```
    pub fn parse(msg: impl Into<String>) -> Self { Self::Parse { message: msg.into() } }
    /// Create a DNS error
    pub fn dns(msg: impl Into<String>) -> Self { Self::Dns { message: msg.into() } }
    /// Create an address error
    pub fn addr(msg: impl Into<String>) -> Self { Self::Addr { message: msg.into() } }
    /// Create a canceled error
    pub fn canceled(operation: impl Into<String>) -> Self { Self::Canceled { operation: operation.into() } }
    /// Create a poison error
    pub fn poison(msg: impl Into<String>) -> Self { Self::Poison { message: msg.into() } }
    /// Create a generic other error with optional source
    pub fn other(msg: impl Into<String>) -> Self { Self::Other { message: msg.into(), source: None } }
    /// Stable error kind for matching in tests and callers
    pub fn kind(&self) -> &'static str {
        match self {
            SbError::Io(_) => "Io",
            SbError::Dns { .. } => "Dns",
            SbError::Parse { .. } => "Parse",
            SbError::Config { .. } => "Config",
            SbError::Network { .. } => "Network",
            SbError::Timeout { .. } => "Timeout",
            SbError::Capacity { .. } => "Capacity",
            SbError::Addr { .. } => "Addr",
            SbError::Canceled { .. } => "Canceled",
            SbError::Poison { .. } => "Poison",
            SbError::Other { .. } => "Other",
        }
    }
}

impl From<io::Error> for SbError {
    fn from(e: io::Error) -> Self { SbError::Io(e) }
}

impl From<anyhow::Error> for SbError {
    fn from(e: anyhow::Error) -> Self { SbError::Other { message: e.to_string(), source: Some(e.into()) } }
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
            SbError::Io(e) => Issue {
                kind: "io".to_string(),
                code: format!("{:?}", e.kind()),
                ptr: "".to_string(),
                msg: e.to_string(),
                hint: None,
            },
            SbError::Dns { message } => Issue {
                kind: "dns".to_string(),
                code: "Dns".to_string(),
                ptr: "".to_string(),
                msg: message,
                hint: None,
            },
            SbError::Parse { message } => Issue {
                kind: "parse".to_string(),
                code: "Parse".to_string(),
                ptr: "".to_string(),
                msg: message,
                hint: None,
            },
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
            SbError::Addr { message } => Issue {
                kind: "addr".to_string(),
                code: "Addr".to_string(),
                ptr: "".to_string(),
                msg: message,
                hint: None,
            },
            SbError::Canceled { operation } => Issue {
                kind: "canceled".to_string(),
                code: "Canceled".to_string(),
                ptr: "".to_string(),
                msg: format!("Operation canceled: {}", operation),
                hint: None,
            },
            SbError::Poison { message } => Issue {
                kind: "poison".to_string(),
                code: "Poison".to_string(),
                ptr: "".to_string(),
                msg: message,
                hint: None,
            },
            SbError::Other { message, .. } => Issue {
                kind: "other".to_string(),
                code: "Other".to_string(),
                ptr: "".to_string(),
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
