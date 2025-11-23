//! Adapter-specific error types and codes
//!
//! This module provides structured error handling for inbound and outbound adapters
//! with unique error codes, contextual information, and actionable hints.

use std::fmt;

/// Adapter error with structured information
#[derive(Debug)]
pub struct AdapterError {
    /// Error code (e.g., "EINB001", "EOUT002")
    pub code: &'static str,
    /// Adapter type (e.g., "socks", "vmess", "shadowsocks")
    pub adapter_type: &'static str,
    /// Adapter direction ("inbound" or "outbound")
    pub direction: AdapterDirection,
    /// Error message
    pub message: String,
    /// Optional hint for fixing the error
    pub hint: Option<String>,
    /// Optional configuration context (field name or path)
    pub context: Option<String>,
}

/// Adapter direction for error classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterDirection {
    Inbound,
    Outbound,
}

impl fmt::Display for AdapterDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inbound => write!(f, "inbound"),
            Self::Outbound => write!(f, "outbound"),
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} {} adapter: {}",
            self.code, self.direction, self.adapter_type, self.message
        )?;

        if let Some(ctx) = &self.context {
            write!(f, " (at: {})", ctx)?;
        }

        if let Some(hint) = &self.hint {
            write!(f, " → Hint: {}", hint)?;
        }

        Ok(())
    }
}

impl std::error::Error for AdapterError {}

impl AdapterError {
    /// Create a new adapter error
    pub fn new(
        code: &'static str,
        adapter_type: &'static str,
        direction: AdapterDirection,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            adapter_type,
            direction,
            message: message.into(),
            hint: None,
            context: None,
        }
    }

    /// Add a hint for fixing the error
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Add configuration context
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }
}

// =============================================================================
// ERROR CODE CONSTANTS
// =============================================================================

/// Inbound adapter error codes (EINB000-EINB999)
pub mod inbound {
    /// Missing required configuration field
    pub const MISSING_FIELD: &str = "EINB001";
    /// Invalid listen address
    pub const INVALID_LISTEN_ADDR: &str = "EINB002";
    /// Invalid port number
    pub const INVALID_PORT: &str = "EINB003";
    /// TLS configuration error
    pub const TLS_CONFIG: &str = "EINB004";
    /// Authentication configuration error
    pub const AUTH_CONFIG: &str = "EINB005";
    /// Protocol-specific configuration error
    pub const PROTOCOL_CONFIG: &str = "EINB006";
    /// Failed to bind to address
    pub const BIND_FAILED: &str = "EINB007";
    /// Failed to start listener
    pub const LISTENER_FAILED: &str = "EINB008";
    /// Invalid transport configuration
    pub const INVALID_TRANSPORT: &str = "EINB009";
    /// Invalid encryption method
    pub const INVALID_ENCRYPTION: &str = "EINB010";
    /// Invalid user configuration
    pub const INVALID_USER: &str = "EINB011";
    /// Invalid multiplex configuration
    pub const INVALID_MULTIPLEX: &str = "EINB012";
}

/// Outbound adapter error codes (EOUT000-EOUT999)
pub mod outbound {
    /// Missing required configuration field
    pub const MISSING_FIELD: &str = "EOUT001";
    /// Invalid server address
    pub const INVALID_SERVER_ADDR: &str = "EOUT002";
    /// Invalid port number
    pub const INVALID_PORT: &str = "EOUT003";
    /// TLS configuration error
    pub const TLS_CONFIG: &str = "EOUT004";
    /// Authentication configuration error
    pub const AUTH_CONFIG: &str = "EOUT005";
    /// Protocol-specific configuration error
    pub const PROTOCOL_CONFIG: &str = "EOUT006";
    /// Connection failed
    pub const CONNECTION_FAILED: &str = "EOUT007";
    /// Handshake failed
    pub const HANDSHAKE_FAILED: &str = "EOUT008";
    /// Invalid transport configuration
    pub const INVALID_TRANSPORT: &str = "EOUT009";
    /// Invalid encryption method
    pub const INVALID_ENCRYPTION: &str = "EOUT010";
    /// Invalid UUID format
    pub const INVALID_UUID: &str = "EOUT011";
    /// Invalid token/password
    pub const INVALID_CREDENTIALS: &str = "EOUT012";
    /// Proxy authentication failed
    pub const PROXY_AUTH_FAILED: &str = "EOUT013";
    /// DNS resolution failed
    pub const DNS_FAILED: &str = "EOUT014";
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Create an inbound adapter error
pub fn inbound_error(
    code: &'static str,
    adapter_type: &'static str,
    message: impl Into<String>,
) -> AdapterError {
    AdapterError::new(code, adapter_type, AdapterDirection::Inbound, message)
}

/// Create an outbound adapter error
pub fn outbound_error(
    code: &'static str,
    adapter_type: &'static str,
    message: impl Into<String>,
) -> AdapterError {
    AdapterError::new(code, adapter_type, AdapterDirection::Outbound, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_error_formatting() {
        let err = inbound_error(
            inbound::INVALID_LISTEN_ADDR,
            "socks",
            "Listen address is required",
        )
        .with_hint("Set 'listen' field to valid IP address")
        .with_context("listen");

        let formatted = err.to_string();
        assert!(formatted.contains("[EINB002]"));
        assert!(formatted.contains("inbound"));
        assert!(formatted.contains("socks"));
        assert!(formatted.contains("Listen address is required"));
        assert!(formatted.contains("Hint:"));
        assert!(formatted.contains("at: listen"));
    }

    #[test]
    fn test_outbound_error_formatting() {
        let err = outbound_error(
            outbound::INVALID_SERVER_ADDR,
            "vmess",
            "Server address is required",
        )
        .with_hint("Set 'server' field to valid hostname or IP");

        let formatted = err.to_string();
        assert!(formatted.contains("[EOUT002]"));
        assert!(formatted.contains("outbound"));
        assert!(formatted.contains("vmess"));
    }

    #[test]
    fn test_error_without_hint() {
        let err = inbound_error(
            inbound::BIND_FAILED,
            "http",
            "Failed to bind to 0.0.0.0:8080",
        );

        let formatted = err.to_string();
        assert!(!formatted.contains("Hint:"));
    }
}
