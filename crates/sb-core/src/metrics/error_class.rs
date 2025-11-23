//! Unified error classification for metrics labels.
//!
//! Provides a single enum `ErrorClass` and helpers to map various error types
//! and messages into a stable label set used across metrics families.

use core::fmt::Display;
use std::io;

/// Stable error classes for metrics `class` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    Timeout,
    Dns,
    Tls,
    Io,
    Auth,
    Protocol,
    Other,
}

impl ErrorClass {
    /// Return canonical label value
    pub const fn as_label(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Dns => "dns",
            Self::Tls => "tls",
            Self::Io => "io",
            Self::Auth => "auth",
            Self::Protocol => "protocol",
            Self::Other => "other",
        }
    }
}

/// Classify std::io::Error into ErrorClass
#[must_use]
pub fn classify_io(e: &io::Error) -> ErrorClass {
    match e.kind() {
        io::ErrorKind::TimedOut => ErrorClass::Timeout,
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable
        | io::ErrorKind::NotConnected
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::WouldBlock
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::HostUnreachable
        | io::ErrorKind::Other => ErrorClass::Io,
        _ => ErrorClass::Io,
    }
}

/// Fallback classification from message text (lowercased)
#[must_use]
pub fn classify_str(msg_lower: &str) -> ErrorClass {
    let s = msg_lower;
    if s.contains("timeout") || s.contains("timed out") {
        ErrorClass::Timeout
    } else if s.contains("dns") || s.contains("resolve") || s.contains("nxdomain") {
        ErrorClass::Dns
    } else if s.contains("tls") || s.contains("certificate") || s.contains("handshake") {
        ErrorClass::Tls
    } else if s.contains("auth") || s.contains("unauthorized") || s.contains("forbidden") {
        ErrorClass::Auth
    } else if s.contains("protocol") || s.contains("invalid") || s.contains("decode") {
        ErrorClass::Protocol
    } else if s.contains("io")
        || s.contains("connection")
        || s.contains("refused")
        || s.contains("unreachable")
    {
        ErrorClass::Io
    } else {
        ErrorClass::Other
    }
}

/// Classify a displayable error using source-aware strategies (io::Error) and
/// then fallback on string heuristics.
#[must_use]
pub fn classify_display(e: &dyn Display) -> ErrorClass {
    // Try downcast to io::Error
    // Note: avoid requiring 'std::error::Error' bound to keep broad compatibility
    // with external error types; attempt parse via Display string otherwise.
    let s = e.to_string();
    classify_str(&s.to_ascii_lowercase())
}

/// Convenience: record outbound connect error using unified classification.
pub fn record_outbound_error(kind: super::outbound::OutboundKind, err: &dyn Display) {
    let ec = classify_display(err);
    let mapped = match ec {
        ErrorClass::Timeout => super::outbound::OutboundErrorClass::Timeout,
        ErrorClass::Io => super::outbound::OutboundErrorClass::Io,
        ErrorClass::Tls => super::outbound::OutboundErrorClass::Handshake,
        ErrorClass::Protocol | ErrorClass::Dns | ErrorClass::Auth | ErrorClass::Other => {
            super::outbound::OutboundErrorClass::Protocol
        }
    };
    super::outbound::record_connect_error(kind, mapped);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_timeout_maps() {
        let e = io::Error::new(io::ErrorKind::TimedOut, "timed out");
        assert_eq!(classify_io(&e), ErrorClass::Timeout);
    }

    #[test]
    fn string_tls_maps() {
        assert_eq!(classify_str("tls handshake failure"), ErrorClass::Tls);
        assert_eq!(classify_str("invalid certificate"), ErrorClass::Tls);
    }

    #[test]
    fn string_dns_maps() {
        assert_eq!(classify_str("dns resolve failed"), ErrorClass::Dns);
        assert_eq!(classify_str("nxdomain"), ErrorClass::Dns);
    }

    #[test]
    fn display_auth_maps() {
        let e = format!("Authentication error: invalid token");
        assert_eq!(classify_display(&e), ErrorClass::Auth);
    }
}
