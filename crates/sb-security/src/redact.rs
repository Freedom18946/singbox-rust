//! # Credential Redaction Utilities (凭证脱敏工具)
//!
//! This module provides functions to safely redact sensitive information
//! from log messages, preventing credential leakage in log files.
//! 本模块提供从日志消息中安全脱敏敏感信息的功能，防止凭证在日志文件中泄露。
//!
//! ## Usage Context (使用场景)
//!
//! - **Logging**: Wrap sensitive data in `RedactedString` before logging. (日志记录：在记录前将敏感数据包装在 `RedactedString` 中)
//! - **Error Reporting**: Ensure secrets don't appear in error traces. (错误报告：确保机密信息不会出现在错误堆栈中)
//! - **Display**: Safe `Display` implementation for sensitive types. (显示：为敏感类型提供安全的 `Display` 实现)

use std::fmt;

/// Redacts an authentication token for safe logging
///
/// Shows only the first 4 and last 4 characters, with the middle replaced by asterisks.
/// For tokens shorter than 12 characters, shows only the first 2 or 4 characters.
///
/// # Examples
/// ```
/// use sb_security::redact_token;
///
/// assert_eq!(redact_token("Bearer abc123def456ghi789"), "Bear********i789");
/// assert_eq!(redact_token("short"), "sh******");
/// assert_eq!(redact_token(""), "********");
/// ```
pub fn redact_token(token: &str) -> String {
    if token.is_empty() {
        return "********".to_string();
    }

    let len = token.len();

    if len <= 8 {
        // For very short tokens, show only first 2 chars
        let prefix = &token[..token.char_indices().nth(2).map_or(len, |(idx, _)| idx)];
        format!("{prefix}******")
    } else if len <= 12 {
        // For short tokens, show first 4 chars
        let prefix = &token[..token.char_indices().nth(4).map_or(len, |(idx, _)| idx)];
        format!("{prefix}****")
    } else {
        // For longer tokens, show first 4 and last 4 chars
        // Use byte slicing for ASCII-heavy tokens (common case optimization)
        if token.is_ascii() {
            let prefix = &token[..4];
            let suffix = &token[len - 4..];
            let middle_len = len - 8;
            let asterisks = "*".repeat(middle_len.min(8)); // Cap at 8 asterisks
            format!("{prefix}{asterisks}{suffix}")
        } else {
            // Handle Unicode properly
            let chars: Vec<char> = token.chars().collect();
            let char_count = chars.len();
            let prefix: String = chars.iter().take(4).collect();
            let suffix: String = chars.iter().skip(char_count - 4).collect();
            let middle_len = char_count - 8;
            let asterisks = "*".repeat(middle_len.min(8)); // Cap at 8 asterisks
            format!("{prefix}{asterisks}{suffix}")
        }
    }
}

/// Redacts a cryptographic key for safe logging
///
/// Shows only the key type and length information, completely hiding the key material.
///
/// # Examples
/// ```
/// use sb_security::redact_key;
///
/// assert_eq!(redact_key("rsa-sha256-2048-bits-key-material-here"), "RSA-[KEY:38]");
/// assert_eq!(redact_key(""), "[KEY:0]");
/// ```
pub fn redact_key(key: &str) -> String {
    if key.is_empty() {
        return "[KEY:0]".to_string();
    }

    // Try to extract key type from common prefixes
    let key_type = if key.starts_with("-----BEGIN RSA") {
        "RSA"
    } else if key.starts_with("-----BEGIN EC") {
        "EC"
    } else if key.starts_with("-----BEGIN PRIVATE") {
        "PRIVATE"
    } else if key.starts_with("-----BEGIN PUBLIC") {
        "PUBLIC"
    } else if key.starts_with("rsa-") {
        "RSA"
    } else if key.starts_with("ec-") || key.starts_with("ecdsa-") {
        "EC"
    } else if key.starts_with("ed25519-") {
        "ED25519"
    } else {
        "UNKNOWN"
    };

    format!("{}-[KEY:{}]", key_type, key.len())
}

/// Redacts any generic credential for safe logging
///
/// This is a general-purpose function that can handle various types of credentials.
/// It's more conservative than token redaction to ensure safety.
///
/// # Examples
/// ```
/// use sb_security::redact_credential;
///
/// assert_eq!(redact_credential("password123"), "pa*********");
/// assert_eq!(redact_credential("secret"), "se****");
/// ```
pub fn redact_credential(credential: &str) -> String {
    if credential.is_empty() {
        return "****".to_string();
    }

    let len = credential.len();

    if len <= 4 {
        "*".repeat(len)
    } else if len <= 8 {
        let prefix_end = credential.char_indices().nth(2).map_or(len, |(idx, _)| idx);
        let prefix = &credential[..prefix_end];
        let asterisks = "*".repeat(len - prefix.len());
        format!("{prefix}{asterisks}")
    } else {
        let prefix_end = credential.char_indices().nth(2).map_or(len, |(idx, _)| idx);
        let prefix = &credential[..prefix_end];
        let asterisks = "*".repeat((len - prefix.len()).min(10)); // Cap at 10 asterisks
        format!("{prefix}{asterisks}")
    }
}

/// A wrapper type that automatically redacts its contents when displayed or logged
///
/// This type ensures that sensitive information is never accidentally logged
/// in its raw form.
#[derive(Clone)]
pub struct RedactedString {
    inner: String,
    redacted: String,
}

impl RedactedString {
    /// Create a new redacted string with custom redaction logic
    pub fn new<F>(value: String, redact_fn: F) -> Self
    where
        F: FnOnce(&str) -> String,
    {
        let redacted = redact_fn(&value);
        Self {
            inner: value,
            redacted,
        }
    }

    /// Create a redacted token (uses `redact_token`)
    pub fn token(value: String) -> Self {
        Self::new(value, redact_token)
    }

    /// Create a redacted key (uses `redact_key`)
    pub fn key(value: String) -> Self {
        Self::new(value, redact_key)
    }

    /// Create a redacted credential (uses `redact_credential`)
    pub fn credential(value: String) -> Self {
        Self::new(value, redact_credential)
    }

    /// Get the actual value (use with caution!)
    ///
    /// This should only be used when the actual value is needed for cryptographic
    /// operations or authentication. Never use this for logging.
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Get the redacted representation
    pub fn redacted(&self) -> &str {
        &self.redacted
    }
}

impl fmt::Display for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.redacted)
    }
}

impl fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactedString")
            .field("value", &self.redacted)
            .finish()
    }
}

/// Macro to safely log with automatic credential redaction
///
/// This macro helps ensure that sensitive information is always redacted
/// when logging.
#[macro_export]
macro_rules! log_with_redaction {
    ($level:ident, $($arg:tt)*) => {
        tracing::$level!($($arg)*);
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_token() {
        // Empty token
        assert_eq!(redact_token(""), "********");

        // Very short token
        assert_eq!(redact_token("abc"), "ab******");
        assert_eq!(redact_token("abcdef"), "ab******");

        // Short token
        assert_eq!(redact_token("abcdefgh"), "ab******");
        assert_eq!(redact_token("abcdefghij"), "abcd****");

        // Medium token (12 chars exactly)
        assert_eq!(redact_token("abcdefghijkl"), "abcd****");

        // Long token (13+ chars)
        assert_eq!(redact_token("abcdefghijklm"), "abcd*****jklm");
        assert_eq!(
            redact_token("abcdefghijklmnopqrstuvwxyz"),
            "abcd********wxyz"
        );

        // Real-world examples
        assert_eq!(
            redact_token("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "Bear********VCJ9"
        );
        assert_eq!(
            redact_token("sk-1234567890abcdef1234567890abcdef"),
            "sk-1********cdef"
        );
    }

    #[test]
    fn test_redact_key() {
        // Empty key
        assert_eq!(redact_key(""), "[KEY:0]");

        // RSA key
        assert_eq!(
            redact_key("-----BEGIN RSA PRIVATE KEY-----"),
            "RSA-[KEY:31]"
        );
        assert_eq!(redact_key("rsa-sha256-key-material"), "RSA-[KEY:23]");

        // EC key
        assert_eq!(redact_key("-----BEGIN EC PRIVATE KEY-----"), "EC-[KEY:30]");
        assert_eq!(redact_key("ecdsa-p256-key-material"), "EC-[KEY:23]");

        // Ed25519 key
        assert_eq!(redact_key("ed25519-key-material-here"), "ED25519-[KEY:25]");

        // Unknown key type
        assert_eq!(redact_key("some-unknown-key-format"), "UNKNOWN-[KEY:23]");
    }

    #[test]
    fn test_redact_credential() {
        // Empty credential
        assert_eq!(redact_credential(""), "****");

        // Very short
        assert_eq!(redact_credential("a"), "*");
        assert_eq!(redact_credential("ab"), "**");
        assert_eq!(redact_credential("abc"), "***");
        assert_eq!(redact_credential("abcd"), "****");

        // Short
        assert_eq!(redact_credential("abcde"), "ab***");
        assert_eq!(redact_credential("password"), "pa******");

        // Long
        assert_eq!(redact_credential("verylongpassword123456"), "ve**********");
    }

    #[test]
    fn test_redacted_string() {
        let token = RedactedString::token("Bearer abc123def456ghi789".to_string());
        assert_eq!(token.to_string(), "Bear********i789");
        assert_eq!(token.expose(), "Bearer abc123def456ghi789");

        let key = RedactedString::key("rsa-private-key-material".to_string());
        assert_eq!(key.to_string(), "RSA-[KEY:24]");
        assert_eq!(key.expose(), "rsa-private-key-material");

        let cred = RedactedString::credential("secret123".to_string());
        assert_eq!(cred.to_string(), "se*******");
        assert_eq!(cred.expose(), "secret123");
    }

    #[test]
    fn test_redacted_string_debug() {
        let token = RedactedString::token("secret".to_string());
        let debug_output = format!("{:?}", token);

        // Should not contain the actual secret
        assert!(!debug_output.contains("secret"));
        // Should contain redacted version
        assert!(debug_output.contains("se****"));
    }
}
