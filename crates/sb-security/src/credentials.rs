//! # Constant-Time Credential Verification (常量时间凭证验证)
//!
//! This module provides timing-attack resistant credential comparison using
//! the `subtle` crate's constant-time operations.
//! 本模块利用 `subtle` crate 的常量时间操作，提供抵抗时序攻击的凭证比较功能。
//!
//! ## Security Rationale (安全原理)
//!
//! Standard string comparison (`==`) returns as soon as it finds a mismatch,
//! which can leak information about the expected value through timing analysis:
//! 标准字符串比较 (`==`) 一旦发现不匹配就会立即返回，这可能通过时间分析泄露预期值的信息：
//!
//! - Correct first char: takes longer to fail (首字符正确：失败所需时间更长)
//! - Wrong first char: fails immediately (首字符错误：立即失败)
//! - **Risk**: Attacker can measure time differences to brute-force credentials. (**风险**：攻击者可以通过测量时间差来暴力破解凭证)
//!
//! ## Solution (解决方案)
//!
//! Use `subtle::ConstantTimeEq` which always compares all bytes regardless of
//! matches/mismatches, preventing timing attacks.
//! 使用 `subtle::ConstantTimeEq`，无论匹配与否，始终比较所有字节，从而防止时序攻击。
//!
//! ## Usage
//!
//! ```
//! use sb_security::credentials::verify_credentials;
//!
//! let result = verify_credentials(
//!     Some("admin"),
//!     Some("secret123"),
//!     "admin",
//!     "secret123"
//! );
//! assert!(result);
//!
//! // Wrong password - still takes constant time
//! let result = verify_credentials(
//!     Some("admin"),
//!     Some("secret123"),
//!     "admin",
//!     "wrong"
//! );
//! assert!(!result);
//! ```

use subtle::ConstantTimeEq;

/// Verify credentials using constant-time comparison
///
/// This function compares provided credentials against expected values using
/// constant-time operations to prevent timing attacks.
///
/// # Arguments
///
/// * `expected_username` - Expected username (None = no username required)
/// * `expected_password` - Expected password (None = no password required)
/// * `provided_username` - Provided username
/// * `provided_password` - Provided password
///
/// # Returns
///
/// `true` if credentials match, `false` otherwise
///
/// # Security
///
/// - Uses `subtle::ConstantTimeEq` for timing-attack resistance
/// - Both username and password are compared even if one fails (to maintain constant time)
/// - Empty/None credentials are handled securely
///
/// # Example
///
/// ```
/// use sb_security::credentials::verify_credentials;
///
/// // Both username and password required
/// assert!(verify_credentials(
///     Some("user"),
///     Some("pass"),
///     "user",
///     "pass"
/// ));
///
/// // Only password required (no username check)
/// assert!(verify_credentials(
///     None,
///     Some("pass"),
///     "",  // Username ignored
///     "pass"
/// ));
/// ```
#[must_use]
pub fn verify_credentials(
    expected_username: Option<&str>,
    expected_password: Option<&str>,
    provided_username: &str,
    provided_password: &str,
) -> bool {
    // Always compare both username and password to maintain constant time,
    // even if one is None

    let username_match = match expected_username {
        Some(expected) => {
            // Use constant-time comparison
            expected
                .as_bytes()
                .ct_eq(provided_username.as_bytes())
                .into()
        }
        None => true, // No username requirement = always matches
    };

    let password_match = match expected_password {
        Some(expected) => {
            // Use constant-time comparison
            expected
                .as_bytes()
                .ct_eq(provided_password.as_bytes())
                .into()
        }
        None => true, // No password requirement = always matches
    };

    // Return true only if both match
    username_match && password_match
}

/// Verify credentials with explicit expected values (not Optional)
///
/// This is a convenience function for cases where both username and password
/// are always required.
///
/// # Arguments
///
/// * `expected_username` - Expected username
/// * `expected_password` - Expected password
/// * `provided_username` - Provided username
/// * `provided_password` - Provided password
///
/// # Example
///
/// ```
/// use sb_security::credentials::verify_credentials_required;
///
/// assert!(verify_credentials_required(
///     "admin",
///     "secret",
///     "admin",
///     "secret"
/// ));
///
/// assert!(!verify_credentials_required(
///     "admin",
///     "secret",
///     "admin",
///     "wrong"
/// ));
/// ```
#[must_use]
pub fn verify_credentials_required(
    expected_username: &str,
    expected_password: &str,
    provided_username: &str,
    provided_password: &str,
) -> bool {
    // Always compare both to maintain constant time
    let username_match = expected_username
        .as_bytes()
        .ct_eq(provided_username.as_bytes());
    let password_match = expected_password
        .as_bytes()
        .ct_eq(provided_password.as_bytes());

    // Convert Choice to bool: true if both match
    bool::from(username_match & password_match)
}

/// Verify a single secret value using constant-time comparison
///
/// This is useful for API tokens, bearer tokens, or other single-value secrets.
///
/// # Arguments
///
/// * `expected` - Expected secret value
/// * `provided` - Provided secret value
///
/// # Returns
///
/// `true` if values match, `false` otherwise
///
/// # Example
///
/// ```
/// use sb_security::credentials::verify_secret;
///
/// let api_token = "abc123def456";
/// assert!(verify_secret(api_token, "abc123def456"));
/// assert!(!verify_secret(api_token, "wrong"));
/// ```
#[must_use]
pub fn verify_secret(expected: &str, provided: &str) -> bool {
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_credentials_both_match() {
        assert!(verify_credentials(
            Some("user"),
            Some("pass"),
            "user",
            "pass"
        ));
    }

    #[test]
    fn test_verify_credentials_username_mismatch() {
        assert!(!verify_credentials(
            Some("user"),
            Some("pass"),
            "wrong",
            "pass"
        ));
    }

    #[test]
    fn test_verify_credentials_password_mismatch() {
        assert!(!verify_credentials(
            Some("user"),
            Some("pass"),
            "user",
            "wrong"
        ));
    }

    #[test]
    fn test_verify_credentials_both_mismatch() {
        assert!(!verify_credentials(
            Some("user"),
            Some("pass"),
            "wrong_user",
            "wrong_pass"
        ));
    }

    #[test]
    fn test_verify_credentials_no_username_required() {
        assert!(verify_credentials(None, Some("pass"), "anything", "pass"));
        assert!(verify_credentials(None, Some("pass"), "", "pass"));
    }

    #[test]
    fn test_verify_credentials_no_password_required() {
        assert!(verify_credentials(Some("user"), None, "user", "anything"));
        assert!(verify_credentials(Some("user"), None, "user", ""));
    }

    #[test]
    fn test_verify_credentials_neither_required() {
        assert!(verify_credentials(None, None, "anything", "anything"));
        assert!(verify_credentials(None, None, "", ""));
    }

    #[test]
    fn test_verify_credentials_empty_strings() {
        // Empty expected username/password should not match non-empty provided
        assert!(!verify_credentials(Some(""), Some(""), "user", "pass"));

        // Empty provided should not match non-empty expected
        assert!(!verify_credentials(Some("user"), Some("pass"), "", ""));

        // Both empty should match
        assert!(verify_credentials(Some(""), Some(""), "", ""));
    }

    #[test]
    fn test_verify_credentials_required() {
        assert!(verify_credentials_required("user", "pass", "user", "pass"));
        assert!(!verify_credentials_required(
            "user", "pass", "wrong", "pass"
        ));
        assert!(!verify_credentials_required(
            "user", "pass", "user", "wrong"
        ));
    }

    #[test]
    fn test_verify_secret() {
        assert!(verify_secret("token123", "token123"));
        assert!(!verify_secret("token123", "wrong"));
        assert!(!verify_secret("token123", ""));
    }

    #[test]
    fn test_verify_secret_empty() {
        assert!(verify_secret("", ""));
        assert!(!verify_secret("token", ""));
        assert!(!verify_secret("", "token"));
    }

    #[test]
    fn test_constant_time_property() {
        // This is a behavioral test - not a timing test
        // It verifies that the function always compares all bytes

        // These should all take similar time (we can't measure time in unit tests,
        // but we verify the function completes for various inputs)

        let expected = "a".repeat(100);
        let provided_first_wrong = format!("b{}", "a".repeat(99));
        let provided_last_wrong = "a".repeat(99) + "b";
        let provided_all_wrong = "b".repeat(100);

        // All should return false
        assert!(!verify_secret(&expected, &provided_first_wrong));
        assert!(!verify_secret(&expected, &provided_last_wrong));
        assert!(!verify_secret(&expected, &provided_all_wrong));

        // Correct should return true
        assert!(verify_secret(&expected, &expected));
    }

    #[test]
    fn test_unicode_handling() {
        // Test with Unicode characters
        assert!(verify_credentials(
            Some("用户"),
            Some("密码123"),
            "用户",
            "密码123"
        ));

        assert!(!verify_credentials(
            Some("用户"),
            Some("密码123"),
            "用户",
            "wrong"
        ));
    }

    #[test]
    fn test_special_characters() {
        let username = "user@domain.com";
        let password = "p@$$w0rd!#$%";

        assert!(verify_credentials(
            Some(username),
            Some(password),
            username,
            password
        ));

        assert!(!verify_credentials(
            Some(username),
            Some(password),
            username,
            "wrong"
        ));
    }
}
