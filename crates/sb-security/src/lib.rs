//! # Security Utilities for SingBox (SingBox 安全工具库)
//!
//! This crate provides security-focused utilities including:
//! 本 crate 提供以安全为核心的工具，包括：
//!
//! - **Credential Redaction** (凭证脱敏): Safe logging of sensitive data. (用于日志的安全脱敏)
//! - **Secure Key Loading** (安全密钥加载): Strategies for loading secrets from env/files. (从环境变量/文件加载密钥的策略)
//! - **Memory Safety** (内存安全): `ZeroizeOnDrop` for clearing secrets from memory. (使用 `ZeroizeOnDrop` 清除内存中的密钥)
//! - **Constant-Time Verification** (常量时间验证): Timing-attack resistant comparisons. (抵抗时序攻击的凭证比较)
//!
//! ## Strategic Role (战略角色)
//!
//! This crate serves as the **Security Primitive Layer** (安全原语层) for the entire SingBox ecosystem.
//! It is designed to be used by:
//! - `sb-config`: For securely loading sensitive configuration fields (keys, passwords).
//! - `sb-api`: For verifying administrative credentials without timing leaks.
//! - `sb-core` / `sb-adapters`: For ensuring sensitive data is redacted in logs.
//!
//! By centralizing these logic here, we ensure consistent security practices across all modules.
//! 通过在此处集中管理这些逻辑，我们确保所有模块遵循一致的安全实践。
//!
//! # Examples
//!
//! ## Constant-time credential verification
//!
//! ```
//! use sb_security::verify_credentials;
//!
//! let valid = verify_credentials(
//!     Some("admin"),
//!     Some("secret"),
//!     "admin",
//!     "secret"
//! );
//! assert!(valid);
//! ```
//!
//! ## Secure credential redaction
//!
//! ```
//! use sb_security::redact_token;
//!
//! let token = "Bearer abc123def456ghi789";
//! let redacted = redact_token(token);
//! assert_eq!(redacted, "Bear********i789");
//! ```
//!
//! ## Secure key loading
//!
//! ```no_run
//! use sb_security::{KeySource, SecretLoader};
//!
//! let mut loader = SecretLoader::new();
//! let source = KeySource::env("API_KEY");
//! let secret = loader.load(&source).expect("Failed to load key");
//!
//! // Use secret.expose() only when needed for actual operations
//! println!("Loaded from: {}", secret.source());
//! ```

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod credentials;
pub mod key_loading;
pub mod redact;

pub use credentials::{verify_credentials, verify_credentials_required, verify_secret};
pub use key_loading::{KeySource, LoadedSecret, SecretLoader};
pub use redact::{redact_credential, redact_key, redact_token};
