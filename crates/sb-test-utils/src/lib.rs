//! Shared test utilities for singbox-rust workspace
//!
//! This crate provides common testing utilities that are used across
//! multiple crates in the workspace, including:
//!
//! - Mock SOCKS5 server implementation
//! - Mock HTTP server utilities
//! - Test data generation helpers
//!
//! ## Usage
//!
//! Add to your crate's `Cargo.toml` dev-dependencies:
//!
//! ```toml
//! [dev-dependencies]
//! sb-test-utils = { path = "../sb-test-utils" }
//! ```
//!
//! Then use in your tests:
//!
//! ```rust,no_run
//! use sb_test_utils::socks5::start_mock_socks5;
//!
//! #[tokio::test]
//! async fn test_with_mock_socks5() {
//!     let (tcp_addr, udp_addr) = start_mock_socks5().await.unwrap();
//!     // Use the mock server...
//! }
//! ```

pub mod socks5;
