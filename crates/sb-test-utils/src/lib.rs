//! Shared test utilities for singbox-rust workspace
//! singbox-rust 工作区的共享测试工具
//!
//! This crate provides common testing utilities used by workspace tests:
//! 本 crate 提供了工作区测试使用的通用测试工具：
//!
//! - Mock SOCKS5 server implementation
//!   Mock SOCKS5 服务器实现
//! - Standardized skip helpers for environment-limited tests
//!   面向环境受限测试的标准化跳过助手
//!
//! # Strategic Context / 战略背景
//!
//! This crate centralizes small reusable test helpers so integration tests can
//! avoid duplicating network mocks and environment skip handling.
//! 本 crate 集中管理小型可复用测试助手，避免集成测试重复实现网络 mock 和环境跳过逻辑。
//!
//! ## Usage / 用法
//!
//! Add to your crate's `Cargo.toml` dev-dependencies:
//! 在 crate 的 `Cargo.toml` dev-dependencies 中添加：
//!
//! ```toml
//! [dev-dependencies]
//! sb-test-utils = { path = "../sb-test-utils" }
//! ```
//!
//! Then use in your tests:
//! 然后在测试中使用：
//!
//! ```rust,no_run
//! use sb_test_utils::socks5::start_mock_socks5;
//!
//! #[tokio::test]
//! async fn test_with_mock_socks5() {
//!     let (tcp_addr, udp_addr) = start_mock_socks5().await.unwrap();
//!     // Use the mock server...
//!     // 使用 mock 服务器...
//! }
//! ```

pub mod skip;
pub mod socks5;
