//! Shared test utilities for singbox-rust workspace
//! singbox-rust 工作区的共享测试工具
//!
//! This crate provides common testing utilities that are used across
//! multiple crates in the workspace, including:
//! 本 crate 提供了在工作区多个 crate 中使用的通用测试工具，包括：
//!
//! - Mock SOCKS5 server implementation
//!   Mock SOCKS5 服务器实现
//! - Mock HTTP server utilities
//!   Mock HTTP 服务器工具
//! - Test data generation helpers
//!   测试数据生成助手
//!
//! # Strategic Context / 战略背景
//!
//! This crate serves as a foundational infrastructure for testing `sb-box`, `sb-inbound`, and `sb-outbound`.
//! By centralizing mock implementations, we ensure consistent behavior across integration tests and avoid code duplication.
//! 本 crate 作为 `sb-box`、`sb-inbound` 和 `sb-outbound` 测试的基础设施。
//! 通过集中管理 Mock 实现，我们确保了集成测试中行为的一致性，并避免了代码重复。
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

pub mod socks5;
