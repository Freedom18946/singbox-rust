//! Shared test utilities for app integration tests
//!
//! This module provides common functionality used across multiple test files:
//! - `workspace`: Locating workspace binaries
//! - `http`: HTTP client helpers for testing
//! - `fixtures`: Test data loading utilities
//!
//! ## Usage
//!
//! ```rust
//! // In test files at app/tests/*.rs
//! mod common;
//!
//! use common::workspace::workspace_bin;
//! use common::http::get;
//! ```

pub mod fixtures;
pub mod http;
pub mod workspace;
