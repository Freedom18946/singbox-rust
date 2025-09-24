//! # sb-api: API Services for singbox-rust
//!
//! This crate provides HTTP and WebSocket API services compatible with Clash and V2Ray APIs.
//! It enables web-based management and monitoring of the proxy server.

#![deny(unused_must_use)]
#![warn(missing_docs)]

pub mod error;
pub mod monitoring;
pub mod types;

#[cfg(feature = "clash-api")]
pub mod clash;

pub mod v2ray;

// Re-export main API types
pub use error::{ApiError, ApiResult};
pub use monitoring::{MonitoringSystem, MonitoringSystemHandle, ReportConfig};
pub use types::*;

#[cfg(feature = "clash-api")]
pub use clash::ClashApiServer;

#[cfg(feature = "v2ray-api")]
pub use v2ray::V2RayApiServer;
