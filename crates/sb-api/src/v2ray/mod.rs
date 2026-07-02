//! V2Ray API implementation
//! V2Ray API 实现
//!
//! This module provides V2Ray-compatible API services for managing
//! and monitoring the proxy server. It supports both gRPC (when v2ray-api
//! feature is enabled) and a simplified implementation (default).
//!
//! 本模块提供兼容 V2Ray 的 API 服务，用于管理和监控代理服务器。它支持 gRPC（当启用
//! v2ray-api 特性时）和简化实现（默认）。

#![warn(missing_docs)]
// This module exposes generated gRPC/protobuf types; crate-level API docs cover
// the public feature surface while generated items retain upstream names.
#![allow(missing_docs)]

pub mod server;
pub mod simple;

#[cfg(feature = "v2ray-api")]
pub mod services;

#[cfg(feature = "v2ray-api")]
pub mod generated {
    //! Generated V2Ray protobuf and tonic service modules.

    pub mod v2ray {
        pub mod core {
            include!(concat!(env!("OUT_DIR"), "/v2ray.core.rs"));

            pub mod app {
                pub mod stats {
                    pub mod command {
                        include!(concat!(env!("OUT_DIR"), "/v2ray.core.app.stats.command.rs"));
                    }
                }

                pub mod proxyman {
                    pub mod command {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/v2ray.core.app.proxyman.command.rs"
                        ));
                    }
                }

                pub mod router {
                    pub mod command {
                        include!(concat!(
                            env!("OUT_DIR"),
                            "/v2ray.core.app.router.command.rs"
                        ));
                    }
                }

                pub mod log {
                    pub mod command {
                        include!(concat!(env!("OUT_DIR"), "/v2ray.core.app.log.command.rs"));
                    }
                }
            }
        }
    }

    pub use v2ray::core::app::log::command::*;
    pub use v2ray::core::app::proxyman::command::*;
    pub use v2ray::core::app::router::command::*;
    pub use v2ray::core::app::stats::command::*;
}

/// Compatibility V2Ray API server surface.
///
/// This deprecated public name is retained as a compatibility surface and its
/// implementation varies by feature mode: without `v2ray-api` it resolves to a
/// simplified no-network wrapper; with `v2ray-api` it resolves to the tonic gRPC
/// server. Network callers should migrate to `GrpcV2RayApiServer`; legacy
/// in-memory callers should migrate to `SimpleV2RayApiServer`.
#[deprecated(
    note = "compatibility alias: use `GrpcV2RayApiServer` for the network gRPC server or `SimpleV2RayApiServer` for the legacy in-memory helper"
)]
pub type V2RayApiServer = server::V2RayApiServer;

#[cfg(feature = "v2ray-api")]
/// Real tonic gRPC V2Ray API server.
///
/// Requires the `v2ray-api` feature. This direct re-export points to the
/// existing sb-api tonic implementation, which binds and serves a network
/// listener.
pub use server::GrpcV2RayApiServer;

/// Legacy-compatible in-memory V2Ray API helper.
///
/// This helper does not bind a TCP listener and does not serve the tonic gRPC
/// V2Ray API.
pub use simple::SimpleV2RayApiServer;
