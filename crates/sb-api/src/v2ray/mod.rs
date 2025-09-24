//! V2Ray API implementation
//!
//! This module provides V2Ray-compatible API services for managing
//! and monitoring the proxy server. It supports both gRPC (when v2ray-api
//! feature is enabled) and a simplified implementation (default).

pub mod server;
pub mod simple;

#[cfg(feature = "v2ray-api")]
pub mod services;

#[cfg(feature = "v2ray-api")]
pub mod generated {
    //! Generated protobuf code for V2Ray API

    tonic::include_proto!("v2ray.core.app.stats.command");
    tonic::include_proto!("v2ray.core.app.proxyman.command");
    tonic::include_proto!("v2ray.core.app.router.command");
    tonic::include_proto!("v2ray.core.app.log.command");
    tonic::include_proto!("v2ray.core");
}

pub use server::V2RayApiServer;
pub use simple::SimpleV2RayApiServer;
