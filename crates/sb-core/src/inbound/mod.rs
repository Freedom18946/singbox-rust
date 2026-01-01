//! Inbound protocol implementations and management.
//! 入站协议实现和管理。
//!
//! # Inbound Layer / 入站层
//! Inbounds are the entry points for traffic into SingBox. They listen on ports
//! (or other mechanisms like TUN) and hand off traffic to the Router.
//! 入站是流量进入 SingBox 的入口点。它们监听端口（或其他机制，如 TUN）并将流量移交给路由器。
//!
//! ## Key Components / 关键组件
//! - [`InboundManager`]: Manages the lifecycle of all inbound instances.
//!   管理所有入站实例的生命周期。
//! - **Protocols**: Implementations like HTTP, SOCKS, Mixed, TUN, etc.
//!   协议实现，如 HTTP, SOCKS, Mixed, TUN 等。

#[cfg(feature = "in_direct")]
pub mod direct;
#[cfg(feature = "in_http")]
pub mod http;
#[cfg(feature = "in_http")]
pub mod http_connect;
#[cfg(feature = "in_mixed")]
pub mod mixed;
#[cfg(feature = "in_socks")]
pub mod socks5;
#[cfg(feature = "in_tun")]
pub mod tun;

pub mod manager;
#[cfg(any(
    feature = "in_direct",
    feature = "in_http",
    feature = "in_mixed",
    feature = "in_socks",
    feature = "in_tun"
))]
pub mod unsupported;

/// Loopback detection for preventing routing loops.
pub mod loopback;

pub use manager::InboundManager;
