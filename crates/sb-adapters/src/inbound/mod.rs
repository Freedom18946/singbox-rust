//! Inbound adapters (server-side protocol implementations).
//! 入站适配器（服务端协议实现）。
//!
//! This module provides server-side implementations for various proxy protocols,
//! including HTTP, SOCKS, TUN, Shadowsocks, VMess, VLESS, Trojan, and more.
//! 本模块提供各种代理协议的服务端实现，包括 HTTP, SOCKS, TUN, Shadowsocks, VMess,
//! VLESS, Trojan 等。
//!
//! Each submodule corresponds to a specific protocol or inbound type.
//! 每个子模块对应一个特定的协议或入站类型。

#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "socks")]
pub mod socks;

#[cfg(all(feature = "http", feature = "socks"))]
pub mod mixed;

pub mod direct;

#[cfg(feature = "tun")]
pub mod tun;

#[cfg(all(feature = "tun_macos", target_os = "macos"))]
pub mod tun_macos;

#[cfg(all(feature = "tun_macos", target_os = "macos"))]
pub mod tun_process_aware;

#[cfg(all(target_os = "linux", feature = "redirect"))]
pub mod redirect;

#[cfg(all(target_os = "linux", feature = "tproxy"))]
pub mod tproxy;

#[cfg(feature = "trojan")]
pub mod trojan;

#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;

#[cfg(feature = "vmess")]
pub mod vmess;

#[cfg(feature = "vless")]
pub mod vless;

#[cfg(feature = "shadowtls")]
pub mod shadowtls;

#[cfg(feature = "adapter-naive")]
pub mod naive;

#[cfg(feature = "tuic")]
pub mod tuic;

#[cfg(feature = "adapter-hysteria")]
pub mod hysteria;

#[cfg(feature = "adapter-hysteria2")]
pub mod hysteria2;

#[cfg(feature = "adapter-anytls")]
pub mod anytls;

#[cfg(feature = "tun")]
pub mod tun_session;

#[cfg(feature = "tun")]
pub mod tun_packet;

#[cfg(feature = "tun")]
pub mod tun_enhanced;
