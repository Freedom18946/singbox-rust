//! Inbound adapters (server-side protocol implementations).
//!
//! This module provides server-side implementations for various proxy protocols,
//! including HTTP, SOCKS, TUN, Shadowsocks, VMess, VLESS, Trojan, and more.

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

/// Router connector module for TUN devices.
#[cfg(feature = "tun")]
pub mod router_connector;

#[cfg(feature = "tun")]
pub mod tun_enhanced;
