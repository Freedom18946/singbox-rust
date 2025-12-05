//! Common utilities for sing-box Rust implementation.
//! sing-box Rust 实现的通用工具库。
//!
//! This crate provides shared utilities used across the sing-box ecosystem:
//! - Connection tracking (`conntrack`)
//! - TLS fragmentation for DPI bypass (`tlsfrag`)
//! - JA3 fingerprinting for TLS client identification (`ja3`)
//! - Bad TLS detection and version validation (`badtls`)
//! - Configuration format conversion (`convertor`) - requires `convertor` feature

#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod badtls;
pub mod conntrack;
pub mod ja3;
pub mod tlsfrag;

#[cfg(feature = "convertor")]
pub mod convertor;

/// Interrupt handling and graceful shutdown coordination.
pub mod interrupt;

/// Pipe listener for IPC (Unix sockets / Windows named pipes).
pub mod pipelistener;

/// Compatibility utilities.
pub mod compatible;

pub use badtls::{is_valid_tls, is_weak_cipher, TlsAnalyzer, TlsIssue, TlsVersion};
pub use conntrack::{global_tracker, ConnId, ConnMetadata, ConnTracker, Network};
pub use ja3::Ja3Fingerprint;
pub use tlsfrag::{extract_sni, fragment_client_hello, is_client_hello, FragmentConfig};

#[cfg(feature = "convertor")]
pub use convertor::{parse_subscription, ConfigConverter, ConfigFormat, ProxyNode};
