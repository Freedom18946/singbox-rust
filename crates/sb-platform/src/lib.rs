//! Platform-specific abstractions for SingBox
//!
//! This crate provides cross-platform abstractions for:
//!
//! ## Process Matching
//! - [`process`]: Identify processes by network connections
//! - Native API support (macOS: libproc, Windows: GetExtendedTcpTable)
//! - Command-line tool fallback (lsof, netstat)
//! - Feature flag: `native-process-match` (default: enabled)
//!
//! ## TUN Device Management
//! - [`tun`]: Create and manage TUN/TAP virtual network devices
//! - Platform-specific implementations:
//!   - Linux: `/dev/net/tun` with ioctl
//!   - macOS: `utun` devices
//!   - Windows: WinTun driver (in progress)
//! - Async I/O support via tokio
//!
//! ## OS Detection
//! - [`os::NAME`]: Compile-time OS identification
//!
//! # Example
//!
//! ```rust
//! use sb_platform::process::ProcessMatcher;
//! use sb_platform::os::NAME;
//!
//! // Platform detection
//! println!("Running on: {}", NAME);
//!
//! // Process matching (async)
//! # tokio_test::block_on(async {
//! let matcher = ProcessMatcher::new().unwrap();
//! # });
//! ```
//!
//! # Features
//!
//! - `native-process-match` (default): Enable native OS APIs for process matching
//! - `linux`: Linux-specific features
//! - `macos`: macOS-specific features
//! - `windows`: Windows-specific features
//! - `tun`: TUN device support
//! - `full`: Enable all platform features

pub mod process;
pub mod tun;

#[cfg(target_os = "linux")]
pub mod os {
    pub const NAME: &str = "linux";
}
#[cfg(target_os = "macos")]
pub mod os {
    pub const NAME: &str = "macos";
}
#[cfg(target_os = "windows")]
pub mod os {
    pub const NAME: &str = "windows";
}
