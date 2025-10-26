//! Platform-specific abstractions for SingBox
//!
//! This crate provides cross-platform abstractions for:
//!
//! ## Process Matching
//! - [`process`]: Identify processes by network connections
//! - Native API support (macOS: libproc, Windows: `GetExtendedTcpTable`)
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
//! ```no_run
//! use sb_platform::process::ProcessMatcher;
//! use sb_platform::os::NAME;
//!
//! // Platform detection
//! println!("Running on: {}", NAME);
//!
//! // Process matching (async)
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let matcher = ProcessMatcher::new()?;
//! # Ok(())
//! # }
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

#![warn(missing_docs)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::undocumented_unsafe_blocks
)]

pub mod process;
pub mod tun;

/// OS detection constants and utilities
pub mod os {
    /// OS name detected at compile time
    #[cfg(target_os = "linux")]
    pub const NAME: &str = "linux";

    /// OS name detected at compile time
    #[cfg(target_os = "macos")]
    pub const NAME: &str = "macos";

    /// OS name detected at compile time
    #[cfg(target_os = "windows")]
    pub const NAME: &str = "windows";

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    compile_error!("Unsupported platform: sb-platform only supports Linux, macOS, and Windows");
}
