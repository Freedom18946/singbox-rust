//! Switchable shim for the `tun2socks` API used by `sb-adapters`.
//!
//! - Default (`stub`): compile-time compatible no-op implementation.
//! - `real` (macOS): delegates to upstream `tun2socks` crate.

/// Compile-time selected implementation mode.
pub const BUILD_MODE: &str = if cfg!(all(feature = "real", target_os = "macos")) {
    "real"
} else {
    "stub"
};

/// Return implementation mode (`stub` or `real`).
#[must_use]
pub const fn implementation_mode() -> &'static str {
    BUILD_MODE
}

/// Start tun2socks runtime.
#[cfg(all(feature = "real", target_os = "macos"))]
pub fn main_from_str(yaml: &str, tun_fd: i32) -> Result<(), i32> {
    tun2socks_real::main_from_str(yaml, tun_fd)
}

/// Start tun2socks runtime (stub fallback).
#[cfg(not(all(feature = "real", target_os = "macos")))]
pub fn main_from_str(_yaml: &str, _tun_fd: i32) -> Result<(), i32> {
    Ok(())
}

/// Request tun2socks shutdown.
#[cfg(all(feature = "real", target_os = "macos"))]
pub fn quit() {
    tun2socks_real::quit();
}

/// Request tun2socks shutdown (stub no-op).
#[cfg(not(all(feature = "real", target_os = "macos")))]
pub fn quit() {}
