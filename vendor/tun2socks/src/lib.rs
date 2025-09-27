//! Minimal build-time stub of the `tun2socks` crate.
//!
//! This stub exposes the small API surface we rely on in the
//! sb-adapters `tun_macos` integration so that the workspace
//! can compile with all features on stable toolchains and
//! without network access. It does not provide any functional
//! implementation.

/// Start the tun2socks runtime using a YAML configuration string and
/// an OS-specific raw file descriptor to an existing TUN device.
///
/// The real crate runs an event loop and only returns on exit. Here we
/// simply return Ok(()) immediately for build-time compatibility.
pub fn main_from_str(_yaml: &str, _tun_fd: i32) -> Result<(), i32> {
    Ok(())
}

/// Request the tun2socks runtime to terminate. No-op in this stub.
pub fn quit() {}

