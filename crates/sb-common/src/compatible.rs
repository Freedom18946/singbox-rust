//! Compatibility utilities for different platforms and environments.
//!
//! Mirrors `common/compatible` in Go reference.

use std::sync::atomic::{AtomicBool, Ordering};

static LOW_MEMORY_DEVICE: AtomicBool = AtomicBool::new(false);

/// Check if the current device is considered "low memory".
/// On Go side, this checks `debug.SetMemoryLimit` or `sys` constraints.
/// Rust stub: defaults to false, can be set by platform init.
pub fn is_low_memory_device() -> bool {
    LOW_MEMORY_DEVICE.load(Ordering::Relaxed)
}

/// Set the low memory device flag.
pub fn set_low_memory_device(is_low: bool) {
    LOW_MEMORY_DEVICE.store(is_low, Ordering::Relaxed);
}

/// Get the OS version as a string.
/// Stub implementation.
pub fn os_version() -> String {
    #[cfg(target_os = "android")]
    {
        // In real impl, use `android.os.Build.VERSION.RELEASE` via JNI
        "Android".to_string()
    }
    #[cfg(target_os = "ios")]
    {
        "iOS".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macOS".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "Windows".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "Linux".to_string()
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "ios",
        target_os = "macos",
        target_os = "windows",
        target_os = "linux"
    )))]
    {
        "Unknown".to_string()
    }
}
