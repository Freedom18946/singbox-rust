//! TUN Platform Hooks - Auto-route and auto-redirect configuration
//!
//! This module provides platform-specific routing configuration for TUN inbound.
//! It handles automatic route table manipulation, firewall rules, and traffic redirection.
//!
//! # Platform Support
//!
//! - **Linux**: iptables/nftables, ip route with policy routing (fwmark)
//! - **macOS**: pf (packet filter), route command
//! - **Windows**: netsh route configuration
//!
//! # Go Parity Reference
//!
//! This module aligns with sing-tun's platform hooks for auto_route, auto_redirect,
//! and strict_route functionality.

use std::io;
use std::net::IpAddr;

/// TUN platform configuration for routing
#[derive(Debug, Clone, Default)]
pub struct TunPlatformConfig {
    /// TUN interface name (e.g., "utun8", "tun0", "wintun")
    pub interface_name: String,
    /// MTU for the interface
    pub mtu: u32,
    /// IPv4 address for the TUN interface
    pub inet4_address: Option<IpAddr>,
    /// IPv6 address for the TUN interface
    pub inet6_address: Option<IpAddr>,
    /// Enable automatic route setup
    pub auto_route: bool,
    /// Enable automatic traffic redirection (iptables REDIRECT / pf rdr)
    pub auto_redirect: bool,
    /// Strict route mode - ensure all traffic goes through TUN
    pub strict_route: bool,
    /// Route table ID (Linux specific)
    pub table_id: Option<u32>,
    /// Mark for policy routing (Linux specific)
    pub fwmark: Option<u32>,
    /// Exclude routes - CIDRs to exclude from TUN routing
    pub exclude_routes: Vec<String>,
    /// Include only these routes (if non-empty, only route these CIDRs)
    pub include_routes: Vec<String>,
    /// Exclude UIDs from TUN routing (Linux specific)
    pub exclude_uids: Vec<u32>,
    /// Include only these UIDs (Linux specific)
    pub include_uids: Vec<u32>,
    /// Exclude processes by name
    pub exclude_processes: Vec<String>,
    /// Include only these processes
    pub include_processes: Vec<String>,
}

/// Platform hook operations for TUN routing
pub trait TunPlatformHook: Send + Sync {
    /// Configure routing and firewall rules on startup
    fn configure(&self, config: &TunPlatformConfig) -> io::Result<()>;

    /// Cleanup routing and firewall rules on shutdown
    fn cleanup(&self) -> io::Result<()>;

    /// Check if the platform hook is supported on this system
    fn is_supported(&self) -> bool;

    /// Get platform name for logging
    fn platform_name(&self) -> &'static str;
}

/// Create platform-specific hook based on target OS
pub fn create_platform_hook() -> Box<dyn TunPlatformHook> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatformHook::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsPlatformHook::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsPlatformHook::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(UnsupportedPlatformHook)
    }
}

/// Unsupported platform fallback
struct UnsupportedPlatformHook;

impl TunPlatformHook for UnsupportedPlatformHook {
    fn configure(&self, _config: &TunPlatformConfig) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN platform hooks not supported on this platform",
        ))
    }

    fn cleanup(&self) -> io::Result<()> {
        Ok(())
    }

    fn is_supported(&self) -> bool {
        false
    }

    fn platform_name(&self) -> &'static str {
        "unsupported"
    }
}

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_config_default() {
        let config = TunPlatformConfig::default();
        assert!(!config.auto_route);
        assert!(!config.auto_redirect);
        assert!(!config.strict_route);
        assert!(config.exclude_routes.is_empty());
    }

    #[test]
    fn test_create_platform_hook() {
        let hook = create_platform_hook();
        // Should be supported on Linux, macOS, Windows; unsupported elsewhere
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert!(hook.is_supported());
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert!(!hook.is_supported());
    }
}
