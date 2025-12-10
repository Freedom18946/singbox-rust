//! Android VPN protect hooks.
//!
//! Provides socket protection for Android VPN service to prevent
//! routing loops through the TUN interface.
//!
//! # Usage
//! ```ignore
//! use sb_platform::android_protect::{protect_socket, set_protect_fd_handler};
//!
//! // Set the protect handler (from Android VpnService.protect callback)
//! set_protect_fd_handler(|fd| {
//!     // Call Android VpnService.protect(fd)
//!     vpn_service.protect(fd)
//! });
//!
//! // When creating outbound sockets:
//! let socket = TcpSocket::new_v4()?;
//! protect_socket(socket.as_raw_fd())?;
//! ```

use std::io;
use std::sync::RwLock;

/// Callback type for protecting a file descriptor.
pub type ProtectFn = Box<dyn Fn(i32) -> bool + Send + Sync>;

/// Global protect handler.
static PROTECT_HANDLER: RwLock<Option<ProtectFn>> = RwLock::new(None);

/// Set the socket protect handler.
///
/// This should be called from Android with a callback that invokes
/// VpnService.protect() on the file descriptor.
///
/// Note: If the RwLock is poisoned (due to a panic in another thread),
/// this function silently fails. This is acceptable since socket protection
/// is best-effort in error scenarios.
pub fn set_protect_handler(handler: ProtectFn) {
    if let Ok(mut guard) = PROTECT_HANDLER.write() {
        *guard = Some(handler);
    }
}

/// Clear the protect handler.
///
/// Note: Silently fails if the RwLock is poisoned.
pub fn clear_protect_handler() {
    if let Ok(mut guard) = PROTECT_HANDLER.write() {
        *guard = None;
    }
}

/// Check if a protect handler is set.
///
/// Returns `false` if the RwLock is poisoned.
pub fn has_protect_handler() -> bool {
    PROTECT_HANDLER.read().is_ok_and(|guard| guard.is_some())
}

/// Protect a socket file descriptor.
///
/// Returns Ok(()) if protection succeeded or no handler is set.
/// Returns Err if the protect callback returned false.
#[cfg(unix)]
pub fn protect_socket(fd: i32) -> io::Result<()> {
    let guard = match PROTECT_HANDLER.read() {
        Ok(g) => g,
        Err(_) => {
            // Lock poisoned, treat as no handler set
            return Ok(());
        }
    };

    if let Some(ref handler) = *guard {
        if handler(fd) {
            tracing::trace!("Protected socket fd={}", fd);
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "Failed to protect socket fd={}",
                fd
            )))
        }
    } else {
        // No handler set, nothing to protect
        Ok(())
    }
}

/// Protect a raw socket (Windows stub).
#[cfg(not(unix))]
pub fn protect_socket(_fd: i32) -> io::Result<()> {
    Ok(())
}

/// Protect a TcpSocket before connecting.
#[cfg(unix)]
pub fn protect_tcp_socket(socket: &tokio::net::TcpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    protect_socket(socket.as_raw_fd())
}

/// Protect a UdpSocket.
#[cfg(unix)]
pub fn protect_udp_socket(socket: &tokio::net::UdpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    protect_socket(socket.as_raw_fd())
}

/// Protect a TcpSocket (Windows stub).
#[cfg(not(unix))]
pub fn protect_tcp_socket(_socket: &tokio::net::TcpSocket) -> io::Result<()> {
    Ok(())
}

/// Protect a UdpSocket (Windows stub).
#[cfg(not(unix))]
pub fn protect_udp_socket(_socket: &tokio::net::UdpSocket) -> io::Result<()> {
    Ok(())
}

/// Android-specific VPN configuration.
#[derive(Debug, Clone, Default)]
pub struct AndroidVpnConfig {
    /// Package name of the app.
    pub package_name: Option<String>,
    /// List of allowed apps (whitelist mode).
    pub allowed_apps: Vec<String>,
    /// List of disallowed apps (blacklist mode).
    pub disallowed_apps: Vec<String>,
    /// Whether to include all apps.
    pub include_all: bool,
    /// MTU for the VPN interface.
    pub mtu: u32,
    /// Session name for VpnService.
    pub session_name: Option<String>,
}

impl AndroidVpnConfig {
    /// Check if an app should go through VPN.
    pub fn should_route_app(&self, package: &str) -> bool {
        if !self.disallowed_apps.is_empty() {
            // Blacklist mode
            return !self.disallowed_apps.iter().any(|p| p == package);
        }

        if !self.allowed_apps.is_empty() {
            // Whitelist mode
            return self.allowed_apps.iter().any(|p| p == package);
        }

        // Default: route all
        self.include_all
    }
}

/// Builder for Android VPN configuration.
#[derive(Default)]
pub struct AndroidVpnConfigBuilder {
    config: AndroidVpnConfig,
}

impl AndroidVpnConfigBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set package name.
    pub fn package_name(mut self, name: impl Into<String>) -> Self {
        self.config.package_name = Some(name.into());
        self
    }

    /// Add allowed app.
    pub fn allow_app(mut self, package: impl Into<String>) -> Self {
        self.config.allowed_apps.push(package.into());
        self
    }

    /// Add disallowed app.
    pub fn disallow_app(mut self, package: impl Into<String>) -> Self {
        self.config.disallowed_apps.push(package.into());
        self
    }

    /// Set MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.config.mtu = mtu;
        self
    }

    /// Build the config.
    pub fn build(self) -> AndroidVpnConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_protect_handler() {
        assert!(!has_protect_handler());
    }

    #[test]
    fn test_android_vpn_config_whitelist() {
        let config = AndroidVpnConfigBuilder::new()
            .allow_app("com.example.app1")
            .allow_app("com.example.app2")
            .build();

        assert!(config.should_route_app("com.example.app1"));
        assert!(!config.should_route_app("com.example.other"));
    }

    #[test]
    fn test_android_vpn_config_blacklist() {
        let mut config = AndroidVpnConfig::default();
        config
            .disallowed_apps
            .push("com.android.chrome".to_string());
        config.include_all = true;

        assert!(!config.should_route_app("com.android.chrome"));
        assert!(config.should_route_app("com.example.other"));
    }
}
