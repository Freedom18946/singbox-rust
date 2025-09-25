//! TUN device abstraction layer
//!
//! This module provides cross-platform TUN device capabilities for transparent
//! proxy functionality with platform-specific implementations.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use thiserror::Error;

/// TUN device configuration
///
/// Example
/// ```
/// use sb_platform::tun::TunConfig;
/// let cfg = TunConfig::default();
/// assert!(cfg.mtu >= 1200);
/// ```
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "utun0", "tun0", "wintun")
    pub name: String,
    /// Maximum transmission unit
    pub mtu: u32,
    /// IPv4 address for the TUN interface
    pub ipv4: Option<IpAddr>,
    /// IPv6 address for the TUN interface
    pub ipv6: Option<IpAddr>,
    /// Whether to enable auto-route setup
    pub auto_route: bool,
    /// Route table ID (Linux specific)
    pub table: Option<u32>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: default_tun_name(),
            mtu: 1500,
            ipv4: None,
            ipv6: None,
            auto_route: false,
            table: None,
        }
    }
}

fn default_tun_name() -> String {
    #[cfg(target_os = "macos")]
    return "utun8".to_string();
    #[cfg(target_os = "linux")]
    return "tun0".to_string();
    #[cfg(target_os = "windows")]
    return "wintun".to_string();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return "tun0".to_string();
}

/// Errors that can occur during TUN device operations
#[derive(Error, Debug)]
pub enum TunError {
    #[error("Platform not supported")]
    UnsupportedPlatform,
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Device busy: {0}")]
    DeviceBusy(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

/// TUN device trait providing platform-agnostic interface
pub trait TunDevice: Send + Sync {
    /// Create and configure a new TUN device
    fn create(config: &TunConfig) -> Result<Self, TunError>
    where
        Self: Sized;

    /// Read data from the TUN device
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError>;

    /// Write data to the TUN device
    fn write(&mut self, buf: &[u8]) -> Result<usize, TunError>;

    /// Close the TUN device
    fn close(&mut self) -> Result<(), TunError>;

    /// Get the device name
    fn name(&self) -> &str;

    /// Get the device MTU
    fn mtu(&self) -> u32;

    /// Check if the device is active
    fn is_active(&self) -> bool;
}

/// Async TUN device wrapper for tokio integration
pub struct AsyncTunDevice {
    inner: Box<dyn TunDevice>,
    #[allow(dead_code)]
    runtime_handle: Arc<tokio::runtime::Handle>,
}

impl AsyncTunDevice {
    /// Create a new async TUN device
    pub fn new(config: &TunConfig) -> Result<Self, TunError> {
        let inner = create_platform_device(config)?;
        let runtime_handle = Arc::new(tokio::runtime::Handle::current());

        Ok(Self {
            inner,
            runtime_handle,
        })
    }

    /// Read data asynchronously
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        tokio::task::block_in_place(|| self.inner.read(buf))
    }

    /// Write data asynchronously
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        tokio::task::block_in_place(|| self.inner.write(buf))
    }

    /// Close the device asynchronously
    pub async fn close(&mut self) -> Result<(), TunError> {
        self.inner.close()
    }

    /// Get device name
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Get device MTU
    pub fn mtu(&self) -> u32 {
        self.inner.mtu()
    }

    /// Check if device is active
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

/// Create a platform-specific TUN device
pub fn create_platform_device(config: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
    #[cfg(target_os = "linux")]
    {
        let device = linux::LinuxTun::create(config)?;
        Ok(Box::new(device))
    }

    #[cfg(target_os = "macos")]
    {
        let device = macos::MacOsTun::create(config)?;
        Ok(Box::new(device))
    }

    #[cfg(target_os = "windows")]
    {
        let device = windows::WindowsTun::create(config)?;
        Ok(Box::new(device))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(TunError::UnsupportedPlatform)
}

/// TUN device manager for handling multiple devices
pub struct TunManager {
    devices: std::collections::HashMap<String, AsyncTunDevice>,
}

impl TunManager {
    /// Create a new TUN manager
    pub fn new() -> Self {
        Self {
            devices: std::collections::HashMap::new(),
        }
    }

    /// Create and register a new TUN device
    pub async fn create_device(&mut self, config: &TunConfig) -> Result<(), TunError> {
        let device = AsyncTunDevice::new(config)?;
        let name = device.name().to_string();
        self.devices.insert(name, device);
        Ok(())
    }

    /// Remove and close a TUN device
    pub async fn remove_device(&mut self, name: &str) -> Result<(), TunError> {
        if let Some(mut device) = self.devices.remove(name) {
            device.close().await?;
        }
        Ok(())
    }

    /// Get a device by name
    pub fn get_device(&mut self, name: &str) -> Option<&mut AsyncTunDevice> {
        self.devices.get_mut(name)
    }

    /// List all active devices
    pub fn list_devices(&self) -> Vec<&str> {
        self.devices.keys().map(|s| s.as_str()).collect()
    }

    /// Close all devices
    pub async fn close_all(&mut self) -> Result<(), TunError> {
        for (_, device) in self.devices.iter_mut() {
            device.close().await?;
        }
        self.devices.clear();
        Ok(())
    }
}

impl Default for TunManager {
    fn default() -> Self {
        Self::new()
    }
}

// Platform-specific implementations
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
pub use macos::MacOsTun;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_default() {
        let config = TunConfig::default();
        assert!(!config.name.is_empty());
        assert_eq!(config.mtu, 1500);
        assert!(!config.auto_route);
    }

    #[test]
    fn test_tun_config_custom() {
        let config = TunConfig {
            name: "test-tun".to_string(),
            mtu: 1400,
            ipv4: Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
            auto_route: true,
            ..Default::default()
        };

        assert_eq!(config.name, "test-tun");
        assert_eq!(config.mtu, 1400);
        assert!(config.ipv4.is_some());
        assert!(config.auto_route);
    }

    #[tokio::test]
    async fn test_tun_manager_creation() {
        let manager = TunManager::new();
        assert!(manager.devices.is_empty());
    }

    #[tokio::test]
    async fn test_tun_manager_operations() {
        let mut manager = TunManager::new();

        let _config = TunConfig {
            name: "test-tun".to_string(),
            ..Default::default()
        };

        // Note: This test may fail on systems without TUN support
        // In practice, these would be integration tests with proper setup
        assert_eq!(manager.list_devices().len(), 0);

        // Test cleanup
        manager.close_all().await.unwrap();
    }

    #[test]
    fn test_error_types() {
        let error = TunError::DeviceNotFound("test".to_string());
        assert!(error.to_string().contains("Device not found: test"));

        let error = TunError::PermissionDenied;
        assert!(error.to_string().contains("Permission denied"));
    }
}
