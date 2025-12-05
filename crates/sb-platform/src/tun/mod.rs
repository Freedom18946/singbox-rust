//! TUN device abstraction layer
//!
//! # 🇨🇳 模块说明 (Module Description)
//!
//! 本模块提供了**虚拟网络设备 (TUN Device)** 的统一抽象。
//! 它是 `SingBox` 实现**透明代理 (Transparent Proxy)** 的核心组件。通过创建 TUN 设备，
//! `SingBox` 可以像操作系统内核一样直接接收和处理 IP 数据包，从而接管系统的网络流量。
//!
//! This module provides a unified abstraction for **TUN Devices**.
//! It is the core component for `SingBox`'s **Transparent Proxy** functionality. By creating a TUN device,
//! `SingBox` can receive and process IP packets directly like an OS kernel, effectively capturing system network traffic.
//!
//! ## 🚀 战略逻辑 (Strategic Logic)
//!
//! 1.  **流量接管 (Traffic Capture)**:
//!     -   作为用户态与内核态之间的桥梁，将网络流量从内核路由表引流到 `SingBox` 进程中。
//!     -   Acts as a bridge between user space and kernel space, diverting network traffic from the kernel routing table into the `SingBox` process.
//!
//! 2.  **跨平台一致性 (Cross-Platform Consistency)**:
//!     -   **Linux**: 封装 `/dev/net/tun` 字符设备与 `ioctl` 调用。
//!     -   **macOS**: 封装 System Configuration 框架管理的 `utun` 设备。
//!     -   **Windows**: 集成高性能的 `WinTun` 驱动接口。
//!     -   对外暴露统一的 `AsyncTunDevice` 接口，使得上层代理逻辑无需关心底层驱动差异。
//!
//! 3.  **高性能 I/O (High-Performance I/O)**:
//!     -   深度集成 `tokio` 异步运行时，支持零拷贝（部分实现）和高并发读写，满足千兆级吞吐需求。
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
    /// Platform is not supported for TUN operations
    #[error("Platform not supported")]
    UnsupportedPlatform,
    /// TUN device not found
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    /// Permission denied when accessing TUN device
    #[error("Permission denied")]
    PermissionDenied,
    /// Device is already in use
    #[error("Device busy: {0}")]
    DeviceBusy(String),
    /// Invalid configuration provided
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    /// Operation failed
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    /// I/O error occurred
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

/// TUN device trait providing platform-agnostic interface
///
/// # 🇨🇳 接口定义 (Interface Definition)
///
/// `TunDevice` 定义了所有平台必须实现的最小功能集。
/// 任何实现了此 Trait 的结构体都可以被 `AsyncTunDevice` 包装，从而接入 `SingBox` 的事件循环。
///
/// `TunDevice` defines the minimal feature set that all platforms must implement.
/// Any struct implementing this trait can be wrapped by `AsyncTunDevice` to integrate with `SingBox`'s event loop.
///
/// ## 关键方法 (Key Methods)
///
/// -   `read/write`: 同步阻塞读写接口（由 `AsyncTunDevice` 在 `spawn_blocking` 中调用，或在支持异步的平台上直接异步调用）。
/// -   `mtu`: 获取最大传输单元，对于分片和重组至关重要。
#[cfg(unix)]
pub trait TunDevice: Send + Sync + std::os::fd::AsRawFd {
    /// Create and configure a new TUN device
    ///
    /// # Errors
    /// Returns error if device creation or configuration fails
    fn create(config: &TunConfig) -> Result<Self, TunError>
    where
        Self: Sized;

    /// Read data from the TUN device
    ///
    /// # Errors
    /// Returns error if read operation fails
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError>;

    /// Write data to the TUN device
    ///
    /// # Errors
    /// Returns error if write operation fails
    fn write(&mut self, buf: &[u8]) -> Result<usize, TunError>;

    /// Close the TUN device
    ///
    /// # Errors
    /// Returns error if close operation fails
    fn close(&mut self) -> Result<(), TunError>;

    /// Get the device name
    fn name(&self) -> &str;

    /// Get the device MTU
    fn mtu(&self) -> u32;

    /// Check if the device is active
    fn is_active(&self) -> bool;
}

#[cfg(not(unix))]
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
    ///
    /// # Errors
    /// Returns error if device creation fails
    pub fn new(config: &TunConfig) -> Result<Self, TunError> {
        let inner = create_platform_device(config)?;
        let runtime_handle = Arc::new(tokio::runtime::Handle::current());

        Ok(Self {
            inner,
            runtime_handle,
        })
    }

    /// Read data asynchronously
    ///
    /// # Errors
    /// Returns error if read fails
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        tokio::task::block_in_place(|| self.inner.read(buf))
    }

    /// Write data asynchronously
    ///
    /// # Errors
    /// Returns error if write fails
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        tokio::task::block_in_place(|| self.inner.write(buf))
    }

    /// Close the device asynchronously
    ///
    /// # Errors
    /// Returns error if close fails
    pub fn close(&mut self) -> Result<(), TunError> {
        self.inner.close()
    }

    /// Get device name
    #[must_use]
    pub fn name(&self) -> &str {
        self.inner.name()
    }

    /// Get device MTU
    #[must_use]
    pub fn mtu(&self) -> u32 {
        self.inner.mtu()
    }

    /// Check if device is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.inner.is_active()
    }
}

/// Create a platform-specific TUN device
///
/// # Errors
/// Returns error if platform is unsupported or device creation fails
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: std::collections::HashMap::new(),
        }
    }

    /// Create and register a new TUN device
    ///
    /// # Errors
    /// Returns error if device creation fails
    pub fn create_device(&mut self, config: &TunConfig) -> Result<(), TunError> {
        let device = AsyncTunDevice::new(config)?;
        let name = device.name().to_string();
        self.devices.insert(name, device);
        Ok(())
    }

    /// Remove and close a TUN device
    ///
    /// # Errors
    /// Returns error if closing the device fails
    pub fn remove_device(&mut self, name: &str) -> Result<(), TunError> {
        if let Some(mut device) = self.devices.remove(name) {
            device.close()?;
        }
        Ok(())
    }

    /// Get a device by name
    pub fn get_device(&mut self, name: &str) -> Option<&mut AsyncTunDevice> {
        self.devices.get_mut(name)
    }

    /// List all active devices
    #[must_use]
    pub fn list_devices(&self) -> Vec<&str> {
        self.devices
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Close all devices
    ///
    /// # Errors
    /// Returns error if closing any device fails
    pub fn close_all(&mut self) -> Result<(), TunError> {
        for device in self.devices.values_mut() {
            device.close()?;
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

/// TUN configuration validation for auto_route and auto_redirect.
pub mod validation;

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

        // Test cleanup - silently ignore errors in test cleanup
        let _ = manager.close_all();
    }

    #[test]
    fn test_error_types() {
        let error = TunError::DeviceNotFound("test".to_string());
        assert!(error.to_string().contains("Device not found: test"));

        let error = TunError::PermissionDenied;
        assert!(error.to_string().contains("Permission denied"));
    }
}
