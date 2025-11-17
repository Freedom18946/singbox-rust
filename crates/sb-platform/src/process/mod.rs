//! Process matching for routing rules
//!
//! This module provides cross-platform process identification capabilities
//! for routing decisions based on process name and path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

/// Process information for a connection
///
/// Contains process name, executable path, and PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process name (e.g., "firefox")
    pub name: String,
    /// Full executable path (e.g., "/usr/bin/firefox")
    pub path: String,
    /// Process ID
    pub pid: u32,
}

impl ProcessInfo {
    /// Create a new process information struct
    #[must_use]
    pub const fn new(name: String, path: String, pid: u32) -> Self {
        Self { name, path, pid }
    }
}

/// Connection information for process matching
///
/// Identifies a network connection by local/remote addresses and protocol.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// Local socket address
    pub local_addr: SocketAddr,
    /// Remote socket address
    pub remote_addr: SocketAddr,
    /// Protocol (TCP or UDP)
    pub protocol: Protocol,
}

/// Network protocol type
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

/// Errors that can occur during process matching
#[derive(Error, Debug)]
pub enum ProcessMatchError {
    /// Platform is not supported for process matching
    #[error("Platform not supported")]
    UnsupportedPlatform,
    /// Process not found for the given connection
    #[error("Process not found for connection")]
    ProcessNotFound,
    /// Permission denied when accessing process information
    #[error("Permission denied accessing process information")]
    PermissionDenied,
    /// System-level error occurred
    #[error("System error: {0}")]
    SystemError(String),
    /// I/O error occurred
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Cache entry for process information
#[derive(Debug, Clone)]
struct CacheEntry {
    process_info: ProcessInfo,
    timestamp: Instant,
}

/// Process matcher with platform-specific implementations
///
/// Provides cross-platform process matching with automatic caching.
/// Uses platform-specific implementations under the hood:
/// - Linux: /proc filesystem
/// - macOS: lsof fallback or native libproc (with `native-process-match` feature)
/// - Windows: netstat fallback or native `GetExtendedTcpTable` (with `native-process-match` feature)
pub struct ProcessMatcher {
    cache: Arc<RwLock<HashMap<u32, CacheEntry>>>,
    cache_ttl: Duration,
    #[cfg(target_os = "linux")]
    linux_impl: linux::LinuxProcessMatcher,
    #[cfg(target_os = "macos")]
    #[cfg(not(feature = "native-process-match"))]
    macos_impl: macos::MacOsProcessMatcher,
    #[cfg(target_os = "macos")]
    #[cfg(feature = "native-process-match")]
    macos_native_impl: native_macos::NativeMacOsProcessMatcher,
    #[cfg(target_os = "windows")]
    #[cfg(not(feature = "native-process-match"))]
    windows_impl: windows::WindowsProcessMatcher,
    #[cfg(target_os = "windows")]
    #[cfg(feature = "native-process-match")]
    windows_native_impl: native_windows::NativeWindowsProcessMatcher,
}

impl ProcessMatcher {
    /// Create a new process matcher
    ///
    /// # Errors
    /// Returns error if platform-specific initialization fails
    pub fn new() -> Result<Self, ProcessMatchError> {
        let cache_ttl = Duration::from_secs(30); // Cache process info for 30 seconds

        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            #[cfg(target_os = "linux")]
            linux_impl: linux::LinuxProcessMatcher::new()?,
            #[cfg(target_os = "macos")]
            #[cfg(not(feature = "native-process-match"))]
            macos_impl: macos::MacOsProcessMatcher::new()?,
            #[cfg(target_os = "macos")]
            #[cfg(feature = "native-process-match")]
            macos_native_impl: native_macos::NativeMacOsProcessMatcher::new()?,
            #[cfg(target_os = "windows")]
            #[cfg(not(feature = "native-process-match"))]
            windows_impl: windows::WindowsProcessMatcher::new()?,
            #[cfg(target_os = "windows")]
            #[cfg(feature = "native-process-match")]
            windows_native_impl: native_windows::NativeWindowsProcessMatcher::new()?,
        })
    }

    /// Match a connection to its process information
    ///
    /// Returns cached result if available and fresh (< 30s old).
    ///
    /// # Errors
    /// Returns error if process cannot be identified or permission denied
    pub async fn match_connection(
        &self,
        conn: &ConnectionInfo,
    ) -> Result<ProcessInfo, ProcessMatchError> {
        // First try to find the process ID for this connection
        let pid = self.find_process_id(conn).await?;

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&pid) {
                if entry.timestamp.elapsed() < self.cache_ttl {
                    return Ok(entry.process_info.clone());
                }
            }
        }

        // Get process information
        let process_info = self.get_process_info(pid).await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                pid,
                CacheEntry {
                    process_info: process_info.clone(),
                    timestamp: Instant::now(),
                },
            );
        }

        Ok(process_info)
    }

    /// Find the process ID for a connection
    async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {
        #[cfg(target_os = "linux")]
        return self.linux_impl.find_process_id(conn).await;

        #[cfg(target_os = "macos")]
        #[cfg(not(feature = "native-process-match"))]
        return self.macos_impl.find_process_id(conn).await;

        #[cfg(target_os = "macos")]
        #[cfg(feature = "native-process-match")]
        return self.macos_native_impl.find_process_id(conn).await;

        #[cfg(target_os = "windows")]
        #[cfg(not(feature = "native-process-match"))]
        return self.windows_impl.find_process_id(conn).await;

        #[cfg(target_os = "windows")]
        #[cfg(feature = "native-process-match")]
        return self.windows_native_impl.find_process_id(conn).await;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err(ProcessMatchError::UnsupportedPlatform)
    }

    /// Get process information by PID
    async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {
        #[cfg(target_os = "linux")]
        return self.linux_impl.get_process_info(pid).await;

        #[cfg(target_os = "macos")]
        #[cfg(not(feature = "native-process-match"))]
        return self.macos_impl.get_process_info(pid).await;

        #[cfg(target_os = "macos")]
        #[cfg(feature = "native-process-match")]
        return self.macos_native_impl.get_process_info(pid).await;

        #[cfg(target_os = "windows")]
        #[cfg(not(feature = "native-process-match"))]
        return self.windows_impl.get_process_info(pid).await;

        #[cfg(target_os = "windows")]
        #[cfg(feature = "native-process-match")]
        return self.windows_native_impl.get_process_info(pid).await;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err(ProcessMatchError::UnsupportedPlatform)
    }

    /// Clean expired cache entries (older than cache TTL)
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.timestamp) < self.cache_ttl);
    }
}

// REMOVED: Default trait implementation that violated workspace lint (unwrap_used = deny)
// If you need a default instance, use ProcessMatcher::new().expect("initialization failed")
// or handle the Result properly in your application code.

// Platform-specific implementations

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
#[cfg(not(feature = "native-process-match"))]
mod macos;

#[cfg(target_os = "macos")]
#[cfg(feature = "native-process-match")]
mod native_macos;

#[cfg(target_os = "windows")]
#[cfg(not(feature = "native-process-match"))]
mod windows;

#[cfg(target_os = "windows")]
#[cfg(feature = "native-process-match")]
mod native_windows;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_process_matcher_creation() {
        let result = ProcessMatcher::new();

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert!(
            result.is_ok(),
            "ProcessMatcher creation should succeed on supported platforms"
        );

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert!(
            result.is_err(),
            "ProcessMatcher creation should fail on unsupported platforms"
        );
    }

    #[tokio::test]
    async fn test_cache_cleanup() -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let matcher = ProcessMatcher::new()?;

            // Add a test entry to cache
            {
                let mut cache = matcher.cache.write().await;
                cache.insert(
                    1234,
                    CacheEntry {
                        process_info: ProcessInfo::new(
                            "test".to_string(),
                            "/test".to_string(),
                            1234,
                        ),
                        timestamp: Instant::now() - Duration::from_secs(60), // Expired
                    },
                );
            }

            matcher.cleanup_cache().await;

            let cache = matcher.cache.read().await;
            assert!(cache.is_empty(), "Cache should be empty after cleanup");
        }
        Ok(())
    }

    #[test]
    fn test_connection_info() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);

        let conn_info = ConnectionInfo {
            local_addr,
            remote_addr,
            protocol: Protocol::Tcp,
        };

        assert_eq!(conn_info.local_addr, local_addr);
        assert_eq!(conn_info.remote_addr, remote_addr);
        assert_eq!(conn_info.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_process_info() {
        let process_info =
            ProcessInfo::new("firefox".to_string(), "/usr/bin/firefox".to_string(), 1234);

        assert_eq!(process_info.name, "firefox");
        assert_eq!(process_info.path, "/usr/bin/firefox");
        assert_eq!(process_info.pid, 1234);
    }
}
