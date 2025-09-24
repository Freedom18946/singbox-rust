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
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessInfo {
    pub name: String,
    pub path: String,
    pub pid: u32,
}

impl ProcessInfo {
    pub fn new(name: String, path: String, pid: u32) -> Self {
        Self { name, path, pid }
    }
}

/// Connection information for process matching
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Errors that can occur during process matching
#[derive(Error, Debug)]
pub enum ProcessMatchError {
    #[error("Platform not supported")]
    UnsupportedPlatform,
    #[error("Process not found for connection")]
    ProcessNotFound,
    #[error("Permission denied accessing process information")]
    PermissionDenied,
    #[error("System error: {0}")]
    SystemError(String),
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
pub struct ProcessMatcher {
    cache: Arc<RwLock<HashMap<u32, CacheEntry>>>,
    cache_ttl: Duration,
    #[cfg(target_os = "linux")]
    linux_impl: linux::LinuxProcessMatcher,
    #[cfg(target_os = "macos")]
    macos_impl: macos::MacOsProcessMatcher,
    #[cfg(target_os = "windows")]
    windows_impl: windows::WindowsProcessMatcher,
}

impl ProcessMatcher {
    /// Create a new process matcher
    pub fn new() -> Result<Self, ProcessMatchError> {
        let cache_ttl = Duration::from_secs(30); // Cache process info for 30 seconds

        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl,
            #[cfg(target_os = "linux")]
            linux_impl: linux::LinuxProcessMatcher::new()?,
            #[cfg(target_os = "macos")]
            macos_impl: macos::MacOsProcessMatcher::new()?,
            #[cfg(target_os = "windows")]
            windows_impl: windows::WindowsProcessMatcher::new()?,
        })
    }

    /// Match a connection to its process information
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
        return self.macos_impl.find_process_id(conn).await;

        #[cfg(target_os = "windows")]
        return self.windows_impl.find_process_id(conn).await;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err(ProcessMatchError::UnsupportedPlatform)
    }

    /// Get process information by PID
    async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {
        #[cfg(target_os = "linux")]
        return self.linux_impl.get_process_info(pid).await;

        #[cfg(target_os = "macos")]
        return self.macos_impl.get_process_info(pid).await;

        #[cfg(target_os = "windows")]
        return self.windows_impl.get_process_info(pid).await;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err(ProcessMatchError::UnsupportedPlatform)
    }

    /// Clean expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.timestamp) < self.cache_ttl);
    }
}

impl Default for ProcessMatcher {
    fn default() -> Self {
        Self::new().expect("Failed to create ProcessMatcher")
    }
}

// Platform-specific implementations

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_process_matcher_creation() {
        let result = ProcessMatcher::new();

        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        assert!(result.is_ok());

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let matcher = ProcessMatcher::new().unwrap();

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
            assert!(cache.is_empty());
        }
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
