//! Android-specific process matching implementation
//!
//! Uses the procfs-based Linux matcher for PID lookup and process metadata.

use super::{ConnectionInfo, ProcessInfo, ProcessMatchError};

/// Android process matcher
///
/// Android exposes procfs, so connection ownership is resolved with the
/// shared Linux matcher. Package-name resolution requires app Context
/// cooperation and is intentionally left to the Android integration layer.
#[derive(Debug)]
pub struct AndroidProcessMatcher {
    /// Linux matcher for procfs operations
    linux_impl: super::linux::LinuxProcessMatcher,
}

impl AndroidProcessMatcher {
    /// Create a new Android process matcher.
    ///
    /// # Errors
    /// Returns error if procfs matcher initialization fails.
    pub fn new() -> Result<Self, ProcessMatchError> {
        Ok(Self {
            linux_impl: super::linux::LinuxProcessMatcher::new()?,
        })
    }

    /// Find the process ID owning a connection.
    ///
    /// # Errors
    /// Returns error if the connection cannot be mapped to a process.
    pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {
        self.linux_impl.find_process_id(conn).await
    }

    /// Get process information by PID.
    ///
    /// # Errors
    /// Returns error if process metadata cannot be read from procfs.
    pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {
        self.linux_impl.get_process_info(pid).await
    }
}
