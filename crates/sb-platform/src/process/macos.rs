//! macOS-specific process matching implementation
//!
//! Uses system calls and `proc_pidinfo` to identify processes and their network connections.
//!
//! ## Performance Note
//! The default implementation uses command-line tools (`lsof`, `ps`) which are **slow**
//! and spawn new processes for each query. For production use, enable the
//! `native-process-match` feature to use native macOS APIs (libproc) for 10-100x speedup.

use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};

/// macOS process matcher
///
/// # Performance
/// This fallback implementation uses external tools and is significantly slower than
/// the native API version. Enable the `native-process-match` feature for better performance.
#[derive(Default)]
pub struct MacOsProcessMatcher;

impl MacOsProcessMatcher {
    /// Create a new macOS process matcher
    ///
    /// # Errors
    /// Returns error if initialization fails (currently infallible on macOS)
    pub fn new() -> Result<Self, ProcessMatchError> {
        Ok(Self)
    }

    /// Find the process ID owning a network connection
    ///
    /// # Performance
    /// This implementation uses `lsof` which is slow. Consider enabling `native-process-match`.
    ///
    /// # Errors
    /// Returns error if connection not found or `lsof` fails
    pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {
        // On macOS, we need to use system calls to find the process
        // This is a simplified implementation that would need proper system call bindings

        // For now, we'll use lsof as a fallback approach
        self.find_process_with_lsof(conn).await
    }

    /// Get detailed process information for a given PID
    ///
    /// # Errors
    /// Returns error if process not found or permission denied
    pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {
        // Use proc_pidpath to get the executable path
        let path = self.get_process_path(pid).await?;

        // Extract process name from path
        let name = std::path::Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(ProcessInfo::new(name, path, pid))
    }

    async fn find_process_with_lsof(
        &self,
        conn: &ConnectionInfo,
    ) -> Result<u32, ProcessMatchError> {
        use tokio::process::Command;

        let protocol_flag = match conn.protocol {
            Protocol::Tcp => "-iTCP",
            Protocol::Udp => "-iUDP",
        };

        let addr_spec = format!("{}:{}", conn.local_addr.ip(), conn.local_addr.port());

        let output = Command::new("lsof")
            .args(["-n", "-P", protocol_flag, &addr_spec])
            .output()
            .await
            .map_err(|e| {
                ProcessMatchError::SystemError(format!("lsof failed (install via brew?): {e}"))
            })?;

        if !output.status.success() {
            return Err(ProcessMatchError::ProcessNotFound);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse lsof output to find PID (format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME)
        for line in stdout.lines().skip(1) {
            // Skip header
            let mut fields = line.split_whitespace();
            // Skip COMMAND (field 0)
            fields.next();
            // Get PID (field 1)
            if let Some(pid_str) = fields.next() {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    return Ok(pid);
                }
            }
        }

        Err(ProcessMatchError::ProcessNotFound)
    }

    async fn get_process_path(&self, pid: u32) -> Result<String, ProcessMatchError> {
        // Use proc_pidpath system call
        // This is a simplified version - in a real implementation, you'd use proper FFI bindings

        use tokio::process::Command;

        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .await
            .map_err(|e| ProcessMatchError::SystemError(format!("ps failed: {e}")))?;

        if !output.status.success() {
            return Err(ProcessMatchError::ProcessNotFound);
        }

        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if path.is_empty() {
            return Err(ProcessMatchError::ProcessNotFound);
        }

        Ok(path)
    }
}

// Note: In a production implementation, you would use proper system call bindings
// such as the libproc crate (enabled via the `native-process-match` feature).
// See `native_macos.rs` for the high-performance native implementation.

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_macos_process_matcher_creation() {
        let result = MacOsProcessMatcher::new();
        assert!(result.is_ok());
    }
}
