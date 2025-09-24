//! macOS-specific process matching implementation
//!
//! Uses system calls and proc_pidinfo to identify processes and their network connections.

use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};

pub struct MacOsProcessMatcher;

impl MacOsProcessMatcher {
    pub fn new() -> Result<Self, ProcessMatchError> {
        Ok(Self)
    }

    pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {
        // On macOS, we need to use system calls to find the process
        // This is a simplified implementation that would need proper system call bindings

        // For now, we'll use lsof as a fallback approach
        self.find_process_with_lsof(conn).await
    }

    pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {
        // Use proc_pidpath to get the executable path
        let path = self.get_process_path(pid)?;

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
            .map_err(|e| ProcessMatchError::SystemError(format!("lsof failed: {}", e)))?;

        if !output.status.success() {
            return Err(ProcessMatchError::ProcessNotFound);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse lsof output to find PID
        for line in stdout.lines().skip(1) {
            // Skip header
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                if let Ok(pid) = fields[1].parse::<u32>() {
                    return Ok(pid);
                }
            }
        }

        Err(ProcessMatchError::ProcessNotFound)
    }

    fn get_process_path(&self, pid: u32) -> Result<String, ProcessMatchError> {
        // Use proc_pidpath system call
        // This is a simplified version - in a real implementation, you'd use proper FFI bindings

        use std::process::Command;

        let output = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .map_err(|e| ProcessMatchError::SystemError(format!("ps failed: {}", e)))?;

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
// such as the libc crate or platform-specific crates like darwin-libproc

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_macos_process_matcher_creation() {
        let result = MacOsProcessMatcher::new();
        assert!(result.is_ok());
    }
}
