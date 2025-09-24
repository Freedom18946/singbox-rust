//! Windows-specific process matching implementation
//!
//! Uses Windows API to identify processes and their network connections.

use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};

pub struct WindowsProcessMatcher;

impl WindowsProcessMatcher {
    pub fn new() -> Result<Self, ProcessMatchError> {
        Ok(Self)
    }

    pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {
        // On Windows, we would use GetExtendedTcpTable or GetExtendedUdpTable
        // This is a simplified implementation

        self.find_process_with_netstat(conn).await
    }

    pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {
        // Use Windows API to get process information
        // This is a simplified implementation using external tools

        let (name, path) = self.get_process_details(pid).await?;
        Ok(ProcessInfo::new(name, path, pid))
    }

    async fn find_process_with_netstat(
        &self,
        conn: &ConnectionInfo,
    ) -> Result<u32, ProcessMatchError> {
        use tokio::process::Command;

        let protocol_flag = match conn.protocol {
            Protocol::Tcp => "-p TCP",
            Protocol::Udp => "-p UDP",
        };

        let output = Command::new("netstat")
            .args(&["-ano", protocol_flag])
            .output()
            .await
            .map_err(|e| ProcessMatchError::SystemError(format!("netstat failed: {}", e)))?;

        if !output.status.success() {
            return Err(ProcessMatchError::ProcessNotFound);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let local_addr_str = conn.local_addr.to_string();
        let remote_addr_str = conn.remote_addr.to_string();

        // Parse netstat output
        for line in stdout.lines() {
            if line.contains(&local_addr_str) && line.contains(&remote_addr_str) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if let Some(pid_str) = fields.last() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        return Ok(pid);
                    }
                }
            }
        }

        Err(ProcessMatchError::ProcessNotFound)
    }

    async fn get_process_details(&self, pid: u32) -> Result<(String, String), ProcessMatchError> {
        use tokio::process::Command;

        // Use tasklist to get process information
        let output = Command::new("tasklist")
            .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .output()
            .await
            .map_err(|e| ProcessMatchError::SystemError(format!("tasklist failed: {}", e)))?;

        if !output.status.success() {
            return Err(ProcessMatchError::ProcessNotFound);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse CSV output
        for line in stdout.lines() {
            if !line.is_empty() {
                let fields: Vec<&str> = line.split(',').map(|s| s.trim_matches('"')).collect();
                if fields.len() >= 2 {
                    let name = fields[0].to_string();

                    // Try to get full path using wmic
                    let path = self
                        .get_process_path(pid)
                        .await
                        .unwrap_or_else(|_| name.clone());

                    return Ok((name, path));
                }
            }
        }

        Err(ProcessMatchError::ProcessNotFound)
    }

    async fn get_process_path(&self, pid: u32) -> Result<String, ProcessMatchError> {
        use tokio::process::Command;

        let output = Command::new("wmic")
            .args(&[
                "process",
                "where",
                &format!("ProcessId={}", pid),
                "get",
                "ExecutablePath",
                "/format:value",
            ])
            .output()
            .await
            .map_err(|e| ProcessMatchError::SystemError(format!("wmic failed: {}", e)))?;

        if !output.status.success() {
            return Err(ProcessMatchError::ProcessNotFound);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse wmic output
        for line in stdout.lines() {
            if line.starts_with("ExecutablePath=") {
                let path = line.strip_prefix("ExecutablePath=").unwrap_or("").trim();
                if !path.is_empty() {
                    return Ok(path.to_string());
                }
            }
        }

        Err(ProcessMatchError::ProcessNotFound)
    }
}

// Note: In a production implementation, you would use proper Windows API bindings
// such as the winapi crate for better performance and reliability

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_windows_process_matcher_creation() {
        let result = WindowsProcessMatcher::new();
        assert!(result.is_ok());
    }
}
