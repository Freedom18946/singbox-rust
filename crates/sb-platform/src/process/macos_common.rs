//! Shared macOS process matching logic

use super::{ConnectionInfo, ProcessMatchError, Protocol};

/// Find process ID by connection information using lsof
///
/// This is a fallback implementation used by both the default and native matchers.
/// Performance: ~100-200ms per query
pub async fn find_process_with_lsof(conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {
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
