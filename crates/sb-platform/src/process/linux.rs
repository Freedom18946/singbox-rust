//! Linux-specific process matching implementation
//!
//! Uses /proc filesystem to identify processes and their network connections.

use super::{ConnectionInfo, ProcessInfo, ProcessMatchError, Protocol};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tokio::fs as async_fs;

pub struct LinuxProcessMatcher {
    // Cache for inode to PID mapping
    inode_cache: std::sync::Mutex<HashMap<u64, u32>>,
}

impl LinuxProcessMatcher {
    pub fn new() -> Result<Self, ProcessMatchError> {
        Ok(Self {
            inode_cache: std::sync::Mutex::new(HashMap::new()),
        })
    }

    pub async fn find_process_id(&self, conn: &ConnectionInfo) -> Result<u32, ProcessMatchError> {
        // Find the socket inode for this connection
        let inode = self.find_socket_inode(conn).await?;

        // Find the process that owns this socket
        self.find_process_by_inode(inode).await
    }

    pub async fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, ProcessMatchError> {
        let comm_path = format!("/proc/{}/comm", pid);
        let exe_path = format!("/proc/{}/exe", pid);

        // Read process name from /proc/PID/comm
        let name = match async_fs::read_to_string(&comm_path).await {
            Ok(content) => content.trim().to_string(),
            Err(_) => return Err(ProcessMatchError::ProcessNotFound),
        };

        // Read process path from /proc/PID/exe
        let path = match async_fs::read_link(&exe_path).await {
            Ok(path_buf) => path_buf.to_string_lossy().to_string(),
            Err(_) => {
                // Fallback to cmdline if exe is not available
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                match async_fs::read_to_string(&cmdline_path).await {
                    Ok(content) => {
                        // cmdline is null-separated, take the first part
                        content.split('\0').next().unwrap_or(&name).to_string()
                    }
                    Err(_) => name.clone(),
                }
            }
        };

        Ok(ProcessInfo::new(name, path, pid))
    }

    async fn find_socket_inode(&self, conn: &ConnectionInfo) -> Result<u64, ProcessMatchError> {
        let proc_net_path = match conn.protocol {
            Protocol::Tcp => "/proc/net/tcp",
            Protocol::Udp => "/proc/net/udp",
        };

        let content = async_fs::read_to_string(proc_net_path)
            .await
            .map_err(|e| ProcessMatchError::IoError(e))?;

        // Parse /proc/net/tcp or /proc/net/udp
        for line in content.lines().skip(1) {
            // Skip header
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            // Parse local address (field 1) and remote address (field 2)
            let local_addr = parse_proc_net_addr(fields[1])?;
            let remote_addr = parse_proc_net_addr(fields[2])?;

            if local_addr == conn.local_addr && remote_addr == conn.remote_addr {
                // Found the connection, extract inode (field 9)
                let inode: u64 = fields[9]
                    .parse()
                    .map_err(|_| ProcessMatchError::SystemError("Invalid inode".to_string()))?;
                return Ok(inode);
            }
        }

        Err(ProcessMatchError::ProcessNotFound)
    }

    async fn find_process_by_inode(&self, inode: u64) -> Result<u32, ProcessMatchError> {
        // Check cache first
        {
            let cache = self.inode_cache.lock().unwrap();
            if let Some(&pid) = cache.get(&inode) {
                return Ok(pid);
            }
        }

        // Scan /proc/*/fd/* for the inode
        let proc_dir = Path::new("/proc");
        let mut entries = async_fs::read_dir(proc_dir)
            .await
            .map_err(|e| ProcessMatchError::IoError(e))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| ProcessMatchError::IoError(e))?
        {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();

            // Skip non-numeric directories
            if let Ok(pid) = pid_str.parse::<u32>() {
                if let Ok(found_inode) = self.check_process_fds(pid, inode).await {
                    if found_inode {
                        // Cache the result
                        {
                            let mut cache = self.inode_cache.lock().unwrap();
                            cache.insert(inode, pid);
                        }
                        return Ok(pid);
                    }
                }
            }
        }

        Err(ProcessMatchError::ProcessNotFound)
    }

    async fn check_process_fds(
        &self,
        pid: u32,
        target_inode: u64,
    ) -> Result<bool, ProcessMatchError> {
        let fd_dir = format!("/proc/{}/fd", pid);
        let fd_path = Path::new(&fd_dir);

        let mut entries = match async_fs::read_dir(fd_path).await {
            Ok(entries) => entries,
            Err(_) => return Ok(false), // Process might have exited or no permission
        };

        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| ProcessMatchError::IoError(e))?
        {
            if let Ok(link_target) = async_fs::read_link(entry.path()).await {
                let link_str = link_target.to_string_lossy();

                // Check if this is a socket with our target inode
                if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                    if let Some(inode_str) = link_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            if inode == target_inode {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}

fn parse_proc_net_addr(addr_str: &str) -> Result<SocketAddr, ProcessMatchError> {
    let parts: Vec<&str> = addr_str.split(':').collect();
    if parts.len() != 2 {
        return Err(ProcessMatchError::SystemError(
            "Invalid address format".to_string(),
        ));
    }

    // Parse hex IP address (little-endian for IPv4)
    let ip_hex = parts[0];
    let port_hex = parts[1];

    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|_| ProcessMatchError::SystemError("Invalid port".to_string()))?;

    if ip_hex.len() == 8 {
        // IPv4 address
        let ip_num = u32::from_str_radix(ip_hex, 16)
            .map_err(|_| ProcessMatchError::SystemError("Invalid IPv4 address".to_string()))?;

        // Convert from little-endian
        let ip_bytes = ip_num.to_le_bytes();
        let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

        Ok(SocketAddr::new(ip.into(), port))
    } else if ip_hex.len() == 32 {
        // IPv6 address
        let mut ip_bytes = [0u8; 16];
        for i in 0..16 {
            let byte_hex = &ip_hex[i * 2..i * 2 + 2];
            ip_bytes[i] = u8::from_str_radix(byte_hex, 16)
                .map_err(|_| ProcessMatchError::SystemError("Invalid IPv6 address".to_string()))?;
        }

        let ip = std::net::Ipv6Addr::from(ip_bytes);
        Ok(SocketAddr::new(ip.into(), port))
    } else {
        Err(ProcessMatchError::SystemError(
            "Unknown address format".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_parse_proc_net_addr_ipv4() {
        // Example from /proc/net/tcp: "0100007F:1F90" = 127.0.0.1:8080
        let addr = parse_proc_net_addr("0100007F:1F90").unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_linux_process_matcher_creation() {
        let result = LinuxProcessMatcher::new();
        assert!(result.is_ok());
    }
}
