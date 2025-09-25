//! macOS TUN device implementation

use super::{TunConfig, TunDevice, TunError};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

/// macOS TUN device implementation using utun
pub struct MacOsTun {
    file: File,
    name: String,
    mtu: u32,
    active: bool,
}

impl MacOsTun {
    /// Open a utun device on macOS
    fn open_utun_device(config: &TunConfig) -> Result<(File, String), TunError> {
        // Create a system socket for utun control
        // SAFETY: We pass valid constants for domain (PF_SYSTEM), type (SOCK_DGRAM), and protocol
        // (SYSPROTO_CONTROL). The returned file descriptor is checked for negative values to map
        // errors into TunError without panicking.
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };

        if fd < 0 {
            return Err(TunError::IoError(std::io::Error::last_os_error()));
        }

        // Get the control ID for utun
        let mut ctl_info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };

        // Ensure the control name is a valid C string (no interior NUL)
        let control_name = CString::new(UTUN_CONTROL_NAME)
            .map_err(|_| TunError::InvalidConfig("Invalid control name".to_string()))?;

        // Copy control name to the structure
        let name_bytes = control_name.as_bytes_with_nul();
        let copy_len = std::cmp::min(name_bytes.len(), ctl_info.ctl_name.len());
        for (i, &byte) in name_bytes.iter().take(copy_len).enumerate() {
            ctl_info.ctl_name[i] = byte as libc::c_char;
        }

        // Get control info
        // SAFETY: We pass a valid file descriptor and a mutable pointer to a properly
        // initialized C structure. Return value is checked for errors (< 0).
        let result = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut ctl_info) };

        if result < 0 {
            // SAFETY: fd is valid, close is idempotent
            unsafe {
                libc::close(fd);
            }
            return Err(TunError::IoError(std::io::Error::last_os_error()));
        }

        // Connect to the utun control
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: ctl_info.ctl_id,
            sc_unit: Self::parse_utun_unit(&config.name)?,
            sc_reserved: [0; 5],
        };

        // SAFETY: We pass a valid file descriptor and a pointer to a SockaddrCtl value. The
        // size is computed from the struct type. Return value is checked (< 0) and mapped.
        let result = unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as u32,
            )
        };

        if result < 0 {
            // SAFETY: fd is valid, close is idempotent
            unsafe {
                libc::close(fd);
            }
            return Err(TunError::IoError(std::io::Error::last_os_error()));
        }

        // Get the actual utun name
        let actual_name = if addr.sc_unit == 0 {
            Self::get_utun_name(fd)?
        } else {
            format!("utun{}", addr.sc_unit - 1)
        };

        // SAFETY: from_raw_fd transfers ownership; fd will be managed by File's Drop impl
        let file = unsafe { File::from_raw_fd(fd) };
        Ok((file, actual_name))
    }

    /// Parse utun unit number from name (e.g., "utun8" -> 9)
    fn parse_utun_unit(name: &str) -> Result<u32, TunError> {
        if let Some(unit_str) = name.strip_prefix("utun") {
            if unit_str.is_empty() {
                return Ok(0); // Let kernel assign
            }
            unit_str
                .parse::<u32>()
                .map(|n| n + 1) // utun kernel numbering starts from 1
                .map_err(|_| TunError::InvalidConfig(format!("Invalid utun name: {}", name)))
        } else if name.is_empty() {
            Ok(0) // Let kernel assign
        } else {
            Err(TunError::InvalidConfig(format!(
                "Invalid utun name: {}",
                name
            )))
        }
    }

    /// Get the actual utun name from the file descriptor
    fn get_utun_name(fd: RawFd) -> Result<String, TunError> {
        // Query the interface name using socket options
        let mut ifname = [0u8; libc::IF_NAMESIZE];
        let mut len = libc::IF_NAMESIZE as libc::socklen_t;

        // SAFETY: We pass a valid fd and a pointer to a mutable buffer sized to IF_NAMESIZE.
        // len tracks the buffer length as required by getsockopt. Return value is checked.
        let result = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };

        if result < 0 {
            return Err(TunError::IoError(std::io::Error::last_os_error()));
        }

        // Find null terminator and convert to string
        let null_pos = ifname.iter().position(|&x| x == 0).unwrap_or(ifname.len());
        let name_str = std::str::from_utf8(&ifname[..null_pos])
            .map_err(|_| TunError::OperationFailed("Invalid interface name".to_string()))?;

        Ok(name_str.to_string())
    }

    /// Configure the utun interface
    fn configure_interface(&self, config: &TunConfig) -> Result<(), TunError> {
        // Set MTU if specified
        if config.mtu > 0 && config.mtu != 1500 {
            self.set_mtu(config.mtu)?;
        }

        // Configure IP addresses if specified
        if let Some(ipv4) = config.ipv4 {
            self.set_ipv4_address(ipv4)?;
        }

        if let Some(ipv6) = config.ipv6 {
            self.set_ipv6_address(ipv6)?;
        }

        Ok(())
    }

    /// Set the MTU of the interface
    fn set_mtu(&self, mtu: u32) -> Result<(), TunError> {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "mtu", &mtu.to_string()])
            .output()
            .map_err(|e| TunError::OperationFailed(format!("Failed to set MTU: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to set MTU: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Set IPv4 address for the interface
    fn set_ipv4_address(&self, addr: std::net::IpAddr) -> Result<(), TunError> {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "inet", &addr.to_string(), &addr.to_string()])
            .output()
            .map_err(|e| TunError::OperationFailed(format!("Failed to set IPv4 address: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to set IPv4 address: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Set IPv6 address for the interface
    fn set_ipv6_address(&self, addr: std::net::IpAddr) -> Result<(), TunError> {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "inet6", &format!("{}/64", addr)])
            .output()
            .map_err(|e| TunError::OperationFailed(format!("Failed to set IPv6 address: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to set IPv6 address: {}",
                stderr
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_utun_name_with_invalid_fd() {
        // Passing an invalid fd should produce an IoError without panic
        let res = MacOsTun::get_utun_name(-1);
        assert!(res.is_err());
    }

    #[test]
    fn test_cstring_new_fails_when_interior_nul() {
        // Ensure CString::new errors are mapped (this is indirect via control name in open)
        // Here we only assert CString::new would fail if given bad input; the open_utun_device
        // uses a constant so this is a direct unit assertion.
        assert!(std::ffi::CString::new(b"bad\0name".as_slice()).is_err());
    }
}

impl TunDevice for MacOsTun {
    fn create(config: &TunConfig) -> Result<Self, TunError>
    where
        Self: Sized,
    {
        let (file, actual_name) = Self::open_utun_device(config)?;

        let device = Self {
            file,
            name: actual_name,
            mtu: config.mtu,
            active: true,
        };

        device.configure_interface(config)?;

        Ok(device)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        // macOS utun includes a 4-byte protocol family header
        let bytes_read = self.file.read(buf).map_err(TunError::IoError)?;

        // Skip the first 4 bytes (protocol family) for the actual packet
        if bytes_read >= 4 {
            buf.copy_within(4..bytes_read, 0);
            Ok(bytes_read - 4)
        } else {
            Ok(bytes_read)
        }
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        // macOS utun requires a 4-byte protocol family header
        // We need to prepend the appropriate family based on IP version
        let mut packet = Vec::with_capacity(buf.len() + 4);

        // Determine protocol family from IP version
        let family = if !buf.is_empty() {
            match buf[0] >> 4 {
                4 => libc::AF_INET as u32,
                6 => libc::AF_INET6 as u32,
                _ => libc::AF_INET as u32, // Default to IPv4
            }
        } else {
            libc::AF_INET as u32
        };

        // Add protocol family header in network byte order
        packet.extend_from_slice(&family.to_be_bytes());
        packet.extend_from_slice(buf);

        let bytes_written = self.file.write(&packet).map_err(TunError::IoError)?;

        // Return the number of payload bytes written (excluding header)
        Ok(bytes_written.saturating_sub(4))
    }

    fn close(&mut self) -> Result<(), TunError> {
        self.active = false;
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }

    fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for MacOsTun {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl AsRawFd for MacOsTun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl MacOsTun {
    /// Expose raw file descriptor for integration layers that need it (e.g. tun2socks).
    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Return the resolved interface name assigned by the kernel.
    pub fn interface_name(&self) -> &str {
        &self.name
    }
}

// macOS utun constants
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYSTEM: u8 = 32;
const AF_SYS_CONTROL: u16 = 2;
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const CTLIOCGINFO: libc::c_ulong = 0xC0644E03;
const UTUN_OPT_IFNAME: libc::c_int = 2;

/// Control info structure for macOS
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [libc::c_char; 96],
}

/// Socket address structure for control sockets
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_utun_unit() {
        assert_eq!(MacOsTun::parse_utun_unit("utun0").unwrap(), 1);
        assert_eq!(MacOsTun::parse_utun_unit("utun8").unwrap(), 9);
        assert_eq!(MacOsTun::parse_utun_unit("utun").unwrap(), 0);
        assert_eq!(MacOsTun::parse_utun_unit("").unwrap(), 0);

        assert!(MacOsTun::parse_utun_unit("invalid").is_err());
        assert!(MacOsTun::parse_utun_unit("utunX").is_err());
    }

    #[test]
    fn test_ctl_info_size() {
        // Ensure the structure has the expected size
        assert_eq!(std::mem::size_of::<CtlInfo>(), 100);
    }

    #[test]
    fn test_sockaddr_ctl_size() {
        // Ensure the structure has the expected size
        assert_eq!(std::mem::size_of::<SockaddrCtl>(), 32);
    }

    // Note: These tests require special privileges on macOS
    #[cfg(feature = "integration_tests")]
    mod integration_tests {
        use super::*;
        use std::net::{IpAddr, Ipv4Addr};

        #[test]
        fn test_macos_tun_creation() {
            let config = TunConfig {
                name: "utun8".to_string(),
                mtu: 1400,
                ipv4: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                ..Default::default()
            };

            // This test requires appropriate privileges
            match MacOsTun::create(&config) {
                Ok(mut tun) => {
                    assert!(tun.name().starts_with("utun"));
                    assert_eq!(tun.mtu(), 1400);
                    assert!(tun.is_active());

                    // Test packet I/O with protocol headers
                    let ipv4_packet = vec![0x45, 0x00, 0x00, 0x14]; // IPv4 header start
                    let mut read_buf = [0u8; 1500];

                    // Note: Actual packet testing would require more setup
                    let _ = tun.close();
                }
                Err(TunError::PermissionDenied) => {
                    println!("Skipping test: requires special privileges");
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }
    }
}
