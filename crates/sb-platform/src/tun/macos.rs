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
        // SAFETY:
        // - 不变量：传递有效的常量参数给 socket 系统调用
        // - 并发/别名：每次调用创建新的文件描述符，无数据竞争
        // - FFI/平台契约：在 macOS 上 PF_SYSTEM/SOCK_DGRAM/SYSPROTO_CONTROL 是有效参数
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
        #[allow(clippy::cast_possible_wrap)] // C API requires c_char which may be i8
        for (i, &byte) in name_bytes.iter().take(copy_len).enumerate() {
            ctl_info.ctl_name[i] = byte as libc::c_char;
        }

        // Get control info
        // SAFETY:
        // - 不变量：fd 是有效的文件描述符，ctl_info 是正确初始化的 C 结构体
        // - 并发/别名：ctl_info 独占访问，fd 由当前线程拥有
        // - FFI/平台契约：CTLIOCGINFO 是 macOS 上有效的 ioctl 命令
        let result = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut ctl_info) };

        if result < 0 {
            // SAFETY:
            // - 不变量：fd 是有效的文件描述符
            // - 并发/别名：close 是幂等的，当前线程拥有 fd
            // - FFI/平台契约：close 系统调用在所有平台上都是安全的
            unsafe {
                libc::close(fd);
            }
            return Err(TunError::IoError(std::io::Error::last_os_error()));
        }

        // Connect to the utun control
        #[allow(clippy::cast_possible_truncation)]
        // SockaddrCtl is always 32 bytes on all platforms
        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_id: ctl_info.ctl_id,
            sc_unit: Self::parse_utun_unit(&config.name)?,
            sc_reserved: [0; 5],
        };

        // SAFETY:
        // - 不变量：fd 是有效的文件描述符，addr 指向有效的 SockaddrCtl 结构体
        // - 并发/别名：addr 为局部变量，由当前线程独占访问
        // - FFI/平台契约：connect 系统调用参数类型转换合法
        #[allow(clippy::ptr_as_ptr, clippy::borrow_as_ptr)] // Required for C FFI
        #[allow(clippy::cast_possible_truncation)] // socklen_t is u32 on macOS
        let result = unsafe {
            libc::connect(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockaddrCtl>() as u32,
            )
        };

        if result < 0 {
            // SAFETY:
            // - 不变量：fd 是有效的文件描述符
            // - 并发/别名：close 是幂等的，当前线程拥有 fd
            // - FFI/平台契约：close 系统调用在所有平台上都是安全的
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

        // SAFETY:
        // - 不变量：fd 是有效的文件描述符，from_raw_fd 转移所有权
        // - 并发/别名：File 的 Drop 实现将管理文件描述符生命周期
        // - FFI/平台契约：文件描述符所有权正确转移
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
                .map_err(|_| TunError::InvalidConfig(format!("Invalid utun name: {name}")))
        } else if name.is_empty() {
            Ok(0) // Let kernel assign
        } else {
            Err(TunError::InvalidConfig(format!(
                "Invalid utun name: {name}"
            )))
        }
    }

    /// Get the actual utun name from the file descriptor
    fn get_utun_name(fd: RawFd) -> Result<String, TunError> {
        // Query the interface name using socket options
        let mut ifname = [0u8; libc::IF_NAMESIZE];
        #[allow(clippy::cast_possible_truncation)] // IF_NAMESIZE is a small constant
        let mut len = libc::IF_NAMESIZE as libc::socklen_t;

        // SAFETY:
        // - 不变量：fd 是有效的文件描述符，ifname 是大小为 IF_NAMESIZE 的可变缓冲区
        // - 并发/别名：ifname 为局部变量，由当前线程独占访问
        // - FFI/平台契约：getsockopt 系统调用参数类型和大小正确
        #[allow(
            clippy::cast_possible_truncation,
            clippy::ptr_as_ptr,
            clippy::borrow_as_ptr
        )] // Required for C FFI
        let result = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                ifname.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut len,
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

        // Configure auto-route if enabled
        if config.auto_route {
            self.setup_route(config)?;
        }

        Ok(())
    }

    /// Set up routing for the interface
    fn setup_route(&self, config: &TunConfig) -> Result<(), TunError> {
        // Add default route for IPv4
        // route add default -interface <name>
        let output = std::process::Command::new("route")
            .args(["add", "default", "-interface", &self.name])
            .output()
            .map_err(|e| {
                TunError::OperationFailed(format!("Failed to add default IPv4 route: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "File exists" error which means route already exists
            if !stderr.contains("File exists") {
                return Err(TunError::OperationFailed(format!(
                    "Failed to add default IPv4 route: {stderr}"
                )));
            }
        }

        // Add default route for IPv6 if configured
        if config.ipv6.is_some() {
            // route add -inet6 default -interface <name>
            let output = std::process::Command::new("route")
                .args(["add", "-inet6", "default", "-interface", &self.name])
                .output()
                .map_err(|e| {
                    TunError::OperationFailed(format!("Failed to add default IPv6 route: {e}"))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.contains("File exists") {
                    return Err(TunError::OperationFailed(format!(
                        "Failed to add default IPv6 route: {stderr}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Set the MTU of the interface
    fn set_mtu(&self, mtu: u32) -> Result<(), TunError> {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "mtu", &mtu.to_string()])
            .output()
            .map_err(|e| TunError::OperationFailed(format!("Failed to set MTU: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to set MTU: {stderr}"
            )));
        }

        Ok(())
    }

    /// Set IPv4 address for the interface
    fn set_ipv4_address(&self, addr: std::net::IpAddr) -> Result<(), TunError> {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "inet", &addr.to_string(), &addr.to_string()])
            .output()
            .map_err(|e| TunError::OperationFailed(format!("Failed to set IPv4 address: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to set IPv4 address: {stderr}"
            )));
        }

        Ok(())
    }

    /// Set IPv6 address for the interface
    fn set_ipv6_address(&self, addr: std::net::IpAddr) -> Result<(), TunError> {
        let output = std::process::Command::new("ifconfig")
            .args([&self.name, "inet6", &format!("{addr}/64")])
            .output()
            .map_err(|e| TunError::OperationFailed(format!("Failed to set IPv6 address: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to set IPv6 address: {stderr}"
            )));
        }

        Ok(())
    }
}

/* first test module removed (duplicate); tests consolidated below */

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
        let family = if buf.is_empty() {
            libc::AF_INET as u32
        } else {
            match buf[0] >> 4 {
                6 => libc::AF_INET6 as u32,
                _ => libc::AF_INET as u32, // Default to IPv4 (includes version 4)
            }
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
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Return the resolved interface name assigned by the kernel.
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.name
    }
}

// macOS utun constants
const SYSPROTO_CONTROL: libc::c_int = 2;
const AF_SYSTEM: u8 = 32;
const AF_SYS_CONTROL: u16 = 2;
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const CTLIOCGINFO: libc::c_ulong = 0xC064_4E03;
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

    #[test]
    fn test_parse_utun_unit() {
        assert_eq!(MacOsTun::parse_utun_unit("utun0").ok(), Some(1));
        assert_eq!(MacOsTun::parse_utun_unit("utun8").ok(), Some(9));
        assert_eq!(MacOsTun::parse_utun_unit("utun").ok(), Some(0));
        assert_eq!(MacOsTun::parse_utun_unit("").ok(), Some(0));

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
    #[allow(clippy::panic)] // Integration tests may panic on unexpected errors
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
                    let _ipv4_packet = [0x45, 0x00, 0x00, 0x14]; // IPv4 header start
                    let _read_buf = [0u8; 1500];

                    // Note: Actual packet testing would require more setup
                    let _ = tun.close();
                }
                Err(TunError::PermissionDenied) => {
                    println!("Skipping test: requires special privileges");
                }
                Err(e) => {
                    panic!("Test failed with unexpected error: {e:?}");
                }
            }
        }
    }
}
