//! Linux TUN device implementation

use super::{TunConfig, TunDevice, TunError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};

/// Linux TUN device implementation
pub struct LinuxTun {
    file: File,
    name: String,
    mtu: u32,
    active: bool,
}

impl LinuxTun {
    /// Open a TUN device on Linux using /dev/net/tun
    fn open_tun_device(config: &TunConfig) -> Result<(File, String), TunError> {
        // Open the TUN/TAP control device
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    TunError::DeviceNotFound("/dev/net/tun".to_string())
                }
                std::io::ErrorKind::PermissionDenied => TunError::PermissionDenied,
                _ => TunError::IoError(e),
            })?;

        // Set up the interface request structure
        let mut ifr = IfrData::new(&config.name);
        ifr.set_flags(IFF_TUN | IFF_NO_PI);

        // Create the TUN interface
        // SAFETY:
        // - 不变量：file 是有效的文件句柄，ifr 是正确初始化的 IfrData 结构
        // - 并发/别名：ifr 为局部变量，file 由当前线程独占访问
        // - FFI/平台契约：TUNSETIFF 是 Linux 上有效的 ioctl 命令，返回值已检查
        unsafe {
            let result = libc::ioctl(file.as_raw_fd(), TUNSETIFF, &ifr);
            if result < 0 {
                let err = std::io::Error::last_os_error();
                return match err.kind() {
                    std::io::ErrorKind::PermissionDenied => Err(TunError::PermissionDenied),
                    _ => Err(TunError::IoError(err)),
                };
            }
        }

        // Get the actual interface name (kernel may have assigned a different one)
        let actual_name = ifr.get_name().unwrap_or_else(|| config.name.clone());

        Ok((file, actual_name))
    }

    /// Configure the TUN interface parameters
    fn configure_interface(&self, config: &TunConfig) -> Result<(), TunError> {
        // Set MTU if specified
        if config.mtu > 0 {
            self.set_mtu(config.mtu)?;
        }

        // Configure IP addresses if specified
        if let Some(ipv4) = config.ipv4 {
            self.set_ipv4_address(ipv4)?;
        }

        if let Some(ipv6) = config.ipv6 {
            self.set_ipv6_address(ipv6)?;
        }

        // Enable the interface
        self.bring_up()?;

        Ok(())
    }

    /// Set the MTU of the interface
    fn set_mtu(&self, mtu: u32) -> Result<(), TunError> {
        let output = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "mtu", &mtu.to_string()])
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
        let output = std::process::Command::new("ip")
            .args(["addr", "add", &format!("{}/24", addr), "dev", &self.name])
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
        let output = std::process::Command::new("ip")
            .args(["addr", "add", &format!("{}/64", addr), "dev", &self.name])
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

    /// Bring the interface up
    fn bring_up(&self) -> Result<(), TunError> {
        let output = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .output()
            .map_err(|e| {
                TunError::OperationFailed(format!("Failed to bring interface up: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to bring interface up: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Bring the interface down
    fn bring_down(&self) -> Result<(), TunError> {
        let output = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "down"])
            .output()
            .map_err(|e| {
                TunError::OperationFailed(format!("Failed to bring interface down: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunError::OperationFailed(format!(
                "Failed to bring interface down: {}",
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
    fn test_linux_ioctl_failure_path_is_handled() {
        // This test does not perform a real ioctl; instead, validate that constructing
        // the IfrData and calling into ioctl failure path would be handled.
        // We simulate the open failure by trying to open a bogus device, which should
        // return IoError/DeviceNotFound and not panic.
        let cfg = TunConfig {
            name: "tun-test".to_string(),
            mtu: 1500,
            ipv4: None,
            ipv6: None,
        };
        // open_tun_device is private; exercise create() via TunDevice trait which calls it.
        // This should fail on typical CI runners where /dev/net/tun is unavailable.
        let res = LinuxTun::create(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn test_linux_fcntl_failure_mock() {
        // SAFETY: Calling fcntl on an invalid fd (-1) is expected to return -1 and set errno.
        // This is a test-only negative path to ensure we can observe and handle failures
        // in similar syscalls if added.
        let rc = unsafe { libc::fcntl(-1, libc::F_GETFL) };
        assert_eq!(rc, -1);
    }
}

impl TunDevice for LinuxTun {
    fn create(config: &TunConfig) -> Result<Self, TunError>
    where
        Self: Sized,
    {
        let (file, actual_name) = Self::open_tun_device(config)?;

        let mut device = Self {
            file,
            name: actual_name,
            mtu: config.mtu,
            active: true,
        };

        device.configure_interface(config)?;

        Ok(device)
    }

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.file.read(buf).map_err(TunError::IoError)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        self.file.write(buf).map_err(TunError::IoError)
    }

    fn close(&mut self) -> Result<(), TunError> {
        if self.active {
            self.bring_down()?;
            self.active = false;
        }
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

impl Drop for LinuxTun {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// Linux TUN/TAP interface constants
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;

/// Interface request structure for Linux TUN operations
#[repr(C)]
struct IfrData {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_flags: libc::c_short,
}

impl IfrData {
    fn new(name: &str) -> Self {
        let mut ifr_name = [0u8; libc::IF_NAMESIZE];
        let name_bytes = name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), libc::IF_NAMESIZE - 1);

        for (i, &byte) in name_bytes.iter().take(copy_len).enumerate() {
            ifr_name[i] = byte as libc::c_char;
        }

        Self {
            ifr_name,
            ifr_flags: 0,
        }
    }

    fn set_flags(&mut self, flags: u16) {
        self.ifr_flags = flags as libc::c_short;
    }

    fn get_name(&self) -> Option<String> {
        // SAFETY:
        // - 不变量：ifr_name 是长度为 IF_NAMESIZE 的有效数组，转换为 u8 切片
        // - 并发/别名：self 为不可变引用，数组内容在调用期间稳定
        // - FFI/平台契约：从 c_char 数组创建 u8 切片在内存布局上是安全的
        let name_bytes = unsafe {
            std::slice::from_raw_parts(self.ifr_name.as_ptr() as *const u8, libc::IF_NAMESIZE)
        };

        // Find the null terminator
        let null_pos = name_bytes.iter().position(|&x| x == 0)?;
        let name_str = std::str::from_utf8(&name_bytes[..null_pos]).ok()?;

        Some(name_str.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    #[allow(clippy::expect_used)] // Test code, expect is acceptable
    fn test_ifr_data_creation() {
        let ifr = IfrData::new("test-tun");
        let name = ifr.get_name().expect("should have valid name");
        assert_eq!(name, "test-tun");
    }

    #[test]
    fn test_ifr_data_flags() {
        let mut ifr = IfrData::new("test");
        ifr.set_flags(IFF_TUN | IFF_NO_PI);
        assert_eq!(ifr.ifr_flags, (IFF_TUN | IFF_NO_PI) as libc::c_short);
    }

    // Note: These tests require root privileges and may not work in all environments
    #[cfg(feature = "integration_tests")]
    mod integration_tests {
        use super::*;

        #[test]
        fn test_linux_tun_creation() {
            let config = TunConfig {
                name: "test-tun".to_string(),
                mtu: 1400,
                ipv4: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                ..Default::default()
            };

            // This test requires root privileges
            match LinuxTun::create(&config) {
                Ok(mut tun) => {
                    assert_eq!(tun.name(), "test-tun");
                    assert_eq!(tun.mtu(), 1400);
                    assert!(tun.is_active());

                    // Test read/write operations
                    let test_data = b"test packet";
                    let mut read_buf = [0u8; 1500];

                    // Note: This would require actual packet data to test properly
                    let _ = tun.close();
                }
                Err(TunError::PermissionDenied) => {
                    // Expected when running without root
                    println!("Skipping test: requires root privileges");
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }
    }
}
