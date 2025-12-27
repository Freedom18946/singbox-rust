//! Network utilities for platform-specific network information.
//!
//! Provides cross-platform network interface queries such as MAC address retrieval,
//! using native system APIs where available.

/// MAC address represented as 6 bytes.
pub type MacAddress = [u8; 6];

/// Get the MAC address of a network interface by name.
///
/// Uses platform-native APIs for best reliability:
/// - Linux: reads from `/sys/class/net/{iface}/address`
/// - macOS/BSD: uses `getifaddrs()` with `AF_LINK`
/// - Windows: uses `GetAdaptersAddresses()` API
///
/// # Arguments
/// * `iface` - The network interface name (e.g., "eth0", "en0", "Ethernet")
///
/// # Returns
/// * `Ok(MacAddress)` - 6-byte MAC address on success
/// * `Err(String)` - Error message if MAC cannot be retrieved
pub fn get_interface_mac(iface: &str) -> Result<MacAddress, String> {
    #[cfg(target_os = "linux")]
    {
        get_mac_linux(iface)
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        get_mac_bsd(iface)
    }
    #[cfg(target_os = "windows")]
    {
        get_mac_windows(iface)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "windows"
    )))]
    {
        Err(format!(
            "MAC address retrieval not supported on this platform for {iface}"
        ))
    }
}

#[cfg(target_os = "linux")]
fn get_mac_linux(iface: &str) -> Result<MacAddress, String> {
    use std::fs;

    let path = format!("/sys/class/net/{iface}/address");
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {path}: {e}"))?
        .trim()
        .to_owned();

    parse_mac_string(&content).ok_or_else(|| format!("invalid MAC format in {path}: {content}"))
}

#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
fn get_mac_bsd(iface: &str) -> Result<MacAddress, String> {
    use std::ffi::CStr;
    use std::ptr;

    // SAFETY: getifaddrs/freeifaddrs are standard POSIX functions.
    // We iterate the linked list safely and free after traversal.
    unsafe {
        let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
        if libc::getifaddrs(&mut addrs) != 0 {
            return Err("getifaddrs failed".to_string());
        }

        let mut cursor = addrs;
        let mut mac = None;

        while !cursor.is_null() {
            let ifa = &*cursor;
            if let Ok(name) = CStr::from_ptr(ifa.ifa_name).to_str() {
                if name == iface
                    && !ifa.ifa_addr.is_null()
                    && (*ifa.ifa_addr).sa_family as i32 == libc::AF_LINK
                {
                    use libc::sockaddr_dl;
                    let sdl: *const sockaddr_dl = ifa.ifa_addr as *const sockaddr_dl;
                    let sdl = &*sdl;
                    let addr_len = sdl.sdl_alen as usize;
                    let base = sdl.sdl_data.as_ptr() as *const u8;
                    let offset = sdl.sdl_nlen as usize;
                    let mac_bytes = std::slice::from_raw_parts(base.add(offset), addr_len.min(6));

                    if mac_bytes.len() == 6 {
                        let mut arr = [0u8; 6];
                        arr.copy_from_slice(mac_bytes);
                        mac = Some(arr);
                        break;
                    }
                }
            }
            cursor = (*cursor).ifa_next;
        }

        libc::freeifaddrs(addrs);

        mac.ok_or_else(|| format!("MAC not found for interface {iface}"))
    }
}

#[cfg(target_os = "windows")]
fn get_mac_windows(iface: &str) -> Result<MacAddress, String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    // Initial buffer size estimate
    let mut buffer_size: u32 = 15000;
    let mut buffer: Vec<u8>;
    let target_lower = iface.to_ascii_lowercase();

    loop {
        buffer = vec![0u8; buffer_size as usize];
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_size,
            )
        };

        match result.0 {
            0 => break, // ERROR_SUCCESS
            111 => continue, // ERROR_BUFFER_OVERFLOW - retry with new size
            code => return Err(format!("GetAdaptersAddresses failed with error {code}")),
        }
    }

    // Parse the linked list of adapters
    let mut adapter_ptr = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    // SAFETY: We iterate a valid linked list returned by Windows API.
    // The buffer is kept alive for the duration of the iteration.
    unsafe {
        while !adapter_ptr.is_null() {
            let adapter = &*adapter_ptr;

            // Get adapter name (FriendlyName is a PWSTR)
            let friendly_name = if !adapter.FriendlyName.is_null() {
                let len = (0..)
                    .take_while(|&i| *adapter.FriendlyName.0.add(i) != 0)
                    .count();
                let slice = std::slice::from_raw_parts(adapter.FriendlyName.0, len);
                String::from_utf16_lossy(slice)
            } else {
                String::new()
            };

            // Also check AdapterName (null-terminated ANSI string)
            let adapter_name = if !adapter.AdapterName.0.is_null() {
                std::ffi::CStr::from_ptr(adapter.AdapterName.0 as *const i8)
                    .to_string_lossy()
                    .to_string()
            } else {
                String::new()
            };

            // Match by friendly name or adapter name (case-insensitive)
            if friendly_name.to_ascii_lowercase() == target_lower
                || adapter_name.to_ascii_lowercase() == target_lower
                || adapter_name.to_ascii_lowercase().contains(&target_lower)
                || friendly_name.to_ascii_lowercase().contains(&target_lower)
            {
                let phy_len = adapter.PhysicalAddressLength as usize;
                if phy_len >= 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&adapter.PhysicalAddress[..6]);
                    // Skip zero/null MACs
                    if mac != [0u8; 6] {
                        return Ok(mac);
                    }
                }
            }

            adapter_ptr = adapter.Next;
        }
    }

    Err(format!(
        "MAC not found for interface {iface} using GetAdaptersAddresses"
    ))
}

/// Parse a MAC address string in various formats (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX).
pub fn parse_mac_string(raw: &str) -> Option<MacAddress> {
    let cleaned = raw.trim().trim_matches('"');
    let parts: Vec<&str> = cleaned
        .split(|c| c == '-' || c == ':' || c == ' ')
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() != 6 {
        return None;
    }

    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_colon_separated() {
        assert_eq!(
            parse_mac_string("00:1A:2B:3C:4D:5E"),
            Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        );
    }

    #[test]
    fn parse_mac_dash_separated() {
        assert_eq!(
            parse_mac_string("00-1A-2B-3C-4D-5E"),
            Some([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E])
        );
    }

    #[test]
    fn parse_mac_invalid_length() {
        assert_eq!(parse_mac_string("00:1A:2B:3C:4D"), None);
    }

    #[test]
    fn parse_mac_invalid_hex() {
        assert_eq!(parse_mac_string("ZZ:1A:2B:3C:4D:5E"), None);
    }
}
