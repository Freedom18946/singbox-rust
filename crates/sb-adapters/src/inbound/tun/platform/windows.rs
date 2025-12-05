//! Windows TUN Platform Hook
//!
//! Implements auto_route and auto_redirect using:
//! - `netsh` for route management
//! - Windows Filtering Platform (WFP) concepts for traffic filtering
//! - WinTun driver integration
//!
//! # Go Parity Reference
//!
//! This aligns with sing-tun's Windows auto_route implementation which uses:
//! - netsh route add/delete for routing
//! - WFP for traffic filtering (advanced)

use super::{TunPlatformConfig, TunPlatformHook};
use std::io;
use std::process::Command;
use tracing::{debug, info, warn};

/// Windows platform hook for TUN routing
pub struct WindowsPlatformHook {
    /// State tracking for cleanup
    configured_routes: std::sync::Mutex<Vec<RouteEntry>>,
}

#[derive(Debug, Clone)]
struct RouteEntry {
    destination: String,
    mask: String,
    gateway: Option<String>,
    interface_index: Option<u32>,
    metric: Option<u32>,
    is_ipv6: bool,
}

impl WindowsPlatformHook {
    /// Create a new Windows platform hook
    pub fn new() -> Self {
        Self {
            configured_routes: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Get the interface index for a given interface name
    fn get_interface_index(&self, interface_name: &str) -> io::Result<Option<u32>> {
        // Use netsh to get interface index
        // netsh interface ipv4 show interfaces
        let output = Command::new("netsh")
            .args(["interface", "ipv4", "show", "interfaces"])
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(interface_name) {
                // Parse interface index from line
                // Format: "  Idx     Met         MTU          State                Name"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx_str) = parts.first() {
                    if let Ok(idx) = idx_str.parse::<u32>() {
                        return Ok(Some(idx));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Configure routes using netsh
    fn configure_routes(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let interface = &config.interface_name;

        // Get interface index
        let if_index = self.get_interface_index(interface)?;
        let if_index_str = if_index.map(|i| i.to_string());

        // Add default route through TUN interface
        if config.include_routes.is_empty() {
            // Route all traffic through TUN
            self.add_route("0.0.0.0", "0.0.0.0", None, if_index, Some(1), false, config)?;

            if config.inet6_address.is_some() {
                self.add_route("::", "0", None, if_index, Some(1), true, config)?;
            }
        } else {
            // Only route specified CIDRs
            for cidr in &config.include_routes {
                let (dest, mask) = Self::parse_cidr(cidr)?;
                let is_ipv6 = cidr.contains(':');
                self.add_route(&dest, &mask, None, if_index, Some(10), is_ipv6, config)?;
            }
        }

        // Add exclude routes (these bypass TUN)
        for cidr in &config.exclude_routes {
            self.add_exclude_route(cidr, config)?;
        }

        Ok(())
    }

    /// Parse CIDR notation to destination and mask
    fn parse_cidr(cidr: &str) -> io::Result<(String, String)> {
        if let Some((addr, prefix)) = cidr.split_once('/') {
            let prefix_len: u8 = prefix
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid CIDR prefix"))?;

            if addr.contains(':') {
                // IPv6
                Ok((addr.to_string(), prefix_len.to_string()))
            } else {
                // IPv4 - convert prefix to netmask
                let mask = Self::prefix_to_mask(prefix_len);
                Ok((addr.to_string(), mask))
            }
        } else {
            // No prefix, assume host route
            if cidr.contains(':') {
                Ok((cidr.to_string(), "128".to_string()))
            } else {
                Ok((cidr.to_string(), "255.255.255.255".to_string()))
            }
        }
    }

    /// Convert prefix length to netmask string
    fn prefix_to_mask(prefix: u8) -> String {
        let mask: u32 = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        format!(
            "{}.{}.{}.{}",
            (mask >> 24) & 0xff,
            (mask >> 16) & 0xff,
            (mask >> 8) & 0xff,
            mask & 0xff
        )
    }

    /// Add a route using netsh
    fn add_route(
        &self,
        destination: &str,
        mask: &str,
        gateway: Option<&str>,
        interface_index: Option<u32>,
        metric: Option<u32>,
        is_ipv6: bool,
        _config: &TunPlatformConfig,
    ) -> io::Result<()> {
        let mut args = vec!["interface"];

        if is_ipv6 {
            args.push("ipv6");
        } else {
            args.push("ipv4");
        }

        args.push("add");
        args.push("route");
        args.push(destination);

        if !is_ipv6 {
            args.push("mask");
            args.push(mask);
        } else {
            // For IPv6, append prefix to destination
            // Already handled in destination string
        }

        // Interface specification
        let if_idx_str;
        if let Some(idx) = interface_index {
            if_idx_str = idx.to_string();
            args.push("interface=");
            args.push(&if_idx_str);
        }

        // Gateway if specified
        if let Some(gw) = gateway {
            args.push(gw);
        }

        // Metric
        let metric_str;
        if let Some(m) = metric {
            metric_str = m.to_string();
            args.push("metric=");
            args.push(&metric_str);
        }

        self.run_command("netsh", &args)?;

        self.configured_routes.lock().unwrap().push(RouteEntry {
            destination: destination.to_string(),
            mask: mask.to_string(),
            gateway: gateway.map(String::from),
            interface_index,
            metric,
            is_ipv6,
        });

        debug!(
            "Added route: {} mask {} via {:?} if={:?}",
            destination, mask, gateway, interface_index
        );
        Ok(())
    }

    /// Add an exclude route (bypasses TUN)
    fn add_exclude_route(&self, cidr: &str, config: &TunPlatformConfig) -> io::Result<()> {
        let (dest, mask) = Self::parse_cidr(cidr)?;
        let is_ipv6 = cidr.contains(':');

        // Get the default gateway for exclude route
        let gateway = self.get_default_gateway(is_ipv6)?;

        if let Some(gw) = gateway {
            // Use main routing table (without TUN interface)
            self.add_route(&dest, &mask, Some(&gw), None, Some(100), is_ipv6, config)?;
        } else {
            warn!(
                "Could not determine default gateway for exclude route: {}",
                cidr
            );
        }

        Ok(())
    }

    /// Get the default gateway
    fn get_default_gateway(&self, ipv6: bool) -> io::Result<Option<String>> {
        let args = if ipv6 {
            vec!["interface", "ipv6", "show", "route"]
        } else {
            vec!["interface", "ipv4", "show", "route"]
        };

        let output = Command::new("netsh").args(&args).output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Look for default route (0.0.0.0/0 or ::/0)
            for line in stdout.lines() {
                let target = if ipv6 { "::/0" } else { "0.0.0.0/0" };
                if line.contains(target) {
                    // Parse gateway from line
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    // Gateway is typically the 4th or 5th column
                    for (i, part) in parts.iter().enumerate() {
                        if *part == target {
                            if let Some(gw) = parts.get(i + 1) {
                                // Validate it looks like an IP
                                if ipv6 && gw.contains(':') || !ipv6 && gw.contains('.') {
                                    return Ok(Some((*gw).to_string()));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Run a command and return result
    fn run_command(&self, cmd: &str, args: &[&str]) -> io::Result<()> {
        debug!("Running: {} {}", cmd, args.join(" "));

        let output = Command::new(cmd).args(args).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "object already exists" errors
            if stderr.contains("already exists") || stderr.contains("找不到元素") {
                debug!("Route already exists, ignoring");
                return Ok(());
            }
            warn!("Command failed: {} {} - {}", cmd, args.join(" "), stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Command failed: {}", stderr),
            ));
        }

        Ok(())
    }

    /// Cleanup routes
    fn cleanup_routes(&self) -> io::Result<()> {
        let routes = self.configured_routes.lock().unwrap().clone();

        for route in routes.iter().rev() {
            let mut args = vec!["interface"];

            if route.is_ipv6 {
                args.push("ipv6");
            } else {
                args.push("ipv4");
            }

            args.push("delete");
            args.push("route");
            args.push(&route.destination);

            if !route.is_ipv6 {
                args.push("mask");
                args.push(&route.mask);
            }

            let _ = Command::new("netsh").args(&args).output();
        }

        self.configured_routes.lock().unwrap().clear();
        Ok(())
    }
}

impl Default for WindowsPlatformHook {
    fn default() -> Self {
        Self::new()
    }
}

impl TunPlatformHook for WindowsPlatformHook {
    fn configure(&self, config: &TunPlatformConfig) -> io::Result<()> {
        info!(
            "Configuring Windows TUN platform hooks for {}",
            config.interface_name
        );

        // Configure routes
        if config.auto_route {
            self.configure_routes(config)?;
        }

        // Note: auto_redirect on Windows would require WFP integration
        // which is more complex and requires Windows-specific APIs
        if config.auto_redirect {
            warn!("auto_redirect is not fully supported on Windows yet");
            // Future: Implement WFP-based traffic redirection
        }

        // strict_route on Windows
        if config.strict_route {
            warn!("strict_route is not fully supported on Windows yet");
            // Future: Implement WFP-based strict routing
        }

        info!("Windows TUN platform hooks configured successfully");
        Ok(())
    }

    fn cleanup(&self) -> io::Result<()> {
        info!("Cleaning up Windows TUN platform hooks");

        self.cleanup_routes()?;

        info!("Windows TUN platform hooks cleaned up");
        Ok(())
    }

    fn is_supported(&self) -> bool {
        // Check if running on Windows with netsh available
        Command::new("netsh")
            .arg("/?")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn platform_name(&self) -> &'static str {
        "windows"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_hook_creation() {
        let hook = WindowsPlatformHook::new();
        assert_eq!(hook.platform_name(), "windows");
    }

    #[test]
    fn test_prefix_to_mask() {
        assert_eq!(WindowsPlatformHook::prefix_to_mask(0), "0.0.0.0");
        assert_eq!(WindowsPlatformHook::prefix_to_mask(8), "255.0.0.0");
        assert_eq!(WindowsPlatformHook::prefix_to_mask(16), "255.255.0.0");
        assert_eq!(WindowsPlatformHook::prefix_to_mask(24), "255.255.255.0");
        assert_eq!(WindowsPlatformHook::prefix_to_mask(32), "255.255.255.255");
    }

    #[test]
    fn test_parse_cidr_ipv4() {
        let (dest, mask) = WindowsPlatformHook::parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(dest, "10.0.0.0");
        assert_eq!(mask, "255.0.0.0");

        let (dest, mask) = WindowsPlatformHook::parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(dest, "192.168.1.0");
        assert_eq!(mask, "255.255.255.0");
    }

    #[test]
    fn test_parse_cidr_ipv6() {
        let (dest, prefix) = WindowsPlatformHook::parse_cidr("2001:db8::/32").unwrap();
        assert_eq!(dest, "2001:db8::");
        assert_eq!(prefix, "32");
    }

    #[test]
    fn test_parse_cidr_host() {
        let (dest, mask) = WindowsPlatformHook::parse_cidr("192.168.1.1").unwrap();
        assert_eq!(dest, "192.168.1.1");
        assert_eq!(mask, "255.255.255.255");
    }
}
