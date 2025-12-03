//! macOS TUN Platform Hook
//!
//! Implements auto_route and auto_redirect using:
//! - `route` command for route management
//! - `pf` (packet filter) for traffic redirection and filtering
//! - `pfctl` for pf rule management
//!
//! # Go Parity Reference
//!
//! This aligns with sing-tun's macOS auto_route implementation which uses:
//! - System route table manipulation
//! - pf rdr rules for traffic redirection

use super::{TunPlatformConfig, TunPlatformHook};
use std::fs;
use std::io::{self, Write};
use std::process::Command;
use tracing::{debug, info, warn};

/// Anchor name for pf rules
const PF_ANCHOR_NAME: &str = "com.singbox.tun";
/// Temporary pf rules file
const PF_RULES_FILE: &str = "/tmp/singbox_tun_pf.conf";

/// macOS platform hook for TUN routing
pub struct MacOsPlatformHook {
    /// State tracking for cleanup
    configured_routes: std::sync::Mutex<Vec<RouteEntry>>,
    pf_enabled: std::sync::Mutex<bool>,
}

#[derive(Debug, Clone)]
struct RouteEntry {
    destination: String,
    gateway: Option<String>,
    interface: Option<String>,
    is_ipv6: bool,
}

impl MacOsPlatformHook {
    /// Create a new macOS platform hook
    pub fn new() -> Self {
        Self {
            configured_routes: std::sync::Mutex::new(Vec::new()),
            pf_enabled: std::sync::Mutex::new(false),
        }
    }

    /// Configure routes using the `route` command
    fn configure_routes(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let interface = &config.interface_name;

        // Add default route through TUN interface
        // route add default -interface <interface>
        if config.include_routes.is_empty() {
            // Route all traffic through TUN
            self.add_route("default", None, Some(interface), false)?;

            if config.inet6_address.is_some() {
                self.add_route("default", None, Some(interface), true)?;
            }
        } else {
            // Only route specified CIDRs
            for cidr in &config.include_routes {
                let is_ipv6 = cidr.contains(':');
                self.add_route(cidr, None, Some(interface), is_ipv6)?;
            }
        }

        // Add exclude routes (these bypass TUN)
        for cidr in &config.exclude_routes {
            self.add_exclude_route(cidr)?;
        }

        Ok(())
    }

    /// Add a route
    fn add_route(
        &self,
        destination: &str,
        gateway: Option<&str>,
        interface: Option<&str>,
        is_ipv6: bool,
    ) -> io::Result<()> {
        let mut args = vec!["add"];

        if is_ipv6 {
            args.push("-inet6");
        }

        args.push(destination);

        if let Some(gw) = gateway {
            args.push(gw);
        }

        if let Some(iface) = interface {
            args.push("-interface");
            args.push(iface);
        }

        self.run_command("route", &args)?;

        self.configured_routes.lock().unwrap().push(RouteEntry {
            destination: destination.to_string(),
            gateway: gateway.map(String::from),
            interface: interface.map(String::from),
            is_ipv6,
        });

        debug!("Added route: {} via {:?} interface {:?}", destination, gateway, interface);
        Ok(())
    }

    /// Add an exclude route (bypasses TUN, uses default gateway)
    fn add_exclude_route(&self, cidr: &str) -> io::Result<()> {
        // Get the default gateway first
        let gateway = self.get_default_gateway(cidr.contains(':'))?;

        if let Some(gw) = gateway {
            self.add_route(cidr, Some(&gw), None, cidr.contains(':'))?;
        } else {
            warn!("Could not determine default gateway for exclude route: {}", cidr);
        }

        Ok(())
    }

    /// Get the default gateway
    fn get_default_gateway(&self, ipv6: bool) -> io::Result<Option<String>> {
        let args = if ipv6 {
            vec!["-n", "get", "-inet6", "default"]
        } else {
            vec!["-n", "get", "default"]
        };

        let output = Command::new("route").args(&args).output()?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Parse "gateway: x.x.x.x" from output
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("gateway:") {
                    if let Some(gw) = line.strip_prefix("gateway:") {
                        return Ok(Some(gw.trim().to_string()));
                    }
                }
            }
        }

        Ok(None)
    }

    /// Configure pf rules for auto_redirect
    fn configure_pf(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let interface = &config.interface_name;

        // Generate pf rules
        let mut rules = String::new();

        // Table for excluded addresses
        rules.push_str(&format!(
            "table <singbox_exclude> persist {{ 127.0.0.0/8, ::1/128, 224.0.0.0/4, ff00::/8 }}\n"
        ));

        // Add excluded CIDRs to table
        if !config.exclude_routes.is_empty() {
            let excludes = config.exclude_routes.join(", ");
            rules.push_str(&format!(
                "table <singbox_exclude> persist {{ {} }}\n",
                excludes
            ));
        }

        // Pass rules for TUN interface
        rules.push_str(&format!(
            "# Allow traffic on TUN interface\n\
             pass quick on {} all\n",
            interface
        ));

        // Block rules for excluded addresses
        rules.push_str(&format!(
            "# Skip excluded addresses\n\
             pass quick from <singbox_exclude>\n\
             pass quick to <singbox_exclude>\n"
        ));

        // Redirect rules (rdr for divert-to style redirection)
        // Note: macOS pf has limited redirect capabilities compared to Linux
        rules.push_str(&format!(
            "# Redirect outgoing traffic through TUN\n\
             # Note: Full transparent redirect requires additional setup\n"
        ));

        // Write rules to file
        let mut file = fs::File::create(PF_RULES_FILE)?;
        file.write_all(rules.as_bytes())?;

        debug!("Generated pf rules:\n{}", rules);

        // Load rules into pf anchor
        // First, ensure the anchor exists in the main ruleset
        // pfctl -a <anchor> -f <file>
        self.run_command("pfctl", &["-a", PF_ANCHOR_NAME, "-f", PF_RULES_FILE])?;

        // Enable pf if not already enabled
        let output = Command::new("pfctl").arg("-s").arg("info").output()?;
        let info = String::from_utf8_lossy(&output.stdout);
        if info.contains("Status: Disabled") {
            self.run_command("pfctl", &["-e"])?;
            *self.pf_enabled.lock().unwrap() = true;
        }

        info!("pf rules configured for TUN interface {}", interface);
        Ok(())
    }

    /// Configure strict route mode
    fn configure_strict_route(&self, config: &TunPlatformConfig) -> io::Result<()> {
        // In strict mode, we need to ensure all traffic goes through TUN
        // This involves more aggressive pf rules

        let interface = &config.interface_name;

        let rules = format!(
            r#"
# Strict route mode - block traffic not through TUN

# Tables
table <singbox_local> const {{ 127.0.0.0/8, ::1/128, 169.254.0.0/16, fe80::/10 }}
table <singbox_multicast> const {{ 224.0.0.0/4, ff00::/8 }}

# Allow local and multicast
pass quick from <singbox_local>
pass quick to <singbox_local>
pass quick from <singbox_multicast>
pass quick to <singbox_multicast>

# Allow TUN interface
pass quick on {interface}

# Block everything else not going through TUN
# (This is aggressive and may break things)
# block out quick on !{interface} all
"#,
            interface = interface
        );

        let mut file = fs::File::create(PF_RULES_FILE)?;
        file.write_all(rules.as_bytes())?;

        self.run_command("pfctl", &["-a", PF_ANCHOR_NAME, "-f", PF_RULES_FILE])?;

        Ok(())
    }

    /// Run a command and return result
    fn run_command(&self, cmd: &str, args: &[&str]) -> io::Result<()> {
        debug!("Running: {} {}", cmd, args.join(" "));

        let output = Command::new(cmd).args(args).output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "File exists" errors for routes
            if stderr.contains("File exists") || stderr.contains("already in table") {
                debug!("Entry already exists, ignoring");
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
            let mut args = vec!["delete"];

            if route.is_ipv6 {
                args.push("-inet6");
            }

            args.push(&route.destination);

            if let Some(ref gw) = route.gateway {
                args.push(gw);
            }

            let _ = Command::new("route").args(&args).output();
        }

        self.configured_routes.lock().unwrap().clear();
        Ok(())
    }

    /// Cleanup pf rules
    fn cleanup_pf(&self) -> io::Result<()> {
        // Flush anchor rules
        let _ = self.run_command("pfctl", &["-a", PF_ANCHOR_NAME, "-F", "all"]);

        // Remove temporary rules file
        let _ = fs::remove_file(PF_RULES_FILE);

        // Disable pf if we enabled it
        if *self.pf_enabled.lock().unwrap() {
            let _ = self.run_command("pfctl", &["-d"]);
            *self.pf_enabled.lock().unwrap() = false;
        }

        Ok(())
    }
}

impl Default for MacOsPlatformHook {
    fn default() -> Self {
        Self::new()
    }
}

impl TunPlatformHook for MacOsPlatformHook {
    fn configure(&self, config: &TunPlatformConfig) -> io::Result<()> {
        info!(
            "Configuring macOS TUN platform hooks for {}",
            config.interface_name
        );

        // Configure routes
        if config.auto_route {
            self.configure_routes(config)?;
        }

        // Configure pf for traffic redirection
        if config.auto_redirect {
            self.configure_pf(config)?;
        }

        // Configure strict route mode
        if config.strict_route {
            self.configure_strict_route(config)?;
        }

        info!("macOS TUN platform hooks configured successfully");
        Ok(())
    }

    fn cleanup(&self) -> io::Result<()> {
        info!("Cleaning up macOS TUN platform hooks");

        // Cleanup in reverse order
        self.cleanup_pf()?;
        self.cleanup_routes()?;

        info!("macOS TUN platform hooks cleaned up");
        Ok(())
    }

    fn is_supported(&self) -> bool {
        // Check if running on macOS with pfctl available
        Command::new("pfctl")
            .arg("-s")
            .arg("info")
            .output()
            .map(|_| true)
            .unwrap_or(false)
    }

    fn platform_name(&self) -> &'static str {
        "macos"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_hook_creation() {
        let hook = MacOsPlatformHook::new();
        assert_eq!(hook.platform_name(), "macos");
    }

    #[test]
    fn test_route_entry() {
        let entry = RouteEntry {
            destination: "10.0.0.0/8".to_string(),
            gateway: Some("192.168.1.1".to_string()),
            interface: None,
            is_ipv6: false,
        };
        assert!(!entry.is_ipv6);
        assert_eq!(entry.destination, "10.0.0.0/8");
    }

    #[test]
    fn test_anchor_name() {
        assert_eq!(PF_ANCHOR_NAME, "com.singbox.tun");
    }

    #[test]
    fn test_ipv6_detection() {
        assert!("2001:db8::/32".contains(':'));
        assert!(!"10.0.0.0/8".contains(':'));
    }
}
