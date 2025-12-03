//! Linux TUN Platform Hook
//!
//! Implements auto_route and auto_redirect using:
//! - `ip route` for route management
//! - `iptables` / `ip6tables` for traffic redirection (auto_redirect)
//! - `nftables` as alternative to iptables
//! - Policy routing with fwmark for excluding specific traffic
//!
//! # Go Parity Reference
//!
//! This aligns with sing-tun's Linux auto_route implementation which uses:
//! - Policy routing with custom table and fwmark
//! - iptables OUTPUT chain for local traffic marking
//! - TPROXY for transparent redirection

use super::{TunPlatformConfig, TunPlatformHook};
use std::io;
use std::process::Command;
use tracing::{debug, info, warn};

/// Default routing table ID for TUN
const DEFAULT_TABLE_ID: u32 = 8500;
/// Default fwmark for policy routing
const DEFAULT_FWMARK: u32 = 0x1f00;
/// iptables chain name for TUN traffic
const CHAIN_NAME: &str = "SINGBOX_TUN";

/// Linux platform hook for TUN routing
pub struct LinuxPlatformHook {
    /// State tracking for cleanup
    configured_routes: std::sync::Mutex<Vec<RouteEntry>>,
    configured_rules: std::sync::Mutex<Vec<String>>,
    nftables_available: bool,
}

#[derive(Debug, Clone)]
struct RouteEntry {
    destination: String,
    is_ipv6: bool,
}

impl LinuxPlatformHook {
    /// Create a new Linux platform hook
    pub fn new() -> Self {
        Self {
            configured_routes: std::sync::Mutex::new(Vec::new()),
            configured_rules: std::sync::Mutex::new(Vec::new()),
            nftables_available: Self::check_nftables_available(),
        }
    }

    /// Check if nftables is available
    fn check_nftables_available() -> bool {
        Command::new("nft")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Check if iptables is available
    fn check_iptables_available() -> bool {
        Command::new("iptables")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Configure basic routes using `ip route`
    fn configure_routes(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let table_id = config.table_id.unwrap_or(DEFAULT_TABLE_ID);
        let interface = &config.interface_name;

        // Add default route to TUN interface in custom table
        // ip route add default dev <interface> table <table_id>
        self.run_command(
            "ip",
            &["route", "add", "default", "dev", interface, "table", &table_id.to_string()],
        )?;

        // Add route entry tracking
        self.configured_routes.lock().unwrap().push(RouteEntry {
            destination: "default".to_string(),
            is_ipv6: false,
        });

        // Configure IPv6 if address is set
        if config.inet6_address.is_some() {
            self.run_command(
                "ip",
                &["-6", "route", "add", "default", "dev", interface, "table", &table_id.to_string()],
            )?;

            self.configured_routes.lock().unwrap().push(RouteEntry {
                destination: "default".to_string(),
                is_ipv6: true,
            });
        }

        // Add exclude routes (routes that bypass TUN)
        for cidr in &config.exclude_routes {
            self.add_exclude_route(cidr)?;
        }

        // Add include routes (if specified, only route these)
        for cidr in &config.include_routes {
            self.add_include_route(cidr, interface, table_id)?;
        }

        Ok(())
    }

    /// Add a route that bypasses TUN
    fn add_exclude_route(&self, cidr: &str) -> io::Result<()> {
        // Add route via main table (bypasses TUN table)
        let is_ipv6 = cidr.contains(':');
        let args = if is_ipv6 {
            vec!["-6", "route", "add", cidr, "table", "main"]
        } else {
            vec!["route", "add", cidr, "table", "main"]
        };

        self.run_command("ip", &args)?;
        debug!("Added exclude route: {}", cidr);
        Ok(())
    }

    /// Add a route through TUN
    fn add_include_route(&self, cidr: &str, interface: &str, table_id: u32) -> io::Result<()> {
        let is_ipv6 = cidr.contains(':');
        let table_str = table_id.to_string();
        let args = if is_ipv6 {
            vec!["-6", "route", "add", cidr, "dev", interface, "table", &table_str]
        } else {
            vec!["route", "add", cidr, "dev", interface, "table", &table_str]
        };

        self.run_command("ip", &args)?;
        debug!("Added include route: {}", cidr);
        Ok(())
    }

    /// Configure policy routing rules using `ip rule`
    fn configure_policy_routing(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let table_id = config.table_id.unwrap_or(DEFAULT_TABLE_ID);
        let fwmark = config.fwmark.unwrap_or(DEFAULT_FWMARK);
        let table_str = table_id.to_string();
        let fwmark_str = format!("0x{:x}", fwmark);

        // Add rule: packets without fwmark go to TUN table
        // ip rule add not fwmark <fwmark> lookup <table_id>
        self.run_command(
            "ip",
            &["rule", "add", "not", "fwmark", &fwmark_str, "lookup", &table_str],
        )?;

        self.configured_rules.lock().unwrap().push(
            format!("ip rule del not fwmark {} lookup {}", fwmark_str, table_str)
        );

        // IPv6 rule if configured
        if config.inet6_address.is_some() {
            self.run_command(
                "ip",
                &["-6", "rule", "add", "not", "fwmark", &fwmark_str, "lookup", &table_str],
            )?;

            self.configured_rules.lock().unwrap().push(
                format!("ip -6 rule del not fwmark {} lookup {}", fwmark_str, table_str)
            );
        }

        Ok(())
    }

    /// Configure iptables for auto_redirect (traffic marking)
    fn configure_iptables(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let fwmark = config.fwmark.unwrap_or(DEFAULT_FWMARK);
        let fwmark_str = format!("0x{:x}", fwmark);

        // Create custom chain
        let _ = self.run_command("iptables", &["-t", "mangle", "-N", CHAIN_NAME]);

        // Add jump to custom chain from OUTPUT
        self.run_command(
            "iptables",
            &["-t", "mangle", "-A", "OUTPUT", "-j", CHAIN_NAME],
        )?;

        // Mark packets that should bypass TUN (e.g., to server)
        // This prevents routing loops

        // Exclude local traffic
        self.run_command(
            "iptables",
            &["-t", "mangle", "-A", CHAIN_NAME, "-d", "127.0.0.0/8", "-j", "RETURN"],
        )?;

        // Exclude multicast
        self.run_command(
            "iptables",
            &["-t", "mangle", "-A", CHAIN_NAME, "-d", "224.0.0.0/4", "-j", "RETURN"],
        )?;

        // Exclude UIDs if specified
        for uid in &config.exclude_uids {
            self.run_command(
                "iptables",
                &[
                    "-t", "mangle", "-A", CHAIN_NAME,
                    "-m", "owner", "--uid-owner", &uid.to_string(),
                    "-j", "MARK", "--set-mark", &fwmark_str,
                ],
            )?;
        }

        // Configure IPv6 iptables
        if config.inet6_address.is_some() {
            let _ = self.run_command("ip6tables", &["-t", "mangle", "-N", CHAIN_NAME]);
            self.run_command(
                "ip6tables",
                &["-t", "mangle", "-A", "OUTPUT", "-j", CHAIN_NAME],
            )?;

            // Exclude local IPv6
            self.run_command(
                "ip6tables",
                &["-t", "mangle", "-A", CHAIN_NAME, "-d", "::1/128", "-j", "RETURN"],
            )?;

            // Exclude link-local
            self.run_command(
                "ip6tables",
                &["-t", "mangle", "-A", CHAIN_NAME, "-d", "fe80::/10", "-j", "RETURN"],
            )?;
        }

        self.configured_rules.lock().unwrap().push(
            format!("iptables -t mangle -D OUTPUT -j {}", CHAIN_NAME)
        );
        self.configured_rules.lock().unwrap().push(
            format!("iptables -t mangle -F {}", CHAIN_NAME)
        );
        self.configured_rules.lock().unwrap().push(
            format!("iptables -t mangle -X {}", CHAIN_NAME)
        );

        Ok(())
    }

    /// Configure nftables for auto_redirect (alternative to iptables)
    fn configure_nftables(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let fwmark = config.fwmark.unwrap_or(DEFAULT_FWMARK);
        let table_name = "singbox_tun";

        // Create nftables table and chain
        let nft_commands = format!(
            r#"
table inet {table} {{
    chain output {{
        type route hook output priority mangle; policy accept;

        # Exclude localhost
        ip daddr 127.0.0.0/8 return
        ip6 daddr ::1/128 return

        # Exclude link-local
        ip6 daddr fe80::/10 return

        # Exclude multicast
        ip daddr 224.0.0.0/4 return
        ip6 daddr ff00::/8 return

        # Mark packets for TUN routing
        meta mark != 0x{fwmark:x} meta mark set 0x{fwmark:x}
    }}
}}
"#,
            table = table_name,
            fwmark = fwmark
        );

        // Apply nftables configuration
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(nft_commands.as_bytes())?;
        }

        let status = child.wait()?;
        if !status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to apply nftables configuration",
            ));
        }

        self.configured_rules.lock().unwrap().push(
            format!("nft delete table inet {}", table_name)
        );

        Ok(())
    }

    /// Run a command and return result
    fn run_command(&self, cmd: &str, args: &[&str]) -> io::Result<()> {
        debug!("Running: {} {}", cmd, args.join(" "));

        let output = Command::new(cmd)
            .args(args)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore "File exists" errors for routes
            if stderr.contains("File exists") || stderr.contains("RTNETLINK answers: File exists") {
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
    fn cleanup_routes(&self, config: &TunPlatformConfig) -> io::Result<()> {
        let table_id = config.table_id.unwrap_or(DEFAULT_TABLE_ID);
        let table_str = table_id.to_string();

        // Flush custom routing table
        let _ = self.run_command("ip", &["route", "flush", "table", &table_str]);
        let _ = self.run_command("ip", &["-6", "route", "flush", "table", &table_str]);

        Ok(())
    }

    /// Cleanup policy rules
    fn cleanup_rules(&self) -> io::Result<()> {
        let rules = self.configured_rules.lock().unwrap().clone();
        for rule_cmd in rules {
            let parts: Vec<&str> = rule_cmd.split_whitespace().collect();
            if !parts.is_empty() {
                let _ = Command::new(parts[0])
                    .args(&parts[1..])
                    .output();
            }
        }
        self.configured_rules.lock().unwrap().clear();
        Ok(())
    }
}

impl Default for LinuxPlatformHook {
    fn default() -> Self {
        Self::new()
    }
}

impl TunPlatformHook for LinuxPlatformHook {
    fn configure(&self, config: &TunPlatformConfig) -> io::Result<()> {
        info!(
            "Configuring Linux TUN platform hooks for {}",
            config.interface_name
        );

        // Configure routes
        if config.auto_route {
            self.configure_routes(config)?;
            self.configure_policy_routing(config)?;
        }

        // Configure traffic redirection
        if config.auto_redirect {
            if self.nftables_available {
                self.configure_nftables(config)?;
            } else if Self::check_iptables_available() {
                self.configure_iptables(config)?;
            } else {
                warn!("Neither nftables nor iptables available for auto_redirect");
            }
        }

        info!("Linux TUN platform hooks configured successfully");
        Ok(())
    }

    fn cleanup(&self) -> io::Result<()> {
        info!("Cleaning up Linux TUN platform hooks");

        // Cleanup in reverse order
        self.cleanup_rules()?;

        // Note: Routes are cleaned up via table flush
        let config = TunPlatformConfig::default();
        self.cleanup_routes(&config)?;

        info!("Linux TUN platform hooks cleaned up");
        Ok(())
    }

    fn is_supported(&self) -> bool {
        // Check if running on Linux with necessary tools
        std::path::Path::new("/dev/net/tun").exists()
    }

    fn platform_name(&self) -> &'static str {
        "linux"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_hook_creation() {
        let hook = LinuxPlatformHook::new();
        assert_eq!(hook.platform_name(), "linux");
    }

    #[test]
    fn test_fwmark_format() {
        let fwmark = DEFAULT_FWMARK;
        let fwmark_str = format!("0x{:x}", fwmark);
        assert_eq!(fwmark_str, "0x1f00");
    }

    #[test]
    fn test_config_defaults() {
        let config = TunPlatformConfig {
            interface_name: "tun0".to_string(),
            auto_route: true,
            ..Default::default()
        };
        assert!(config.auto_route);
        assert!(!config.auto_redirect);
        assert!(config.fwmark.is_none());
    }
}
