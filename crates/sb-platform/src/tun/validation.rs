//! TUN auto_route and auto_redirect validation.
//!
//! Validates TUN configuration for routing table conflicts and
//! ensures proper setup for transparent proxying.
//!
//! # Example
//! ```ignore
//! use sb_platform::tun::validation::{validate_auto_route, ValidationResult};
//!
//! let result = validate_auto_route(&config);
//! if !result.is_valid() {
//!     for error in result.errors() {
//!         eprintln!("Error: {}", error);
//!     }
//! }
//! ```

use std::net::IpAddr;

/// Validation result for TUN configuration.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Validation errors.
    errors: Vec<ValidationError>,
    /// Validation warnings.
    warnings: Vec<String>,
}

impl ValidationResult {
    /// Create a new empty validation result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if validation passed.
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Add an error.
    pub fn add_error(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Add a warning.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// Get all errors.
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    /// Get all warnings.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// Validation error types.
#[derive(Debug, Clone)]
pub enum ValidationError {
    /// Route conflict with existing route.
    RouteConflict {
        /// CIDR that caused the conflict.
        cidr: String,
        /// Existing route that conflicts.
        existing: String,
    },
    /// Invalid MTU value.
    InvalidMtu {
        /// The invalid MTU value.
        value: u32,
        /// Reason why it's invalid.
        reason: String,
    },
    /// Missing required permissions.
    PermissionDenied {
        /// Operation that requires permission.
        operation: String,
    },
    /// Interface name too long.
    InvalidInterfaceName {
        /// The invalid interface name.
        name: String,
        /// Maximum allowed length.
        max_len: usize,
    },
    /// Invalid IP address configuration.
    InvalidAddress {
        /// The invalid address.
        addr: String,
        /// Reason why it's invalid.
        reason: String,
    },
    /// Conflicting configuration.
    ConfigConflict {
        /// First conflicting field.
        field1: String,
        /// Second conflicting field.
        field2: String,
        /// Reason for conflict.
        reason: String,
    },
    /// Other error.
    Other(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouteConflict { cidr, existing } => {
                write!(
                    f,
                    "Route {} conflicts with existing route {}",
                    cidr, existing
                )
            }
            Self::InvalidMtu { value, reason } => {
                write!(f, "Invalid MTU {}: {}", value, reason)
            }
            Self::PermissionDenied { operation } => {
                write!(f, "Permission denied for {}", operation)
            }
            Self::InvalidInterfaceName { name, max_len } => {
                write!(
                    f,
                    "Interface name '{}' exceeds max length {}",
                    name, max_len
                )
            }
            Self::InvalidAddress { addr, reason } => {
                write!(f, "Invalid address {}: {}", addr, reason)
            }
            Self::ConfigConflict {
                field1,
                field2,
                reason,
            } => {
                write!(
                    f,
                    "Config conflict between {} and {}: {}",
                    field1, field2, reason
                )
            }
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// TUN configuration for validation.
#[derive(Debug, Clone, Default)]
pub struct TunValidationConfig {
    /// Interface name.
    pub name: String,
    /// MTU value.
    pub mtu: u32,
    /// IPv4 address.
    pub ipv4: Option<IpAddr>,
    /// IPv6 address.
    pub ipv6: Option<IpAddr>,
    /// Enable auto_route.
    pub auto_route: bool,
    /// Enable auto_redirect.
    pub auto_redirect: bool,
    /// Strict route mode.
    pub strict_route: bool,
    /// Include routes.
    pub include_routes: Vec<String>,
    /// Exclude routes.
    pub exclude_routes: Vec<String>,
    /// Default interface for excluded traffic.
    pub default_interface: Option<String>,
    /// Enable IPv4.
    pub ipv4_enabled: bool,
    /// Enable IPv6.
    pub ipv6_enabled: bool,
}

/// Validate auto_route configuration.
pub fn validate_auto_route(config: &TunValidationConfig) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Validate interface name
    validate_interface_name(&config.name, &mut result);

    // Validate MTU
    validate_mtu(config.mtu, &mut result);

    // Validate IP addresses
    if let Some(ref ipv4) = config.ipv4 {
        validate_ipv4_address(ipv4, &mut result);
    }
    if let Some(ref ipv6) = config.ipv6 {
        validate_ipv6_address(ipv6, &mut result);
    }

    // Validate auto_route specific settings
    if config.auto_route {
        validate_auto_route_config(config, &mut result);
    }

    // Validate auto_redirect specific settings
    if config.auto_redirect {
        validate_auto_redirect_config(config, &mut result);
    }

    // Validate route configurations
    validate_routes(config, &mut result);

    result
}

/// Validate interface name.
fn validate_interface_name(name: &str, result: &mut ValidationResult) {
    #[cfg(target_os = "linux")]
    const MAX_IF_NAME_LEN: usize = 15; // IFNAMSIZ - 1

    #[cfg(target_os = "macos")]
    const MAX_IF_NAME_LEN: usize = 15; // IFNAMSIZ - 1

    #[cfg(target_os = "windows")]
    const MAX_IF_NAME_LEN: usize = 255;

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    const MAX_IF_NAME_LEN: usize = 15;

    if name.len() > MAX_IF_NAME_LEN {
        result.add_error(ValidationError::InvalidInterfaceName {
            name: name.to_string(),
            max_len: MAX_IF_NAME_LEN,
        });
    }

    // Check for invalid characters
    if name.contains('/') || name.contains('\0') {
        result.add_error(ValidationError::Other(format!(
            "Interface name '{}' contains invalid characters",
            name
        )));
    }
}

/// Validate MTU value.
fn validate_mtu(mtu: u32, result: &mut ValidationResult) {
    const MIN_MTU: u32 = 576; // Minimum for IPv4
    const MAX_MTU: u32 = 65535;
    const RECOMMENDED_MIN: u32 = 1280; // IPv6 minimum

    if mtu < MIN_MTU {
        result.add_error(ValidationError::InvalidMtu {
            value: mtu,
            reason: format!("MTU must be at least {} (IPv4 minimum)", MIN_MTU),
        });
    } else if mtu > MAX_MTU {
        result.add_error(ValidationError::InvalidMtu {
            value: mtu,
            reason: format!("MTU cannot exceed {}", MAX_MTU),
        });
    } else if mtu < RECOMMENDED_MIN {
        result.add_warning(format!(
            "MTU {} is below recommended minimum {} for IPv6 support",
            mtu, RECOMMENDED_MIN
        ));
    }
}

/// Validate IPv4 address.
fn validate_ipv4_address(addr: &IpAddr, result: &mut ValidationResult) {
    if let IpAddr::V4(v4) = addr {
        // Check for reserved addresses that shouldn't be used
        if v4.is_broadcast() {
            result.add_error(ValidationError::InvalidAddress {
                addr: addr.to_string(),
                reason: "Cannot use broadcast address".to_string(),
            });
        }
        if v4.is_unspecified() {
            result.add_error(ValidationError::InvalidAddress {
                addr: addr.to_string(),
                reason: "Cannot use unspecified address 0.0.0.0".to_string(),
            });
        }
    } else {
        result.add_error(ValidationError::InvalidAddress {
            addr: addr.to_string(),
            reason: "Expected IPv4 address".to_string(),
        });
    }
}

/// Validate IPv6 address.
fn validate_ipv6_address(addr: &IpAddr, result: &mut ValidationResult) {
    if let IpAddr::V6(v6) = addr {
        if v6.is_unspecified() {
            result.add_error(ValidationError::InvalidAddress {
                addr: addr.to_string(),
                reason: "Cannot use unspecified address ::".to_string(),
            });
        }
    } else {
        result.add_error(ValidationError::InvalidAddress {
            addr: addr.to_string(),
            reason: "Expected IPv6 address".to_string(),
        });
    }
}

/// Validate auto_route specific configuration.
fn validate_auto_route_config(config: &TunValidationConfig, result: &mut ValidationResult) {
    // At least one IP version must be enabled
    if !config.ipv4_enabled && !config.ipv6_enabled {
        result.add_error(ValidationError::ConfigConflict {
            field1: "ipv4_enabled".to_string(),
            field2: "ipv6_enabled".to_string(),
            reason: "At least one IP version must be enabled for auto_route".to_string(),
        });
    }

    // Warn if no address is configured
    if config.ipv4.is_none() && config.ipv6.is_none() {
        result.add_warning("No IP address configured for TUN interface");
    }

    // Check strict_route implications
    if config.strict_route {
        result.add_warning("strict_route enabled - all traffic will go through TUN");

        if config.default_interface.is_none() {
            result.add_warning("strict_route without default_interface may cause routing issues");
        }
    }
}

/// Validate auto_redirect specific configuration.
fn validate_auto_redirect_config(config: &TunValidationConfig, result: &mut ValidationResult) {
    // auto_redirect requires auto_route
    if !config.auto_route {
        result.add_error(ValidationError::ConfigConflict {
            field1: "auto_redirect".to_string(),
            field2: "auto_route".to_string(),
            reason: "auto_redirect requires auto_route to be enabled".to_string(),
        });
    }

    // Platform-specific checks
    #[cfg(target_os = "linux")]
    {
        result.add_warning("auto_redirect on Linux requires nftables or iptables-nft");
    }

    #[cfg(target_os = "windows")]
    {
        result.add_warning("auto_redirect on Windows requires administrator privileges");
    }
}

/// Validate route configurations.
fn validate_routes(config: &TunValidationConfig, result: &mut ValidationResult) {
    // Check for conflicting include/exclude routes
    for include in &config.include_routes {
        for exclude in &config.exclude_routes {
            if include == exclude {
                result.add_error(ValidationError::ConfigConflict {
                    field1: format!("include_routes[{}]", include),
                    field2: format!("exclude_routes[{}]", exclude),
                    reason: "Same route in both include and exclude".to_string(),
                });
            }
        }
    }

    // Validate CIDR format
    for route in config
        .include_routes
        .iter()
        .chain(config.exclude_routes.iter())
    {
        if !is_valid_cidr(route) {
            result.add_error(ValidationError::Other(format!(
                "Invalid CIDR notation: {}",
                route
            )));
        }
    }
}

/// Check if a string is valid CIDR notation.
fn is_valid_cidr(cidr: &str) -> bool {
    if let Some((ip_part, prefix_part)) = cidr.split_once('/') {
        // Check IP part
        if ip_part.parse::<IpAddr>().is_err() {
            return false;
        }
        // Check prefix part
        if let Ok(prefix) = prefix_part.parse::<u8>() {
            // IPv4: 0-32, IPv6: 0-128
            if ip_part.contains(':') {
                prefix <= 128
            } else {
                prefix <= 32
            }
        } else {
            false
        }
    } else {
        // Single IP address (implicit /32 or /128)
        cidr.parse::<IpAddr>().is_ok()
    }
}

/// Check platform-specific route conflicts.
#[cfg(target_os = "linux")]
pub fn check_route_conflicts(routes: &[String]) -> Vec<ValidationError> {
    let mut conflicts = Vec::new();

    // Read existing routes from /proc/net/route
    if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let _iface = parts[0];
                // Simple conflict detection - can be enhanced
                for route in routes {
                    if route.contains("0.0.0.0/0") {
                        conflicts.push(ValidationError::RouteConflict {
                            cidr: route.clone(),
                            existing: "default route".to_string(),
                        });
                    }
                }
            }
        }
    }

    conflicts
}

#[cfg(not(target_os = "linux"))]
/// Check platform-specific route conflicts (stub for non-Linux).
pub fn check_route_conflicts(_routes: &[String]) -> Vec<ValidationError> {
    Vec::new()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = TunValidationConfig {
            name: "tun0".to_string(),
            mtu: 1500,
            ipv4: Some("10.0.0.1".parse().expect("valid ipv4")),
            ipv4_enabled: true,
            ..Default::default()
        };

        let result = validate_auto_route(&config);
        assert!(result.is_valid());
    }

    #[test]
    fn test_invalid_mtu() {
        let config = TunValidationConfig {
            name: "tun0".to_string(),
            mtu: 100, // Too small
            ..Default::default()
        };

        let result = validate_auto_route(&config);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_interface_name_too_long() {
        let config = TunValidationConfig {
            name: "this_name_is_way_too_long_for_linux".to_string(),
            mtu: 1500,
            ..Default::default()
        };

        let result = validate_auto_route(&config);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_valid_cidr() {
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("0.0.0.0/0"));
        assert!(is_valid_cidr("::0/0"));
        assert!(is_valid_cidr("fe80::/10"));
        assert!(!is_valid_cidr("invalid"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
    }

    #[test]
    fn test_auto_redirect_requires_auto_route() {
        let config = TunValidationConfig {
            name: "tun0".to_string(),
            mtu: 1500,
            auto_redirect: true,
            auto_route: false,
            ..Default::default()
        };

        let result = validate_auto_route(&config);
        assert!(!result.is_valid());
    }
}
