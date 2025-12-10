//! Loopback detection for direct inbound.
//!
//! Prevents routing loops by detecting when a connection would be routed
//! back to the same inbound listener.
//!
//! # Usage
//! ```ignore
//! use sb_core::inbound::loopback::LoopbackDetector;
//!
//! let detector = LoopbackDetector::new();
//! detector.register_inbound("127.0.0.1:1080");
//!
//! if detector.is_loopback("127.0.0.1", 1080) {
//!     // Skip routing, use block or direct
//! }
//! ```

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::RwLock;

/// Loopback detector for preventing routing loops.
#[derive(Debug, Default)]
pub struct LoopbackDetector {
    /// Set of registered inbound addresses.
    inbound_addrs: RwLock<HashSet<SocketAddr>>,
    /// Local interface addresses.
    local_addrs: RwLock<HashSet<IpAddr>>,
}

impl LoopbackDetector {
    /// Create a new loopback detector.
    pub fn new() -> Self {
        let detector = Self::default();
        detector.refresh_local_addrs();
        detector
    }

    /// Register an inbound listener address.
    pub fn register_inbound(&self, addr: impl Into<SocketAddr>) {
        let addr = addr.into();
        tracing::debug!("Registering inbound address: {}", addr);
        self.inbound_addrs.write().unwrap().insert(addr);
    }

    /// Unregister an inbound listener address.
    pub fn unregister_inbound(&self, addr: &SocketAddr) {
        self.inbound_addrs.write().unwrap().remove(addr);
    }

    /// Check if destination would cause a routing loop.
    pub fn is_loopback(&self, host: &str, port: u16) -> bool {
        // Parse host as IP
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.is_loopback_ip(ip, port);
        }

        // Check common loopback hostnames
        let host_lower = host.to_lowercase();
        if host_lower == "localhost" || host_lower == "localhost." {
            return self.is_loopback_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        }

        false
    }

    /// Check if IP:port would cause a routing loop.
    pub fn is_loopback_ip(&self, ip: IpAddr, port: u16) -> bool {
        let addr = SocketAddr::new(ip, port);

        // Check if this is a registered inbound
        if self.inbound_addrs.read().unwrap().contains(&addr) {
            return true;
        }

        // Check if IP is local and port matches any inbound
        if self.is_local_ip(ip) {
            let inbounds = self.inbound_addrs.read().unwrap();
            for inbound in inbounds.iter() {
                if inbound.port() == port {
                    // Same port on local IP - likely a loop
                    return true;
                }
            }
        }

        // Check wildcard addresses (0.0.0.0:port or [::]:port)
        let wildcard_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let wildcard_v6 = SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port);

        if self.is_local_ip(ip) {
            let inbounds = self.inbound_addrs.read().unwrap();
            if inbounds.contains(&wildcard_v4) || inbounds.contains(&wildcard_v6) {
                return true;
            }
        }

        false
    }

    /// Check if IP is a local address.
    pub fn is_local_ip(&self, ip: IpAddr) -> bool {
        // Standard loopback
        if ip.is_loopback() {
            return true;
        }

        // Registered local addresses
        if self.local_addrs.read().unwrap().contains(&ip) {
            return true;
        }

        // Link-local addresses
        match ip {
            IpAddr::V4(v4) => {
                // 169.254.0.0/16 (link-local)
                v4.octets()[0] == 169 && v4.octets()[1] == 254
            }
            IpAddr::V6(v6) => {
                // fe80::/10 (link-local)
                let segments = v6.segments();
                (segments[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// Refresh local interface addresses.
    pub fn refresh_local_addrs(&self) {
        let mut addrs = HashSet::new();

        // Add standard loopback
        addrs.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        addrs.insert(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));

        // Try to get interface addresses (platform-specific)
        #[cfg(unix)]
        {
            if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for addr_str in stdout.split_whitespace() {
                        if let Ok(ip) = addr_str.parse::<IpAddr>() {
                            addrs.insert(ip);
                        }
                    }
                }
            }
        }

        *self.local_addrs.write().unwrap() = addrs;
    }

    /// Get count of registered inbounds.
    pub fn inbound_count(&self) -> usize {
        self.inbound_addrs.read().unwrap().len()
    }
}

/// Global loopback detector instance.
static DETECTOR: std::sync::OnceLock<LoopbackDetector> = std::sync::OnceLock::new();

/// Get the global loopback detector.
pub fn detector() -> &'static LoopbackDetector {
    DETECTOR.get_or_init(LoopbackDetector::new)
}

/// Convenience: check if destination is a loopback.
pub fn is_loopback(host: &str, port: u16) -> bool {
    detector().is_loopback(host, port)
}

/// Convenience: register an inbound address.
pub fn register_inbound(addr: impl Into<SocketAddr>) {
    detector().register_inbound(addr);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_detection() {
        let detector = LoopbackDetector::new();
        detector.register_inbound(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            1080,
        ));

        assert!(detector.is_loopback("127.0.0.1", 1080));
        assert!(detector.is_loopback("localhost", 1080));
        assert!(!detector.is_loopback("192.168.1.1", 1080));
    }

    #[test]
    fn test_wildcard_detection() {
        let detector = LoopbackDetector::new();
        detector.register_inbound(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080));

        // Any local IP on same port should be detected
        assert!(detector.is_loopback("127.0.0.1", 8080));
    }

    #[test]
    fn test_is_local_ip() {
        let detector = LoopbackDetector::new();

        assert!(detector.is_local_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(detector.is_local_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!detector.is_local_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }
}
