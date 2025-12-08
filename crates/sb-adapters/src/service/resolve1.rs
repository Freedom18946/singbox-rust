//! D-Bus server interface for org.freedesktop.resolve1.Manager.
//!
//! This module implements the D-Bus server side of systemd-resolved,
//! allowing external programs to configure per-link DNS settings.
//!
//! Mirrors Go's `service/resolved/resolve1.go`.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Per-link DNS configuration.
///
/// Tracks DNS servers, domains, and settings for a specific network interface.
/// Mirrors Go's `TransportLink` struct.
#[derive(Debug, Clone, Default)]
pub struct TransportLink {
    /// Interface index.
    pub if_index: i32,
    /// Interface name (for logging).
    pub if_name: String,
    /// DNS server addresses (simple format).
    pub addresses: Vec<LinkDNS>,
    /// DNS server addresses with port and SNI (extended format).
    pub addresses_ex: Vec<LinkDNSEx>,
    /// Search domains configuration.
    pub domains: Vec<LinkDomain>,
    /// Whether this link is a default route for DNS queries.
    pub default_route: bool,
    /// Whether DNS-over-TLS is enabled.
    pub dns_over_tls: bool,
}

/// Simple DNS server address (family + raw IP bytes).
#[derive(Debug, Clone)]
pub struct LinkDNS {
    /// Address family (AF_INET=2 or AF_INET6=10).
    pub family: i32,
    /// Raw IP address bytes.
    pub address: Vec<u8>,
}

impl LinkDNS {
    /// Convert to IpAddr.
    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match self.family {
            2 if self.address.len() == 4 => {
                let bytes: [u8; 4] = self.address[..4].try_into().ok()?;
                Some(IpAddr::V4(bytes.into()))
            }
            10 if self.address.len() == 16 => {
                let bytes: [u8; 16] = self.address[..16].try_into().ok()?;
                Some(IpAddr::V6(bytes.into()))
            }
            _ => None,
        }
    }
}

/// Extended DNS server address with port and SNI.
#[derive(Debug, Clone)]
pub struct LinkDNSEx {
    /// Address family (AF_INET=2 or AF_INET6=10).
    pub family: i32,
    /// Raw IP address bytes.
    pub address: Vec<u8>,
    /// Port (0 means default 53 or 853 for DoT).
    pub port: u16,
    /// Server Name Indication for TLS.
    pub server_name: String,
}

impl LinkDNSEx {
    /// Convert to IpAddr.
    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match self.family {
            2 if self.address.len() == 4 => {
                let bytes: [u8; 4] = self.address[..4].try_into().ok()?;
                Some(IpAddr::V4(bytes.into()))
            }
            10 if self.address.len() == 16 => {
                let bytes: [u8; 16] = self.address[..16].try_into().ok()?;
                Some(IpAddr::V6(bytes.into()))
            }
            _ => None,
        }
    }
}

/// DNS domain configuration.
#[derive(Debug, Clone)]
pub struct LinkDomain {
    /// Domain name.
    pub domain: String,
    /// If true, domain is only used for routing, not search.
    pub routing_only: bool,
}

/// Callback type for link updates.
pub type UpdateCallback = Box<dyn Fn(&TransportLink) -> Result<(), String> + Send + Sync>;

/// Callback type for link deletion.
pub type DeleteCallback = Box<dyn Fn(&TransportLink) + Send + Sync>;

/// Shared state for the resolve1 Manager.
pub struct Resolve1ManagerState {
    /// Per-link configuration.
    pub links: RwLock<HashMap<i32, TransportLink>>,
    /// Default route sequence (most recent is last).
    pub default_route_sequence: RwLock<Vec<i32>>,
    /// Callback when a link is updated.
    pub update_callback: RwLock<Option<UpdateCallback>>,
    /// Callback when a link is deleted.
    pub delete_callback: RwLock<Option<DeleteCallback>>,
}

impl Default for Resolve1ManagerState {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolve1ManagerState {
    /// Create a new empty state.
    pub fn new() -> Self {
        Self {
            links: RwLock::new(HashMap::new()),
            default_route_sequence: RwLock::new(Vec::new()),
            update_callback: RwLock::new(None),
            delete_callback: RwLock::new(None),
        }
    }

    /// Set the update callback.
    pub fn set_update_callback(&self, callback: UpdateCallback) {
        *self.update_callback.write() = Some(callback);
    }

    /// Set the delete callback.
    pub fn set_delete_callback(&self, callback: DeleteCallback) {
        *self.delete_callback.write() = Some(callback);
    }

    /// Get or create a link.
    fn get_or_create_link(&self, if_index: i32, if_name: &str) -> TransportLink {
        let mut links = self.links.write();
        links
            .entry(if_index)
            .or_insert_with(|| TransportLink {
                if_index,
                if_name: if_name.to_string(),
                ..Default::default()
            })
            .clone()
    }

    /// Update a link and call the update callback.
    fn update_link(&self, link: TransportLink) -> Result<(), String> {
        let if_index = link.if_index;
        {
            let mut links = self.links.write();
            links.insert(if_index, link.clone());
        }
        if let Some(ref callback) = *self.update_callback.read() {
            callback(&link)?;
        }
        Ok(())
    }

    /// Delete a link and call the delete callback.
    fn delete_link(&self, if_index: i32) {
        let link = {
            let mut links = self.links.write();
            links.remove(&if_index)
        };
        if let Some(link) = link {
            // Remove from default route sequence
            {
                let mut seq = self.default_route_sequence.write();
                seq.retain(|&idx| idx != if_index);
            }
            if let Some(ref callback) = *self.delete_callback.read() {
                callback(&link);
            }
        }
    }

    /// Get the current default route link (if any).
    pub fn default_route_link(&self) -> Option<TransportLink> {
        let seq = self.default_route_sequence.read();
        if let Some(&if_index) = seq.last() {
            let links = self.links.read();
            links.get(&if_index).cloned()
        } else {
            None
        }
    }

    /// Get all links.
    pub fn all_links(&self) -> Vec<TransportLink> {
        self.links.read().values().cloned().collect()
    }

    /// Get all links that are default routes, in order.
    pub fn default_route_links(&self) -> Vec<TransportLink> {
        let seq = self.default_route_sequence.read();
        let links = self.links.read();
        seq.iter()
            .filter_map(|idx| links.get(idx).cloned())
            .collect()
    }
}

// D-Bus interface implementation (zbus)
#[cfg(all(target_os = "linux", feature = "service_resolved"))]
pub mod dbus_server {
    use super::*;
    use zbus::{interface, Connection, Result as ZbusResult};

    /// D-Bus interface for org.freedesktop.resolve1.Manager.
    ///
    /// This struct wraps the shared state and exposes D-Bus methods.
    pub struct Resolve1Manager {
        state: Arc<Resolve1ManagerState>,
    }

    impl Resolve1Manager {
        /// Create a new Resolve1Manager.
        pub fn new(state: Arc<Resolve1ManagerState>) -> Self {
            Self { state }
        }
    }

    #[interface(name = "org.freedesktop.resolve1.Manager")]
    impl Resolve1Manager {
        /// Set DNS servers for a link (simple format).
        async fn set_link_dns(&self, if_index: i32, addresses: Vec<(i32, Vec<u8>)>) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.addresses = addresses
                .into_iter()
                .map(|(family, address)| LinkDNS { family, address })
                .collect();

            if !link.addresses.is_empty() {
                info!(
                    if_name = %link.if_name,
                    "SetLinkDNS: {}",
                    link.addresses
                        .iter()
                        .filter_map(|a| a.to_ip_addr())
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            } else {
                debug!(if_name = %link.if_name, "SetLinkDNS: (empty)");
            }

            self.state.update_link(link).map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set DNS servers for a link (extended format with port and SNI).
        async fn set_link_dns_ex(
            &self,
            if_index: i32,
            addresses: Vec<(i32, Vec<u8>, u16, String)>,
        ) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.addresses_ex = addresses
                .into_iter()
                .map(|(family, address, port, server_name)| LinkDNSEx {
                    family,
                    address,
                    port,
                    server_name,
                })
                .collect();

            if !link.addresses_ex.is_empty() {
                info!(
                    if_name = %link.if_name,
                    "SetLinkDNSEx: {}",
                    link.addresses_ex
                        .iter()
                        .filter_map(|a| {
                            a.to_ip_addr().map(|ip| {
                                if a.port == 0 {
                                    ip.to_string()
                                } else {
                                    format!("{}:{}", ip, a.port)
                                }
                            })
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            } else {
                debug!(if_name = %link.if_name, "SetLinkDNSEx: (empty)");
            }

            self.state.update_link(link).map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set search/routing domains for a link.
        async fn set_link_domains(&self, if_index: i32, domains: Vec<(String, bool)>) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.domains = domains
                .into_iter()
                .map(|(domain, routing_only)| LinkDomain {
                    domain,
                    routing_only,
                })
                .collect();

            if !link.domains.is_empty() {
                info!(
                    if_name = %link.if_name,
                    "SetLinkDomains: {}",
                    link.domains
                        .iter()
                        .map(|d| if d.routing_only {
                            format!("~{}", d.domain)
                        } else {
                            d.domain.clone()
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            } else {
                debug!(if_name = %link.if_name, "SetLinkDomains: (empty)");
            }

            self.state.update_link(link).map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set whether this link is a default route for DNS.
        async fn set_link_default_route(&self, if_index: i32, default_route: bool) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);
            link.default_route = default_route;

            // Update default route sequence
            {
                let mut seq = self.state.default_route_sequence.write();
                seq.retain(|&idx| idx != if_index);
                if default_route {
                    seq.push(if_index);
                }
            }

            info!(
                if_name = %link.if_name,
                "SetLinkDefaultRoute: {}",
                if default_route { "yes" } else { "no" }
            );

            self.state.update_link(link).map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set DNS-over-TLS mode for a link.
        async fn set_link_dns_over_tls(&self, if_index: i32, dot_mode: &str) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.dns_over_tls = match dot_mode {
                "yes" => true,
                "" | "no" | "opportunistic" => false,
                _ => {
                    warn!(if_name = %link.if_name, "Unknown DoT mode: {}", dot_mode);
                    false
                }
            };

            info!(
                if_name = %link.if_name,
                "SetLinkDNSOverTLS: {}",
                if link.dns_over_tls { "yes" } else { "no" }
            );

            self.state.update_link(link).map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Stub implementations for unused methods.
        async fn set_link_llmnr(&self, _if_index: i32, _mode: &str) -> ZbusResult<()> {
            Ok(())
        }

        async fn set_link_multicast_dns(&self, _if_index: i32, _mode: &str) -> ZbusResult<()> {
            Ok(())
        }

        async fn set_link_dnssec(&self, _if_index: i32, _mode: &str) -> ZbusResult<()> {
            Ok(())
        }

        async fn set_link_dnssec_negative_trust_anchors(
            &self,
            _if_index: i32,
            _domains: Vec<String>,
        ) -> ZbusResult<()> {
            Ok(())
        }

        /// Revert link configuration.
        async fn revert_link(&self, if_index: i32) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            info!(if_name = %if_name, "RevertLink");
            self.state.delete_link(if_index);
            Ok(())
        }

        /// Flush DNS caches (no-op for now, can integrate with DNS router).
        async fn flush_caches(&self) -> ZbusResult<()> {
            info!("FlushCaches");
            // TODO: Integrate with DNS router cache
            Ok(())
        }

        /// Reset server features (no-op).
        async fn reset_server_features(&self) -> ZbusResult<()> {
            Ok(())
        }

        /// Reset statistics (no-op).
        async fn reset_statistics(&self) -> ZbusResult<()> {
            Ok(())
        }
    }

    /// Get interface name from index (fallback to index if not found).
    fn get_interface_name(if_index: i32) -> String {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CStr;
            let mut buf = [0u8; libc::IF_NAMESIZE];
            let result = unsafe { libc::if_indextoname(if_index as u32, buf.as_mut_ptr() as *mut i8) };
            if !result.is_null() {
                if let Ok(name) = unsafe { CStr::from_ptr(result) }.to_str() {
                    return name.to_string();
                }
            }
        }
        format!("if{}", if_index)
    }

    /// Start the D-Bus server and export the resolve1 Manager.
    pub async fn start_dbus_server(state: Arc<Resolve1ManagerState>) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
        let connection = Connection::system().await?;

        // Export the interface
        let manager = Resolve1Manager::new(state);
        connection
            .object_server()
            .at("/org/freedesktop/resolve1", manager)
            .await?;

        // Request the well-known name
        connection
            .request_name("org.freedesktop.resolve1")
            .await?;

        info!("D-Bus server started: org.freedesktop.resolve1");
        Ok(connection)
    }
}

// Non-Linux stub
#[cfg(not(all(target_os = "linux", feature = "service_resolved")))]
pub mod dbus_server {
    use super::*;

    /// Stub implementation for non-Linux platforms.
    pub async fn start_dbus_server(
        _state: Arc<Resolve1ManagerState>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        warn!("D-Bus server not supported on this platform");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_link_default() {
        let link = TransportLink::default();
        assert_eq!(link.if_index, 0);
        assert!(!link.default_route);
        assert!(!link.dns_over_tls);
        assert!(link.addresses.is_empty());
        assert!(link.domains.is_empty());
    }

    #[test]
    fn test_link_dns_to_ip() {
        let ipv4 = LinkDNS {
            family: 2,
            address: vec![192, 168, 1, 1],
        };
        assert_eq!(
            ipv4.to_ip_addr(),
            Some(IpAddr::V4([192, 168, 1, 1].into()))
        );

        let ipv6 = LinkDNS {
            family: 10,
            address: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        };
        assert!(ipv6.to_ip_addr().is_some());
    }

    #[test]
    fn test_state_get_or_create_link() {
        let state = Resolve1ManagerState::new();
        let link = state.get_or_create_link(1, "eth0");
        assert_eq!(link.if_index, 1);
        assert_eq!(link.if_name, "eth0");

        // Should return same link
        let link2 = state.get_or_create_link(1, "eth0");
        assert_eq!(link2.if_index, 1);
    }

    #[test]
    fn test_state_default_route_sequence() {
        let state = Resolve1ManagerState::new();

        // Create links with default routes
        let mut link1 = state.get_or_create_link(1, "eth0");
        link1.default_route = true;
        state.update_link(link1).unwrap();
        state.default_route_sequence.write().push(1);

        let mut link2 = state.get_or_create_link(2, "wlan0");
        link2.default_route = true;
        state.update_link(link2).unwrap();
        state.default_route_sequence.write().push(2);

        // Most recent is last
        let def = state.default_route_link();
        assert!(def.is_some());
        assert_eq!(def.unwrap().if_index, 2);

        // Delete link 2
        state.delete_link(2);
        let def = state.default_route_link();
        assert!(def.is_some());
        assert_eq!(def.unwrap().if_index, 1);
    }
}
