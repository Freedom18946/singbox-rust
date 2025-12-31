//! D-Bus server interface for org.freedesktop.resolve1.Manager.
//!
//! This module implements the D-Bus server side of systemd-resolved,
//! allowing external programs to configure per-link DNS settings.
//!
//! Mirrors Go's `service/resolved/resolve1.go`.

use std::sync::Arc;
#[cfg(all(target_os = "linux", feature = "service_resolved"))]
use tracing::{debug, info, warn};
#[cfg(not(all(target_os = "linux", feature = "service_resolved")))]
use tracing::warn;

use sb_core::dns::transport::resolved::Resolve1ManagerState;

// D-Bus interface implementation (zbus)
#[cfg(all(target_os = "linux", feature = "service_resolved"))]
pub mod dbus_server {
    use super::*;
    use sb_core::dns::transport::resolved::{LinkDNS, LinkDNSEx, LinkDomainConfig};
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
        async fn set_link_dns(
            &self,
            if_index: i32,
            addresses: Vec<(i32, Vec<u8>)>,
        ) -> ZbusResult<()> {
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

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
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

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set search/routing domains for a link.
        async fn set_link_domains(
            &self,
            if_index: i32,
            domains: Vec<(String, bool)>,
        ) -> ZbusResult<()> {
            let if_name = get_interface_name(if_index);
            let mut link = self.state.get_or_create_link(if_index, &if_name);

            link.domains = domains
                .into_iter()
                .map(|(domain, routing_only)| LinkDomainConfig {
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

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
            Ok(())
        }

        /// Set whether this link is a default route for DNS.
        async fn set_link_default_route(
            &self,
            if_index: i32,
            default_route: bool,
        ) -> ZbusResult<()> {
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

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
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

            self.state
                .update_link(link)
                .map_err(|e| zbus::Error::Failure(e))?;
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

        /// Flush DNS caches (wired to DNS router).
        async fn flush_caches(&self) -> ZbusResult<()> {
            info!("FlushCaches");
            self.state.clear_cache();
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
            let result =
                unsafe { libc::if_indextoname(if_index as u32, buf.as_mut_ptr() as *mut i8) };
            if !result.is_null() {
                if let Ok(name) = unsafe { CStr::from_ptr(result) }.to_str() {
                    return name.to_string();
                }
            }
        }
        format!("if{}", if_index)
    }

    /// Start the D-Bus server and export the resolve1 Manager.
    pub async fn start_dbus_server(
        state: Arc<Resolve1ManagerState>,
    ) -> Result<Connection, Box<dyn std::error::Error + Send + Sync>> {
        let connection = Connection::system().await?;

        // Export the interface
        let manager = Resolve1Manager::new(state);
        connection
            .object_server()
            .at("/org/freedesktop/resolve1", manager)
            .await?;

        // Request the well-known name
        connection.request_name("org.freedesktop.resolve1").await?;

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
    use super::Resolve1ManagerState;
    use sb_core::dns::transport::resolved::{LinkDNS, TransportLink};
    use std::net::IpAddr;

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
        assert_eq!(ipv4.to_ip_addr(), Some(IpAddr::V4([192, 168, 1, 1].into())));

        let ipv6 = LinkDNS {
            family: 10,
            address: vec![
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
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
        let def = default_route_link(&state);
        assert!(def.is_some());
        assert_eq!(def.unwrap().if_index, 2);

        // Delete link 2
        state.delete_link(2);
        let def = default_route_link(&state);
        assert!(def.is_some());
        assert_eq!(def.unwrap().if_index, 1);
    }

    fn default_route_link(state: &Resolve1ManagerState) -> Option<TransportLink> {
        let seq = state.default_route_sequence.read();
        let links = state.links.read();
        for &if_index in seq.iter().rev() {
            if let Some(link) = links.get(&if_index) {
                return Some(link.clone());
            }
        }
        None
    }
}
