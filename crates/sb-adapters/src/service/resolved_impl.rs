//! Resolved service implementation for systemd-resolved integration.
//!
//! This module provides a minimal implementation of the Resolved service
//! that integrates with systemd-resolved via D-Bus on Linux systems.

use sb_config::ir::ServiceIR;
use sb_core::service::{Service, ServiceContext};
use std::sync::Arc;

#[cfg(all(target_os = "linux", feature = "service_resolved"))]
mod dbus_impl {
    use super::*;
    use sb_core::dns::DnsResolver;
    use sb_core::service::StartStage;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;

    /// Resolved service implementation using systemd-resolved D-Bus interface.
    pub struct ResolvedService {
        tag: String,
        listen_addr: String,
        listen_port: u16,
        connection: parking_lot::Mutex<Option<zbus::Connection>>,
        started: AtomicBool,
        server_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
        /// DNS resolver for query handling
        resolver: Arc<dyn DnsResolver>,
    }

    impl ResolvedService {
        pub fn new(ir: &ServiceIR) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let tag = ir.tag.as_deref().unwrap_or("resolved").to_string();
            let listen_addr = ir
                .resolved_listen
                .as_deref()
                .unwrap_or("127.0.0.53")
                .to_string();
            let listen_port = ir.resolved_listen_port.unwrap_or(53);

            // Create default DNS resolver
            // Uses system resolver as fallback; can be enhanced to use configured upstreams
            let resolver = Arc::new(sb_core::dns::system::SystemResolver::new(
                std::time::Duration::from_secs(60),
            )) as Arc<dyn DnsResolver>;

            Ok(Self {
                tag,
                listen_addr,
                listen_port,
                connection: parking_lot::Mutex::new(None),
                started: AtomicBool::new(false),
                server_task: parking_lot::Mutex::new(None),
                resolver,
            })
        }

        /// Connect to systemd-resolved via D-Bus.
        fn connect_dbus(
            &self,
        ) -> Result<zbus::blocking::Connection, Box<dyn std::error::Error + Send + Sync>> {
            let conn = zbus::blocking::Connection::system()
                .map_err(|e| format!("Failed to connect to system D-Bus: {}", e))?;

            // Verify systemd-resolved is available
            let proxy = zbus::blocking::fdo::DBusProxy::new(&conn)
                .map_err(|e| format!("Failed to create D-Bus proxy: {}", e))?;

            let has_resolved = proxy
                .list_names()
                .map_err(|e| format!("Failed to list D-Bus names: {}", e))?
                .iter()
                .any(|name| name.as_str() == "org.freedesktop.resolve1");

            if !has_resolved {
                return Err("systemd-resolved is not available on D-Bus".into());
            }

            tracing::info!(
                target: "sb_adapters::service",
                service = "resolved",
                tag = %self.tag,
                "Connected to systemd-resolved via D-Bus"
            );

            Ok(conn)
        }

        /// Handle a single DNS query and return a response packet.
        async fn handle_dns_query(
            query_packet: &[u8],
            resolver: Arc<dyn DnsResolver>,
        ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            // Parse the DNS query to extract the domain name and query type
            if query_packet.len() < 12 {
                return Err("DNS query too short".into());
            }

            let transaction_id = u16::from_be_bytes([query_packet[0], query_packet[1]]);

            // Extract QNAME (domain name) from question section
            let mut i = 12;
            let mut domain_labels = Vec::new();

            while i < query_packet.len() && query_packet[i] != 0 {
                let label_len = query_packet[i] as usize;
                i += 1;
                if i + label_len > query_packet.len() {
                    return Err("Invalid domain name in query".into());
                }
                let label = String::from_utf8_lossy(&query_packet[i..i + label_len]).to_string();
                domain_labels.push(label);
                i += label_len;
            }

            let domain = domain_labels.join(".");
            i += 1; // Skip the zero byte

            if i + 4 > query_packet.len() {
                return Err("Query packet truncated".into());
            }

            let qtype = u16::from_be_bytes([query_packet[i], query_packet[i + 1]]);

            tracing::debug!(
                target: "sb_adapters::service",
                service = "resolved",
                domain = %domain,
                qtype = ?qtype,
                "Received DNS query"
            );

            // Use sb-core DNS resolver for query resolution
            let answer = resolver
                .resolve(&domain)
                .await
                .map_err(|e| format!("DNS resolution failed: {}", e))?;

            // Filter IPs by query type
            let ips: Vec<_> = answer
                .ips
                .into_iter()
                .filter(|ip| {
                    match (qtype, ip) {
                        (1, std::net::IpAddr::V4(_)) => true,  // A record
                        (28, std::net::IpAddr::V6(_)) => true, // AAAA record
                        _ => false,
                    }
                })
                .collect();

            let ttl = answer.ttl.as_secs() as u32;

            // Build DNS response packet
            let mut response = Vec::with_capacity(512);

            // Header
            response.extend_from_slice(&transaction_id.to_be_bytes()); // Transaction ID
            response.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: response, recursion available
            response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
            response.extend_from_slice(&(ips.len() as u16).to_be_bytes()); // ANCOUNT
            response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
            response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

            // Question section (copy from query)
            response.extend_from_slice(&query_packet[12..i + 4]);

            // Answer section
            for ip in ips {
                // NAME (pointer to question)
                response.extend_from_slice(&0xC00Cu16.to_be_bytes());

                match ip {
                    std::net::IpAddr::V4(ipv4) => {
                        response.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
                        response.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
                        response.extend_from_slice(&ttl.to_be_bytes()); // TTL from resolver
                        response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
                        response.extend_from_slice(&ipv4.octets()); // IPv4 address
                    }
                    std::net::IpAddr::V6(ipv6) => {
                        response.extend_from_slice(&28u16.to_be_bytes()); // TYPE = AAAA
                        response.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
                        response.extend_from_slice(&ttl.to_be_bytes()); // TTL from resolver
                        response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH = 16
                        response.extend_from_slice(&ipv6.octets()); // IPv6 address
                    }
                }
            }

            Ok(response)
        }

        /// Spawn the DNS server task.
        async fn spawn_dns_server(
            addr: String,
            port: u16,
            tag: String,
            resolver: Arc<dyn DnsResolver>,
        ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
            let bind_addr = format!("{}:{}", addr, port);
            let socket = UdpSocket::bind(&bind_addr)
                .await
                .map_err(|e| format!("Failed to bind DNS server to {}: {}", bind_addr, e))?;

            tracing::info!(
                target: "sb_adapters::service",
                service = "resolved",
                tag = %tag,
                bind_addr = %bind_addr,
                "DNS server listening"
            );

            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];

                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((len, peer)) => {
                            let query_packet = &buf[..len];

                            // Handle query in a separate task to avoid blocking
                            let query_data = query_packet.to_vec();
                            let socket_clone = socket.try_clone();
                            let resolver_clone = resolver.clone();

                            if let Ok(socket) = socket_clone {
                                tokio::spawn(async move {
                                    match Self::handle_dns_query(&query_data, resolver_clone).await
                                    {
                                        Ok(response) => {
                                            if let Err(e) = socket.send_to(&response, peer).await {
                                                tracing::error!(
                                                    target: "sb_adapters::service",
                                                    service = "resolved",
                                                    error = %e,
                                                    "Failed to send DNS response"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!(
                                                target: "sb_adapters::service",
                                                service = "resolved",
                                                peer = %peer,
                                                error = %e,
                                                "Failed to handle DNS query"
                                            );
                                        }
                                    }
                                });
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "sb_adapters::service",
                                service = "resolved",
                                error = %e,
                                "DNS server recv error"
                            );
                            break;
                        }
                    }
                }

                tracing::info!(
                    target: "sb_adapters::service",
                    service = "resolved",
                    tag = %tag,
                    "DNS server stopped"
                );
            });

            Ok(handle)
        }
    }

    impl Service for ResolvedService {
        fn service_type(&self) -> &str {
            "resolved"
        }

        fn tag(&self) -> &str {
            &self.tag
        }

        fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            match stage {
                StartStage::Initialize => {
                    tracing::debug!(
                        target: "sb_adapters::service",
                        service = "resolved",
                        tag = %self.tag,
                        "Initializing Resolved service"
                    );

                    // Connect to D-Bus during initialization
                    let conn = self.connect_dbus()?;
                    *self.connection.lock() = Some(conn);
                    Ok(())
                }
                StartStage::Start => {
                    tracing::info!(
                        target: "sb_adapters::service",
                        service = "resolved",
                        tag = %self.tag,
                        listen_addr = %self.listen_addr,
                        listen_port = %self.listen_port,
                        "Starting Resolved DNS server"
                    );

                    // Verify connection is still valid
                    let conn_guard = self.connection.lock();
                    if conn_guard.is_none() {
                        return Err("D-Bus connection not initialized".into());
                    }
                    drop(conn_guard);

                    // Spawn DNS server task
                    let addr = self.listen_addr.clone();
                    let port = self.listen_port;
                    let tag = self.tag.clone();
                    let resolver = self.resolver.clone();

                    let handle = tokio::runtime::Handle::try_current()
                        .map_err(|_| "No tokio runtime available")?
                        .block_on(Self::spawn_dns_server(addr, port, tag, resolver))?;

                    *self.server_task.lock() = Some(handle);
                    self.started.store(true, Ordering::SeqCst);
                    Ok(())
                }
                StartStage::PostStart => {
                    tracing::debug!(
                        target: "sb_adapters::service",
                        service = "resolved",
                        tag = %self.tag,
                        "Post-start phase for Resolved service"
                    );
                    Ok(())
                }
                StartStage::Started => {
                    tracing::info!(
                        target: "sb_adapters::service",
                        service = "resolved",
                        tag = %self.tag,
                        "Resolved service fully started"
                    );
                    Ok(())
                }
            }
        }

        fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            tracing::info!(
                target: "sb_adapters::service",
                service = "resolved",
                tag = %self.tag,
                "Closing Resolved service"
            );

            self.started.store(false, Ordering::SeqCst);

            // Abort the DNS server task
            if let Some(handle) = self.server_task.lock().take() {
                handle.abort();
            }

            *self.connection.lock() = None;
            Ok(())
        }
    }
}

/// Build a Resolved service.
///
/// On Linux with the `service_resolved` feature, returns a working implementation.
/// Otherwise, returns a stub that logs a warning.
pub fn build_resolved_service(ir: &ServiceIR, _ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    #[cfg(all(target_os = "linux", feature = "service_resolved"))]
    {
        match dbus_impl::ResolvedService::new(ir) {
            Ok(service) => {
                tracing::info!(
                    target: "sb_adapters::service",
                    service_type = "resolved",
                    tag = ir.tag.as_deref().unwrap_or("resolved"),
                    "Built Resolved service with systemd-resolved D-Bus integration"
                );
                return Some(Arc::new(service));
            }
            Err(e) => {
                tracing::warn!(
                    target: "sb_adapters::service",
                    service_type = "resolved",
                    tag = ir.tag.as_deref().unwrap_or("resolved"),
                    error = %e,
                    "Failed to build Resolved service; falling back to stub"
                );
            }
        }
    }

    // Fallback to stub
    let tag = ir.tag.as_deref().unwrap_or("resolved");
    tracing::warn!(
        service_type = "resolved",
        tag = tag,
        "Resolved DNS service is not implemented on this platform; requires Linux with systemd-resolved"
    );

    Some(Arc::new(crate::service_stubs::StubService::new(
        "resolved",
        tag.to_string(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::ServiceType;

    #[test]
    fn test_resolved_service_creation() {
        let ir = ServiceIR {
            ty: ServiceType::Resolved,
            tag: Some("test-resolved".to_string()),
            resolved_listen: Some("127.0.0.1".to_string()),
            resolved_listen_port: Some(5353),
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_listen: None,
            derp_listen_port: None,
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_stun_enabled: None,
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
            derp_server_key_path: None,
        };

        let ctx = ServiceContext::default();
        let service = build_resolved_service(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "resolved");
        assert_eq!(service.tag(), "test-resolved");
    }

    #[cfg(all(target_os = "linux", feature = "service_resolved"))]
    #[test]
    fn test_resolved_service_lifecycle() {
        use sb_core::service::StartStage;

        let ir = ServiceIR {
            ty: ServiceType::Resolved,
            tag: Some("lifecycle-test".to_string()),
            resolved_listen: Some("127.0.0.1".to_string()),
            resolved_listen_port: Some(5353),
            ssmapi_listen: None,
            ssmapi_listen_port: None,
            ssmapi_servers: None,
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            derp_listen: None,
            derp_listen_port: None,
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_stun_enabled: None,
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
            derp_server_key_path: None,
        };

        // Note: This test will fail if systemd-resolved is not available
        // In CI or non-systemd environments, it should gracefully skip
        match dbus_impl::ResolvedService::new(&ir) {
            Ok(service) => {
                // Test lifecycle stages
                let init_result = service.start(StartStage::Initialize);
                if init_result.is_ok() {
                    assert!(service.start(StartStage::Start).is_ok());
                    assert!(service.start(StartStage::PostStart).is_ok());
                    assert!(service.start(StartStage::Started).is_ok());
                    assert!(service.close().is_ok());
                } else {
                    // Expected in environments without systemd-resolved
                    println!("Skipping lifecycle test: systemd-resolved not available");
                }
            }
            Err(_e) => {
                println!("Skipping lifecycle test: failed to create service");
            }
        }
    }
}
