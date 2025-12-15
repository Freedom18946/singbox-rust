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
    ///
    /// This service operates in two modes:
    /// 1. **D-Bus Server Mode**: Exports `org.freedesktop.resolve1.Manager` interface
    ///    allowing external programs to configure per-link DNS settings.
    /// 2. **DNS Stub Listener**: Listens on configured address for DNS queries.
    pub struct ResolvedService {
        tag: String,
        listen_addr: String,
        listen_port: u16,
        connection: parking_lot::Mutex<Option<zbus::Connection>>,
        started: AtomicBool,
        server_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
        /// DNS resolver for query handling
        resolver: Arc<dyn DnsResolver>,
        /// D-Bus server state for per-link DNS configuration
        resolve1_state: Arc<crate::service::resolve1::Resolve1ManagerState>,
        /// D-Bus server connection (for cleanup)
        dbus_server_connection: parking_lot::Mutex<Option<zbus::Connection>>,
        /// Network monitor for tracking network changes
        #[cfg(feature = "network_monitor")]
        network_monitor: Option<Arc<sb_platform::NetworkMonitor>>,
        /// Network monitor task handle
        #[cfg(feature = "network_monitor")]
        network_monitor_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
    }

    impl ResolvedService {
        pub fn new(ir: &ServiceIR, ctx: &ServiceContext) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let tag = ir.tag.as_deref().unwrap_or("resolved").to_string();
            let listen_addr = ir
                .listen
                .as_deref()
                .unwrap_or("127.0.0.53")
                .to_string();
            let listen_port = ir.listen_port.unwrap_or(53);

            // Use injected DNS resolver from context, or fallback to system resolver
            // 使用上下文中注入的 DNS 解析器，或回退到系统解析器
            let resolver = ctx.dns_resolver.clone().unwrap_or_else(|| {
                Arc::new(sb_core::dns::system::SystemResolver::new(
                    std::time::Duration::from_secs(60),
                )) as Arc<dyn DnsResolver>
            });

            // Create resolve1 manager state
            let resolve1_state = Arc::new(crate::service::resolve1::Resolve1ManagerState::new());

            Ok(Self {
                tag,
                listen_addr,
                listen_port,
                connection: parking_lot::Mutex::new(None),
                started: AtomicBool::new(false),
                server_task: parking_lot::Mutex::new(None),
                resolver,
                resolve1_state,
                dbus_server_connection: parking_lot::Mutex::new(None),
                #[cfg(feature = "network_monitor")]
                network_monitor: ctx.network_monitor.clone(),
                #[cfg(feature = "network_monitor")]
                network_monitor_task: parking_lot::Mutex::new(None),
            })
        }

        /// Connect to systemd-resolved via D-Bus.
        async fn connect_dbus(
            &self,
        ) -> Result<zbus::Connection, Box<dyn std::error::Error + Send + Sync>> {
            // Reuse if already connected
            if let Some(conn) = self.connection.lock().clone() {
                return Ok(conn);
            }

            let conn = zbus::Connection::system()
                .await
                .map_err(|e| format!("Failed to connect to system D-Bus: {}", e))?;

            // Verify systemd-resolved is available
            let proxy = zbus::fdo::DBusProxy::new(&conn)
                .await
                .map_err(|e| format!("Failed to create D-Bus proxy: {}", e))?;

            let has_resolved = proxy
                .list_names()
                .await
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

            *self.connection.lock() = Some(conn.clone());
            Ok(conn)
        }

        /// Resolve hostname via systemd-resolved D-Bus.
        async fn resolve_via_resolved(
            &self,
            name: &str,
            qtype: u16,
        ) -> Result<Vec<IpAddr>, Box<dyn std::error::Error + Send + Sync>> {
            // family: AF_INET(2) or AF_INET6(10) or 0 (unspecified)
            let family = match qtype {
                1 => 2,   // A
                28 => 10, // AAAA
                _ => 0,   // fallback
            };

            let conn = self.connect_dbus().await?;
            let proxy = zbus::ProxyBuilder::new_bare(&conn)
                .destination("org.freedesktop.resolve1")?
                .path("/org/freedesktop/resolve1")?
                .interface("org.freedesktop.resolve1.Manager")?
                .build()
                .await?;

            // ResolveHostname(ifindex=0, name, family, flags=0) -> (addresses, canonical)
            let (addresses, _canonical): (Vec<(i32, i32, Vec<u8>)>, String) = proxy
                .call("ResolveHostname", &(0i32, name, family, 0u32))
                .await?;

            let mut ips = Vec::new();
            for (_family, _ifindex, raw) in addresses {
                if raw.len() == 4 {
                    let octets: [u8; 4] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid IPv4 length")?;
                    ips.push(IpAddr::from(octets));
                } else if raw.len() == 16 {
                    let octets: [u8; 16] = raw
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid IPv6 length")?;
                    ips.push(IpAddr::from(octets));
                }
            }

            if ips.is_empty() {
                return Err("systemd-resolved returned no addresses".into());
            }

            Ok(ips)
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

            // Use systemd-resolved via D-Bus; fallback to core resolver on failure.
            let ips = match Self::resolve_via_resolved(self, &domain, qtype).await {
                Ok(addrs) => addrs,
                Err(e) => {
                    tracing::warn!(
                        target: "sb_adapters::service",
                        service = "resolved",
                        domain = %domain,
                        error = %e,
                        "D-Bus resolve failed; falling back to core resolver"
                    );
                    resolver
                        .resolve(&domain)
                        .await
                        .map(|ans| ans.ips)
                        .unwrap_or_default()
                }
            };

            let ttl = 60; // placeholder TTL; systemd-resolved does not expose TTL via this call

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

                    // Start D-Bus server to export org.freedesktop.resolve1.Manager
                    // This allows external programs (like systemd-networkd, NetworkManager)
                    // to configure per-link DNS settings via D-Bus.
                    let state = self.resolve1_state.clone();
                    let handle = tokio::runtime::Handle::try_current()
                        .map_err(|_| "No tokio runtime available for D-Bus server")?;

                    let dbus_conn = handle.block_on(async {
                        crate::service::resolve1::dbus_server::start_dbus_server(state).await
                    })?;

                    *self.dbus_server_connection.lock() = Some(dbus_conn);

                    tracing::info!(
                        target: "sb_adapters::service",
                        service = "resolved",
                        tag = %self.tag,
                        "D-Bus server started: org.freedesktop.resolve1.Manager"
                    );

                    // Register network monitor callback if available
                    #[cfg(feature = "network_monitor")]
                    if let Some(monitor) = &self.network_monitor {
                        let resolve1_state = self.resolve1_state.clone();
                        let tag = self.tag.clone();
                        monitor.register_callback(Box::new(move |event| {
                            use sb_platform::NetworkEvent;
                            match event {
                                NetworkEvent::LinkUp { interface } => {
                                    tracing::info!(
                                        target: "sb_adapters::service",
                                        service = "resolved",
                                        tag = %tag,
                                        interface = %interface,
                                        "Network interface up, refreshing DNS configuration"
                                    );
                                }
                                NetworkEvent::LinkDown { interface } => {
                                    tracing::info!(
                                        target: "sb_adapters::service",
                                        service = "resolved",
                                        tag = %tag,
                                        interface = %interface,
                                        "Network interface down, updating DNS configuration"
                                    );
                                }
                                NetworkEvent::AddressAdded { interface, address } => {
                                    tracing::debug!(
                                        target: "sb_adapters::service",
                                        service = "resolved",
                                        tag = %tag,
                                        interface = %interface,
                                        address = %address,
                                        "Address added to interface"
                                    );
                                }
                                NetworkEvent::AddressRemoved { interface, address } => {
                                    tracing::debug!(
                                        target: "sb_adapters::service",
                                        service = "resolved",
                                        tag = %tag,
                                        interface = %interface,
                                        address = %address,
                                        "Address removed from interface"
                                    );
                                }
                                NetworkEvent::RouteChanged | NetworkEvent::Changed => {
                                    tracing::debug!(
                                        target: "sb_adapters::service",
                                        service = "resolved",
                                        tag = %tag,
                                        "Network route changed"
                                    );
                                }
                            }
                        }));

                        // Start the network monitor
                        match monitor.start() {
                            Ok(handle) => {
                                *self.network_monitor_task.lock() = Some(handle);
                                tracing::info!(
                                    target: "sb_adapters::service",
                                    service = "resolved",
                                    tag = %self.tag,
                                    "Network monitor started"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    target: "sb_adapters::service",
                                    service = "resolved",
                                    tag = %self.tag,
                                    error = %e,
                                    "Failed to start network monitor (continuing without it)"
                                );
                            }
                        }
                    }

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

            // Close D-Bus server connection
            if let Some(_conn) = self.dbus_server_connection.lock().take() {
                tracing::debug!(
                    target: "sb_adapters::service",
                    service = "resolved",
                    tag = %self.tag,
                    "D-Bus server connection closed"
                );
            }

            // Stop network monitor
            #[cfg(feature = "network_monitor")]
            {
                if let Some(handle) = self.network_monitor_task.lock().take() {
                    handle.abort();
                }
                if let Some(monitor) = &self.network_monitor {
                    monitor.stop();
                    tracing::debug!(
                        target: "sb_adapters::service",
                        service = "resolved",
                        tag = %self.tag,
                        "Network monitor stopped"
                    );
                }
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
        match dbus_impl::ResolvedService::new(ir, _ctx) {
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
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(5353),
            ..Default::default()
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
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(5353),
            ..Default::default()
        };

        // Note: This test will fail if systemd-resolved is not available
        // In CI or non-systemd environments, it should gracefully skip
        let ctx = ServiceContext::default();
        match dbus_impl::ResolvedService::new(&ir, &ctx) {
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
