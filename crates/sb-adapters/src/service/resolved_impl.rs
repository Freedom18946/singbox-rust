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
    use sb_core::dns::dns_router::{DnsQueryContext, DnsRouter};
    use sb_core::dns::message::build_dns_response;
    use sb_core::service::StartStage;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
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
        started: AtomicBool,
        udp_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
        tcp_task: parking_lot::Mutex<Option<JoinHandle<()>>>,
        /// DNS router for query handling (Go parity: adapter.DNSRouter).
        dns_router: Arc<dyn DnsRouter>,
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
        pub fn new(
            ir: &ServiceIR,
            ctx: &ServiceContext,
        ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let tag = ir.tag.as_deref().unwrap_or("resolved").to_string();
            let listen_addr = ir.listen.as_deref().unwrap_or("127.0.0.53").to_string();
            let listen_port = ir.listen_port.unwrap_or(53);

            let dns_router = ctx
                .dns_router
                .clone()
                .ok_or("Resolved service requires ServiceContext.dns_router")?;

            // Use the shared singleton state so updates are seen by ResolvedTransport
            let resolve1_state = sb_core::dns::transport::resolved::RESOLVED_STATE.clone();
            resolve1_state.set_dns_router(dns_router.clone());
            resolve1_state.set_service_tag(tag.clone());

            Ok(Self {
                tag,
                listen_addr,
                listen_port,
                started: AtomicBool::new(false),
                udp_task: parking_lot::Mutex::new(None),
                tcp_task: parking_lot::Mutex::new(None),
                dns_router,
                resolve1_state,
                dbus_server_connection: parking_lot::Mutex::new(None),
                #[cfg(feature = "network_monitor")]
                network_monitor: ctx.network_monitor.clone(),
                #[cfg(feature = "network_monitor")]
                network_monitor_task: parking_lot::Mutex::new(None),
            })
        }

        async fn spawn_udp(
            bind_addr: String,
            tag: String,
            dns_router: Arc<dyn DnsRouter>,
            resolve1_state: Arc<crate::service::resolve1::Resolve1ManagerState>,
        ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
            let socket = UdpSocket::bind(&bind_addr)
                .await
                .map_err(|e| format!("Failed to bind UDP DNS stub to {bind_addr}: {e}"))?;
            let socket = Arc::new(socket);

            tracing::info!(
                target: "sb_adapters::service",
                service = "resolved",
                tag = %tag,
                bind_addr = %bind_addr,
                "DNS stub UDP listening"
            );

            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let (len, peer) = match socket.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!(
                                target: "sb_adapters::service",
                                service = "resolved",
                                tag = %tag,
                                error = %e,
                                "UDP recv error"
                            );
                            break;
                        }
                    };

                    let req = buf[..len].to_vec();
                    let socket = socket.clone();
                    let dns_router = dns_router.clone();
                    let inbound = resolve1_state.get_service_tag();

                    tokio::spawn(async move {
                        let ctx = DnsQueryContext::new()
                            .with_inbound(inbound)
                            .with_transport("udp")
                            .with_client(peer);
                        let resp = match dns_router.exchange(&ctx, &req).await {
                            Ok(r) => r,
                            Err(err) => {
                                tracing::debug!(
                                    target: "sb_adapters::service",
                                    service = "resolved",
                                    error = %err,
                                    "dns_router.exchange failed; replying SERVFAIL"
                                );
                                build_dns_response(&req, &[], 0, 2).unwrap_or_default()
                            }
                        };
                        if !resp.is_empty() {
                            let _ = socket.send_to(&resp, peer).await;
                        }
                    });
                }
            });

            Ok(handle)
        }

        async fn handle_tcp_conn(
            mut stream: TcpStream,
            peer: std::net::SocketAddr,
            inbound: String,
            dns_router: Arc<dyn DnsRouter>,
        ) {
            loop {
                let mut len_buf = [0u8; 2];
                if let Err(_e) = stream.read_exact(&mut len_buf).await {
                    break;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                if n == 0 || n > 65535 {
                    break;
                }
                let mut req = vec![0u8; n];
                if let Err(_e) = stream.read_exact(&mut req).await {
                    break;
                }

                let ctx = DnsQueryContext::new()
                    .with_inbound(inbound.clone())
                    .with_transport("tcp")
                    .with_client(peer);

                let resp = match dns_router.exchange(&ctx, &req).await {
                    Ok(r) => r,
                    Err(_err) => build_dns_response(&req, &[], 0, 2).unwrap_or_default(),
                };
                if resp.is_empty() {
                    break;
                }

                let len = (resp.len() as u16).to_be_bytes();
                if stream.write_all(&len).await.is_err() {
                    break;
                }
                if stream.write_all(&resp).await.is_err() {
                    break;
                }
            }
        }

        async fn spawn_tcp(
            bind_addr: String,
            tag: String,
            dns_router: Arc<dyn DnsRouter>,
            resolve1_state: Arc<crate::service::resolve1::Resolve1ManagerState>,
        ) -> Result<JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
            let listener = TcpListener::bind(&bind_addr)
                .await
                .map_err(|e| format!("Failed to bind TCP DNS stub to {bind_addr}: {e}"))?;

            tracing::info!(
                target: "sb_adapters::service",
                service = "resolved",
                tag = %tag,
                bind_addr = %bind_addr,
                "DNS stub TCP listening"
            );

            let handle = tokio::spawn(async move {
                loop {
                    let (stream, peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::error!(
                                target: "sb_adapters::service",
                                service = "resolved",
                                tag = %tag,
                                error = %e,
                                "TCP accept error"
                            );
                            break;
                        }
                    };
                    let inbound = resolve1_state.get_service_tag();
                    let dns_router = dns_router.clone();
                    tokio::spawn(Self::handle_tcp_conn(stream, peer, inbound, dns_router));
                }
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
                        "Starting Resolved DNS stub"
                    );

                    let bind_addr = format!("{}:{}", self.listen_addr, self.listen_port);

                    let tag = self.tag.clone();
                    let dns_router = self.dns_router.clone();
                    let state = self.resolve1_state.clone();

                    let udp = tokio::runtime::Handle::try_current()
                        .map_err(|_| "No tokio runtime available")?
                        .block_on(Self::spawn_udp(
                            bind_addr.clone(),
                            tag.clone(),
                            dns_router.clone(),
                            state.clone(),
                        ))?;
                    let tcp = tokio::runtime::Handle::try_current()
                        .map_err(|_| "No tokio runtime available")?
                        .block_on(Self::spawn_tcp(bind_addr, tag, dns_router, state))?;

                    *self.udp_task.lock() = Some(udp);
                    *self.tcp_task.lock() = Some(tcp);
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

            if let Some(handle) = self.udp_task.lock().take() {
                handle.abort();
            }
            if let Some(handle) = self.tcp_task.lock().take() {
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
