use std::sync::Arc;

#[cfg(feature = "router")]
use sb_core::outbound::OutboundRegistryHandle;
#[cfg(feature = "router")]
use sb_core::router::RouterHandle;
use tracing::{error, info, warn};

pub(crate) struct ServiceHandle {
    #[allow(dead_code)]
    pub(crate) name: &'static str,
    shutdown: ServiceShutdown,
}

/// How a service is shut down. The `Task` variant is the bare oneshot+join path (used by the
/// bootstrap V2Ray sidecar); the `Clash` variant carries the unified runtime-completion controller
/// so a deliberate shutdown publishes `ShutdownRequested` before signalling and awaits the monitor.
enum ServiceShutdown {
    Task {
        shutdown: tokio::sync::oneshot::Sender<()>,
        join: tokio::task::JoinHandle<()>,
    },
    #[cfg(all(feature = "router", feature = "clash_api"))]
    Clash(crate::run_engine_runtime::admin_start::ClashShutdownHandle),
}

impl ServiceHandle {
    /// Construct a bare task-backed service handle (oneshot shutdown + join). Used by the bootstrap
    /// V2Ray sidecar and by callers in sibling modules that own a plain serve task.
    pub(crate) fn from_task(
        name: &'static str,
        shutdown: tokio::sync::oneshot::Sender<()>,
        join: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            name,
            shutdown: ServiceShutdown::Task { shutdown, join },
        }
    }

    pub(crate) async fn shutdown(self) {
        match self.shutdown {
            ServiceShutdown::Task { shutdown, join } => {
                let _ = shutdown.send(());
                let _ = join.await;
            }
            #[cfg(all(feature = "router", feature = "clash_api"))]
            ServiceShutdown::Clash(mut handle) => handle.shutdown().await,
        }
    }
}

#[cfg(feature = "clash_api")]
pub(crate) fn start_clash_api_server(
    listen: &str,
    secret: Option<String>,
    router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
    config_ir: Arc<sb_config::ir::ConfigIR>,
    conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
    cache_file: Option<Arc<dyn sb_core::context::CacheFile>>,
    urltest_history: Option<Arc<dyn sb_core::context::URLTestHistoryStorage>>,
) -> Option<ServiceHandle> {
    use std::net::SocketAddr;

    let listen_addr: SocketAddr = match listen.parse() {
        Ok(addr) => addr,
        Err(error) => {
            warn!(error = %error, listen = %listen, "Invalid Clash API listen address, skipping");
            return None;
        }
    };

    let config = sb_api::types::ApiConfig {
        listen_addr,
        enable_cors: true,
        cors_origins: None,
        auth_token: secret,
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    match sb_api::clash::ClashApiServer::new(config) {
        Ok(server) => {
            let provider_manager = Arc::new(sb_api::managers::ProviderManager::default());
            let mut server = server
                .with_dns_resolver(Arc::new(sb_api::managers::DnsResolver::new()))
                .with_provider_manager(provider_manager)
                .with_outbound_registry(outbounds)
                .with_config_ir(config_ir)
                .with_conn_tracker(conn_tracker);

            if let Some(cache_file) = cache_file {
                server = server.with_cache_file(cache_file);
            }

            if let Some(history) = urltest_history {
                server = server.with_urltest_history(history);
            }

            let server = server.with_router(router);

            match crate::run_engine_runtime::admin_start::spawn_prebound_clash_api_server(
                listen_addr,
                server,
            ) {
                Ok(handle) => Some(ServiceHandle {
                    name: "clash_api",
                    shutdown: ServiceShutdown::Clash(handle.shutdown),
                }),
                Err(error) => {
                    warn!(error = %error, listen = %listen_addr, "Failed to start Clash API server, skipping");
                    None
                }
            }
        }
        Err(error) => {
            error!(error = %error, "Failed to create Clash API server");
            None
        }
    }
}

#[cfg(feature = "v2ray_api")]
pub(crate) fn start_v2ray_api_server(
    listen: &str,
    stats: Option<sb_config::ir::StatsIR>,
) -> Option<ServiceHandle> {
    use sb_core::context::V2RayServer;

    let listen = listen.trim();
    if listen.is_empty() {
        warn!("V2Ray API listen address is empty, skipping");
        return None;
    }
    let listen_addr: std::net::SocketAddr = match listen.parse() {
        Ok(addr) => addr,
        Err(error) => {
            warn!(error = %error, listen = %listen, "Invalid V2Ray API listen address, skipping");
            return None;
        }
    };
    let listen = listen_addr.to_string();

    let config = sb_config::ir::V2RayApiIR {
        listen: Some(listen.clone()),
        stats,
    };

    let server = Arc::new(sb_core::services::v2ray_api::V2RayApiServer::new(config));
    match server.start() {
        Ok(()) => {
            info!(listen = %listen, "Started V2Ray API server");
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let join = tokio::spawn(async move {
                let _ = shutdown_rx.await;
                if let Err(error) = server.close() {
                    error!(error = %error, "Failed to close V2Ray API server");
                }
                wait_for_v2ray_api_bind_release(listen_addr).await;
            });
            Some(ServiceHandle::from_task("v2ray_api", shutdown_tx, join))
        }
        Err(error) => {
            warn!(error = %error, listen = %listen, "Failed to start V2Ray API server, skipping");
            None
        }
    }
}

#[cfg(feature = "v2ray_api")]
async fn wait_for_v2ray_api_bind_release(addr: std::net::SocketAddr) {
    for _ in 0..80 {
        match std::net::TcpListener::bind(addr) {
            Ok(listener) => {
                drop(listener);
                return;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "clash_api")]
    use crate::run_engine_runtime::admin_start::spawn_prebound_clash_api_server;
    use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[cfg(feature = "clash_api")]
    fn build_clash_api_server(listen_addr: std::net::SocketAddr) -> sb_api::clash::ClashApiServer {
        let config = sb_api::types::ApiConfig {
            listen_addr,
            enable_cors: true,
            cors_origins: None,
            auth_token: None,
            enable_traffic_ws: true,
            enable_logs_ws: true,
            traffic_broadcast_interval_ms: 1000,
            log_buffer_size: 100,
        };
        sb_api::clash::ClashApiServer::new(config).expect("create Clash API server")
    }

    fn empty_outbound_handle() -> Arc<OutboundRegistryHandle> {
        let registry = OutboundRegistry::new(HashMap::<String, OutboundImpl>::new());
        Arc::new(OutboundRegistryHandle::new(registry))
    }

    #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
    async fn wait_for_tcp_connect(addr: std::net::SocketAddr) -> bool {
        for _ in 0..80 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
    async fn wait_for_bind_release(addr: std::net::SocketAddr) -> bool {
        for _ in 0..80 {
            if let Ok(listener) = std::net::TcpListener::bind(addr) {
                drop(listener);
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    #[cfg(feature = "clash_api")]
    async fn shutdown_prebound_handle(
        mut handle: crate::run_engine_runtime::admin_start::PreboundClashApiHandle,
    ) {
        handle.shutdown.shutdown().await;
    }

    #[tokio::test]
    async fn service_handle_shutdown_waits_for_background_task() {
        let observed = Arc::new(AtomicBool::new(false));
        let observed_clone = observed.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            observed_clone.store(true, Ordering::SeqCst);
        });

        ServiceHandle::from_task("test", shutdown_tx, join)
            .shutdown()
            .await;

        assert!(observed.load(Ordering::SeqCst));
    }

    #[cfg(feature = "clash_api")]
    #[test]
    fn clash_api_starter_skips_invalid_listen_addresses() {
        let handle = start_clash_api_server(
            "invalid",
            None,
            Arc::new(sb_core::router::dns_integration::setup_dns_routing()),
            empty_outbound_handle(),
            Arc::new(sb_config::ir::ConfigIR::default()),
            Arc::new(sb_common::conntrack::ConnTracker::new()),
            None,
            Some(Arc::new(
                sb_core::services::urltest_history::URLTestHistoryService::new(),
            )),
        );

        assert!(handle.is_none());
    }

    #[cfg(feature = "clash_api")]
    #[tokio::test]
    async fn clash_bind_conflict_returns_error_before_handle() {
        let occupier = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("Skipping clash_bind_conflict test (cannot bind): {error}");
                return;
            }
        };
        let listen_addr = occupier.local_addr().unwrap();
        let server = build_clash_api_server(listen_addr);

        let error = match spawn_prebound_clash_api_server(listen_addr, server) {
            Ok(_) => panic!("bind conflict must return Err before handle"),
            Err(error) => error,
        };
        let message = error.to_string().to_lowercase();
        assert!(
            message.contains("bind")
                || message.contains("address")
                || message.contains("in use")
                || message.contains("addrinuse"),
            "error must contain bind/address-in-use semantics, got: {message}"
        );
    }

    #[cfg(feature = "clash_api")]
    #[tokio::test]
    async fn clash_successful_bind_returns_handle() {
        let probe = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("Skipping clash_successful_bind test (cannot bind): {error}");
                return;
            }
        };
        let listen_addr = probe.local_addr().unwrap();
        drop(probe);

        let server = build_clash_api_server(listen_addr);
        let handle = spawn_prebound_clash_api_server(listen_addr, server)
            .expect("pre-bound Clash API server must return a handle");

        assert_eq!(handle.listen_addr, listen_addr);
        assert!(
            wait_for_tcp_connect(handle.listen_addr).await,
            "pre-bound Clash API server must accept local TCP connections"
        );
        let bound_addr = handle.listen_addr;
        shutdown_prebound_handle(handle).await;
        assert!(
            wait_for_bind_release(bound_addr).await,
            "shutdown must release the Clash API listen port"
        );
    }

    #[cfg(feature = "clash_api")]
    #[tokio::test]
    async fn clash_restart_after_failed_bind() {
        let occupier = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("Skipping clash_restart_after_failed_bind test (cannot bind): {error}");
                return;
            }
        };
        let listen_addr = occupier.local_addr().unwrap();
        let first = build_clash_api_server(listen_addr);

        assert!(
            spawn_prebound_clash_api_server(listen_addr, first).is_err(),
            "occupied port must fail before handle creation"
        );

        drop(occupier);
        let second = build_clash_api_server(listen_addr);
        let handle = spawn_prebound_clash_api_server(listen_addr, second)
            .expect("retry after releasing occupied port must succeed");
        assert!(
            wait_for_tcp_connect(handle.listen_addr).await,
            "retry server must accept local TCP connections"
        );
        shutdown_prebound_handle(handle).await;
    }

    #[cfg(feature = "clash_api")]
    #[tokio::test]
    async fn bootstrap_clash_callsite_does_not_return_handle_on_bind_error() {
        let occupier = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!(
                    "Skipping bootstrap_callsite_does_not_return_handle_on_bind_error test: {error}"
                );
                return;
            }
        };
        let listen_addr = occupier.local_addr().unwrap();

        let handle = start_clash_api_server(
            &listen_addr.to_string(),
            None,
            Arc::new(sb_core::router::dns_integration::setup_dns_routing()),
            empty_outbound_handle(),
            Arc::new(sb_config::ir::ConfigIR::default()),
            Arc::new(sb_common::conntrack::ConnTracker::new()),
            None,
            Some(Arc::new(
                sb_core::services::urltest_history::URLTestHistoryService::new(),
            )),
        );

        assert!(
            handle.is_none(),
            "bootstrap Clash API bind failure must not return a live-looking handle"
        );
    }

    #[cfg(feature = "v2ray_api")]
    #[test]
    fn v2ray_api_starter_skips_invalid_listen_addresses() {
        assert!(start_v2ray_api_server("invalid", None).is_none());
    }

    #[cfg(feature = "v2ray_api")]
    #[test]
    fn v2ray_api_starter_skips_empty_listen_addresses() {
        assert!(start_v2ray_api_server("", None).is_none());
        assert!(start_v2ray_api_server("   ", None).is_none());
    }

    #[cfg(feature = "v2ray_api")]
    #[tokio::test]
    async fn v2ray_bind_conflict_returns_no_handle() {
        let occupier = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("Skipping v2ray_bind_conflict test (cannot bind): {error}");
                return;
            }
        };
        let listen_addr = occupier.local_addr().unwrap();

        let handle = start_v2ray_api_server(&listen_addr.to_string(), None);

        assert!(
            handle.is_none(),
            "bootstrap V2Ray API bind failure must not return a live-looking handle"
        );
    }

    #[cfg(feature = "v2ray_api")]
    #[tokio::test]
    async fn v2ray_successful_bind_accepts_tcp_and_shutdown_releases_port() {
        let probe = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("Skipping v2ray_successful_bind test (cannot bind): {error}");
                return;
            }
        };
        let listen_addr = probe.local_addr().unwrap();
        drop(probe);

        let handle = start_v2ray_api_server(
            &listen_addr.to_string(),
            Some(sb_config::ir::StatsIR {
                enabled: true,
                inbounds: Vec::new(),
                outbounds: Vec::new(),
                users: Vec::new(),
                inbound: Some(true),
                outbound: Some(true),
            }),
        )
        .expect("bootstrap V2Ray API must return handle after a successful bind");

        assert!(
            wait_for_tcp_connect(listen_addr).await,
            "bootstrap V2Ray API must accept local TCP connections"
        );

        handle.shutdown().await;
        assert!(
            wait_for_bind_release(listen_addr).await,
            "shutdown must release the V2Ray API listen port"
        );
    }

    #[test]
    fn wp30an_pin_api_service_owner_lives_in_bootstrap_runtime() {
        let source = include_str!("api_services.rs");
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(source.contains("pub(crate) struct ServiceHandle"));
        assert!(source.contains(".with_conn_tracker(conn_tracker)"));
        assert!(!bootstrap.contains("struct ServiceHandle {"));
        assert!(!bootstrap.contains("fn start_clash_api_server("));
        assert!(!bootstrap.contains("fn start_v2ray_api_server("));
        assert!(
            bootstrap.contains("crate::bootstrap_runtime::api_services::start_clash_api_server(")
        );
        assert!(bootstrap.contains("runtime_conn_tracker.clone()"));
        assert!(
            bootstrap.contains("crate::bootstrap_runtime::api_services::start_v2ray_api_server(")
        );
    }
}
