use std::sync::Arc;

#[cfg(feature = "router")]
use sb_core::outbound::OutboundRegistryHandle;
#[cfg(feature = "router")]
use sb_core::router::RouterHandle;
use tracing::{error, info, warn};

pub(crate) struct ServiceHandle {
    #[allow(dead_code)]
    pub(crate) name: &'static str,
    pub(crate) shutdown: tokio::sync::oneshot::Sender<()>,
    pub(crate) join: tokio::task::JoinHandle<()>,
}

impl ServiceHandle {
    pub(crate) async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.join.await;
    }
}

#[cfg(feature = "clash_api")]
pub(crate) fn start_clash_api_server(
    listen: &str,
    secret: Option<String>,
    router: Arc<RouterHandle>,
    outbounds: Arc<OutboundRegistryHandle>,
    config_ir: Arc<sb_config::ir::ConfigIR>,
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
                .with_config_ir(config_ir);

            if let Some(cache_file) = cache_file {
                server = server.with_cache_file(cache_file);
            }

            if let Some(history) = urltest_history {
                server = server.with_urltest_history(history);
            }

            let server = server.with_router(router);

            info!(listen = %listen_addr, "Starting Clash API server");
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let join = tokio::spawn(async move {
                if let Err(error) = server.start_with_shutdown(shutdown_rx).await {
                    error!(error = %error, "Clash API server error");
                }
            });
            Some(ServiceHandle {
                name: "clash_api",
                shutdown: shutdown_tx,
                join,
            })
        }
        Err(error) => {
            error!(error = %error, "Failed to create Clash API server");
            None
        }
    }
}

#[cfg(feature = "v2ray_api")]
pub(crate) fn start_v2ray_api_server(listen: &str) -> Option<ServiceHandle> {
    use std::net::SocketAddr;

    let listen_addr: SocketAddr = match listen.parse() {
        Ok(addr) => addr,
        Err(error) => {
            warn!(error = %error, listen = %listen, "Invalid V2Ray API listen address, skipping");
            return None;
        }
    };

    let config = sb_api::types::ApiConfig {
        listen_addr,
        enable_cors: false,
        cors_origins: None,
        auth_token: None,
        enable_traffic_ws: false,
        enable_logs_ws: false,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    match sb_api::v2ray::SimpleV2RayApiServer::new(config) {
        Ok(server) => {
            info!(listen = %listen_addr, "Starting V2Ray API server");
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
            let join = tokio::spawn(async move {
                if let Err(error) = server.start_with_shutdown(shutdown_rx).await {
                    error!(error = %error, "V2Ray API server error");
                }
            });
            Some(ServiceHandle {
                name: "v2ray_api",
                shutdown: shutdown_tx,
                join,
            })
        }
        Err(error) => {
            error!(error = %error, "Failed to create V2Ray API server");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_core::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    fn empty_outbound_handle() -> Arc<OutboundRegistryHandle> {
        let registry = OutboundRegistry::new(HashMap::<String, OutboundImpl>::new());
        Arc::new(OutboundRegistryHandle::new(registry))
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

        ServiceHandle {
            name: "test",
            shutdown: shutdown_tx,
            join,
        }
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
            None,
            Some(Arc::new(
                sb_core::services::urltest_history::URLTestHistoryService::new(),
            )),
        );

        assert!(handle.is_none());
    }

    #[cfg(feature = "v2ray_api")]
    #[test]
    fn v2ray_api_starter_skips_invalid_listen_addresses() {
        assert!(start_v2ray_api_server("invalid").is_none());
    }

    #[test]
    fn wp30an_pin_api_service_owner_lives_in_bootstrap_runtime() {
        let source = include_str!("api_services.rs");
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(source.contains("pub(crate) struct ServiceHandle"));
        assert!(!bootstrap.contains("struct ServiceHandle {"));
        assert!(!bootstrap.contains("fn start_clash_api_server("));
        assert!(!bootstrap.contains("fn start_v2ray_api_server("));
        assert!(
            bootstrap.contains("crate::bootstrap_runtime::api_services::start_clash_api_server(")
        );
        assert!(
            bootstrap.contains("crate::bootstrap_runtime::api_services::start_v2ray_api_server(")
        );
    }
}
