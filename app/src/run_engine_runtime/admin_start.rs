use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info};

#[derive(Default)]
pub struct AdminServices {
    #[cfg(feature = "clash_api")]
    clash_api: Option<ClashApiHandle>,
    #[cfg(feature = "admin_debug")]
    admin_debug: Option<app::admin_debug::http_server::AdminDebugHandle>,
}

impl AdminServices {
    pub async fn shutdown(self) {
        #[cfg(feature = "clash_api")]
        if let Some(handle) = self.clash_api {
            handle.shutdown().await;
        }

        #[cfg(feature = "admin_debug")]
        if let Some(handle) = self.admin_debug {
            handle.shutdown().await;
        }
    }
}

pub struct AdminStartContext<'a> {
    opts: &'a crate::run_engine::RunOptions,
    supervisor: &'a Arc<sb_core::runtime::supervisor::Supervisor>,
    runtime: &'a crate::run_engine_runtime::context::RuntimeContext,
}

impl<'a> AdminStartContext<'a> {
    #[must_use]
    pub const fn new(
        opts: &'a crate::run_engine::RunOptions,
        supervisor: &'a Arc<sb_core::runtime::supervisor::Supervisor>,
        runtime: &'a crate::run_engine_runtime::context::RuntimeContext,
    ) -> Self {
        Self {
            opts,
            supervisor,
            runtime,
        }
    }
}

#[cfg(all(feature = "router", feature = "clash_api"))]
struct ClashApiHandle {
    listen_addr: std::net::SocketAddr,
    shutdown: oneshot::Sender<()>,
    join: JoinHandle<()>,
}

#[cfg(all(feature = "router", feature = "clash_api"))]
impl ClashApiHandle {
    async fn shutdown(self) {
        if self.shutdown.send(()).is_err() {
            tracing::debug!("clash api shutdown signal dropped before shutdown");
        }
        if let Err(error) = self.join.await {
            tracing::warn!(%error, "clash api join failed during shutdown");
        }
    }
}

#[cfg(all(feature = "router", feature = "clash_api"))]
fn build_outbound_registry_handle(
    bridge: &sb_core::adapter::Bridge,
) -> Arc<sb_core::outbound::OutboundRegistryHandle> {
    let mut registry = sb_core::outbound::OutboundRegistry::default();
    for (name, _kind, connector) in &bridge.outbounds {
        registry.insert(
            name.clone(),
            sb_core::outbound::OutboundImpl::Connector(connector.clone()),
        );
    }
    Arc::new(sb_core::outbound::OutboundRegistryHandle::new(registry))
}

#[cfg(all(feature = "router", feature = "clash_api"))]
fn clash_api_listen_addr(ir: &sb_config::ir::ConfigIR) -> Option<std::net::SocketAddr> {
    let listen = ir
        .experimental
        .as_ref()
        .and_then(|experimental| experimental.clash_api.as_ref())
        .and_then(|config| config.external_controller.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())?;

    match listen.parse() {
        Ok(addr) => Some(addr),
        Err(error) => {
            tracing::warn!(
                error = %error,
                listen = %listen,
                "invalid clash_api listen address, skipping clash api startup"
            );
            None
        }
    }
}

#[cfg(all(feature = "router", feature = "clash_api"))]
async fn start_clash_api_from_supervisor(
    supervisor: &Arc<sb_core::runtime::supervisor::Supervisor>,
) -> Option<ClashApiHandle> {
    let state_lock = supervisor.handle().state().await;
    let state_guard = state_lock.read().await;

    let listen_addr = clash_api_listen_addr(&state_guard.current_ir)?;
    let clash_cfg = state_guard
        .current_ir
        .experimental
        .as_ref()
        .and_then(|experimental| experimental.clash_api.as_ref())?;

    let config = sb_api::types::ApiConfig {
        listen_addr,
        enable_cors: true,
        cors_origins: None,
        auth_token: clash_cfg.secret.clone(),
        enable_traffic_ws: true,
        enable_logs_ws: true,
        traffic_broadcast_interval_ms: 1000,
        log_buffer_size: 100,
    };

    let mut server = match sb_api::clash::ClashApiServer::new(config) {
        Ok(server) => server,
        Err(error) => {
            error!(error = %error, "failed to create clash api server");
            return None;
        }
    };

    if let Some(router) = state_guard.bridge.router.clone() {
        server = server.with_router(router);
    }

    let provider_manager = Arc::new(
        sb_api::managers::ProviderManager::default()
            .with_reload_channel(supervisor.handle().reload_sender()),
    );

    server = server
        .with_dns_resolver(Arc::new(sb_api::managers::DnsResolver::new()))
        .with_provider_manager(provider_manager)
        .with_service_manager(state_guard.context.service_manager.clone())
        .with_outbound_registry(build_outbound_registry_handle(&state_guard.bridge))
        .with_config_ir(Arc::new(state_guard.current_ir.clone()));

    if let Some(cache) = state_guard.context.cache_file.clone() {
        server = server.with_cache_file(cache);
    }
    if let Some(history) = state_guard.context.urltest_history.clone() {
        server = server.with_urltest_history(history);
    }

    drop(state_guard);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        if let Err(error) = server.start_with_shutdown(shutdown_rx).await {
            error!(error = %error, "clash api server exited with error");
        }
    });

    info!(listen = %listen_addr, "started clash api server from run_engine");
    Some(ClashApiHandle {
        listen_addr,
        shutdown: shutdown_tx,
        join,
    })
}

pub async fn start_admin_services(ctx: AdminStartContext<'_>) -> Result<AdminServices> {
    let opts = ctx.opts;
    let supervisor = ctx.supervisor;

    #[cfg(feature = "clash_api")]
    let clash_api = start_clash_api_from_supervisor(supervisor).await;

    #[cfg(not(feature = "clash_api"))]
    let _ = supervisor;

    #[cfg(feature = "admin_debug")]
    let mut admin_debug = None;

    if let Some(addr) = opts.admin_listen.as_ref() {
        #[cfg(feature = "clash_api")]
        if let Some(handle) = clash_api.as_ref() {
            if let Ok(admin_addr) = addr.parse::<std::net::SocketAddr>() {
                if admin_addr == handle.listen_addr {
                    tracing::warn!(
                        admin_addr = %admin_addr,
                        clash_addr = %handle.listen_addr,
                        "admin_listen conflicts with clash_api listen address; admin may fail to bind"
                    );
                }
            }
        }

        match opts.admin_impl {
            crate::run_engine::AdminImpl::Debug => {
                #[cfg(feature = "admin_debug")]
                {
                    let socket_addr: std::net::SocketAddr = addr
                        .parse()
                        .map_err(|error| anyhow!("Invalid admin listen address: {error}"))?;

                    let tls_conf = app::admin_debug::http_server::TlsConf::from_env();
                    let auth_conf = app::admin_debug::http_server::AuthConf::from_env();
                    let tls_opt = if tls_conf.enabled {
                        Some(tls_conf)
                    } else {
                        None
                    };
                    let admin_state = ctx.runtime.admin_state();

                    let handle = admin_state
                        .spawn_http_server(socket_addr, tls_opt, auth_conf)
                        .await
                        .map_err(|error| anyhow!("Failed to start admin debug server: {error}"))?;
                    info!(addr = %socket_addr, r#impl = "debug", "Started admin debug server");
                    admin_debug = Some(handle);
                }

                #[cfg(not(feature = "admin_debug"))]
                {
                    return Err(anyhow!(
                        "admin_debug feature not enabled, cannot use admin_impl=debug"
                    ));
                }
            }
            crate::run_engine::AdminImpl::Core => {
                if let Err(error) = app::util::spawn_core_admin_from_supervisor(
                    addr,
                    opts.admin_token.clone(),
                    supervisor.clone(),
                )
                .await
                {
                    error!(error=%error, "failed to start core admin server");
                }
            }
        }
    }

    Ok(AdminServices {
        #[cfg(feature = "clash_api")]
        clash_api,
        #[cfg(feature = "admin_debug")]
        admin_debug,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "clash_api")]
    use super::clash_api_listen_addr;

    #[cfg(feature = "clash_api")]
    use sb_config::ir::{ClashApiIR, ConfigIR, ExperimentalIR};

    #[cfg(feature = "clash_api")]
    fn clash_ir(listen: Option<&str>) -> ConfigIR {
        ConfigIR {
            experimental: Some(ExperimentalIR {
                clash_api: Some(ClashApiIR {
                    external_controller: listen.map(str::to_string),
                    ..ClashApiIR::default()
                }),
                ..ExperimentalIR::default()
            }),
            ..ConfigIR::default()
        }
    }

    #[cfg(feature = "clash_api")]
    #[test]
    fn clash_api_listen_addr_accepts_valid_socket_addr() {
        assert_eq!(
            clash_api_listen_addr(&clash_ir(Some("127.0.0.1:9090")))
                .map(|addr| addr.to_string())
                .as_deref(),
            Some("127.0.0.1:9090")
        );
    }

    #[cfg(feature = "clash_api")]
    #[test]
    fn clash_api_listen_addr_rejects_invalid_or_blank_values() {
        assert!(clash_api_listen_addr(&clash_ir(Some("invalid"))).is_none());
        assert!(clash_api_listen_addr(&clash_ir(Some("   "))).is_none());
        assert!(clash_api_listen_addr(&clash_ir(None)).is_none());
    }

    #[test]
    fn wp30ao_pin_admin_start_owner_moved_out_of_run_engine_rs() {
        let source = include_str!("admin_start.rs");
        let run_engine = include_str!("../run_engine.rs");

        assert!(source.contains("pub struct AdminStartContext"));
        assert!(source.contains("async fn start_admin_services("));
        assert!(source.contains("admin_state.spawn_http_server("));
        assert!(
            source.contains(".with_service_manager(state_guard.context.service_manager.clone())")
        );
        assert!(!run_engine.contains("fn start_clash_api_from_supervisor("));
        assert!(!run_engine.contains("fn build_outbound_registry_handle("));
    }
}
