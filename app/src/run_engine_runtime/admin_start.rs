use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info};

#[cfg(all(feature = "router", feature = "clash_api"))]
use crate::sidecar_runtime::{
    SidecarActiveGeneration, SidecarActivePhase, SidecarExit, SidecarExitRecord,
    SidecarRuntimeSnapshot,
};
#[cfg(all(feature = "router", feature = "clash_api"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(feature = "router", feature = "clash_api"))]
use tokio::sync::watch;

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
    shutdown: ClashShutdownHandle,
}

#[cfg(all(feature = "router", feature = "clash_api"))]
pub struct PreboundClashApiHandle {
    pub listen_addr: std::net::SocketAddr,
    pub shutdown: ClashShutdownHandle,
}

#[cfg(all(feature = "router", feature = "clash_api"))]
impl ClashApiHandle {
    async fn shutdown(self) {
        let mut shutdown = self.shutdown;
        shutdown.shutdown().await;
    }
}

/// Source-of-truth publisher for a single Clash serve generation (handle-local `generation = 1`).
///
/// Owns the one `watch::Sender<SidecarRuntimeSnapshot>` and the generation-local shutdown marker.
/// Mutation + publication are done atomically inside `send_if_modified` (no borrow-then-delayed-send
/// backflow). Monotonic: `ShutdownRequested` never overwrites a terminal, and a terminal is written
/// at most once.
#[cfg(all(feature = "router", feature = "clash_api"))]
#[derive(Clone)]
struct ClashRuntimePublisher {
    runtime_tx: watch::Sender<SidecarRuntimeSnapshot>,
    shutdown_requested: Arc<AtomicBool>,
}

#[cfg(all(feature = "router", feature = "clash_api"))]
impl ClashRuntimePublisher {
    fn new_running() -> Self {
        let (runtime_tx, _) = watch::channel(SidecarRuntimeSnapshot {
            current: Some(SidecarActiveGeneration {
                generation: 1,
                phase: SidecarActivePhase::Running,
            }),
            last_exit: None,
        });
        Self {
            runtime_tx,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Capability accessor for a future consumer (no resident observer is created in this card).
    #[allow(dead_code)]
    fn subscribe(&self) -> watch::Receiver<SidecarRuntimeSnapshot> {
        self.runtime_tx.subscribe()
    }

    fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }

    /// Mark a deliberate shutdown and publish `ShutdownRequested(1)` while Running. No-op once
    /// already shutting down or terminated (a terminal must never be reverted).
    fn mark_shutdown_requested(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.runtime_tx
            .send_if_modified(|snapshot| match snapshot.current.as_mut() {
                Some(active) if active.phase == SidecarActivePhase::Running => {
                    active.phase = SidecarActivePhase::ShutdownRequested;
                    true
                }
                _ => false,
            });
    }

    /// Commit the single generation-1 terminal (idempotent: a second terminal is ignored).
    fn commit_terminal(&self, exit: SidecarExit) {
        self.runtime_tx.send_if_modified(move |snapshot| {
            if snapshot.last_exit.is_some() {
                return false;
            }
            snapshot.current = None;
            snapshot.last_exit = Some(SidecarExitRecord {
                generation: 1,
                exit,
            });
            true
        });
    }
}

/// Unified Clash shutdown controller: replaces the bare `oneshot::Sender` + `JoinHandle` so a
/// deliberate shutdown publishes `ShutdownRequested` before signalling, and the outer monitor (the
/// sole terminal writer) is awaited on shutdown.
#[cfg(all(feature = "router", feature = "clash_api"))]
pub struct ClashShutdownHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    monitor_join: Option<JoinHandle<()>>,
    runtime: ClashRuntimePublisher,
}

#[cfg(all(feature = "router", feature = "clash_api"))]
impl ClashShutdownHandle {
    /// Capability accessor for a future consumer (bootstrap observer / run-engine). Unused here.
    #[allow(dead_code)]
    pub(crate) fn subscribe_runtime_state(&self) -> watch::Receiver<SidecarRuntimeSnapshot> {
        self.runtime.subscribe()
    }

    /// Synchronous-publish then async-drain: mark + publish `ShutdownRequested` (in the watch lock),
    /// send the shutdown signal outside any lock, then await the outer monitor's terminal commit.
    /// Idempotent — a repeated call is a safe no-op (sender/join already taken).
    pub(crate) async fn shutdown(&mut self) {
        self.runtime.mark_shutdown_requested();
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.monitor_join.take() {
            let _ = join.await;
        }
    }
}

/// Map a monitored Clash serve task's join outcome to a terminal exit. Generic over the serve error
/// type so tests can synthesize outcomes without an `ApiError`.
#[cfg(all(feature = "router", feature = "clash_api"))]
fn classify_clash_exit<E: std::fmt::Display>(
    outcome: Result<std::result::Result<(), E>, tokio::task::JoinError>,
    shutdown_requested: bool,
) -> SidecarExit {
    match outcome {
        Ok(Ok(())) => {
            if shutdown_requested {
                SidecarExit::CleanShutdown
            } else {
                SidecarExit::UnexpectedCompletion
            }
        }
        Ok(Err(error)) => SidecarExit::ServeError(error.to_string()),
        Err(join_error) => {
            if join_error.is_panic() {
                let payload = join_error.into_panic();
                let message = payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "panic with non-string payload".to_string());
                SidecarExit::Panicked(message)
            } else if join_error.is_cancelled() {
                SidecarExit::Cancelled
            } else {
                // No other JoinError kind exists today; map to the nearest defined terminal.
                SidecarExit::Cancelled
            }
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
fn pre_bind_clash_api_listener(
    listen_addr: std::net::SocketAddr,
) -> Result<tokio::net::TcpListener> {
    let std_listener = std::net::TcpListener::bind(listen_addr)
        .map_err(|error| anyhow!("failed to bind Clash API listener on {listen_addr}: {error}",))?;
    std_listener.set_nonblocking(true).map_err(|error| {
        anyhow!("failed to set Clash API listener nonblocking on {listen_addr}: {error}",)
    })?;
    tokio::net::TcpListener::from_std(std_listener).map_err(|error| {
        anyhow!("failed to register Clash API listener on {listen_addr}: {error}",)
    })
}

#[cfg(all(feature = "router", feature = "clash_api"))]
pub fn spawn_prebound_clash_api_server(
    listen_addr: std::net::SocketAddr,
    server: sb_api::clash::ClashApiServer,
) -> Result<PreboundClashApiHandle> {
    let listener = pre_bind_clash_api_listener(listen_addr)?;
    let actual_addr = listener.local_addr().map_err(|error| {
        anyhow!("failed to read Clash API listener address for {listen_addr}: {error}",)
    })?;

    info!(listen = %actual_addr, "Starting Clash API server");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    // Publish Running(1) BEFORE spawning. Between this publish and the monitor spawn there is no
    // fallible op / early return, so there is no reachable path where Running is published but the
    // monitor never spawns.
    let publisher = ClashRuntimePublisher::new_running();
    let monitor_publisher = publisher.clone();

    // The outer monitor is the SOLE terminal writer and the SOLE terminal logger for this handle.
    // It owns the inner serve task's JoinHandle, classifies its outcome, and commits the terminal
    // exactly once.
    let monitor_join = tokio::spawn(async move {
        let inner = tokio::spawn(async move {
            server
                .serve_with_listener_and_shutdown(listener, shutdown_rx)
                .await
        });
        let exit = classify_clash_exit(inner.await, monitor_publisher.shutdown_requested());
        match &exit {
            SidecarExit::CleanShutdown => {
                info!("Clash API server stopped (clean shutdown)");
            }
            SidecarExit::UnexpectedCompletion => {
                tracing::warn!("Clash API server completed without a shutdown request");
            }
            SidecarExit::ServeError(error) => {
                error!(error = %error, "Clash API server error");
            }
            SidecarExit::Panicked(panic) => {
                error!(panic = %panic, "Clash API server panicked");
            }
            SidecarExit::Cancelled => {
                tracing::warn!("Clash API server cancelled");
            }
            SidecarExit::Unknown => {
                tracing::warn!("Clash API server terminated (unknown)");
            }
        }
        monitor_publisher.commit_terminal(exit);
    });

    Ok(PreboundClashApiHandle {
        listen_addr: actual_addr,
        shutdown: ClashShutdownHandle {
            shutdown_tx: Some(shutdown_tx),
            monitor_join: Some(monitor_join),
            runtime: publisher,
        },
    })
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

    let handle = match spawn_prebound_clash_api_server(listen_addr, server) {
        Ok(handle) => handle,
        Err(error) => {
            error!(error = %error, listen = %listen_addr, "failed to start clash api server");
            return None;
        }
    };

    info!(listen = %handle.listen_addr, "started clash api server from run_engine");
    Some(ClashApiHandle {
        listen_addr: handle.listen_addr,
        shutdown: handle.shutdown,
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

    #[cfg(feature = "clash_api")]
    #[test]
    fn run_engine_clash_callsite_does_not_report_started_on_bind_error() {
        let source = include_str!("admin_start.rs");
        let implementation = source
            .split("#[cfg(test)]")
            .next()
            .expect("implementation section exists before tests");
        let err_branch = implementation
            .find("\"failed to start clash api server\"")
            .expect("run_engine clash api bind failure log is present");
        let started_log = implementation
            .find("\"started clash api server from run_engine\"")
            .expect("run_engine clash api started log is present");

        assert!(
            implementation.contains("spawn_prebound_clash_api_server(listen_addr, server)"),
            "run_engine Clash API must use the shared pre-bound startup helper"
        );
        assert!(
            !implementation.contains("server.start_with_shutdown(shutdown_rx).await"),
            "run_engine Clash API must not bind inside the spawned task"
        );
        assert!(
            err_branch < started_log,
            "bind/start failure handling must precede the started log"
        );
        assert!(
            implementation[err_branch..started_log].contains("return None"),
            "bind/start failure must return without creating a live-looking handle"
        );
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

    // ── APP-SIDECAR-LIVENESS-01G-B: Clash runtime completion projection ──
    #[cfg(all(feature = "router", feature = "clash_api"))]
    mod clash_runtime {
        use super::super::*;

        fn current(snapshot: &SidecarRuntimeSnapshot) -> Option<(u64, SidecarActivePhase)> {
            snapshot
                .current
                .as_ref()
                .map(|g| (g.generation, g.phase.clone()))
        }

        // ── A. Initial Running(1) ──
        #[test]
        fn publisher_starts_running() {
            let publisher = ClashRuntimePublisher::new_running();
            let rx = publisher.subscribe();
            let snapshot = rx.borrow();
            assert_eq!(current(&snapshot), Some((1, SidecarActivePhase::Running)));
            assert!(snapshot.last_exit.is_none());
        }

        // ── B. Explicit shutdown marks ShutdownRequested(1) ──
        #[test]
        fn mark_shutdown_requested_publishes_shutdown_requested() {
            let publisher = ClashRuntimePublisher::new_running();
            let rx = publisher.subscribe();
            publisher.mark_shutdown_requested();
            assert!(publisher.shutdown_requested());
            assert_eq!(
                current(&rx.borrow()),
                Some((1, SidecarActivePhase::ShutdownRequested))
            );
        }

        // ── C. Terminal monotonicity: first terminal wins; shutdown never reverts it ──
        #[test]
        fn terminal_is_monotonic() {
            let publisher = ClashRuntimePublisher::new_running();
            let rx = publisher.subscribe();
            publisher.commit_terminal(SidecarExit::ServeError("first".to_string()));
            // A later shutdown request and a second terminal must not overwrite the first terminal.
            publisher.mark_shutdown_requested();
            publisher.commit_terminal(SidecarExit::CleanShutdown);
            let snapshot = rx.borrow();
            assert!(snapshot.current.is_none());
            assert_eq!(
                snapshot.last_exit,
                Some(SidecarExitRecord {
                    generation: 1,
                    exit: SidecarExit::ServeError("first".to_string()),
                })
            );
        }

        // ── D. Drop / no shutdown request → UnexpectedCompletion (never faked clean) ──
        #[test]
        fn classify_ok_without_request_is_unexpected() {
            assert_eq!(
                classify_clash_exit::<String>(Ok(Ok(())), false),
                SidecarExit::UnexpectedCompletion
            );
        }

        // ── E. Clean shutdown ──
        #[test]
        fn classify_ok_with_request_is_clean() {
            assert_eq!(
                classify_clash_exit::<String>(Ok(Ok(())), true),
                SidecarExit::CleanShutdown
            );
        }

        // ── F. Serve error ──
        #[test]
        fn classify_serve_error() {
            assert_eq!(
                classify_clash_exit(Ok(Err("boom".to_string())), false),
                SidecarExit::ServeError("boom".to_string())
            );
        }

        // ── G. Panic ──
        #[tokio::test]
        async fn classify_panic() {
            let handle = tokio::spawn(async {
                panic!("kaboom");
            });
            let outcome = handle.await.map(|()| Ok::<(), String>(()));
            match classify_clash_exit(outcome, false) {
                SidecarExit::Panicked(message) => assert!(message.contains("kaboom")),
                other => panic!("expected Panicked, got {other:?}"),
            }
        }

        // ── H. Cancellation ──
        #[tokio::test]
        async fn classify_cancelled() {
            let handle = tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            });
            handle.abort();
            let outcome = handle.await.map(|()| Ok::<(), String>(()));
            assert_eq!(classify_clash_exit(outcome, false), SidecarExit::Cancelled);
        }

        fn test_clash_server(listen_addr: std::net::SocketAddr) -> sb_api::clash::ClashApiServer {
            sb_api::clash::ClashApiServer::new(sb_api::types::ApiConfig {
                listen_addr,
                enable_cors: true,
                cors_origins: None,
                auth_token: None,
                enable_traffic_ws: false,
                enable_logs_ws: false,
                traffic_broadcast_interval_ms: 1000,
                log_buffer_size: 100,
            })
            .expect("create clash api server")
        }

        // ── N. Bind conflict → Err, no handle (startup honesty) ──
        #[tokio::test]
        async fn bind_conflict_returns_error() {
            let occupier = match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => listener,
                Err(error) => {
                    eprintln!("Skipping bind_conflict test (cannot bind): {error}");
                    return;
                }
            };
            let addr = occupier.local_addr().unwrap();
            let server = test_clash_server(addr);
            assert!(
                spawn_prebound_clash_api_server(addr, server).is_err(),
                "occupied port must surface Err, not a live-looking handle"
            );
            drop(occupier);
        }

        // ── M. Early shutdown → clean terminal via the real pre-bound server + monitor ──
        #[tokio::test]
        async fn immediate_shutdown_yields_clean_terminal() {
            let port = match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(probe) => probe.local_addr().unwrap().port(),
                Err(error) => {
                    eprintln!("Skipping immediate_shutdown test (cannot bind): {error}");
                    return;
                }
            };
            let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let server = test_clash_server(addr);
            let mut handle = match spawn_prebound_clash_api_server(addr, server) {
                Ok(handle) => handle,
                Err(error) => {
                    eprintln!("Skipping immediate_shutdown test (bind race): {error}");
                    return;
                }
            };

            let rx = handle.shutdown.subscribe_runtime_state();
            assert_eq!(
                current(&rx.borrow()),
                Some((1, SidecarActivePhase::Running))
            );

            // shutdown() awaits the monitor, so the terminal is committed by the time it returns.
            handle.shutdown.shutdown().await;
            let snapshot = rx.borrow();
            assert!(snapshot.current.is_none());
            assert_eq!(
                snapshot.last_exit,
                Some(SidecarExitRecord {
                    generation: 1,
                    exit: SidecarExit::CleanShutdown,
                })
            );
        }
    }
}
