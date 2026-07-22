//! Runtime supervisor for hot reload and graceful shutdown.
//!
//! # Global Strategic Logic
//! This module implements the **Supervisor Pattern** to manage the application lifecycle.
//!
//! ## Strategic Workflow
//! `Start` -> `Event Loop` -> `Reload (Diff & Apply)` -> `Shutdown (Drain & Stop)`
//!
//! ## Strategic Features
//! - **Hot Reload**: Applies new configurations without dropping existing connections (where possible).
//! - **Graceful Shutdown**: Waits for active connections to drain before terminating, ensuring zero data loss.
//! - **Diffing**: Calculates the difference between old and new configs to minimize churn (e.g., only restarting changed inbounds).

use crate::adapter::Bridge;
#[cfg(test)]
use crate::adapter::InboundTaskDriver;
use crate::context::{Context, ManagedApiActivePhase, ManagedApiServer, Startable};
use crate::endpoint::{Endpoint, StartStage as EndpointStage};

use crate::router::Engine;
use crate::service::{Service, StartStage as ServiceStage};
use anyhow::{Context as AnyhowContext, Result};
use sb_config::ir::diff::Diff;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_util::sync::CancellationToken;

const INBOUND_READY_TIMEOUT: Duration = Duration::from_secs(10);
const INBOUND_MONITOR_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

fn ensure_bridge_startup_ready(bridge: &Bridge) -> Result<()> {
    if bridge.startup_errors.is_empty() {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "runtime startup blocked by adapter errors: {}",
        bridge.startup_errors.join("; ")
    ))
}

fn apply_tls_certificate_config(cert: Option<&sb_config::ir::CertificateIR>) {
    if let Some(certificate) = cert {
        sb_tls::global::apply_certificate_config(
            certificate.store.as_deref(),
            &certificate.ca_paths,
            &certificate.ca_pem,
            certificate.certificate_directory_path.as_deref(),
        );
    } else {
        sb_tls::global::apply_certificate_config(None, &[], &[], None);
    }
}

/// Messages sent to supervisor event loop
#[derive(Debug)]
pub enum ReloadMsg {
    /// Apply new configuration with hot reload
    Apply {
        ir: Box<sb_config::ir::ConfigIR>,
        result: Option<oneshot::Sender<Result<(), String>>>,
    },
    /// Update providers: merge new outbounds and rule entries into current config.
    /// This takes the current ConfigIR, patches it with the provider data, and
    /// performs a full reload via the same path as `Apply`.
    UpdateProviders {
        /// New outbound proxies from proxy providers (replace provider-sourced outbounds).
        outbounds: Vec<sb_config::ir::OutboundIR>,
        /// New rule entries from rule providers (plain rule strings like "DOMAIN,example.com").
        rules: Vec<String>,
        /// Provider name (for logging).
        provider_name: String,
    },
    /// Begin graceful shutdown with deadline
    Shutdown { deadline: Instant },
}

#[derive(Debug, Clone, Default)]
struct ProviderOverlayState {
    outbounds_by_provider: HashMap<String, Vec<String>>,
    rules_by_provider: HashMap<String, Vec<sb_config::ir::RuleIR>>,
}

#[derive(Clone, Debug)]
struct InboundRuntimeLabel {
    tag: String,
    kind: String,
    phase: &'static str,
}

struct InboundRuntimeMonitor {
    label: InboundRuntimeLabel,
    shutdown_requested: Arc<AtomicBool>,
    join: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for InboundRuntimeMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundRuntimeMonitor")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// Runtime state managed by supervisor

#[derive(Debug)]
pub struct State {
    pub engine: Engine,
    pub bridge: Arc<Bridge>,
    pub context: Context,
    dns_runtime: Option<RuntimeDns>,
    inbound_monitors: Vec<InboundRuntimeMonitor>,
    pub health: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "service_ntp")]
    pub ntp: Option<tokio::task::JoinHandle<()>>,
    pub started_at: Instant,
    /// Current configuration IR for diff computation during reload
    pub current_ir: sb_config::ir::ConfigIR,
    provider_overlay: ProviderOverlayState,
}

/// Supervisor manages runtime state and hot reload/shutdown
pub struct Supervisor {
    tx: mpsc::Sender<ReloadMsg>,
    handle: tokio::task::JoinHandle<()>,
    state: Arc<RwLock<State>>,
    cancel: CancellationToken,
}

/// Handle to supervisor that allows graceful shutdown without taking ownership
#[derive(Clone)]
pub struct SupervisorHandle {
    tx: mpsc::Sender<ReloadMsg>,
    state: Arc<RwLock<State>>,
    cancel: CancellationToken,
}

impl State {
    fn new(
        engine: Engine,
        bridge: Bridge,
        context: Context,
        dns_runtime: Option<RuntimeDns>,
        ir: sb_config::ir::ConfigIR,
    ) -> Self {
        Self {
            engine,
            bridge: Arc::new(bridge),
            context,
            dns_runtime,
            inbound_monitors: Vec::new(),
            health: None,
            #[cfg(feature = "service_ntp")]
            ntp: None,
            started_at: Instant::now(),
            current_ir: ir,
            provider_overlay: ProviderOverlayState::default(),
        }
    }
}

#[derive(Clone)]
struct RuntimeDns {
    resolver: Arc<dyn crate::dns::Resolver>,
    router: Option<Arc<dyn crate::dns::dns_router::DnsRouter>>,
}

impl std::fmt::Debug for RuntimeDns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeDns")
            .field("resolver", &self.resolver.name())
            .field("has_router", &self.router.is_some())
            .finish()
    }
}

impl RuntimeDns {
    async fn start(&self, stage: ServiceStage) -> Result<()> {
        let Some(dns_stage) = dns_stage_for_service_stage(stage) else {
            return Ok(());
        };
        self.resolver
            .start(dns_stage)
            .await
            .with_context(|| format!("failed to start DNS runtime at {stage}"))?;
        Ok(())
    }

    async fn close(&self) -> Result<()> {
        self.resolver
            .close()
            .await
            .context("failed to close DNS runtime")
    }

    fn publish_global(&self) {
        crate::dns::global::set(self.resolver.clone());
    }
}

fn dns_stage_for_service_stage(
    stage: ServiceStage,
) -> Option<crate::dns::transport::DnsStartStage> {
    match stage {
        ServiceStage::Initialize => Some(crate::dns::transport::DnsStartStage::Initialize),
        ServiceStage::Start => Some(crate::dns::transport::DnsStartStage::Start),
        ServiceStage::PostStart => Some(crate::dns::transport::DnsStartStage::PostStart),
        // Rust DNS transports currently expose three stages. The coordinator
        // still schedules DNS at `Started`; DNS treats it as a no-op.
        ServiceStage::Started => None,
    }
}

fn build_runtime_dns_from_ir(
    ir: &sb_config::ir::ConfigIR,
    cache_file: Option<Arc<dyn crate::context::CacheFile>>,
    options: Arc<crate::runtime_options::DnsRuntimeOptions>,
) -> Result<Option<RuntimeDns>> {
    if ir.dns.is_none() {
        return Ok(None);
    }
    let (resolver, router) =
        crate::dns::config_builder::build_dns_components_with_options(ir, cache_file, options)
            .context("failed to build DNS runtime")?;
    Ok(Some(RuntimeDns { resolver, router }))
}

fn publish_runtime_dns(dns_runtime: Option<&RuntimeDns>) {
    if let Some(dns) = dns_runtime {
        dns.publish_global();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleComponent {
    Network,
    Dns,
    Connections,
    TaskMonitor,
    Platform,
    Outbound,
    Inbound,
    Endpoint,
    Service,
}

impl LifecycleComponent {
    fn label(self) -> &'static str {
        match self {
            Self::Network => "NetworkManager",
            Self::Dns => "DNSRuntime",
            Self::Connections => "ConnectionManager",
            Self::TaskMonitor => "TaskMonitor",
            Self::Platform => "PlatformInterface",
            Self::Outbound => "OutboundManager",
            Self::Inbound => "InboundManager",
            Self::Endpoint => "EndpointManager",
            Self::Service => "ServiceManager",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecyclePass {
    Initialize,
    StartCore,
    StartEdge,
    PostStart,
    Started,
}

impl LifecyclePass {
    const fn stage(self) -> ServiceStage {
        match self {
            Self::Initialize => ServiceStage::Initialize,
            Self::StartCore | Self::StartEdge => ServiceStage::Start,
            Self::PostStart => ServiceStage::PostStart,
            Self::Started => ServiceStage::Started,
        }
    }
}

const INITIALIZE_COMPONENTS: &[LifecycleComponent] = &[
    LifecycleComponent::Network,
    LifecycleComponent::Dns,
    LifecycleComponent::Connections,
    LifecycleComponent::TaskMonitor,
    LifecycleComponent::Platform,
    LifecycleComponent::Outbound,
    LifecycleComponent::Inbound,
    LifecycleComponent::Endpoint,
    LifecycleComponent::Service,
];
const START_CORE_COMPONENTS: &[LifecycleComponent] = &[
    LifecycleComponent::Outbound,
    LifecycleComponent::Dns,
    LifecycleComponent::Network,
    LifecycleComponent::Connections,
    LifecycleComponent::TaskMonitor,
    LifecycleComponent::Platform,
];
const START_EDGE_COMPONENTS: &[LifecycleComponent] = &[
    LifecycleComponent::Inbound,
    LifecycleComponent::Endpoint,
    LifecycleComponent::Service,
];
const POST_START_COMPONENTS: &[LifecycleComponent] = &[
    LifecycleComponent::Outbound,
    LifecycleComponent::Network,
    LifecycleComponent::Dns,
    LifecycleComponent::Connections,
    LifecycleComponent::TaskMonitor,
    LifecycleComponent::Platform,
    LifecycleComponent::Inbound,
    LifecycleComponent::Endpoint,
    LifecycleComponent::Service,
];
const STARTED_COMPONENTS: &[LifecycleComponent] = &[
    LifecycleComponent::Network,
    LifecycleComponent::Dns,
    LifecycleComponent::Connections,
    LifecycleComponent::TaskMonitor,
    LifecycleComponent::Platform,
    LifecycleComponent::Outbound,
    LifecycleComponent::Inbound,
    LifecycleComponent::Endpoint,
    LifecycleComponent::Service,
];
const CLOSE_COMPONENTS: &[LifecycleComponent] = &[
    LifecycleComponent::Service,
    LifecycleComponent::Endpoint,
    LifecycleComponent::Inbound,
    LifecycleComponent::Outbound,
    LifecycleComponent::Platform,
    LifecycleComponent::TaskMonitor,
    LifecycleComponent::Connections,
    LifecycleComponent::Dns,
    LifecycleComponent::Network,
];

fn lifecycle_components_for(pass: LifecyclePass) -> &'static [LifecycleComponent] {
    match pass {
        LifecyclePass::Initialize => INITIALIZE_COMPONENTS,
        LifecyclePass::StartCore => START_CORE_COMPONENTS,
        LifecyclePass::StartEdge => START_EDGE_COMPONENTS,
        LifecyclePass::PostStart => POST_START_COMPONENTS,
        LifecyclePass::Started => STARTED_COMPONENTS,
    }
}

struct LifecycleCoordinator<'a> {
    context: &'a Context,
    dns: Option<&'a RuntimeDns>,
}

impl<'a> LifecycleCoordinator<'a> {
    const fn new(context: &'a Context, dns: Option<&'a RuntimeDns>) -> Self {
        Self { context, dns }
    }

    async fn run_pass(&self, pass: LifecyclePass) -> Result<()> {
        let stage = pass.stage();
        for component in lifecycle_components_for(pass) {
            self.start_component(*component, stage)
                .await
                .with_context(|| {
                    format!(
                        "failed to run lifecycle pass {:?} for {}",
                        pass,
                        component.label()
                    )
                })?;
        }
        Ok(())
    }

    async fn close_all(&self, close_v2ray: bool) {
        for component in CLOSE_COMPONENTS {
            if let Err(e) = self.close_component(*component).await {
                tracing::warn!(
                    target: "sb_core::runtime",
                    component = component.label(),
                    error = %e,
                    "failed to close lifecycle component"
                );
            }
        }

        if close_v2ray {
            if let Some(v2ray) = &self.context.v2ray_server {
                if let Err(e) = v2ray.close() {
                    tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close V2Ray API server");
                }
            }
        }
    }

    async fn start_component(
        &self,
        component: LifecycleComponent,
        stage: ServiceStage,
    ) -> Result<()> {
        match component {
            LifecycleComponent::Network => self
                .context
                .network
                .start(stage)
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Dns => {
                if let Some(dns) = self.dns {
                    dns.start(stage).await
                } else {
                    Ok(())
                }
            }
            LifecycleComponent::Connections => self
                .context
                .connections
                .start(stage)
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::TaskMonitor => self
                .context
                .task_monitor
                .start(stage)
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Platform => self
                .context
                .platform
                .start(stage)
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Outbound => self
                .context
                .outbound_manager
                .start_all_ordered(stage)
                .await
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Inbound => self
                .context
                .inbound_manager
                .start(stage)
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Endpoint => self
                .context
                .endpoint_manager
                .start(stage)
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Service => self
                .context
                .service_manager
                .start(stage)
                .map_err(|e| anyhow::anyhow!(e)),
        }
    }

    async fn close_component(&self, component: LifecycleComponent) -> Result<()> {
        match component {
            LifecycleComponent::Network => {
                self.context.network.close().map_err(|e| anyhow::anyhow!(e))
            }
            LifecycleComponent::Dns => {
                if let Some(dns) = self.dns {
                    dns.close().await
                } else {
                    Ok(())
                }
            }
            LifecycleComponent::Connections => self
                .context
                .connections
                .close()
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::TaskMonitor => self
                .context
                .task_monitor
                .close()
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Platform => self
                .context
                .platform
                .close()
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Outbound => self
                .context
                .outbound_manager
                .close_all_ordered()
                .await
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Inbound => self
                .context
                .inbound_manager
                .close()
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Endpoint => self
                .context
                .endpoint_manager
                .close()
                .map_err(|e| anyhow::anyhow!(e)),
            LifecycleComponent::Service => self
                .context
                .service_manager
                .close()
                .map_err(|e| anyhow::anyhow!(e)),
        }
    }
}

impl Supervisor {
    /// Start supervisor with initial configuration
    pub async fn start(ir: sb_config::ir::ConfigIR) -> Result<Self> {
        Self::start_with_registry(ir, None).await
    }

    /// Start supervisor with an explicit adapter registry snapshot.
    pub async fn start_with_registry(
        ir: sb_config::ir::ConfigIR,
        adapter_registry: Option<crate::adapter::registry::RegistrySnapshot>,
    ) -> Result<Self> {
        Self::start_with_registry_and_options(
            ir,
            adapter_registry,
            Arc::new(crate::runtime_options::CoreRuntimeOptions::default()),
        )
        .await
    }

    /// Start supervisor with an explicit adapter registry and immutable runtime options.
    pub async fn start_with_registry_and_options(
        ir: sb_config::ir::ConfigIR,
        adapter_registry: Option<crate::adapter::registry::RegistrySnapshot>,
        runtime_options: crate::runtime_options::SharedCoreRuntimeOptions,
    ) -> Result<Self> {
        #[cfg(feature = "rule_coverage")]
        crate::router::coverage::set_enabled(runtime_options.router.rule_coverage);
        if let Some(snapshot) = adapter_registry.as_ref() {
            crate::adapter::registry::install_snapshot(snapshot);
        }

        // Ensure TLS crypto provider is installed before any TLS usage
        #[cfg(feature = "tls_rustls")]
        sb_tls::ensure_crypto_provider();

        let (tx, mut rx) = mpsc::channel::<ReloadMsg>(32);
        let cancel = CancellationToken::new();

        // Configure logging
        if let Some(log_ir) = &ir.log {
            crate::log::configure(log_ir);
        }

        // Build initial engine and bridge
        let engine = Engine::from_ir(&ir).context("failed to build engine from initial config")?;
        let engine_for_state = engine.clone();

        // Create runtime context and wire experimental sidecars from IR
        let context = build_context_from_ir_with_options(&ir, None, runtime_options)?;
        ensure_geo_assets(&ir).await;
        let dns_runtime = match build_runtime_dns_from_ir(
            &ir,
            context.cache_file.clone(),
            Arc::new(context.runtime_options.dns.clone()),
        ) {
            Ok(runtime) => runtime,
            Err(e) => {
                shutdown_context(&context);
                return Err(e);
            }
        };

        // Initialize context managers (Box Runtime Parity: Go box.go lifecycle)
        {
            let lifecycle = LifecycleCoordinator::new(&context, dns_runtime.as_ref());
            if let Err(e) = lifecycle.run_pass(LifecyclePass::Initialize).await {
                lifecycle.close_all(true).await;
                return Err(e);
            }
        }
        tracing::debug!(target: "sb_core::runtime", "Context managers initialized");

        // Build bridge via adapter bridge to enable routed inbounds/outbounds
        let bridge =
            crate::adapter::bridge::build_bridge_async(&ir, engine.clone(), context.clone()).await;
        if let Err(e) = ensure_bridge_startup_ready(&bridge) {
            LifecycleCoordinator::new(&context, dns_runtime.as_ref())
                .close_all(true)
                .await;
            return Err(e);
        }

        // Register bridge components (endpoints, services, outbounds) into the
        // context managers BEFORE Start stage, so EndpointManager.run_stage and
        // ServiceManager.start_stage can drive each component through its
        // lifecycle and persist failure status on bind errors. If services were
        // registered after Start stage, the manager would never observe their
        // Start failures (regression: /services/health misreporting Failed
        // services as Running, see LC-003 p1_service_failure_isolation).
        if let Err(e) = populate_bridge_managers(&context, &bridge).await {
            tracing::error!(target: "sb_core::runtime", error = %e, "startup failed during outbound registration, rolling back");
            LifecycleCoordinator::new(&context, dns_runtime.as_ref())
                .close_all(true)
                .await;
            return Err(e);
        }

        // Start context managers (after bridge components are registered).
        // ServiceManager.start_stage(Start) iterates registered services and
        // writes Failed status on per-service bind errors with fault isolation.
        {
            let lifecycle = LifecycleCoordinator::new(&context, dns_runtime.as_ref());
            if let Err(e) = lifecycle.run_pass(LifecyclePass::StartCore).await {
                lifecycle.close_all(true).await;
                return Err(e);
            }
        }
        tracing::info!(target: "sb_core::runtime", "Context managers started");

        // Apply TLS certificate configuration (global trust augmentation)
        apply_tls_certificate_config(ir.certificate.as_ref());

        let health_enabled = context.runtime_options.services.health_enabled;
        let initial_state = State::new(engine_for_state, bridge, context, dns_runtime.clone(), ir);
        let state = Arc::new(RwLock::new(initial_state));

        // Start inbound listeners
        let (inbounds, endpoints, services, bridge_for_health) = {
            let state_guard = state.read().await;
            (
                state_guard.bridge.inbounds.clone(),
                state_guard.bridge.endpoints.clone(),
                state_guard.bridge.services.clone(),
                state_guard.bridge.clone(),
            )
        };

        let inbound_monitors = match start_inbounds_until_ready(&bridge_for_health, "startup").await
        {
            Ok(monitors) => monitors,
            Err(e) => {
                tracing::error!(target: "sb_core::runtime", error = %e, "inbound startup failed, rolling back");
                stop_endpoints(&endpoints);
                stop_services(&services);
                let (context, dns_runtime) = {
                    let state_guard = state.read().await;
                    (state_guard.context.clone(), state_guard.dns_runtime.clone())
                };
                LifecycleCoordinator::new(&context, dns_runtime.as_ref())
                    .close_all(true)
                    .await;
                return Err(e);
            }
        };

        // The coordinator has already driven Initialize and core Start. The
        // free-standing start_endpoints/start_services helpers are intentionally
        // NOT invoked here; using them would create a second lifecycle driver
        // that bypasses ServiceManager.statuses, recreating the LC-003
        // misreporting bug.

        // PostStart stage for context managers (after all inbounds/endpoints/services started)
        {
            let (context, dns_runtime) = {
                let state_guard = state.read().await;
                (state_guard.context.clone(), state_guard.dns_runtime.clone())
            };
            let lifecycle = LifecycleCoordinator::new(&context, dns_runtime.as_ref());
            if let Err(e) = lifecycle.run_pass(LifecyclePass::StartEdge).await {
                tracing::error!(target: "sb_core::runtime", error = %e, "Start edge failed, rolling back");
                shutdown_inbounds_and_monitors(&inbounds, inbound_monitors, "startup-rollback")
                    .await;
                stop_endpoints(&endpoints);
                stop_services(&services);
                lifecycle.close_all(true).await;
                return Err(e);
            }
            if let Err(e) = lifecycle.run_pass(LifecyclePass::PostStart).await {
                tracing::error!(target: "sb_core::runtime", error = %e, "PostStart failed, rolling back");
                shutdown_inbounds_and_monitors(&inbounds, inbound_monitors, "startup-rollback")
                    .await;
                stop_endpoints(&endpoints);
                stop_services(&services);
                lifecycle.close_all(true).await;
                return Err(e);
            }
            if let Err(e) = lifecycle.run_pass(LifecyclePass::Started).await {
                tracing::error!(target: "sb_core::runtime", error = %e, "Started stage failed, rolling back");
                shutdown_inbounds_and_monitors(&inbounds, inbound_monitors, "startup-rollback")
                    .await;
                stop_endpoints(&endpoints);
                stop_services(&services);
                lifecycle.close_all(true).await;
                return Err(e);
            }
            tracing::debug!(target: "sb_core::runtime", "Context managers post-start complete");
            let state_guard = state.read().await;
            crate::adapter::bridge::publish_runtime_registries(&state_guard.bridge);
            publish_runtime_dns(state_guard.dns_runtime.as_ref());
        }

        state.write().await.inbound_monitors = inbound_monitors;

        // Optional health task
        if health_enabled {
            let health_bridge = bridge_for_health.clone();
            let tok = cancel.clone();
            let health_handle = tokio::spawn(async move {
                spawn_health_task_async(health_bridge, tok).await;
            });
            state.write().await.health = Some(health_handle);
        }
        #[cfg(feature = "service_ntp")]
        {
            let ntp_cfg = { state.read().await.current_ir.ntp.clone() };
            install_ntp_task(&state, ntp_cfg).await;
        }

        let state_clone = Arc::clone(&state);

        // Event loop
        let cancel_ev = cancel.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    ReloadMsg::Apply { ir: new_ir, result } => {
                        let outcome = Self::handle_reload(&state_clone, *new_ir).await;
                        if let Err(e) = &outcome {
                            tracing::error!(target: "sb_core::runtime", error = %e, "reload failed");
                        } else {
                            state_clone.write().await.provider_overlay =
                                ProviderOverlayState::default();
                        }
                        if let Some(tx) = result {
                            let _ = tx.send(outcome.map_err(|e| e.to_string()));
                        }
                    }
                    ReloadMsg::UpdateProviders {
                        outbounds,
                        rules,
                        provider_name,
                    } => {
                        let (merged_ir, overlay) = Self::merge_provider_updates(
                            &state_clone,
                            outbounds,
                            rules,
                            &provider_name,
                        )
                        .await;
                        if let Err(e) = Self::handle_reload(&state_clone, merged_ir).await {
                            tracing::error!(target: "sb_core::runtime", error = %e, "provider reload failed for '{}'", provider_name);
                        } else {
                            state_clone.write().await.provider_overlay = overlay;
                        }
                    }
                    ReloadMsg::Shutdown { deadline } => {
                        cancel_ev.cancel();
                        Self::handle_shutdown(&state_clone, deadline).await;
                        break;
                    }
                }
            }
        });

        Ok(Self {
            tx,
            handle,
            state,
            cancel,
        })
    }

    /// Get a handle to this supervisor for operations that don't require ownership
    pub fn handle(&self) -> SupervisorHandle {
        SupervisorHandle {
            tx: self.tx.clone(),
            state: Arc::clone(&self.state),
            cancel: self.cancel.clone(),
        }
    }

    /// Trigger hot reload with new configuration
    pub async fn reload(&self, new_ir: sb_config::ir::ConfigIR) -> Result<Diff> {
        // Extract old IR from current state before applying new config
        let old_ir = {
            let state_guard = self.state.read().await;
            state_guard.current_ir.clone()
        };

        let runtime_diff = {
            let state_guard = self.state.read().await;
            state_guard.context.runtime_options.services.runtime_diff
        };
        let diff = if runtime_diff {
            let diff = sb_config::ir::diff::diff(&old_ir, &new_ir);
            tracing::debug!(
                target: "sb_core::runtime",
                added_inbounds = diff.inbounds.added.len(),
                removed_inbounds = diff.inbounds.removed.len(),
                added_outbounds = diff.outbounds.added.len(),
                removed_outbounds = diff.outbounds.removed.len(),
                "Configuration diff computed"
            );
            diff
        } else {
            let _ = &new_ir;
            Diff::default()
        };

        let (result_tx, result_rx) = oneshot::channel();
        self.tx
            .send(ReloadMsg::Apply {
                ir: Box::new(new_ir),
                result: Some(result_tx),
            })
            .await
            .context("failed to send reload message")?;

        result_rx
            .await
            .context("reload result channel closed before completion")?
            .map_err(anyhow::Error::msg)?;

        Ok(diff)
    }

    /// Begin graceful shutdown
    pub async fn shutdown_graceful(self, dur: Duration) -> Result<()> {
        let deadline = Instant::now() + dur;

        self.tx
            .send(ReloadMsg::Shutdown { deadline })
            .await
            .context("failed to send shutdown message")?;

        self.cancel.cancel();

        // Wait for event loop to finish
        if let Err(e) = self.handle.await {
            tracing::error!(target: "sb_core::runtime", error = %e, "supervisor task join failed");
        }

        Ok(())
    }

    /// Get read-only access to current state
    pub async fn state(&self) -> Arc<RwLock<State>> {
        Arc::clone(&self.state)
    }

    // Internal: handle reload in event loop

    async fn handle_reload(
        state: &Arc<RwLock<State>>,
        new_ir: sb_config::ir::ConfigIR,
    ) -> Result<()> {
        // Configure logging
        if let Some(log_ir) = &new_ir.log {
            crate::log::configure(log_ir);
        }

        let (
            old_inbounds,
            old_endpoints,
            old_services,
            old_context,
            old_dns_runtime,
            old_v2ray_cfg,
            old_ir,
        ) = {
            let state_guard = state.read().await;
            (
                state_guard.bridge.inbounds.clone(),
                state_guard.bridge.endpoints.clone(),
                state_guard.bridge.services.clone(),
                state_guard.context.clone(),
                state_guard.dns_runtime.clone(),
                state_guard
                    .current_ir
                    .experimental
                    .as_ref()
                    .and_then(|e| e.v2ray_api.clone()),
                state_guard.current_ir.clone(),
            )
        };

        reject_same_port_reload(&old_ir, &new_ir)?;

        // Build new engine and bridge
        let new_engine = Engine::from_ir(&new_ir).context("failed to build new engine")?;
        let new_engine_for_state = new_engine.clone();

        // APP-RELOAD-SIDECAR-ORDER-01C: reuse the old V2Ray server across an equivalent reload
        // (same enabled config + currently Running) instead of rebuilding/rebinding it.
        let inherited_v2ray = reusable_v2ray_server(
            old_v2ray_cfg.as_ref(),
            new_ir
                .experimental
                .as_ref()
                .and_then(|e| e.v2ray_api.as_ref()),
            old_context.v2ray_server.as_ref(),
        );
        let inherited_cache_file = reusable_cache_file(
            old_ir
                .experimental
                .as_ref()
                .and_then(|e| e.cache_file.as_ref()),
            new_ir
                .experimental
                .as_ref()
                .and_then(|e| e.cache_file.as_ref()),
            old_context.cache_file.as_ref(),
        );

        // Build new context from new IR (supports dynamic service reconfiguration)
        let new_context = build_context_from_ir_with_cache_and_options(
            &new_ir,
            inherited_v2ray,
            inherited_cache_file,
            old_context.runtime_options.clone(),
        )?;
        ensure_geo_assets(&new_ir).await;

        // APP-RELOAD-CONTEXT-CLEANUP-01B: every fallible pre-swap activation stage runs inside
        // this single transaction block so that ANY failure (current or future-added) funnels
        // into the one rollback branch below instead of leaking the new construction through a
        // bare `?` (fresh V2Ray listener, new inbound listeners, started endpoints/services —
        // see the 01A audit). The bridge is exported via `new_bridge_slot` so a failure after
        // bridge construction can still stop bridge-owned resources.
        let mut new_bridge_slot: Option<Arc<Bridge>> = None;
        let mut new_dns_runtime_slot: Option<RuntimeDns> = None;
        let mut new_inbound_monitors_slot: Option<Vec<InboundRuntimeMonitor>> = None;
        let activation_result: Result<(Arc<Bridge>, Option<RuntimeDns>, Vec<InboundRuntimeMonitor>)> = async {
            let new_dns_runtime =
                build_runtime_dns_from_ir(
                    &new_ir,
                    new_context.cache_file.clone(),
                    Arc::new(new_context.runtime_options.dns.clone()),
                )?;
            new_dns_runtime_slot = new_dns_runtime.clone();

            // Initialize new context managers
            let lifecycle = LifecycleCoordinator::new(&new_context, new_dns_runtime.as_ref());
            lifecycle.run_pass(LifecyclePass::Initialize).await?;
            tracing::debug!(target: "sb_core::runtime", "New context managers initialized on reload");

            // Build new bridge via adapter bridge
            let new_bridge = crate::adapter::bridge::build_bridge_async(
                &new_ir,
                new_engine.clone(),
                new_context.clone(),
            )
            .await;
            ensure_bridge_startup_ready(&new_bridge)?;

            // Wrap in Arc and register components BEFORE Start stage. See LC-003
            // lifecycle fix in initial-start path for rationale.
            let new_bridge_arc = Arc::new(new_bridge);
            new_bridge_slot = Some(new_bridge_arc.clone());
            populate_bridge_managers(&new_context, &new_bridge_arc).await?;

            // Start new context managers (drives Start stage on registered services)
            let lifecycle = LifecycleCoordinator::new(&new_context, new_dns_runtime.as_ref());
            lifecycle.run_pass(LifecyclePass::StartCore).await?;
            tracing::info!(target: "sb_core::runtime", "New context managers started on reload");

            // Refresh global TLS trust configuration from IR
            apply_tls_certificate_config(new_ir.certificate.as_ref());

            let new_inbound_monitors = start_inbounds_until_ready(&new_bridge_arc, "reload").await?;
            new_inbound_monitors_slot = Some(new_inbound_monitors);
            // Endpoints/services already driven through Start above; do not invoke
            // start_endpoints/start_services here (would re-trigger lifecycle and
            // bypass ServiceManager.statuses).

            // PostStart stage for new managers
            let lifecycle = LifecycleCoordinator::new(&new_context, new_dns_runtime.as_ref());
            lifecycle.run_pass(LifecyclePass::StartEdge).await?;
            lifecycle.run_pass(LifecyclePass::PostStart).await?;
            lifecycle.run_pass(LifecyclePass::Started).await?;
            tracing::debug!(target: "sb_core::runtime", "New context managers post-start complete on reload");

            let new_inbound_monitors = new_inbound_monitors_slot
                .take()
                .expect("reload inbound monitors present after readiness");
            Ok((new_bridge_arc, new_dns_runtime, new_inbound_monitors))
        }
        .await;

        let (new_bridge_arc, new_dns_runtime, new_inbound_monitors) = match activation_result {
            Ok((bridge, dns_runtime, monitors)) => (bridge, dns_runtime, monitors),
            Err(error) => {
                tracing::error!(target: "sb_core::runtime", error = %error, "reload activation failed before swap, rolling back new construction");
                let (new_inbounds, new_endpoints, new_services) = new_bridge_slot
                    .as_deref()
                    .map(|b| (&b.inbounds[..], &b.endpoints[..], &b.services[..]))
                    .unwrap_or((&[], &[], &[]));
                if let Some(monitors) = new_inbound_monitors_slot.take() {
                    shutdown_inbounds_and_monitors(new_inbounds, monitors, "reload-rollback").await;
                }
                shutdown_failed_reload_context_lifecycle(
                    &old_context,
                    &new_context,
                    new_dns_runtime_slot.as_ref(),
                    &[],
                    new_endpoints,
                    new_services,
                )
                .await;
                return Err(error);
            }
        };

        // APP-RELOAD-SIDECAR-ORDER-01C: compute the reuse-exclusion flag while BOTH contexts are
        // in scope; the new context is moved into state at the swap below.
        let preserve_v2ray = same_v2ray_server(&old_context, &new_context);

        // Update state atomically
        let old_inbound_monitors = {
            let mut state_guard = state.write().await;

            // Stop old health task if any
            if let Some(old_health) = state_guard.health.take() {
                old_health.abort();
            }
            #[cfg(feature = "service_ntp")]
            if let Some(old_ntp) = state_guard.ntp.take() {
                old_ntp.abort();
            }
            #[cfg(feature = "service_ntp")]
            {
                if let Some(h) = state_guard.ntp.take() {
                    h.abort();
                }
            }

            // Replace engine, bridge, context, and current IR
            state_guard.engine = new_engine_for_state;
            state_guard.bridge = new_bridge_arc;
            state_guard.context = new_context;
            state_guard.dns_runtime = new_dns_runtime;
            state_guard.current_ir = new_ir;
            let old_inbound_monitors =
                std::mem::replace(&mut state_guard.inbound_monitors, new_inbound_monitors);
            crate::adapter::bridge::publish_runtime_registries(&state_guard.bridge);
            publish_runtime_dns(state_guard.dns_runtime.as_ref());
            // Start new health task if needed
            if state_guard.context.runtime_options.services.health_enabled {
                let health_bridge = state_guard.bridge.clone();
                let health_cancel = CancellationToken::new();
                let health_handle = tokio::spawn(async move {
                    spawn_health_task_async(health_bridge, health_cancel).await;
                });
                state_guard.health = Some(health_handle);
            }
            old_inbound_monitors
        };

        #[cfg(feature = "service_ntp")]
        {
            let ntp_cfg = { state.read().await.current_ir.ntp.clone() };
            install_ntp_task(state, ntp_cfg).await;
        }

        shutdown_inbounds_and_monitors(&old_inbounds, old_inbound_monitors, "reload-replaced")
            .await;
        stop_endpoints(&old_endpoints);
        stop_services(&old_services);
        LifecycleCoordinator::new(&old_context, old_dns_runtime.as_ref())
            .close_all(!preserve_v2ray)
            .await;

        tracing::info!(target: "sb_core::runtime", "configuration reloaded successfully");

        Ok(())
    }

    async fn merge_provider_updates(
        state: &Arc<RwLock<State>>,
        outbounds: Vec<sb_config::ir::OutboundIR>,
        rules: Vec<String>,
        provider_name: &str,
    ) -> (sb_config::ir::ConfigIR, ProviderOverlayState) {
        let state_guard = state.read().await;
        let mut ir = state_guard.current_ir.clone();
        let mut overlay = state_guard.provider_overlay.clone();
        drop(state_guard);

        let ob_count = outbounds.len();
        let rule_count = rules.len();
        let previous_outbounds = overlay
            .outbounds_by_provider
            .remove(provider_name)
            .unwrap_or_default();
        let previous_rules = overlay
            .rules_by_provider
            .remove(provider_name)
            .unwrap_or_default();

        if !previous_outbounds.is_empty() {
            ir.outbounds.retain(|existing| {
                existing
                    .name
                    .as_deref()
                    .is_none_or(|name| !previous_outbounds.iter().any(|prev| prev == name))
            });
        }
        if !previous_rules.is_empty() {
            ir.route
                .rules
                .retain(|existing| !previous_rules.iter().any(|prev| prev == existing));
        }

        let mut injected_outbound_names = Vec::new();
        for new_ob in outbounds {
            let name = new_ob.name.as_deref().unwrap_or("");
            if !name.is_empty() {
                ir.outbounds
                    .retain(|existing| existing.name.as_deref() != Some(name));
                injected_outbound_names.push(name.to_string());
            }
            ir.outbounds.push(new_ob);
        }

        let mut injected_rules = Vec::new();
        for rule_str in &rules {
            if let Some(rule_ir) = parse_simple_rule(rule_str) {
                injected_rules.push(rule_ir.clone());
                ir.route.rules.push(rule_ir);
            } else {
                tracing::warn!(
                    target: "sb_core::runtime",
                    "provider '{}': skipping unrecognized rule: {}",
                    provider_name,
                    rule_str
                );
            }
        }

        tracing::info!(
            target: "sb_core::runtime",
            "provider '{}': merged {} outbounds and {} rules",
            provider_name,
            ob_count,
            rule_count
        );

        overlay
            .outbounds_by_provider
            .insert(provider_name.to_string(), injected_outbound_names);
        overlay
            .rules_by_provider
            .insert(provider_name.to_string(), injected_rules);

        (ir, overlay)
    }

    // Internal: handle graceful shutdown
    async fn handle_shutdown(state: &Arc<RwLock<State>>, deadline: Instant) {
        let start_shutdown = Instant::now();

        // Stop accepting new connections (best-effort) and mark committed monitors as deliberate.
        let (inbounds, inbound_monitors) = {
            let mut state_guard = state.write().await;
            (
                state_guard.bridge.inbounds.clone(),
                std::mem::take(&mut state_guard.inbound_monitors),
            )
        };
        for monitor in &inbound_monitors {
            monitor.shutdown_requested.store(true, Ordering::SeqCst);
        }
        for inbound in &inbounds {
            if let Err(error) = inbound.close() {
                tracing::warn!(%error, tag = %inbound.tag(), "canonical inbound close failed");
            }
        }
        tracing::warn!(
            target: "sb_core::runtime",
            deadline_ms = deadline.saturating_duration_since(start_shutdown).as_millis() as u64,
            "beginning graceful shutdown"
        );

        // Wait for active connections to finish or timeout
        let wait_start = Instant::now();
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }

            // Aggregate active connection counts from inbounds that expose it
            let active_total: u64 = {
                let guard = state.read().await;
                guard
                    .bridge
                    .inbounds
                    .iter()
                    .filter_map(|ib| ib.active_connections())
                    .sum()
            };

            if active_total == 0 {
                tracing::info!(target: "sb_core::runtime", "all inbound connections drained");
                break;
            }

            // Sleep a bit and re-check
            tokio::time::sleep(Duration::from_millis(100)).await;

            // Safety valve: don't wait extremely short -- allow minimal drain window
            if now.duration_since(wait_start) > Duration::from_millis(500) && active_total == 0 {
                break;
            }
        }

        let wait_ms = Instant::now()
            .saturating_duration_since(wait_start)
            .as_millis();
        let shutdown_success = Instant::now() < deadline;

        let (endpoints, services, ctx, dns_runtime) = {
            let guard = state.read().await;
            (
                guard.bridge.endpoints.clone(),
                guard.bridge.services.clone(),
                guard.context.clone(),
                guard.dns_runtime.clone(),
            )
        };

        // Cleanup state
        {
            let mut state_guard = state.write().await;
            if let Some(health) = state_guard.health.take() {
                health.abort();
            }
            #[cfg(feature = "service_ntp")]
            if let Some(ntp) = state_guard.ntp.take() {
                ntp.abort();
            }
        }

        stop_endpoints(&endpoints);
        stop_services(&services);
        LifecycleCoordinator::new(&ctx, dns_runtime.as_ref())
            .close_all(true)
            .await;
        drain_inbound_monitors(inbound_monitors, "shutdown").await;

        // Log shutdown completion
        let shutdown_json = serde_json::json!({
            "event": "shutdown",
            "ok": shutdown_success,
            "wait_ms": wait_ms,
            "fingerprint": env!("CARGO_PKG_VERSION")
        });

        if let Ok(s) = serde_json::to_string(&shutdown_json) {
            tracing::info!(target: "sb_core::runtime", event = %s, "shutdown summary");
        } else {
            tracing::info!(target: "sb_core::runtime", ok = shutdown_success, wait_ms = wait_ms as u64, "shutdown completed");
        }
    }
}

impl SupervisorHandle {
    pub fn reload_sender(&self) -> mpsc::Sender<ReloadMsg> {
        self.tx.clone()
    }

    /// Begin graceful shutdown via handle (doesn't require ownership)
    pub async fn shutdown_graceful(&self, dur: Duration) -> Result<()> {
        let _ = &self.cancel;
        let deadline = Instant::now() + dur;

        self.tx
            .send(ReloadMsg::Shutdown { deadline })
            .await
            .context("failed to send shutdown message")?;

        Ok(())
    }

    /// Trigger hot reload with new configuration via handle
    pub async fn reload(&self, new_ir: sb_config::ir::ConfigIR) -> Result<Diff> {
        // Touch cancel to avoid unused-field warnings
        let _ = &self.cancel;

        // Extract old IR from current state before applying new config
        let old_ir = {
            let state_guard = self.state.read().await;
            state_guard.current_ir.clone()
        };

        let runtime_diff = {
            let state_guard = self.state.read().await;
            state_guard.context.runtime_options.services.runtime_diff
        };
        let diff = if runtime_diff {
            sb_config::ir::diff::diff(&old_ir, &new_ir)
        } else {
            let _ = &new_ir;
            Diff::default()
        };

        let (result_tx, result_rx) = oneshot::channel();
        self.tx
            .send(ReloadMsg::Apply {
                ir: Box::new(new_ir),
                result: Some(result_tx),
            })
            .await
            .context("failed to send reload message")?;

        result_rx
            .await
            .context("reload result channel closed before completion")?
            .map_err(anyhow::Error::msg)?;

        Ok(diff)
    }

    /// Get read-only access to current state
    pub async fn state(&self) -> Arc<RwLock<State>> {
        let _ = &self.cancel;
        Arc::clone(&self.state)
    }
}

// Helper functions for supervisor

/// Parse a simple rule string (e.g. "DOMAIN,example.com") into a RuleIR.
///
/// Supported formats:
/// - `DOMAIN,value` -> domain exact match
/// - `DOMAIN-SUFFIX,value` -> domain suffix match
/// - `DOMAIN-KEYWORD,value` -> domain keyword match
/// - `IP-CIDR,value` -> source IP CIDR match
/// - `GEOIP,value` -> GeoIP match
/// - `GEOSITE,value` -> treated as domain keyword (best-effort)
///
/// All parsed rules get `outbound: "direct"` as default (providers
/// typically supply the outbound context separately).
fn parse_simple_rule(rule_str: &str) -> Option<sb_config::ir::RuleIR> {
    let rule_str = rule_str.trim();
    if rule_str.is_empty() || rule_str.starts_with('#') {
        return None;
    }

    let (rule_type, value) = rule_str.split_once(',')?;
    let value = value.trim().to_string();
    if value.is_empty() {
        return None;
    }

    let mut rule = sb_config::ir::RuleIR {
        outbound: Some("direct".to_string()),
        ..Default::default()
    };

    match rule_type.trim().to_uppercase().as_str() {
        "DOMAIN" => rule.domain = vec![value],
        "DOMAIN-SUFFIX" => rule.domain_suffix = vec![value],
        "DOMAIN-KEYWORD" => rule.domain_keyword = vec![value],
        "IP-CIDR" | "IP-CIDR6" => rule.ipcidr = vec![value],
        "GEOIP" => rule.geoip = vec![value],
        "GEOSITE" => rule.geosite = vec![value],
        _ => return None,
    }

    Some(rule)
}

/// Placeholder async health task spawning function
pub async fn spawn_health_task_async(bridge: Arc<Bridge>, cancel: CancellationToken) {
    // Placeholder for async health checking
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
            // Perform health checks
            tracing::debug!(
                target: "sb_core::runtime",
                outbounds = bridge.outbounds_snapshot().len(),
                "health check completed"
            );
        }
    })
    .await
    .ok();
}

fn has_async_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

fn inbound_runtime_label(
    bridge: &Bridge,
    index: usize,
    phase: &'static str,
) -> InboundRuntimeLabel {
    let kind = bridge
        .inbound_kinds
        .get(index)
        .filter(|kind| !kind.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let tag = bridge
        .inbound_tags
        .get(index)
        .and_then(|tag| tag.as_ref())
        .filter(|tag| !tag.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| format!("{kind}#{index}"));
    InboundRuntimeLabel { tag, kind, phase }
}

async fn drain_inbound_monitors(monitors: Vec<InboundRuntimeMonitor>, reason: &'static str) {
    for monitor in monitors {
        let label = monitor.label.clone();
        let mut join = monitor.join;
        tokio::select! {
            result = &mut join => {
                if let Err(error) = result {
                    tracing::warn!(
                        target: "sb_core::runtime",
                        component = "inbound",
                        tag = %label.tag,
                        kind = %label.kind,
                        phase = label.phase,
                        reason,
                        error = %error,
                        "inbound runtime monitor join failed"
                    );
                }
            }
            () = tokio::time::sleep(INBOUND_MONITOR_DRAIN_TIMEOUT) => {
                join.abort();
                let _ = join.await;
                tracing::warn!(
                    target: "sb_core::runtime",
                    component = "inbound",
                    tag = %label.tag,
                    kind = %label.kind,
                    phase = label.phase,
                    reason,
                    timeout_ms = INBOUND_MONITOR_DRAIN_TIMEOUT.as_millis() as u64,
                    "inbound runtime monitor drain timed out"
                );
            }
        }
    }
}

async fn shutdown_inbounds_and_monitors(
    inbounds: &[Arc<dyn sb_types::Inbound>],
    monitors: Vec<InboundRuntimeMonitor>,
    reason: &'static str,
) {
    for monitor in &monitors {
        monitor.shutdown_requested.store(true, Ordering::SeqCst);
    }
    for inbound in inbounds {
        if let Err(error) = inbound.close() {
            tracing::warn!(%error, reason, tag = %inbound.tag(), "canonical inbound close failed");
        }
    }
    drain_inbound_monitors(monitors, reason).await;
}

async fn start_inbounds_until_ready(
    bridge: &Bridge,
    phase: &'static str,
) -> Result<Vec<InboundRuntimeMonitor>> {
    let monitors = Vec::new();
    for (index, inbound) in bridge.inbounds.iter().enumerate() {
        let label = inbound_runtime_label(bridge, index, phase);
        if !inbound.supports_startup_readiness() {
            tracing::warn!(
                target: "sb_core::runtime",
                phase,
                tag = %label.tag,
                kind = %label.kind,
                "inbound does not expose bind readiness; starting best-effort"
            );
        }
        let ib = inbound.clone();
        let started = tokio::time::timeout(
            INBOUND_READY_TIMEOUT,
            tokio::task::spawn_blocking(move || ib.start(sb_types::StartStage::Start)),
        )
        .await;
        match started {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                shutdown_inbounds_and_monitors(&bridge.inbounds, monitors, "readiness-failed")
                    .await;
                return Err(anyhow::anyhow!("{phase} inbound readiness failed: {error}"));
            }
            Ok(Err(error)) => {
                shutdown_inbounds_and_monitors(&bridge.inbounds, monitors, "readiness-join").await;
                return Err(anyhow::anyhow!(
                    "{phase} inbound start task failed: {error}"
                ));
            }
            Err(_) => {
                shutdown_inbounds_and_monitors(&bridge.inbounds, monitors, "readiness-timeout")
                    .await;
                return Err(anyhow::anyhow!(
                    "{phase} inbound readiness timed out after {:?}",
                    INBOUND_READY_TIMEOUT
                ));
            }
        }
    }
    Ok(monitors)
}

fn inbound_endpoint_key(ib: &sb_config::ir::InboundIR) -> Option<(String, u16)> {
    if ib.port == 0 {
        return None;
    }
    let listen = ib.listen.trim();
    if listen.is_empty() {
        return None;
    }
    Some((listen.to_string(), ib.port))
}

fn inbound_endpoints_overlap(left: &(String, u16), right: &(String, u16)) -> bool {
    if left.1 != right.1 {
        return false;
    }
    if left.0.eq_ignore_ascii_case(&right.0) {
        return true;
    }
    match (left.0.parse::<IpAddr>(), right.0.parse::<IpAddr>()) {
        (Ok(left_ip), Ok(right_ip)) => {
            left_ip == right_ip || left_ip.is_unspecified() || right_ip.is_unspecified()
        }
        _ => false,
    }
}

fn inbound_label(ib: &sb_config::ir::InboundIR) -> String {
    ib.tag
        .as_deref()
        .filter(|tag| !tag.trim().is_empty())
        .unwrap_or_else(|| ib.ty.ty_str())
        .to_string()
}

fn reject_same_port_reload(
    old_ir: &sb_config::ir::ConfigIR,
    new_ir: &sb_config::ir::ConfigIR,
) -> Result<()> {
    let mut old_endpoints: Vec<((String, u16), String)> = Vec::new();
    for inbound in &old_ir.inbounds {
        if let Some(endpoint) = inbound_endpoint_key(inbound) {
            old_endpoints.push((endpoint, inbound_label(inbound)));
        }
    }

    for inbound in &new_ir.inbounds {
        let Some(new_endpoint) = inbound_endpoint_key(inbound) else {
            continue;
        };
        let (listen, port) = (&new_endpoint.0, new_endpoint.1);
        if let Some((old_endpoint, old_label)) = old_endpoints
            .iter()
            .find(|(old_endpoint, _)| inbound_endpoints_overlap(old_endpoint, &new_endpoint))
        {
            let new_label = inbound_label(inbound);
            let (old_listen, old_port) = old_endpoint;
            return Err(anyhow::anyhow!(
                "same-port in-process reload is unsupported for inbound '{new_label}' at {listen}:{port} (overlaps old inbound '{old_label}' at {old_listen}:{old_port}); use GUI/process restart or change the listen endpoint"
            ));
        }
    }

    Ok(())
}

fn wire_experimental_sidecars(
    mut context: Context,
    ir: &sb_config::ir::ConfigIR,
    inherited_v2ray_server: Option<Arc<dyn ManagedApiServer>>,
    inherited_cache_file: Option<Arc<dyn crate::context::CacheFile>>,
) -> Result<Context> {
    if let Some(exp) = &ir.experimental {
        if let Some(cache_cfg) = &exp.cache_file {
            if cache_cfg.enabled {
                if let Some(cache_svc) = inherited_cache_file {
                    restore_clash_mode_from_cache(cache_svc.as_ref());
                    context = context.with_cache_file(cache_svc);
                    tracing::info!(target: "sb_core::runtime", path = ?cache_cfg.path, "cache file service reused across equivalent reload");
                } else {
                    let cache_svc = Arc::new(
                        crate::services::cache_file::CacheFileService::try_new(cache_cfg)
                            .with_context(|| {
                                format!(
                                    "failed to initialize cache file service at {:?}",
                                    cache_cfg.path
                                )
                            })?,
                    );
                    restore_clash_mode_from_cache(cache_svc.as_ref());
                    context = context.with_cache_file(cache_svc);
                    tracing::info!(target: "sb_core::runtime", path = ?cache_cfg.path, "cache file service wired");
                }
            }
        }

        if let Some(v2ray_cfg) = &exp.v2ray_api {
            if let Some(inherited) = inherited_v2ray_server {
                // APP-RELOAD-SIDECAR-ORDER-01C: an equivalent reload reuses the still-Running
                // server instead of rebuilding/rebinding it. No new listener is bound (so the
                // same-address rebind that would EADDRINUSE-collide with the still-alive old
                // listener never happens), and the StatsManager identity is preserved. The old
                // context's teardown excludes this shared Arc (see shutdown_replaced_context).
                context = context.with_v2ray_server(inherited);
                tracing::info!(target: "sb_core::runtime", listen = ?v2ray_cfg.listen, "V2Ray API server reused across equivalent reload (no rebind)");
            } else {
                let Some(v2ray_server) = crate::service::build_v2ray_server(v2ray_cfg.clone())
                else {
                    tracing::warn!(target: "sb_core::runtime", "V2Ray API requested but no control-plane factory is registered");
                    return Ok(context);
                };
                if let Err(e) = v2ray_server.start() {
                    tracing::warn!(target: "sb_core::runtime", error = %e, "failed to start V2Ray API server");
                } else {
                    context = context.with_v2ray_server(v2ray_server);
                    tracing::info!(target: "sb_core::runtime", listen = ?v2ray_cfg.listen, "V2Ray API server wired");
                }
            }
        }
    }

    Ok(context)
}

fn restore_clash_mode_from_cache(cache: &dyn crate::context::CacheFile) {
    let Some(mode) = cache.get_clash_mode() else {
        return;
    };
    match mode.parse() {
        Ok(mode) => crate::adapter::clash::set_mode(mode),
        Err(error) => {
            tracing::warn!(
                target: "sb_core::runtime",
                mode = %mode,
                error = %error,
                "ignoring invalid persisted Clash mode; keeping current default"
            );
        }
    }
}

/// Decide whether the old V2Ray API server can be carried into the new context unchanged
/// instead of rebuilt+rebound (APP-RELOAD-SIDECAR-ORDER-01C reuse handoff).
///
/// Returns `Some(Arc::clone(old))` iff ALL hold:
/// - old config enabled (`old_v2ray` is `Some`) AND new config enabled (`new_v2ray` is `Some`);
/// - the two `V2RayApiIR`s are structurally equal (covers `listen` AND `stats`; for `listen =
///   ":0"` this compares the *config* string, never the resolved ephemeral port, so reuse keeps
///   the already-bound port);
/// - the old context actually holds a server, and that server is a real, introspectable
///   implementation (`subscribe_runtime_state()` returns `Some` — the trait default returns
///   `None`);
/// - the old server's latest runtime snapshot has a `current` generation in phase `Running`
///   (NOT `ShutdownRequested`, NOT exited/`None`).
///
/// Otherwise returns `None`, leaving the existing rebuild path intact. Never infers reusability
/// from `last_exit`. Reads the snapshot via a non-blocking `watch::Receiver::borrow()` (no await).
fn reusable_v2ray_server(
    old_v2ray: Option<&sb_config::ir::V2RayApiIR>,
    new_v2ray: Option<&sb_config::ir::V2RayApiIR>,
    old_server: Option<&Arc<dyn ManagedApiServer>>,
) -> Option<Arc<dyn ManagedApiServer>> {
    let old_cfg = old_v2ray?;
    let new_cfg = new_v2ray?;
    if old_cfg != new_cfg {
        tracing::debug!(target: "sb_core::runtime", "V2Ray reload: config changed, rebuilding (no reuse)");
        return None;
    }
    let server = old_server?;
    let rx = server.subscribe_runtime_state()?;
    let is_running = matches!(
        rx.borrow().current.as_ref().map(|g| &g.phase),
        Some(ManagedApiActivePhase::Running)
    );
    if !is_running {
        tracing::debug!(target: "sb_core::runtime", "V2Ray reload: old server not Running, rebuilding (no reuse)");
        return None;
    }
    tracing::debug!(target: "sb_core::runtime", listen = ?new_cfg.listen, "V2Ray reload: reusing Running server across equivalent config");
    Some(Arc::clone(server))
}

fn reusable_cache_file(
    old_cache: Option<&sb_config::ir::CacheFileIR>,
    new_cache: Option<&sb_config::ir::CacheFileIR>,
    old_service: Option<&Arc<dyn crate::context::CacheFile>>,
) -> Option<Arc<dyn crate::context::CacheFile>> {
    let old_cfg = old_cache?;
    let new_cfg = new_cache?;
    if !old_cfg.enabled || !new_cfg.enabled || old_cfg != new_cfg {
        return None;
    }
    old_service.cloned()
}

/// True iff both contexts hold the SAME `ManagedApiServer` instance (i.e. the server was reused across
/// a reload). Used to decide whether the old context's teardown must skip closing it.
fn same_v2ray_server(a: &Context, b: &Context) -> bool {
    match (a.v2ray_server.as_ref(), b.v2ray_server.as_ref()) {
        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
        _ => false,
    }
}

fn build_context_from_ir(
    ir: &sb_config::ir::ConfigIR,
    inherited_v2ray_server: Option<Arc<dyn ManagedApiServer>>,
) -> Result<Context> {
    build_context_from_ir_with_options(
        ir,
        inherited_v2ray_server,
        Arc::new(crate::runtime_options::CoreRuntimeOptions::default()),
    )
}

fn build_context_from_ir_with_options(
    ir: &sb_config::ir::ConfigIR,
    inherited_v2ray_server: Option<Arc<dyn ManagedApiServer>>,
    runtime_options: crate::runtime_options::SharedCoreRuntimeOptions,
) -> Result<Context> {
    build_context_from_ir_with_cache_and_options(ir, inherited_v2ray_server, None, runtime_options)
}

fn build_context_from_ir_with_cache(
    ir: &sb_config::ir::ConfigIR,
    inherited_v2ray_server: Option<Arc<dyn ManagedApiServer>>,
    inherited_cache_file: Option<Arc<dyn crate::context::CacheFile>>,
) -> Result<Context> {
    build_context_from_ir_with_cache_and_options(
        ir,
        inherited_v2ray_server,
        inherited_cache_file,
        Arc::new(crate::runtime_options::CoreRuntimeOptions::default()),
    )
}

fn build_context_from_ir_with_cache_and_options(
    ir: &sb_config::ir::ConfigIR,
    inherited_v2ray_server: Option<Arc<dyn ManagedApiServer>>,
    inherited_cache_file: Option<Arc<dyn crate::context::CacheFile>>,
    runtime_options: crate::runtime_options::SharedCoreRuntimeOptions,
) -> Result<Context> {
    let mut ctx = Context::with_runtime_options(runtime_options);
    ctx.network.apply_route_options(&ir.route);
    ctx = wire_experimental_sidecars(ctx, ir, inherited_v2ray_server, inherited_cache_file)?;
    log_geo_download_hints(ir);
    if let Some(p) = &ir.route.geoip_path {
        std::env::set_var("GEOIP_PATH", p);
    }
    if let Some(p) = &ir.route.geosite_path {
        std::env::set_var("GEOSITE_PATH", p);
    }
    #[cfg(feature = "service_ntp")]
    {
        if let Some(ntp_cfg) = &ir.ntp {
            if ntp_cfg.enabled {
                let marker = Arc::new(crate::services::ntp::NtpMarker::from(ntp_cfg));
                ctx = ctx.with_ntp_service(marker);
            }
        }
    }
    Ok(ctx)
}

fn log_geo_download_hints(ir: &sb_config::ir::ConfigIR) {
    if ir.route.geoip_download_url.is_some() || ir.route.geoip_download_detour.is_some() {
        tracing::info!(
            target: "sb_core::runtime",
            url = ?ir.route.geoip_download_url,
            detour = ?ir.route.geoip_download_detour,
            path = ?ir.route.geoip_path,
            "geoip download options detected (download not yet automated; ensure path is pre-seeded)"
        );
    }
    if ir.route.geosite_download_url.is_some() || ir.route.geosite_download_detour.is_some() {
        tracing::info!(
            target: "sb_core::runtime",
            url = ?ir.route.geosite_download_url,
            detour = ?ir.route.geosite_download_detour,
            path = ?ir.route.geosite_path,
            "geosite download options detected (download not yet automated; ensure path is pre-seeded)"
        );
    }
}

/// Best-effort GeoIP/Geosite fetcher (ignores detour for now).
async fn ensure_geo_assets(ir: &sb_config::ir::ConfigIR) {
    if let (Some(path), Some(url)) = (&ir.route.geoip_path, &ir.route.geoip_download_url) {
        if !Path::new(path).exists() {
            if let Err(e) = download_file(url, path).await {
                tracing::warn!(
                    target: "sb_core::runtime",
                    error = %e,
                    path = %path,
                    detour = ?ir.route.geoip_download_detour,
                    "geoip download failed"
                );
            } else {
                tracing::info!(target: "sb_core::runtime", path = %path, url = %url, "geoip downloaded");
            }
        }
    }
    if let (Some(path), Some(url)) = (&ir.route.geosite_path, &ir.route.geosite_download_url) {
        if !Path::new(path).exists() {
            if let Err(e) = download_file(url, path).await {
                tracing::warn!(
                    target: "sb_core::runtime",
                    error = %e,
                    path = %path,
                    detour = ?ir.route.geosite_download_detour,
                    "geosite download failed"
                );
            } else {
                tracing::info!(target: "sb_core::runtime", path = %path, url = %url, "geosite downloaded");
            }
        }
    }
}

async fn download_file(url: &str, path: &str) -> Result<()> {
    use sb_types::ports::http::HttpRequest;
    let req = HttpRequest::get(url, 30);
    let resp = crate::http_client::http_execute(req)
        .await
        .map_err(|e| anyhow::anyhow!("http client error: {}", e))?;
    if !resp.is_success() {
        anyhow::bail!("geo download HTTP error: status {}", resp.status);
    }
    let bytes = resp.body;

    if let Some(parent) = Path::new(path).parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("create geo download directory")?;
    }
    tokio::fs::write(path, &bytes)
        .await
        .context("write geo download file")?;
    Ok(())
}

/// Reload-only teardown of the replaced (old) context after a successful swap.
///
/// `preserve_v2ray` is true exactly when the new (now-committed) context shares the old context's
/// `Arc<dyn ManagedApiServer>` — i.e. the server was reused (APP-RELOAD-SIDECAR-ORDER-01C). In that
/// case the new context is the close owner, so this teardown must NOT close the shared server;
/// all other managers close as usual. The flag is computed via `same_v2ray_server` BEFORE the
/// swap, because the new context is moved into state at commit and is no longer reachable here.
#[cfg(test)]
fn shutdown_replaced_context(old_context: &Context, preserve_v2ray: bool) {
    shutdown_context_inner(old_context, !preserve_v2ray);
}

/// Pre-swap rollback for a FAILED reload (APP-RELOAD-CONTEXT-CLEANUP-01B).
///
/// When any activation stage of the new construction fails before the state swap, the old
/// context/bridge stay committed and keep running; this tears down only what the failed reload
/// freshly created:
/// - new inbounds: `request_shutdown` (the spawned serve task holds its own Arc, so dropping the
///   bridge alone never stops the accept loop or releases the listener);
/// - new endpoints/services: explicit `stop_endpoints`/`stop_services` (required because
///   `ServiceManager::close()` is a no-op and `shutdown_context_inner` alone would leave started
///   services running — independent defect noted in the 01A audit);
/// - the new context's sidecars/managers via `shutdown_context_inner`, closing the V2Ray server
///   ONLY when it is a fresh instance. An inherited server is the same `Arc` the old (still
///   active) context owns (APP-RELOAD-SIDECAR-ORDER-01C) and must keep serving, so it is
///   discriminated by pointer identity via `same_v2ray_server`. A `None` server (disabled or
///   bind-failed-and-skipped) makes the close flag a safe no-op.
///
/// Cleanup is best-effort and infallible: every stop/close helper logs failures internally and
/// returns `()`, so the caller's original reload error is always preserved unchanged.
#[cfg(test)]
fn shutdown_failed_reload_context(
    old_context: &Context,
    new_context: &Context,
    new_inbounds: &[Arc<dyn sb_types::Inbound>],
    new_endpoints: &[Arc<dyn Endpoint>],
    new_services: &[Arc<dyn Service>],
) {
    for ib in new_inbounds {
        let _ = ib.close();
    }
    stop_endpoints(new_endpoints);
    stop_services(new_services);
    shutdown_context_inner(new_context, !same_v2ray_server(old_context, new_context));
}

async fn shutdown_failed_reload_context_lifecycle(
    old_context: &Context,
    new_context: &Context,
    new_dns_runtime: Option<&RuntimeDns>,
    new_inbounds: &[Arc<dyn sb_types::Inbound>],
    new_endpoints: &[Arc<dyn Endpoint>],
    new_services: &[Arc<dyn Service>],
) {
    for ib in new_inbounds {
        let _ = ib.close();
    }
    stop_endpoints(new_endpoints);
    stop_services(new_services);
    LifecycleCoordinator::new(new_context, new_dns_runtime)
        .close_all(!same_v2ray_server(old_context, new_context))
        .await;
}

/// Tear down a context's sidecars and managers. The public entry used by startup-rollback and
/// graceful shutdown always closes the V2Ray server (`close_v2ray = true`); only the reload path
/// (via `shutdown_replaced_context`) may pass `false` to skip a reused server.
fn shutdown_context(ctx: &Context) {
    shutdown_context_inner(ctx, true);
}

fn shutdown_context_inner(ctx: &Context, close_v2ray: bool) {
    // Close sidecars

    if close_v2ray {
        if let Some(v2ray) = &ctx.v2ray_server {
            if let Err(e) = v2ray.close() {
                tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close V2Ray API server");
            }
        }
    }

    // Close managers (reverse order of start)
    if let Err(e) = ctx.service_manager.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close ServiceManager");
    }
    if let Err(e) = ctx.endpoint_manager.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close EndpointManager");
    }
    if let Err(e) = ctx.outbound_manager.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close OutboundManager");
    }
    if let Err(e) = ctx.inbound_manager.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close InboundManager");
    }
    if let Err(e) = ctx.platform.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close PlatformInterface");
    }
    if let Err(e) = ctx.task_monitor.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close TaskMonitor");
    }
    if let Err(e) = ctx.connections.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close ConnectionManager");
    }
    if let Err(e) = ctx.network.close() {
        tracing::warn!(target: "sb_core::runtime", error = %e, "failed to close NetworkManager");
    }
}

#[cfg(feature = "service_ntp")]
fn spawn_ntp_from_ir(ntp_cfg: Option<sb_config::ir::NtpIR>) -> Option<tokio::task::JoinHandle<()>> {
    let ntp_cfg = ntp_cfg?;
    if !ntp_cfg.enabled {
        return None;
    }
    let server = match (&ntp_cfg.server, ntp_cfg.server_port) {
        (Some(s), Some(p)) => format!("{s}:{p}"),
        (Some(s), None) => {
            if s.contains(':') {
                s.clone()
            } else {
                format!("{s}:123")
            }
        }
        (None, Some(p)) => format!("time.google.com:{p}"),
        (None, None) => crate::services::ntp::NtpConfig::default().server,
    };
    let interval = std::time::Duration::from_millis(ntp_cfg.interval_ms.unwrap_or(30 * 60 * 1000));
    let timeout = std::time::Duration::from_millis(ntp_cfg.timeout_ms.unwrap_or(1500));
    crate::services::ntp::NtpService::new(crate::services::ntp::NtpConfig {
        enabled: true,
        server,
        interval,
        timeout,
    })
    .spawn()
}

#[cfg(feature = "service_ntp")]
async fn install_ntp_task(state: &Arc<RwLock<State>>, cfg: Option<sb_config::ir::NtpIR>) {
    let ntp_marker = cfg.as_ref().filter(|c| c.enabled).map(|c| {
        Arc::new(crate::services::ntp::NtpMarker::from(c)) as Arc<dyn crate::context::NtpService>
    });
    let handle = spawn_ntp_from_ir(cfg);

    let mut guard = state.write().await;
    guard.ntp = handle;
    guard.context.ntp_service = ntp_marker;
}

/// Populate endpoint/service managers from the assembled bridge for parity with Go managers.
async fn populate_bridge_managers(ctx: &Context, bridge: &Bridge) -> Result<()> {
    // Note: Bridge maintains its own `inbounds` vector for legacy InboundTaskDriver types.
    // InboundManager now expects Arc<dyn InboundAdapter> with lifecycle support.
    // New inbound adapters should be registered via InboundManager.add_handler().
    // Legacy bridge inbounds start directly, not through InboundManager.

    // Register real bridge connectors into OutboundManager using the same
    // canonical objects owned by the bridge.  No TcpStream-shaped adapter is
    // inserted between the two registries.
    for (name, _kind, connector) in &bridge.outbounds {
        ctx.outbound_manager
            .add_adapter(name.clone(), connector.clone())
            .await;
    }

    // Register dependency edges
    for (tag, deps) in &bridge.outbound_deps {
        for dep in deps {
            ctx.outbound_manager.add_dependency(tag, dep).await;
        }
    }

    // Validate dependency topology (cycle detection)
    let all_tags: Vec<String> = bridge.outbounds.iter().map(|(n, _, _)| n.clone()).collect();
    if let Err(cycle_err) =
        crate::outbound::manager::validate_and_sort(&all_tags, &bridge.outbound_deps)
    {
        return Err(anyhow::anyhow!("outbound {}", cycle_err));
    }

    // Resolve default outbound (route.final/default -> first registered -> explicit error)
    let route_opts = ctx.network.route_options();
    let default_tag = route_opts
        .final_outbound
        .as_deref()
        .or(route_opts.default_outbound.as_deref());
    ctx.outbound_manager
        .resolve_default(default_tag)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    tracing::info!(
        target: "sb_core::runtime",
        "===== OUTBOUND READY CHECKPOINT ====="
    );

    // Register endpoints with EndpointManager
    for ep in &bridge.endpoints {
        ctx.endpoint_manager
            .add_endpoint(ep.tag().to_string(), ep.clone())
            .await;
    }

    // Register services with ServiceManager
    for svc in &bridge.services {
        ctx.service_manager
            .add_service(svc.tag().to_string(), svc.clone())
            .await;
    }

    tracing::info!(
        target: "sb_core::runtime",
        inbounds = bridge.inbounds.len(),
        outbounds = bridge.outbounds.len(),
        endpoints = bridge.endpoints.len(),
        services = bridge.services.len(),
        "Bridge components registered with context managers"
    );

    Ok(())
}

/// Start all endpoints through their lifecycle stages. Uses best-effort logging on failure.
pub(crate) fn start_endpoints(endpoints: &[Arc<dyn Endpoint>]) {
    if endpoints.is_empty() {
        return;
    }
    if !has_async_runtime() {
        tracing::warn!(
            target: "sb_core::runtime",
            count = endpoints.len(),
            "skipping endpoint start: no Tokio runtime available"
        );
        return;
    }

    for ep in endpoints {
        for stage in [
            EndpointStage::Initialize,
            EndpointStage::Start,
            EndpointStage::PostStart,
            EndpointStage::Started,
        ] {
            if let Err(e) = ep.start(stage) {
                tracing::warn!(
                    target: "sb_core::runtime",
                    endpoint = ep.endpoint_type(),
                    tag = ep.tag(),
                    ?stage,
                    error = %e,
                    "endpoint start failed"
                );
                break;
            }
        }
    }
}

/// Stop all endpoints (best-effort).
pub(crate) fn stop_endpoints(endpoints: &[Arc<dyn Endpoint>]) {
    for ep in endpoints {
        if let Err(e) = ep.close() {
            tracing::warn!(
                target: "sb_core::runtime",
                endpoint = ep.endpoint_type(),
                tag = ep.tag(),
                error = %e,
                "failed to stop endpoint"
            );
        }
    }
}

/// Start all background services through their lifecycle stages. Uses best-effort logging on failure.
pub(crate) fn start_services(services: &[Arc<dyn Service>]) {
    if services.is_empty() {
        return;
    }
    if !has_async_runtime() {
        tracing::warn!(
            target: "sb_core::runtime",
            count = services.len(),
            "skipping service start: no Tokio runtime available"
        );
        return;
    }

    for svc in services {
        for stage in [
            ServiceStage::Initialize,
            ServiceStage::Start,
            ServiceStage::PostStart,
            ServiceStage::Started,
        ] {
            if let Err(e) = svc.start(stage) {
                tracing::warn!(
                    target: "sb_core::runtime",
                    service = svc.service_type(),
                    tag = svc.tag(),
                    ?stage,
                    error = %e,
                    "service start failed"
                );
                break;
            }
        }
    }
}

/// Stop all background services (best-effort).
pub(crate) fn stop_services(services: &[Arc<dyn Service>]) {
    for svc in services {
        if let Err(e) = svc.close() {
            tracing::warn!(
                target: "sb_core::runtime",
                service = svc.service_type(),
                tag = svc.tag(),
                error = %e,
                "failed to stop service"
            );
        }
    }
}

impl Engine {
    /// Create engine from IR configuration
    pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Engine> {
        Ok(Engine::new(std::sync::Arc::new(ir.clone())))
    }
}

impl Bridge {
    /// Create bridge from IR configuration
    pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Self> {
        // This should use existing bridge construction logic
        // For now, create a minimal bridge
        Self::new_from_config(ir, crate::context::Context::new())
            .context("failed to create bridge from config")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    static SUPERVISOR_ADAPTER_REGISTRY_TEST_LOCK: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
        once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

    #[derive(Debug)]
    struct TestDirectOutbound;

    impl sb_types::Outbound for TestDirectOutbound {
        fn r#type(&self) -> &str {
            "direct"
        }

        fn tag(&self) -> sb_types::OutboundTag {
            sb_types::OutboundTag::new("direct")
        }

        fn network(&self) -> &[sb_types::NetworkKind] {
            &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
        }

        fn dial<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
            Box::pin(async { Err(sb_types::CoreError::policy("test direct outbound")) })
        }

        fn listen_packet<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
        {
            Box::pin(async { Err(sb_types::CoreError::policy("test direct outbound")) })
        }
    }

    fn build_test_direct_outbound(
        _param: &crate::adapter::OutboundParam,
        _ir: &sb_config::ir::OutboundIR,
        _ctx: &crate::adapter::registry::AdapterOutboundContext,
    ) -> Option<Arc<dyn sb_types::Outbound>> {
        Some(Arc::new(TestDirectOutbound))
    }

    fn test_registry_snapshot() -> crate::adapter::registry::RegistrySnapshot {
        let mut snapshot = crate::adapter::registry::RegistrySnapshot::new();
        let _ = snapshot.register_outbound("direct", build_test_direct_outbound);
        snapshot
    }

    #[derive(Clone)]
    struct DummyEndpoint {
        stages: Arc<Mutex<Vec<EndpointStage>>>,
        closes: Arc<AtomicUsize>,
        tag: &'static str,
    }

    impl DummyEndpoint {
        fn new(tag: &'static str) -> Self {
            Self {
                stages: Arc::new(Mutex::new(Vec::new())),
                closes: Arc::new(AtomicUsize::new(0)),
                tag,
            }
        }
    }

    impl Endpoint for DummyEndpoint {
        fn endpoint_type(&self) -> &str {
            "dummy-endpoint"
        }

        fn tag(&self) -> &str {
            self.tag
        }

        fn start(
            &self,
            stage: EndpointStage,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.stages.lock().unwrap().push(stage);
            Ok(())
        }

        fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct DummyService {
        stages: Arc<Mutex<Vec<ServiceStage>>>,
        closes: Arc<AtomicUsize>,
        tag: &'static str,
    }

    impl DummyService {
        fn new(tag: &'static str) -> Self {
            Self {
                stages: Arc::new(Mutex::new(Vec::new())),
                closes: Arc::new(AtomicUsize::new(0)),
                tag,
            }
        }
    }

    impl Service for DummyService {
        fn service_type(&self) -> &str {
            "dummy-service"
        }

        fn tag(&self) -> &str {
            self.tag
        }

        fn start(
            &self,
            stage: ServiceStage,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.stages.lock().unwrap().push(stage);
            Ok(())
        }

        fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn start_stop_endpoints_runs_all_stages() {
        let ep_impl = Arc::new(DummyEndpoint::new("ep1"));
        let ep: Arc<dyn Endpoint> = ep_impl.clone();
        start_endpoints(std::slice::from_ref(&ep));
        let stages = ep_impl.stages.lock().unwrap().clone();
        assert_eq!(
            stages,
            vec![
                EndpointStage::Initialize,
                EndpointStage::Start,
                EndpointStage::PostStart,
                EndpointStage::Started
            ]
        );
        stop_endpoints(std::slice::from_ref(&ep));
        assert_eq!(ep_impl.closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn start_stop_services_runs_all_stages() {
        let svc_impl = Arc::new(DummyService::new("svc1"));
        let svc: Arc<dyn Service> = svc_impl.clone();
        start_services(std::slice::from_ref(&svc));
        let stages = svc_impl.stages.lock().unwrap().clone();
        assert_eq!(
            stages,
            vec![
                ServiceStage::Initialize,
                ServiceStage::Start,
                ServiceStage::PostStart,
                ServiceStage::Started
            ]
        );
        stop_services(std::slice::from_ref(&svc));
        assert_eq!(svc_impl.closes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn start_with_registry_accepts_explicit_snapshot() {
        let _serial = SUPERVISOR_ADAPTER_REGISTRY_TEST_LOCK.lock().await;
        let ir = sb_config::ir::ConfigIR {
            outbounds: vec![sb_config::ir::OutboundIR {
                ty: sb_config::ir::OutboundType::Direct,
                name: Some("direct".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };

        let sup = Supervisor::start_with_registry(ir, Some(test_registry_snapshot()))
            .await
            .expect("start supervisor with explicit registry");

        sup.handle()
            .shutdown_graceful(std::time::Duration::from_millis(100))
            .await
            .expect("shutdown supervisor with explicit registry");
    }

    #[derive(Debug)]
    struct TestInbound {
        shutdown: AtomicBool,
        fail: bool,
    }

    impl TestInbound {
        const fn new(fail: bool) -> Self {
            Self {
                shutdown: AtomicBool::new(false),
                fail,
            }
        }
    }

    impl InboundTaskDriver for TestInbound {
        fn serve(&self) -> std::io::Result<()> {
            if self.fail {
                return Err(std::io::Error::other("test inbound failure"));
            }
            while !self.shutdown.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Ok(())
        }

        fn request_shutdown(&self) {
            self.shutdown.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_inbound_close_drains_clean_shutdown_without_hanging() {
        let inbound: Arc<dyn InboundTaskDriver> = Arc::new(TestInbound::new(false));
        let mut bridge = Bridge::new(Context::new());
        bridge.add_inbound_with_meta("test", Some("clean-test".into()), inbound);
        let monitors = start_inbounds_until_ready(&bridge, "startup")
            .await
            .expect("best-effort inbound starts");
        assert!(monitors.is_empty());
        shutdown_inbounds_and_monitors(&bridge.inbounds, monitors, "test-clean").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn canonical_inbound_close_drains_abnormal_return() {
        let inbound: Arc<dyn InboundTaskDriver> = Arc::new(TestInbound::new(true));
        let mut bridge = Bridge::new(Context::new());
        bridge.add_inbound_with_meta("test", Some("serve-error-test".into()), inbound);
        let monitors = start_inbounds_until_ready(&bridge, "startup")
            .await
            .expect("best-effort inbound starts even without readiness");
        assert!(monitors.is_empty());
        shutdown_inbounds_and_monitors(&bridge.inbounds, monitors, "test-error").await;
    }

    #[test]
    fn transition_inbound_liveness_logs_keep_stable_fields() {
        let source = include_str!("../adapter/inbound_transition.rs");
        for needle in [
            "component = \"inbound\"",
            "tag = %tag",
            "kind,",
            "phase = \"transition\"",
            "exit_kind,",
            "error = error.unwrap_or(\"\")",
        ] {
            assert!(
                source.contains(needle),
                "missing stable inbound log field: {needle}"
            );
        }
    }

    fn lifecycle_labels(pass: LifecyclePass) -> Vec<&'static str> {
        lifecycle_components_for(pass)
            .iter()
            .map(|component| component.label())
            .collect()
    }

    #[test]
    fn lifecycle_stage_plans_are_go_shaped() {
        assert_eq!(
            lifecycle_labels(LifecyclePass::Initialize),
            vec![
                "NetworkManager",
                "DNSRuntime",
                "ConnectionManager",
                "TaskMonitor",
                "PlatformInterface",
                "OutboundManager",
                "InboundManager",
                "EndpointManager",
                "ServiceManager",
            ]
        );
        assert_eq!(
            lifecycle_labels(LifecyclePass::StartCore),
            vec![
                "OutboundManager",
                "DNSRuntime",
                "NetworkManager",
                "ConnectionManager",
                "TaskMonitor",
                "PlatformInterface",
            ]
        );
        assert_eq!(
            lifecycle_labels(LifecyclePass::StartEdge),
            vec!["InboundManager", "EndpointManager", "ServiceManager"]
        );
        assert_eq!(
            lifecycle_labels(LifecyclePass::PostStart),
            vec![
                "OutboundManager",
                "NetworkManager",
                "DNSRuntime",
                "ConnectionManager",
                "TaskMonitor",
                "PlatformInterface",
                "InboundManager",
                "EndpointManager",
                "ServiceManager",
            ]
        );
        assert_eq!(
            lifecycle_labels(LifecyclePass::Started),
            vec![
                "NetworkManager",
                "DNSRuntime",
                "ConnectionManager",
                "TaskMonitor",
                "PlatformInterface",
                "OutboundManager",
                "InboundManager",
                "EndpointManager",
                "ServiceManager",
            ]
        );
        assert_eq!(
            CLOSE_COMPONENTS
                .iter()
                .map(|component| component.label())
                .collect::<Vec<_>>(),
            vec![
                "ServiceManager",
                "EndpointManager",
                "InboundManager",
                "OutboundManager",
                "PlatformInterface",
                "TaskMonitor",
                "ConnectionManager",
                "DNSRuntime",
                "NetworkManager",
            ]
        );
    }

    struct TestDnsResolver {
        name: &'static str,
        starts: Arc<Mutex<Vec<crate::dns::transport::DnsStartStage>>>,
        closes: Arc<AtomicUsize>,
        fail_stage: Option<crate::dns::transport::DnsStartStage>,
        fail_close: bool,
    }

    #[async_trait::async_trait]
    impl crate::dns::Resolver for TestDnsResolver {
        async fn resolve(&self, _domain: &str) -> Result<crate::dns::DnsAnswer> {
            Ok(crate::dns::DnsAnswer::new(
                Vec::new(),
                Duration::from_secs(0),
                crate::dns::cache::Source::Static,
                crate::dns::cache::Rcode::NoError,
            ))
        }

        fn name(&self) -> &str {
            self.name
        }

        async fn start(&self, stage: crate::dns::transport::DnsStartStage) -> Result<()> {
            self.starts.lock().unwrap().push(stage);
            if self.fail_stage == Some(stage) {
                anyhow::bail!("dns start failure at {stage:?}");
            }
            Ok(())
        }

        async fn close(&self) -> Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            if self.fail_close {
                anyhow::bail!("dns close failure");
            }
            Ok(())
        }
    }

    fn test_dns_resolver(name: &'static str) -> Arc<TestDnsResolver> {
        Arc::new(TestDnsResolver {
            name,
            starts: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(AtomicUsize::new(0)),
            fail_stage: None,
            fail_close: false,
        })
    }

    #[tokio::test]
    async fn lifecycle_start_failure_cleanup_preserves_original_error() {
        let resolver = Arc::new(TestDnsResolver {
            name: "failing-dns",
            starts: Arc::new(Mutex::new(Vec::new())),
            closes: Arc::new(AtomicUsize::new(0)),
            fail_stage: Some(crate::dns::transport::DnsStartStage::Start),
            fail_close: true,
        });
        let dns_runtime = RuntimeDns {
            resolver: resolver.clone(),
            router: None,
        };
        let context = Context::new();
        let lifecycle = LifecycleCoordinator::new(&context, Some(&dns_runtime));

        let err = lifecycle
            .run_pass(LifecyclePass::StartCore)
            .await
            .expect_err("DNS start failure should abort the pass");
        assert!(format!("{err:#}").contains("dns start failure at Start"));

        lifecycle.close_all(true).await;
        assert_eq!(resolver.closes.load(Ordering::SeqCst), 1);
    }

    struct RuntimeRegistryGuard(crate::adapter::registry::RuntimeRegistrySnapshot);

    impl RuntimeRegistryGuard {
        fn capture() -> Self {
            Self(crate::adapter::registry::runtime_snapshot())
        }
    }

    impl Drop for RuntimeRegistryGuard {
        fn drop(&mut self) {
            crate::adapter::registry::install_runtime_snapshot(self.0.clone());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_dns_global_publish_is_commit_only() {
        let _dns_guard = crate::dns::global::test_guard().await;
        let old_resolver = test_dns_resolver("old-dns");
        let new_resolver = test_dns_resolver("new-dns");
        crate::dns::global::set(old_resolver);

        let dns_runtime = RuntimeDns {
            resolver: new_resolver,
            router: None,
        };
        assert_eq!(crate::dns::global::get().unwrap().name(), "old-dns");

        publish_runtime_dns(Some(&dns_runtime));
        assert_eq!(crate::dns::global::get().unwrap().name(), "new-dns");
    }

    #[test]
    fn configured_dns_build_failure_blocks_activation() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.dns = Some(sb_config::ir::DnsIR {
            servers: vec![sb_config::ir::DnsServerIR {
                tag: "bad-udp".to_string(),
                server_type: Some("udp".to_string()),
                address: "udp://".to_string(),
                ..Default::default()
            }],
            default: Some("bad-udp".to_string()),
            ..Default::default()
        });

        let err = build_runtime_dns_from_ir(
            &ir,
            None,
            Arc::new(crate::runtime_options::DnsRuntimeOptions::default()),
        )
        .expect_err("invalid UDP DNS transport should block activation");
        assert!(format!("{err:#}").contains("invalid socket address syntax"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_dns_build_failure_keeps_global_resolver_and_registries() {
        let _adapter_serial = SUPERVISOR_ADAPTER_REGISTRY_TEST_LOCK.lock().await;
        let _dns_guard = crate::dns::global::test_guard().await;
        let _registry_guard = RuntimeRegistryGuard::capture();
        crate::adapter::registry::clear_runtime_registries();
        crate::dns::global::set(test_dns_resolver("old-global-dns"));

        fn direct_ir(tag: &str) -> sb_config::ir::ConfigIR {
            let raw = serde_json::json!({
                "outbounds": [{
                    "type": "direct",
                    "tag": tag
                }],
                "route": { "final": tag }
            });
            let (_cfg, ir) = sb_config::config_from_raw_value(raw).expect("test config parses");
            ir
        }

        let supervisor = Supervisor::start_with_registry(
            direct_ir("old-direct-dns"),
            Some(test_registry_snapshot()),
        )
        .await
        .expect("old runtime starts");
        let old_runtime =
            crate::adapter::registry::runtime_outbounds().expect("old runtime outbounds published");
        assert!(old_runtime.resolve("old-direct-dns").is_some());

        let mut new_ir = direct_ir("new-direct-dns");
        new_ir.dns = Some(sb_config::ir::DnsIR {
            servers: vec![sb_config::ir::DnsServerIR {
                tag: "bad-udp".to_string(),
                server_type: Some("udp".to_string()),
                address: "udp://".to_string(),
                ..Default::default()
            }],
            default: Some("bad-udp".to_string()),
            ..Default::default()
        });

        let err = supervisor
            .reload(new_ir)
            .await
            .expect_err("DNS build failure must fail reload activation");
        assert!(err.to_string().contains("failed to build DNS runtime"));
        assert_eq!(crate::dns::global::get().unwrap().name(), "old-global-dns");

        let runtime = crate::adapter::registry::runtime_outbounds()
            .expect("old runtime outbounds remain published");
        assert!(runtime.resolve("old-direct-dns").is_some());
        assert!(runtime.resolve("new-direct-dns").is_none());

        supervisor
            .shutdown_graceful(Duration::from_millis(500))
            .await
            .expect("shutdown old runtime");
    }

    mod reload_atomicity {
        use super::*;
        use crate::adapter::registry::{AdapterInboundContext, RegistrySnapshot};
        use crate::adapter::{InboundParam, InboundReadySender};
        use sb_config::ir::ConfigIR;
        use serde_json::json;
        use std::net::{SocketAddr, TcpListener};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use std::time::Duration as StdDuration;

        #[derive(Debug)]
        struct ReadyTcpInbound {
            listen: SocketAddr,
            shutdown: AtomicBool,
        }

        impl ReadyTcpInbound {
            const fn new(listen: SocketAddr) -> Self {
                Self {
                    listen,
                    shutdown: AtomicBool::new(false),
                }
            }
        }

        impl InboundTaskDriver for ReadyTcpInbound {
            fn serve(&self) -> std::io::Result<()> {
                self.serve_with_ready(None)
            }

            fn supports_startup_readiness(&self) -> bool {
                true
            }

            fn serve_with_ready(&self, ready: Option<InboundReadySender>) -> std::io::Result<()> {
                let listener = match TcpListener::bind(self.listen) {
                    Ok(listener) => listener,
                    Err(error) => {
                        if let Some(tx) = ready {
                            let _ =
                                tx.send(Err(std::io::Error::new(error.kind(), error.to_string())));
                        }
                        return Err(error);
                    }
                };
                listener.set_nonblocking(true)?;
                if let Some(tx) = ready {
                    let _ = tx.send(Ok(()));
                }
                while !self.shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((_stream, _peer)) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(StdDuration::from_millis(10));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Ok(())
            }

            fn request_shutdown(&self) {
                self.shutdown.store(true, Ordering::SeqCst);
            }
        }

        fn build_ready_inbound(
            param: &InboundParam,
            _ctx: &AdapterInboundContext,
        ) -> Option<Arc<dyn sb_types::Inbound>> {
            let listen = format!("{}:{}", param.listen, param.port)
                .parse::<SocketAddr>()
                .ok()?;
            Some(crate::adapter::manage_inbound(
                Arc::new(ReadyTcpInbound::new(listen)),
                "http",
                param.tag.clone().unwrap_or_else(|| "http".to_string()),
            ))
        }

        fn registry_snapshot() -> RegistrySnapshot {
            let mut snapshot = test_registry_snapshot();
            let _ = snapshot.register_inbound("http", build_ready_inbound);
            snapshot
        }

        fn reserve_port() -> Option<u16> {
            match TcpListener::bind("127.0.0.1:0") {
                Ok(listener) => {
                    let port = listener.local_addr().ok()?.port();
                    drop(listener);
                    Some(port)
                }
                Err(error) => {
                    eprintln!("skip reload atomicity test: cannot reserve port: {error}");
                    None
                }
            }
        }

        fn ir_with_http(port: u16, inbound_tag: &str, outbound_tag: &str) -> ConfigIR {
            ir_with_http_at("127.0.0.1", port, inbound_tag, outbound_tag)
        }

        fn ir_with_http_at(
            listen: &str,
            port: u16,
            inbound_tag: &str,
            outbound_tag: &str,
        ) -> ConfigIR {
            let raw = json!({
                "inbounds": [{
                    "type": "http",
                    "tag": inbound_tag,
                    "listen": listen,
                    "listen_port": port
                }],
                "outbounds": [{
                    "type": "direct",
                    "tag": outbound_tag
                }],
                "route": { "final": outbound_tag }
            });
            let (_cfg, ir) = sb_config::config_from_raw_value(raw).expect("test config parses");
            ir
        }

        async fn connect_ok(port: u16) -> bool {
            for _ in 0..40 {
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_ok()
                {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            false
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn startup_bind_conflict_fails_before_supervisor_ready() {
            let _serial = SUPERVISOR_ADAPTER_REGISTRY_TEST_LOCK.lock().await;
            let _guard = RuntimeRegistryGuard::capture();
            crate::adapter::registry::clear_runtime_registries();
            let Some(port) = reserve_port() else { return };
            let holder = TcpListener::bind(("127.0.0.1", port)).expect("hold startup port");

            let err = match Supervisor::start_with_registry(
                ir_with_http(port, "startup-http-conflict", "startup-direct-conflict"),
                Some(registry_snapshot()),
            )
            .await
            {
                Ok(supervisor) => {
                    let _ = supervisor
                        .shutdown_graceful(Duration::from_millis(500))
                        .await;
                    panic!("startup bind conflict must fail");
                }
                Err(err) => err,
            };

            assert!(err.to_string().contains("startup inbound readiness failed"));
            assert!(
                crate::adapter::registry::runtime_outbounds()
                    .and_then(|runtime| runtime.resolve("startup-direct-conflict"))
                    .is_none(),
                "failed startup must not publish its runtime outbound tag"
            );
            assert!(
                crate::adapter::registry::runtime_inbounds()
                    .and_then(|runtime| runtime.get("startup-http-conflict"))
                    .is_none(),
                "failed startup must not publish its runtime inbound tag"
            );
            drop(holder);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn failed_reload_keeps_old_listener_and_registry() {
            let _serial = SUPERVISOR_ADAPTER_REGISTRY_TEST_LOCK.lock().await;
            let _guard = RuntimeRegistryGuard::capture();
            crate::adapter::registry::clear_runtime_registries();
            let Some(old_port) = reserve_port() else {
                return;
            };
            let Some(new_port) = reserve_port() else {
                return;
            };
            let holder = TcpListener::bind(("127.0.0.1", new_port)).expect("hold new port");

            let supervisor = Supervisor::start_with_registry(
                ir_with_http(old_port, "old-http-reload", "old-direct-reload"),
                Some(registry_snapshot()),
            )
            .await
            .expect("old runtime starts");
            assert!(
                connect_ok(old_port).await,
                "old listener accepts before reload"
            );

            let err = supervisor
                .reload(ir_with_http(
                    new_port,
                    "new-http-reload",
                    "new-direct-reload",
                ))
                .await
                .expect_err("new bind conflict must fail reload");
            assert!(err.to_string().contains("reload inbound readiness failed"));
            assert!(
                connect_ok(old_port).await,
                "old listener must keep accepting after failed reload"
            );
            {
                let state = supervisor.state().await;
                let guard = state.read().await;
                let inbounds = &guard.bridge.inbounds;
                assert_eq!(inbounds.len(), 1);
                assert_eq!(inbounds[0].tag().as_str(), "old-http-reload");
            }

            let runtime = crate::adapter::registry::runtime_outbounds()
                .expect("old runtime outbounds remain published");
            assert!(runtime.resolve("old-direct-reload").is_some());
            assert!(
                runtime.resolve("new-direct-reload").is_none(),
                "failed reload must not leak the new outbound tag"
            );
            let runtime_inbounds = crate::adapter::registry::runtime_inbounds()
                .expect("old runtime inbounds remain published");
            assert!(runtime_inbounds.get("old-http-reload").is_some());
            assert!(
                runtime_inbounds.get("new-http-reload").is_none(),
                "failed reload must not leak the new inbound tag"
            );

            drop(holder);
            supervisor
                .shutdown_graceful(Duration::from_millis(500))
                .await
                .expect("shutdown old runtime");
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn same_port_reload_is_rejected_without_stopping_old_listener() {
            let _serial = SUPERVISOR_ADAPTER_REGISTRY_TEST_LOCK.lock().await;
            let _guard = RuntimeRegistryGuard::capture();
            crate::adapter::registry::clear_runtime_registries();
            let Some(port) = reserve_port() else { return };

            let supervisor = Supervisor::start_with_registry(
                ir_with_http_at(
                    "0.0.0.0",
                    port,
                    "old-http-same-port",
                    "old-direct-same-port",
                ),
                Some(registry_snapshot()),
            )
            .await
            .expect("old runtime starts");
            assert!(connect_ok(port).await, "old listener accepts before reload");

            let err = supervisor
                .reload(ir_with_http(
                    port,
                    "new-http-same-port",
                    "new-direct-same-port",
                ))
                .await
                .expect_err("same-port reload must be rejected");
            let msg = err.to_string();
            assert!(msg.contains("same-port in-process reload is unsupported"));
            assert!(msg.contains("127.0.0.1"));
            assert!(msg.contains("0.0.0.0"));
            assert!(
                connect_ok(port).await,
                "old listener must remain available after same-port rejection"
            );

            supervisor
                .shutdown_graceful(Duration::from_millis(500))
                .await
                .expect("shutdown old runtime");
        }
    }

    // ── APP-RELOAD-SIDECAR-ORDER-01C: V2Ray same-config reload reuse handoff ──
    mod reuse_handoff {
        use super::super::{
            reusable_v2ray_server, same_v2ray_server, shutdown_context, shutdown_replaced_context,
        };
        use crate::context::{
            Context, ManagedApiActiveGeneration, ManagedApiActivePhase, ManagedApiExit,
            ManagedApiExitRecord, ManagedApiRuntimeSnapshot, ManagedApiServer,
        };
        use sb_config::ir::{StatsIR, V2RayApiIR};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::sync::watch;

        /// A `ManagedApiServer` test double that records `close()` calls and publishes a fixed runtime
        /// snapshot (or none). It keeps the watch sender alive so the receiver stays valid.
        #[derive(Debug)]
        struct MockV2Ray {
            closes: Arc<AtomicUsize>,
            rx: Option<watch::Receiver<ManagedApiRuntimeSnapshot>>,
            _tx: Option<watch::Sender<ManagedApiRuntimeSnapshot>>,
        }

        impl ManagedApiServer for MockV2Ray {
            fn start(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) -> anyhow::Result<()> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn subscribe_runtime_state(
                &self,
            ) -> Option<watch::Receiver<ManagedApiRuntimeSnapshot>> {
                self.rx.clone()
            }
        }

        /// Build a mock server + a handle to its close counter. `snapshot = None` means the server
        /// exposes NO runtime state (mirrors a non-introspectable / trait-default implementor).
        fn mock(
            snapshot: Option<ManagedApiRuntimeSnapshot>,
        ) -> (Arc<dyn ManagedApiServer>, Arc<AtomicUsize>) {
            let closes = Arc::new(AtomicUsize::new(0));
            let (rx, _tx) = match snapshot {
                Some(s) => {
                    let (tx, rx) = watch::channel(s);
                    (Some(rx), Some(tx))
                }
                None => (None, None),
            };
            let server: Arc<dyn ManagedApiServer> = Arc::new(MockV2Ray {
                closes: closes.clone(),
                rx,
                _tx,
            });
            (server, closes)
        }

        fn running_snapshot(phase: ManagedApiActivePhase) -> ManagedApiRuntimeSnapshot {
            ManagedApiRuntimeSnapshot {
                current: Some(ManagedApiActiveGeneration {
                    generation: 1,
                    phase,
                }),
                last_exit: None,
            }
        }

        fn mock_running() -> (Arc<dyn ManagedApiServer>, Arc<AtomicUsize>) {
            mock(Some(running_snapshot(ManagedApiActivePhase::Running)))
        }

        fn cfg(listen: &str, stats_enabled: bool) -> V2RayApiIR {
            V2RayApiIR {
                listen: Some(listen.to_string()),
                stats: Some(StatsIR {
                    enabled: stats_enabled,
                    ..Default::default()
                }),
            }
        }

        // ── A. Running + equivalent config → reuse the SAME Arc ──
        #[test]
        fn a_reuse_running_equivalent_config() {
            let (server, _) = mock_running();
            let a = cfg("127.0.0.1:10085", true);
            let reused = reusable_v2ray_server(Some(&a), Some(&a), Some(&server))
                .expect("running + equal config must be reusable");
            assert!(
                Arc::ptr_eq(&server, &reused),
                "reuse must return the same server instance"
            );
        }

        // ── B. Config change (listen or stats) → no reuse ──
        #[test]
        fn b_no_reuse_on_config_change() {
            let (server, _) = mock_running();
            let a = cfg("127.0.0.1:10085", true);
            let b_listen = cfg("127.0.0.1:10086", true);
            assert!(reusable_v2ray_server(Some(&a), Some(&b_listen), Some(&server)).is_none());
            let b_stats = cfg("127.0.0.1:10085", false);
            assert!(
                reusable_v2ray_server(Some(&a), Some(&b_stats), Some(&server)).is_none(),
                "a stats-only config change must NOT reuse"
            );
        }

        // ── C. disabled variants → no reuse ──
        #[test]
        fn c_no_reuse_on_disabled_variants() {
            let (server, _) = mock_running();
            let a = cfg("127.0.0.1:10085", true);
            assert!(reusable_v2ray_server(None, None, Some(&server)).is_none());
            assert!(reusable_v2ray_server(None, Some(&a), Some(&server)).is_none());
            assert!(reusable_v2ray_server(Some(&a), None, Some(&server)).is_none());
        }

        // ── D. non-Running (ShutdownRequested / exited / no-snapshot / no-server) → no reuse ──
        #[test]
        fn d_no_reuse_when_not_running() {
            let a = cfg("127.0.0.1:10085", true);

            let (sr, _) = mock(Some(running_snapshot(
                ManagedApiActivePhase::ShutdownRequested,
            )));
            assert!(reusable_v2ray_server(Some(&a), Some(&a), Some(&sr)).is_none());

            let (exited, _) = mock(Some(ManagedApiRuntimeSnapshot {
                current: None,
                last_exit: Some(ManagedApiExitRecord {
                    generation: 1,
                    exit: ManagedApiExit::CleanShutdown,
                }),
            }));
            assert!(
                reusable_v2ray_server(Some(&a), Some(&a), Some(&exited)).is_none(),
                "an exited server (current=None) must NOT be reused via last_exit"
            );

            let (no_snap, _) = mock(None);
            assert!(
                reusable_v2ray_server(Some(&a), Some(&a), Some(&no_snap)).is_none(),
                "a non-introspectable server (no snapshot) must NOT be reused"
            );

            assert!(
                reusable_v2ray_server(Some(&a), Some(&a), None).is_none(),
                "no old server present → no reuse"
            );
        }

        // ── E. `:0` ephemeral config compares the IR, not the bound port → reuse ──
        #[test]
        fn e_reuse_ephemeral_zero_port() {
            let (server, _) = mock_running();
            let z = cfg("127.0.0.1:0", true);
            let reused = reusable_v2ray_server(Some(&z), Some(&z), Some(&server))
                .expect(":0 == :0 config must be reusable (keeps the real bound port)");
            assert!(Arc::ptr_eq(&server, &reused));
        }

        // ── F. reload teardown skips a reused (shared) server ──
        #[test]
        fn f_teardown_skips_reused_server() {
            let (server, closes) = mock_running();
            let old = Context::new().with_v2ray_server(server.clone());
            let new = Context::new().with_v2ray_server(server.clone());
            let preserve = same_v2ray_server(&old, &new);
            assert!(preserve, "shared Arc must be detected by ptr_eq");
            shutdown_replaced_context(&old, preserve);
            assert_eq!(
                closes.load(Ordering::SeqCst),
                0,
                "a reused server must NOT be closed by the old context's teardown"
            );
        }

        // ── G. reload teardown closes a distinct (rebuilt) server ──
        #[test]
        fn g_teardown_closes_distinct_server() {
            let (x, x_closes) = mock_running();
            let (y, _y_closes) = mock_running();
            let old = Context::new().with_v2ray_server(x.clone());
            let new = Context::new().with_v2ray_server(y.clone());
            let preserve = same_v2ray_server(&old, &new);
            assert!(!preserve, "distinct Arcs must not be treated as reused");
            shutdown_replaced_context(&old, preserve);
            assert_eq!(
                x_closes.load(Ordering::SeqCst),
                1,
                "a non-reused old server must be closed exactly once"
            );
        }

        // ── H. final (non-reload) shutdown still closes the reused server ──
        #[test]
        fn h_final_shutdown_closes_reused_server() {
            let (x, x_closes) = mock_running();
            let current = Context::new().with_v2ray_server(x.clone());
            shutdown_context(&current);
            assert_eq!(
                x_closes.load(Ordering::SeqCst),
                1,
                "the owning context's final shutdown must close the server"
            );
        }

        // ── I. None → None teardown is safe (no false preserve, no panic) ──
        #[test]
        fn i_none_to_none_teardown_is_safe() {
            let old = Context::new();
            let new = Context::new();
            assert!(!same_v2ray_server(&old, &new));
            shutdown_replaced_context(&old, same_v2ray_server(&old, &new));
        }

        // ── J. pre-swap borrowed rollback drops the new context without closing the server ──
        #[test]
        fn j_pre_swap_borrowed_rollback_does_not_close() {
            let (x, x_closes) = mock_running();
            let old = Context::new().with_v2ray_server(x.clone());
            let a = cfg("127.0.0.1:10085", true);
            let inherited = reusable_v2ray_server(Some(&a), Some(&a), old.v2ray_server.as_ref())
                .expect("eligible for reuse");
            {
                let new_tmp = Context::new().with_v2ray_server(inherited);
                assert!(same_v2ray_server(&old, &new_tmp));
                // Simulate a pre-swap stage failure: the new context is dropped WITHOUT any
                // teardown call (Context has no Drop). The old context keeps owning the server.
            }
            assert!(
                old.v2ray_server.is_some(),
                "old context still owns the server"
            );
            assert!(Arc::ptr_eq(old.v2ray_server.as_ref().unwrap(), &x));
            assert_eq!(
                x_closes.load(Ordering::SeqCst),
                0,
                "borrowed-then-dropped new context must not close the shared server"
            );
        }
    }

    // ── APP-RELOAD-CONTEXT-CLEANUP-01B: pre-swap failed-reload rollback guard ──
    mod rollback_guard {
        use super::super::shutdown_failed_reload_context;
        use super::{DummyEndpoint, DummyService};
        use crate::adapter::InboundTaskDriver;
        use crate::context::{Context, ManagedApiServer};
        use crate::endpoint::{Endpoint, StartStage as EndpointStage};
        use crate::service::Service;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        /// An `InboundTaskDriver` test double that counts `request_shutdown` calls.
        #[derive(Debug)]
        struct CountingInbound {
            shutdowns: AtomicUsize,
        }

        impl InboundTaskDriver for CountingInbound {
            fn serve(&self) -> std::io::Result<()> {
                Ok(())
            }
            fn request_shutdown(&self) {
                self.shutdowns.fetch_add(1, Ordering::SeqCst);
            }
        }

        /// An `InboundTaskDriver` test double that holds a REAL bound listener until
        /// `request_shutdown` releases it (mirrors the accept-loop-exits-on-flag contract:
        /// dropping the Arc alone never frees the port; only request_shutdown does).
        #[derive(Debug)]
        struct PortHoldingInbound {
            listener: Mutex<Option<std::net::TcpListener>>,
        }

        impl InboundTaskDriver for PortHoldingInbound {
            fn serve(&self) -> std::io::Result<()> {
                Ok(())
            }
            fn request_shutdown(&self) {
                self.listener.lock().unwrap().take();
            }
        }

        /// An `Endpoint` whose `close()` always fails — proves cleanup is best-effort and a
        /// cleanup error never disrupts the remaining rollback steps.
        #[derive(Debug)]
        struct FailingCloseEndpoint;

        impl Endpoint for FailingCloseEndpoint {
            fn endpoint_type(&self) -> &str {
                "failing-endpoint"
            }
            fn tag(&self) -> &str {
                "failing-ep"
            }
            fn start(
                &self,
                _stage: EndpointStage,
            ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Ok(())
            }
            fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                Err("simulated endpoint close failure".into())
            }
        }

        /// A `ManagedApiServer` test double that records `close()` calls.
        #[derive(Debug)]
        struct CloseCountingV2Ray {
            closes: Arc<AtomicUsize>,
        }

        impl ManagedApiServer for CloseCountingV2Ray {
            fn start(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) -> anyhow::Result<()> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        fn counting_v2ray() -> (Arc<dyn ManagedApiServer>, Arc<AtomicUsize>) {
            let closes = Arc::new(AtomicUsize::new(0));
            let server: Arc<dyn ManagedApiServer> = Arc::new(CloseCountingV2Ray {
                closes: closes.clone(),
            });
            (server, closes)
        }

        // ── G/S. inbound request_shutdown + endpoint/service stop all invoked ──
        #[test]
        fn g_rollback_stops_inbounds_endpoints_and_services() {
            let inbound_impl = Arc::new(CountingInbound {
                shutdowns: AtomicUsize::new(0),
            });
            let inbound = crate::adapter::manage_inbound(inbound_impl.clone(), "test", "counting");
            let ep_impl = Arc::new(DummyEndpoint::new("rollback-ep"));
            let ep: Arc<dyn Endpoint> = ep_impl.clone();
            let svc_impl = Arc::new(DummyService::new("rollback-svc"));
            let svc: Arc<dyn Service> = svc_impl.clone();

            shutdown_failed_reload_context(
                &Context::new(),
                &Context::new(),
                std::slice::from_ref(&inbound),
                std::slice::from_ref(&ep),
                std::slice::from_ref(&svc),
            );

            assert_eq!(inbound_impl.shutdowns.load(Ordering::SeqCst), 1);
            assert_eq!(ep_impl.closes.load(Ordering::SeqCst), 1);
            assert_eq!(svc_impl.closes.load(Ordering::SeqCst), 1);
        }

        // ── F. a new inbound's REAL listener port is re-bindable after rollback ──
        #[test]
        fn f_rollback_releases_new_inbound_listener_port() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind inbound port");
            let port = listener.local_addr().expect("local addr").port();
            let inbound = crate::adapter::manage_inbound(
                Arc::new(PortHoldingInbound {
                    listener: Mutex::new(Some(listener)),
                }),
                "test",
                "port-holder",
            );

            shutdown_failed_reload_context(
                &Context::new(),
                &Context::new(),
                std::slice::from_ref(&inbound),
                &[],
                &[],
            );

            assert!(
                std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(),
                "inbound listener port must be re-bindable after rollback"
            );
        }

        // ── D (proxy). a cleanup error neither panics nor stops the remaining cleanup;
        // all cleanup APIs return `()`, so the caller's original reload error is preserved
        // structurally (the rollback branch returns the activation error unchanged). ──
        #[test]
        fn d_cleanup_error_does_not_disrupt_remaining_rollback() {
            let failing_ep: Arc<dyn Endpoint> = Arc::new(FailingCloseEndpoint);
            let svc_impl = Arc::new(DummyService::new("after-failing-ep"));
            let svc: Arc<dyn Service> = svc_impl.clone();
            let (server, closes) = counting_v2ray();
            let new = Context::new().with_v2ray_server(server);

            shutdown_failed_reload_context(
                &Context::new(),
                &new,
                &[],
                std::slice::from_ref(&failing_ep),
                std::slice::from_ref(&svc),
            );

            assert_eq!(
                svc_impl.closes.load(Ordering::SeqCst),
                1,
                "service must still be stopped after an endpoint close failure"
            );
            assert_eq!(
                closes.load(Ordering::SeqCst),
                1,
                "fresh v2ray must still be closed after an endpoint close failure"
            );
        }

        // ── fresh vs inherited vs none discrimination (mock-level, feature-independent) ──
        #[test]
        fn rollback_closes_fresh_v2ray_but_preserves_inherited() {
            // fresh: old holds X, new holds a distinct Y → close Y, never touch X.
            let (x, x_closes) = counting_v2ray();
            let (y, y_closes) = counting_v2ray();
            let old = Context::new().with_v2ray_server(x.clone());
            let new = Context::new().with_v2ray_server(y);
            shutdown_failed_reload_context(&old, &new, &[], &[], &[]);
            assert_eq!(
                y_closes.load(Ordering::SeqCst),
                1,
                "fresh server must close"
            );
            assert_eq!(
                x_closes.load(Ordering::SeqCst),
                0,
                "old server must be untouched"
            );

            // inherited: old and new share the SAME Arc → rollback must NOT close it.
            let (shared, shared_closes) = counting_v2ray();
            let old = Context::new().with_v2ray_server(shared.clone());
            let new = Context::new().with_v2ray_server(shared);
            shutdown_failed_reload_context(&old, &new, &[], &[], &[]);
            assert_eq!(
                shared_closes.load(Ordering::SeqCst),
                0,
                "inherited (shared-Arc) server must NOT be closed by rollback"
            );

            // none: new context has no server (disabled or bind-skipped) → safe no-op.
            let (z, z_closes) = counting_v2ray();
            let old = Context::new().with_v2ray_server(z);
            shutdown_failed_reload_context(&old, &Context::new(), &[], &[], &[]);
            assert_eq!(z_closes.load(Ordering::SeqCst), 0);
        }
    }
}
