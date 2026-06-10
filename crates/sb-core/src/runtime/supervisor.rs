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

use crate::adapter::{Bridge, InboundService};
use crate::context::{Context, Startable, V2RayServer, V2RayServerActivePhase};
use crate::endpoint::{Endpoint, StartStage as EndpointStage};
#[cfg(feature = "router")]
use crate::routing::engine::Engine;
use crate::service::{Service, StartStage as ServiceStage};
use anyhow::{Context as AnyhowContext, Result};
use sb_config::ir::diff::Diff;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;

/// Messages sent to supervisor event loop
#[derive(Debug)]
pub enum ReloadMsg {
    /// Apply new configuration with hot reload
    Apply(Box<sb_config::ir::ConfigIR>),
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

/// Runtime state managed by supervisor
#[cfg(feature = "router")]
#[derive(Debug)]
pub struct State {
    pub engine: Engine,
    pub bridge: Arc<Bridge>,
    pub context: Context,
    pub health: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "service_ntp")]
    pub ntp: Option<tokio::task::JoinHandle<()>>,
    pub started_at: Instant,
    /// Current configuration IR for diff computation during reload
    pub current_ir: sb_config::ir::ConfigIR,
    provider_overlay: ProviderOverlayState,
}

#[cfg(not(feature = "router"))]
#[derive(Debug)]
pub struct State {
    pub bridge: Arc<Bridge>,
    pub context: Context,
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

#[cfg(feature = "router")]
impl State {
    pub fn new(
        engine: Engine,
        bridge: Bridge,
        context: Context,
        ir: sb_config::ir::ConfigIR,
    ) -> Self {
        Self {
            engine,
            bridge: Arc::new(bridge),
            context,
            health: None,
            #[cfg(feature = "service_ntp")]
            ntp: None,
            started_at: Instant::now(),
            current_ir: ir,
            provider_overlay: ProviderOverlayState::default(),
        }
    }
}

#[cfg(not(feature = "router"))]
impl State {
    pub fn new(_engine: (), bridge: Bridge, context: Context, ir: sb_config::ir::ConfigIR) -> Self {
        Self {
            bridge: Arc::new(bridge),
            context,
            health: None,
            #[cfg(feature = "service_ntp")]
            ntp: None,
            started_at: Instant::now(),
            current_ir: ir,
            provider_overlay: ProviderOverlayState::default(),
        }
    }
}

impl Supervisor {
    /// Start supervisor with initial configuration
    #[cfg(feature = "router")]
    pub async fn start(ir: sb_config::ir::ConfigIR) -> Result<Self> {
        Self::start_with_registry(ir, None).await
    }

    /// Start supervisor with an explicit adapter registry snapshot.
    #[cfg(feature = "router")]
    pub async fn start_with_registry(
        ir: sb_config::ir::ConfigIR,
        adapter_registry: Option<crate::adapter::registry::RegistrySnapshot>,
    ) -> Result<Self> {
        if let Some(snapshot) = adapter_registry.as_ref() {
            crate::adapter::registry::install_snapshot(snapshot);
        }

        // Ensure TLS crypto provider is installed before any TLS usage
        #[cfg(feature = "tls_rustls")]
        crate::tls::ensure_rustls_crypto_provider();

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
        let context = build_context_from_ir(&ir, None);
        ensure_geo_assets(&ir).await;

        // Initialize context managers (Box Runtime Parity: Go box.go lifecycle)
        run_context_stage(&context, ServiceStage::Initialize)?;
        tracing::debug!(target: "sb_core::runtime", "Context managers initialized");

        // Build bridge via adapter bridge to enable routed inbounds/outbounds
        let bridge = crate::adapter::bridge::build_bridge(&ir, engine.clone(), context.clone());

        // Register bridge components (endpoints, services, outbounds) into the
        // context managers BEFORE Start stage, so EndpointManager.run_stage and
        // ServiceManager.start_stage can drive each component through its
        // lifecycle and persist failure status on bind errors. If services were
        // registered after Start stage, the manager would never observe their
        // Start failures (regression: /services/health misreporting Failed
        // services as Running, see LC-003 p1_service_failure_isolation).
        populate_bridge_managers(&context, &bridge).await.map_err(|e| {
            tracing::error!(target: "sb_core::runtime", error = %e, "startup failed during outbound registration, rolling back");
            shutdown_context(&context);
            e
        })?;

        // Start context managers (after bridge components are registered).
        // ServiceManager.start_stage(Start) iterates registered services and
        // writes Failed status on per-service bind errors with fault isolation.
        run_context_stage(&context, ServiceStage::Start)
            .inspect_err(|_| shutdown_context(&context))?;
        tracing::info!(target: "sb_core::runtime", "Context managers started");

        // Configure DNS resolver from IR (if provided)
        if ir.dns.is_some() {
            if let Ok(resolver) = crate::dns::config_builder::resolver_from_ir(&ir) {
                crate::dns::global::set(resolver);
            }
        }
        // Apply TLS certificate configuration (global trust augmentation)
        crate::tls::global::apply_from_ir(ir.certificate.as_ref());

        let initial_state = State::new(engine_for_state, bridge, context, ir);
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

        for inbound in &inbounds {
            let ib = inbound.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = ib.serve() {
                    tracing::error!(target: "sb_core::runtime", error = %e, "inbound serve failed");
                }
            });
        }

        // Endpoints and services have already been driven through Initialize
        // and Start stages by run_context_stage above. PostStart and Started
        // follow next. The free-standing start_endpoints/start_services
        // helpers are intentionally NOT invoked here; using them would create
        // a second lifecycle driver that bypasses ServiceManager.statuses,
        // recreating the LC-003 misreporting bug.

        // PostStart stage for context managers (after all inbounds/endpoints/services started)
        {
            let state_guard = state.read().await;
            if let Err(e) = run_context_stage(&state_guard.context, ServiceStage::PostStart) {
                tracing::error!(target: "sb_core::runtime", error = %e, "PostStart failed, rolling back");
                for ib in &inbounds {
                    ib.request_shutdown();
                }
                stop_endpoints(&endpoints);
                stop_services(&services);
                shutdown_context(&state_guard.context);
                return Err(e);
            }
            if let Err(e) = run_context_stage(&state_guard.context, ServiceStage::Started) {
                tracing::error!(target: "sb_core::runtime", error = %e, "Started stage failed, rolling back");
                for ib in &inbounds {
                    ib.request_shutdown();
                }
                stop_endpoints(&endpoints);
                stop_services(&services);
                shutdown_context(&state_guard.context);
                return Err(e);
            }
            tracing::debug!(target: "sb_core::runtime", "Context managers post-start complete");
        }

        // Optional health task
        if std::env::var("SB_HEALTH_ENABLE").is_ok() {
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
                    ReloadMsg::Apply(new_ir) => {
                        if let Err(e) = Self::handle_reload(&state_clone, *new_ir).await {
                            tracing::error!(target: "sb_core::runtime", error = %e, "reload failed");
                        } else {
                            state_clone.write().await.provider_overlay =
                                ProviderOverlayState::default();
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

    /// Start supervisor with initial configuration (router feature disabled)
    #[cfg(not(feature = "router"))]
    pub async fn start(ir: sb_config::ir::ConfigIR) -> Result<Self> {
        Self::start_with_registry(ir, None).await
    }

    /// Start supervisor with an explicit adapter registry snapshot (router feature disabled).
    #[cfg(not(feature = "router"))]
    pub async fn start_with_registry(
        ir: sb_config::ir::ConfigIR,
        adapter_registry: Option<crate::adapter::registry::RegistrySnapshot>,
    ) -> Result<Self> {
        if let Some(snapshot) = adapter_registry.as_ref() {
            crate::adapter::registry::install_snapshot(snapshot);
        }

        // Ensure TLS crypto provider is installed before any TLS usage
        #[cfg(feature = "tls_rustls")]
        crate::tls::ensure_rustls_crypto_provider();

        let (tx, mut rx) = mpsc::channel::<ReloadMsg>(32);
        let cancel = CancellationToken::new();

        // Configure logging
        if let Some(log_ir) = &ir.log {
            crate::log::configure(log_ir);
        }

        // Create runtime context and wire experimental sidecars from IR
        let context = build_context_from_ir(&ir, None);
        ensure_geo_assets(&ir).await;

        // Initialize context managers (Box Runtime Parity: Go box.go lifecycle)
        run_context_stage(&context, ServiceStage::Initialize)?;
        tracing::debug!(target: "sb_core::runtime", "Context managers initialized (no-router)");

        let bridge = crate::adapter::bridge::build_bridge(&ir, (), context.clone());

        // Register bridge components into context managers BEFORE Start stage.
        // See router-init path for the rationale (LC-003 lifecycle fix).
        populate_bridge_managers(&context, &bridge).await.map_err(|e| {
            tracing::error!(target: "sb_core::runtime", error = %e, "startup failed during outbound registration (no-router), rolling back");
            shutdown_context(&context);
            e
        })?;

        // Start context managers
        run_context_stage(&context, ServiceStage::Start).map_err(|e| {
            shutdown_context(&context);
            e
        })?;
        tracing::info!(target: "sb_core::runtime", "Context managers started (no-router)");

        let initial_state = State::new((), bridge, context, ir);

        let state = Arc::new(RwLock::new(initial_state));

        // Start inbound listeners
        let (inbounds, endpoints, services) = {
            let state_guard = state.read().await;
            (
                state_guard.bridge.inbounds.clone(),
                state_guard.bridge.endpoints.clone(),
                state_guard.bridge.services.clone(),
            )
        };

        for inbound in &inbounds {
            let ib = inbound.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = ib.serve() {
                    tracing::error!(target: "sb_core::runtime", error = %e, "inbound serve failed");
                }
            });
        }

        // Endpoints/services already driven through Initialize+Start by
        // run_context_stage above; PostStart and Started follow.

        #[cfg(feature = "service_ntp")]
        {
            let ntp_cfg = { state.read().await.current_ir.ntp.clone() };
            install_ntp_task(&state, ntp_cfg).await;
        }

        // PostStart stage for context managers
        {
            let state_guard = state.read().await;
            if let Err(e) = run_context_stage(&state_guard.context, ServiceStage::PostStart) {
                tracing::error!(target: "sb_core::runtime", error = %e, "PostStart failed (no-router), rolling back");
                for ib in &inbounds {
                    ib.request_shutdown();
                }
                stop_endpoints(&endpoints);
                stop_services(&services);
                shutdown_context(&state_guard.context);
                return Err(e);
            }
            if let Err(e) = run_context_stage(&state_guard.context, ServiceStage::Started) {
                tracing::error!(target: "sb_core::runtime", error = %e, "Started stage failed (no-router), rolling back");
                for ib in &inbounds {
                    ib.request_shutdown();
                }
                stop_endpoints(&endpoints);
                stop_services(&services);
                shutdown_context(&state_guard.context);
                return Err(e);
            }
            tracing::debug!(target: "sb_core::runtime", "Context managers post-start complete (no-router)");
        }

        // Event loop (simplified for non-router case)
        let state_clone = Arc::clone(&state);
        let cancel_ev = cancel.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    ReloadMsg::Apply(new_ir) => {
                        if let Err(e) = Self::handle_reload_no_router(&state_clone, *new_ir).await {
                            tracing::error!(target: "sb_core::runtime", error = %e, "reload failed");
                        } else {
                            state_clone.write().await.provider_overlay =
                                ProviderOverlayState::default();
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
                        if let Err(e) = Self::handle_reload_no_router(&state_clone, merged_ir).await
                        {
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

        // Always apply the new IR to the runtime
        self.tx
            .send(ReloadMsg::Apply(Box::new(new_ir.clone())))
            .await
            .context("failed to send reload message")?;

        // Compute diff between old and new configuration
        if runtime_diff_from_env() {
            // Compute actual diff for debugging/monitoring purposes
            let diff = sb_config::ir::diff::diff(&old_ir, &new_ir);
            tracing::debug!(
                target: "sb_core::runtime",
                added_inbounds = diff.inbounds.added.len(),
                removed_inbounds = diff.inbounds.removed.len(),
                added_outbounds = diff.outbounds.added.len(),
                removed_outbounds = diff.outbounds.removed.len(),
                "Configuration diff computed"
            );
            Ok(diff)
        } else {
            // Fast path: skip diff computation unless explicitly requested
            let _ = &new_ir; // mark as used in minimal path
            Ok(Diff::default())
        }
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
    #[cfg(feature = "router")]
    async fn handle_reload(
        state: &Arc<RwLock<State>>,
        new_ir: sb_config::ir::ConfigIR,
    ) -> Result<()> {
        // Configure logging
        if let Some(log_ir) = &new_ir.log {
            crate::log::configure(log_ir);
        }

        // Step 0: Ask old inbounds to stop accepting (best-effort)
        let (old_endpoints, old_services, old_context, old_v2ray_cfg) = {
            let state_guard = state.read().await;
            for ib in &state_guard.bridge.inbounds {
                ib.request_shutdown();
            }
            (
                state_guard.bridge.endpoints.clone(),
                state_guard.bridge.services.clone(),
                state_guard.context.clone(),
                state_guard
                    .current_ir
                    .experimental
                    .as_ref()
                    .and_then(|e| e.v2ray_api.clone()),
            )
        };

        // Give old listeners a short grace to release ports
        let grace_ms = std::env::var("SB_INBOUND_RELOAD_GRACE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1200);
        if grace_ms > 0 {
            tokio::time::sleep(Duration::from_millis(grace_ms)).await;
        }

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

        // Build new context from new IR (supports dynamic service reconfiguration)
        let new_context = build_context_from_ir(&new_ir, inherited_v2ray);
        ensure_geo_assets(&new_ir).await;

        // APP-RELOAD-CONTEXT-CLEANUP-01B: every fallible pre-swap activation stage runs inside
        // this single transaction block so that ANY failure (current or future-added) funnels
        // into the one rollback branch below instead of leaking the new construction through a
        // bare `?` (fresh V2Ray listener, new inbound listeners, started endpoints/services —
        // see the 01A audit). The bridge is exported via `new_bridge_slot` so a failure after
        // bridge construction can still stop bridge-owned resources.
        let mut new_bridge_slot: Option<Arc<Bridge>> = None;
        let activation_result: Result<Arc<Bridge>> = async {
            // Initialize new context managers
            run_context_stage(&new_context, ServiceStage::Initialize)?;
            tracing::debug!(target: "sb_core::runtime", "New context managers initialized on reload");

            // Build new bridge via adapter bridge
            let new_bridge = crate::adapter::bridge::build_bridge(
                &new_ir,
                new_engine.clone(),
                new_context.clone(),
            );

            // Wrap in Arc and register components BEFORE Start stage. See LC-003
            // lifecycle fix in initial-start path for rationale.
            let new_bridge_arc = Arc::new(new_bridge);
            new_bridge_slot = Some(new_bridge_arc.clone());
            populate_bridge_managers(&new_context, &new_bridge_arc).await?;

            // Start new context managers (drives Start stage on registered services)
            run_context_stage(&new_context, ServiceStage::Start)?;
            tracing::info!(target: "sb_core::runtime", "New context managers started on reload");

            // Update DNS resolver from IR if present
            if new_ir.dns.is_some() {
                if let Ok(resolver) = crate::dns::config_builder::resolver_from_ir(&new_ir) {
                    crate::dns::global::set(resolver);
                }
            }
            // Refresh global TLS trust configuration from IR
            crate::tls::global::apply_from_ir(new_ir.certificate.as_ref());

            // Start new inbound listeners
            for inbound in &new_bridge_arc.inbounds {
                let ib = inbound.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = ib.serve() {
                        tracing::error!(target: "sb_core::runtime", error = %e, "new inbound serve failed");
                    }
                });
            }
            // Endpoints/services already driven through Start above; do not invoke
            // start_endpoints/start_services here (would re-trigger lifecycle and
            // bypass ServiceManager.statuses).

            // PostStart stage for new managers
            run_context_stage(&new_context, ServiceStage::PostStart)?;
            run_context_stage(&new_context, ServiceStage::Started)?;
            tracing::debug!(target: "sb_core::runtime", "New context managers post-start complete on reload");

            Ok(new_bridge_arc)
        }
        .await;

        let new_bridge_arc = match activation_result {
            Ok(bridge) => bridge,
            Err(error) => {
                tracing::error!(target: "sb_core::runtime", error = %error, "reload activation failed before swap, rolling back new construction");
                let (new_inbounds, new_endpoints, new_services) = new_bridge_slot
                    .as_deref()
                    .map(|b| (&b.inbounds[..], &b.endpoints[..], &b.services[..]))
                    .unwrap_or((&[], &[], &[]));
                shutdown_failed_reload_context(
                    &old_context,
                    &new_context,
                    new_inbounds,
                    new_endpoints,
                    new_services,
                );
                return Err(error);
            }
        };

        // APP-RELOAD-SIDECAR-ORDER-01C: compute the reuse-exclusion flag while BOTH contexts are
        // in scope; the new context is moved into state at the swap below.
        let preserve_v2ray = same_v2ray_server(&old_context, &new_context);

        // Update state atomically
        {
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
            state_guard.current_ir = new_ir;
            // Start new health task if needed
            if std::env::var("SB_HEALTH_ENABLE").is_ok() {
                let health_bridge = state_guard.bridge.clone();
                let health_cancel = CancellationToken::new();
                let health_handle = tokio::spawn(async move {
                    spawn_health_task_async(health_bridge, health_cancel).await;
                });
                state_guard.health = Some(health_handle);
            }
        }

        #[cfg(feature = "service_ntp")]
        {
            let ntp_cfg = { state.read().await.current_ir.ntp.clone() };
            install_ntp_task(state, ntp_cfg).await;
        }

        stop_endpoints(&old_endpoints);
        stop_services(&old_services);
        shutdown_replaced_context(&old_context, preserve_v2ray);

        tracing::info!(target: "sb_core::runtime", "configuration reloaded successfully");

        Ok(())
    }

    // Internal: handle reload in event loop (router feature disabled)
    #[cfg(not(feature = "router"))]
    async fn handle_reload_no_router(
        state: &Arc<RwLock<State>>,
        new_ir: sb_config::ir::ConfigIR,
    ) -> Result<()> {
        // Configure logging
        if let Some(log_ir) = &new_ir.log {
            crate::log::configure(log_ir);
        }

        // Step 0: Ask old inbounds to stop accepting (best-effort)
        let (old_endpoints, old_services, old_context, old_v2ray_cfg) = {
            let state_guard = state.read().await;
            for ib in &state_guard.bridge.inbounds {
                ib.request_shutdown();
            }
            (
                state_guard.bridge.endpoints.clone(),
                state_guard.bridge.services.clone(),
                state_guard.context.clone(),
                state_guard
                    .current_ir
                    .experimental
                    .as_ref()
                    .and_then(|e| e.v2ray_api.clone()),
            )
        };

        // Give old listeners a short grace to release ports
        let grace_ms = std::env::var("SB_INBOUND_RELOAD_GRACE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1200);
        if grace_ms > 0 {
            tokio::time::sleep(Duration::from_millis(grace_ms)).await;
        }

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

        // Build new context from new IR (supports dynamic service reconfiguration)
        let new_context = build_context_from_ir(&new_ir, inherited_v2ray);
        ensure_geo_assets(&new_ir).await;

        // APP-RELOAD-CONTEXT-CLEANUP-01B: same single pre-swap transaction block as the router
        // path (see handle_reload) — any activation failure funnels into the shared
        // shutdown_failed_reload_context rollback instead of leaking the new construction.
        let mut new_bridge_slot: Option<Arc<Bridge>> = None;
        let activation_result: Result<Arc<Bridge>> = async {
            // Initialize new context managers (Box Runtime Parity)
            run_context_stage(&new_context, ServiceStage::Initialize)?;
            tracing::debug!(target: "sb_core::runtime", "New context managers initialized on reload (no-router)");

            // Build new bridge (no engine needed)
            let new_bridge =
                crate::adapter::bridge::build_bridge(&new_ir, (), new_context.clone());

            // Wrap and register BEFORE Start (LC-003 lifecycle fix).
            let new_bridge_arc = Arc::new(new_bridge);
            new_bridge_slot = Some(new_bridge_arc.clone());
            populate_bridge_managers(&new_context, &new_bridge_arc).await?;

            // Start new context managers
            run_context_stage(&new_context, ServiceStage::Start)?;
            tracing::info!(target: "sb_core::runtime", "New context managers started on reload (no-router)");

            // Start new inbound listeners
            for inbound in &new_bridge_arc.inbounds {
                let ib = inbound.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = ib.serve() {
                        tracing::error!(target: "sb_core::runtime", error = %e, "new inbound serve failed");
                    }
                });
            }
            // Endpoints/services already driven through Start above.

            // PostStart stage for new managers (no-router)
            run_context_stage(&new_context, ServiceStage::PostStart)?;
            run_context_stage(&new_context, ServiceStage::Started)?;
            tracing::debug!(target: "sb_core::runtime", "New context managers post-start complete on reload (no-router)");

            Ok(new_bridge_arc)
        }
        .await;

        let new_bridge_arc = match activation_result {
            Ok(bridge) => bridge,
            Err(error) => {
                tracing::error!(target: "sb_core::runtime", error = %error, "reload activation failed before swap (no-router), rolling back new construction");
                let (new_inbounds, new_endpoints, new_services) = new_bridge_slot
                    .as_deref()
                    .map(|b| (&b.inbounds[..], &b.endpoints[..], &b.services[..]))
                    .unwrap_or((&[], &[], &[]));
                shutdown_failed_reload_context(
                    &old_context,
                    &new_context,
                    new_inbounds,
                    new_endpoints,
                    new_services,
                );
                return Err(error);
            }
        };

        // APP-RELOAD-SIDECAR-ORDER-01C: compute the reuse-exclusion flag while BOTH contexts are
        // in scope; the new context is moved into state at the swap below.
        let preserve_v2ray = same_v2ray_server(&old_context, &new_context);

        // Update state atomically
        {
            let mut state_guard = state.write().await;

            // Stop old health task if any
            if let Some(old_health) = state_guard.health.take() {
                old_health.abort();
            }

            // Replace bridge, context, and current IR (no engine field in non-router State)
            state_guard.bridge = new_bridge_arc;
            state_guard.context = new_context;
            state_guard.current_ir = new_ir;
            // Start new health task if needed
            if std::env::var("SB_HEALTH_ENABLE").is_ok() {
                let health_bridge = state_guard.bridge.clone();
                let health_cancel = CancellationToken::new();
                let health_handle = tokio::spawn(async move {
                    spawn_health_task_async(health_bridge, health_cancel).await;
                });
                state_guard.health = Some(health_handle);
            }
        }

        #[cfg(feature = "service_ntp")]
        {
            let ntp_cfg = { state.read().await.current_ir.ntp.clone() };
            install_ntp_task(state, ntp_cfg).await;
        }

        stop_endpoints(&old_endpoints);
        stop_services(&old_services);
        shutdown_replaced_context(&old_context, preserve_v2ray);

        tracing::info!(target: "sb_core::runtime", "configuration reloaded successfully (no router)");

        Ok(())
    }

    /// Merge provider-supplied outbounds and rules into the current ConfigIR.
    ///
    /// Strategy:
    /// - Provider outbounds are **appended** to the current outbound list (duplicates by name
    ///   are replaced to avoid conflicts).
    /// - Provider rules are appended as domain rules to the route's rule list.
    /// - The merged IR is then applied via the standard reload path.
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

        // Merge outbounds: replace existing by name, append new ones
        let mut injected_outbound_names = Vec::new();
        for new_ob in outbounds {
            let name = new_ob.name.as_deref().unwrap_or("");
            if !name.is_empty() {
                // Remove existing outbound with same name (if any)
                ir.outbounds
                    .retain(|existing| existing.name.as_deref() != Some(name));
                injected_outbound_names.push(name.to_string());
            }
            ir.outbounds.push(new_ob);
        }

        // Merge rules: parse simple rule strings and append as RuleIR entries.
        // Format: "TYPE,VALUE" -> creates a RuleIR with the appropriate field set.
        // Unrecognized formats are logged and skipped.
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

        // Stop accepting new connections (best-effort)
        {
            let state_guard = state.read().await;
            for ib in &state_guard.bridge.inbounds {
                ib.request_shutdown();
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

        let (endpoints, services, ctx) = {
            let guard = state.read().await;
            (
                guard.bridge.endpoints.clone(),
                guard.bridge.services.clone(),
                guard.context.clone(),
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
        shutdown_context(&ctx);

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

        // Always forward the reload request
        self.tx
            .send(ReloadMsg::Apply(Box::new(new_ir.clone())))
            .await
            .context("failed to send reload message")?;

        if runtime_diff_from_env() {
            let diff = sb_config::ir::diff::diff(&old_ir, &new_ir);
            Ok(diff)
        } else {
            let _ = &new_ir;
            Ok(Diff::default())
        }
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

fn run_context_stage(ctx: &Context, stage: ServiceStage) -> Result<()> {
    let label = match stage {
        ServiceStage::Initialize => "initialize",
        ServiceStage::Start => "start",
        ServiceStage::PostStart => "post-start",
        ServiceStage::Started => "mark started",
    };

    ctx.network
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} NetworkManager"))?;
    ctx.connections
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} ConnectionManager"))?;
    ctx.task_monitor
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} TaskMonitor"))?;
    ctx.platform
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} PlatformInterface"))?;
    ctx.inbound_manager
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} InboundManager"))?;
    ctx.outbound_manager
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} OutboundManager"))?;
    ctx.endpoint_manager
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} EndpointManager"))?;
    ctx.service_manager
        .start(stage)
        .map_err(|e| anyhow::anyhow!(e))
        .context(format!("failed to {label} ServiceManager"))?;

    Ok(())
}

fn wire_experimental_sidecars(
    mut context: Context,
    ir: &sb_config::ir::ConfigIR,
    inherited_v2ray_server: Option<Arc<dyn V2RayServer>>,
) -> Context {
    if let Some(exp) = &ir.experimental {
        if let Some(cache_cfg) = &exp.cache_file {
            if cache_cfg.enabled {
                let cache_svc = Arc::new(crate::services::cache_file::CacheFileService::new(
                    cache_cfg,
                ));
                context = context.with_cache_file(cache_svc);
                tracing::info!(target: "sb_core::runtime", path = ?cache_cfg.path, "cache file service wired");
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
                let v2ray_server = Arc::new(crate::services::v2ray_api::V2RayApiServer::new(
                    v2ray_cfg.clone(),
                ));
                if let Err(e) = v2ray_server.start() {
                    tracing::warn!(target: "sb_core::runtime", error = %e, "failed to start V2Ray API server");
                } else {
                    context = context.with_v2ray_server(v2ray_server);
                    tracing::info!(target: "sb_core::runtime", listen = ?v2ray_cfg.listen, "V2Ray API server wired");
                }
            }
        }
    }

    context
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
    old_server: Option<&Arc<dyn V2RayServer>>,
) -> Option<Arc<dyn V2RayServer>> {
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
        Some(V2RayServerActivePhase::Running)
    );
    if !is_running {
        tracing::debug!(target: "sb_core::runtime", "V2Ray reload: old server not Running, rebuilding (no reuse)");
        return None;
    }
    tracing::debug!(target: "sb_core::runtime", listen = ?new_cfg.listen, "V2Ray reload: reusing Running server across equivalent config");
    Some(Arc::clone(server))
}

/// True iff both contexts hold the SAME `V2RayServer` instance (i.e. the server was reused across
/// a reload). Used to decide whether the old context's teardown must skip closing it.
fn same_v2ray_server(a: &Context, b: &Context) -> bool {
    match (a.v2ray_server.as_ref(), b.v2ray_server.as_ref()) {
        (Some(x), Some(y)) => Arc::ptr_eq(x, y),
        _ => false,
    }
}

fn build_context_from_ir(
    ir: &sb_config::ir::ConfigIR,
    inherited_v2ray_server: Option<Arc<dyn V2RayServer>>,
) -> Context {
    let mut ctx = Context::new();
    ctx.network.apply_route_options(&ir.route);
    ctx = wire_experimental_sidecars(ctx, ir, inherited_v2ray_server);
    log_geo_download_hints(ir);
    if let Some(p) = &ir.route.geoip_path {
        std::env::set_var("GEOIP_PATH", p);
    }
    if let Some(p) = &ir.route.geosite_path {
        std::env::set_var("GEOSITE_PATH", p);
    }
    if let Some(strategy) = &ir.route.network_strategy {
        std::env::set_var("SB_NETWORK_STRATEGY", strategy);
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
    ctx
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
/// `Arc<dyn V2RayServer>` — i.e. the server was reused (APP-RELOAD-SIDECAR-ORDER-01C). In that
/// case the new context is the close owner, so this teardown must NOT close the shared server;
/// all other managers close as usual. The flag is computed via `same_v2ray_server` BEFORE the
/// swap, because the new context is moved into state at commit and is no longer reachable here.
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
fn shutdown_failed_reload_context(
    old_context: &Context,
    new_context: &Context,
    new_inbounds: &[Arc<dyn InboundService>],
    new_endpoints: &[Arc<dyn Endpoint>],
    new_services: &[Arc<dyn Service>],
) {
    for ib in new_inbounds {
        ib.request_shutdown();
    }
    stop_endpoints(new_endpoints);
    stop_services(new_services);
    shutdown_context_inner(new_context, !same_v2ray_server(old_context, new_context));
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
    // Note: Bridge maintains its own `inbounds` vector for legacy InboundService types.
    // InboundManager now expects Arc<dyn InboundAdapter> with lifecycle support.
    // New inbound adapters should be registered via InboundManager.add_handler().
    // Legacy inbounds are started via bridge.inbounds directly, not through InboundManager.

    #[derive(Clone, Debug)]
    struct ManagerConnectorBridge {
        inner: std::sync::Arc<dyn crate::adapter::OutboundConnector>,
    }

    #[async_trait::async_trait]
    impl crate::outbound::traits::OutboundConnector for ManagerConnectorBridge {
        async fn connect_tcp(
            &self,
            ctx: &crate::types::ConnCtx,
        ) -> crate::error::SbResult<tokio::net::TcpStream> {
            let host = ctx.dst.host.to_string();
            self.inner
                .connect(&host, ctx.dst.port)
                .await
                .map_err(crate::error::SbError::io)
        }

        async fn connect_udp(
            &self,
            _ctx: &crate::types::ConnCtx,
        ) -> crate::error::SbResult<Box<dyn crate::outbound::traits::UdpTransport>> {
            Err(crate::error::SbError::network(
                crate::error::ErrorClass::Protocol,
                "udp not supported by manager connector bridge".to_string(),
            ))
        }
    }

    // Register real bridge connectors into OutboundManager so startup/default
    // resolution and runtime fetch paths stay aligned with assembled outbounds.
    for (name, _kind, connector) in &bridge.outbounds {
        ctx.outbound_manager
            .add_connector(
                name.clone(),
                std::sync::Arc::new(ManagerConnectorBridge {
                    inner: connector.clone(),
                }),
            )
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

#[cfg(feature = "router")]
impl Engine {
    /// Create engine from IR configuration
    pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Engine> {
        Ok(Engine::new(std::sync::Arc::new(ir.clone())))
    }
}

#[cfg(not(feature = "router"))]
pub fn engine_from_ir(_ir: &sb_config::ir::ConfigIR) -> Result<()> {
    anyhow::bail!("app built without `router` feature")
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

fn parse_runtime_diff_env(value: Option<&str>) -> Result<bool, Arc<str>> {
    match value {
        Some(v) if v == "1" || v.eq_ignore_ascii_case("true") => Ok(true),
        Some(v) if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("false") => Ok(false),
        Some(raw) => Err(format!(
            "runtime env 'SB_RUNTIME_DIFF' value '{raw}' is not a recognized boolean; silent parse fallback is disabled; use '1'/'true' or '0'/'false'"
        )
        .into()),
        None => Ok(false),
    }
}

fn runtime_diff_from_env() -> bool {
    let raw = std::env::var("SB_RUNTIME_DIFF").ok();
    match parse_runtime_diff_env(raw.as_deref()) {
        Ok(val) => val,
        Err(reason) => {
            tracing::warn!("{reason}; using default false");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

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
        let ir = sb_config::ir::ConfigIR {
            outbounds: vec![sb_config::ir::OutboundIR {
                ty: sb_config::ir::OutboundType::Direct,
                name: Some("direct".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };

        let sup = Supervisor::start_with_registry(
            ir,
            Some(crate::adapter::registry::RegistrySnapshot::new()),
        )
        .await
        .expect("start supervisor with explicit registry");

        sup.handle()
            .shutdown_graceful(std::time::Duration::from_millis(100))
            .await
            .expect("shutdown supervisor with explicit registry");
    }

    #[test]
    fn invalid_runtime_diff_env_reports_explicitly() {
        let err = super::parse_runtime_diff_env(Some("on"))
            .expect_err("unrecognized boolean env should be rejected explicitly");
        let msg = err.to_string();
        assert!(msg.contains("SB_RUNTIME_DIFF"));
        assert!(msg.contains("silent parse fallback is disabled"));
    }

    // ── APP-RELOAD-SIDECAR-ORDER-01C: V2Ray same-config reload reuse handoff ──
    mod reuse_handoff {
        use super::super::{
            build_context_from_ir, reusable_v2ray_server, same_v2ray_server, shutdown_context,
            shutdown_replaced_context,
        };
        use crate::context::{
            Context, V2RayServer, V2RayServerActiveGeneration, V2RayServerActivePhase,
            V2RayServerExit, V2RayServerExitRecord, V2RayServerRuntimeSnapshot,
        };
        use sb_config::ir::{StatsIR, V2RayApiIR};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::sync::watch;

        /// A `V2RayServer` test double that records `close()` calls and publishes a fixed runtime
        /// snapshot (or none). It keeps the watch sender alive so the receiver stays valid.
        #[derive(Debug)]
        struct MockV2Ray {
            closes: Arc<AtomicUsize>,
            rx: Option<watch::Receiver<V2RayServerRuntimeSnapshot>>,
            _tx: Option<watch::Sender<V2RayServerRuntimeSnapshot>>,
        }

        impl V2RayServer for MockV2Ray {
            fn start(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) -> anyhow::Result<()> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn subscribe_runtime_state(
                &self,
            ) -> Option<watch::Receiver<V2RayServerRuntimeSnapshot>> {
                self.rx.clone()
            }
        }

        /// Build a mock server + a handle to its close counter. `snapshot = None` means the server
        /// exposes NO runtime state (mirrors a non-introspectable / trait-default implementor).
        fn mock(
            snapshot: Option<V2RayServerRuntimeSnapshot>,
        ) -> (Arc<dyn V2RayServer>, Arc<AtomicUsize>) {
            let closes = Arc::new(AtomicUsize::new(0));
            let (rx, _tx) = match snapshot {
                Some(s) => {
                    let (tx, rx) = watch::channel(s);
                    (Some(rx), Some(tx))
                }
                None => (None, None),
            };
            let server: Arc<dyn V2RayServer> = Arc::new(MockV2Ray {
                closes: closes.clone(),
                rx,
                _tx,
            });
            (server, closes)
        }

        fn running_snapshot(phase: V2RayServerActivePhase) -> V2RayServerRuntimeSnapshot {
            V2RayServerRuntimeSnapshot {
                current: Some(V2RayServerActiveGeneration {
                    generation: 1,
                    phase,
                }),
                last_exit: None,
            }
        }

        fn mock_running() -> (Arc<dyn V2RayServer>, Arc<AtomicUsize>) {
            mock(Some(running_snapshot(V2RayServerActivePhase::Running)))
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
                V2RayServerActivePhase::ShutdownRequested,
            )));
            assert!(reusable_v2ray_server(Some(&a), Some(&a), Some(&sr)).is_none());

            let (exited, _) = mock(Some(V2RayServerRuntimeSnapshot {
                current: None,
                last_exit: Some(V2RayServerExitRecord {
                    generation: 1,
                    exit: V2RayServerExit::CleanShutdown,
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

        // ── K + L. Real listener + StatsManager continuity across an equivalent reload ──
        // (feature-gated: binds a real gRPC listener; properly closed at the end — no leak).
        #[cfg(feature = "service_v2ray_api")]
        #[tokio::test]
        async fn k_equivalent_reload_reuses_real_listener_and_stats() {
            async fn connect_ok(addr: &str) -> bool {
                for _ in 0..40 {
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        return true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                false
            }

            let port = match std::net::TcpListener::bind("127.0.0.1:0") {
                Ok(l) => {
                    let p = l.local_addr().unwrap().port();
                    drop(l);
                    p
                }
                Err(e) => {
                    eprintln!("skip k_equivalent_reload (cannot reserve port): {e}");
                    return;
                }
            };
            let listen = format!("127.0.0.1:{port}");
            let ir = sb_config::ir::ConfigIR {
                experimental: Some(sb_config::ir::ExperimentalIR {
                    v2ray_api: Some(cfg(&listen, true)),
                    ..Default::default()
                }),
                ..Default::default()
            };

            // Initial build binds + serves a real listener.
            let ctx1 = build_context_from_ir(&ir, None);
            let server1 = ctx1
                .v2ray_server
                .clone()
                .expect("v2ray server wired on build");
            assert!(
                connect_ok(&listen).await,
                "listener must be bound after the initial build"
            );

            // Equivalent reload: eligibility yields the SAME Arc; wiring skips new()+start().
            let v2 = ir.experimental.as_ref().and_then(|e| e.v2ray_api.as_ref());
            let inherited = reusable_v2ray_server(v2, v2, ctx1.v2ray_server.as_ref())
                .expect("a Running equivalent server must be reusable");
            let ctx2 = build_context_from_ir(&ir, Some(inherited));
            let server2 = ctx2
                .v2ray_server
                .clone()
                .expect("v2ray server present after reuse");
            assert!(
                Arc::ptr_eq(&server1, &server2),
                "equivalent reload must reuse the same server (no rebind)"
            );

            // Stats continuity: the same StatsManager instance (no new one created).
            let s1 = server1.stats().expect("real server exposes stats");
            let s2 = server2.stats().expect("real server exposes stats");
            assert!(
                Arc::ptr_eq(&s1, &s2),
                "reuse must preserve StatsManager identity"
            );

            // The old context's reload teardown must NOT close the shared listener.
            let preserve = same_v2ray_server(&ctx1, &ctx2);
            assert!(preserve);
            shutdown_replaced_context(&ctx1, preserve);
            assert!(
                connect_ok(&listen).await,
                "listener must survive the reuse-reload old-context teardown"
            );

            // Final shutdown of the owning context releases the listener (no leak).
            shutdown_context(&ctx2);
        }
    }

    // ── APP-RELOAD-CONTEXT-CLEANUP-01B: pre-swap failed-reload rollback guard ──
    mod rollback_guard {
        use super::super::shutdown_failed_reload_context;
        use super::{DummyEndpoint, DummyService};
        use crate::adapter::InboundService;
        use crate::context::{Context, V2RayServer};
        use crate::endpoint::{Endpoint, StartStage as EndpointStage};
        use crate::service::Service;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        /// An `InboundService` test double that counts `request_shutdown` calls.
        #[derive(Debug)]
        struct CountingInbound {
            shutdowns: AtomicUsize,
        }

        impl InboundService for CountingInbound {
            fn serve(&self) -> std::io::Result<()> {
                Ok(())
            }
            fn request_shutdown(&self) {
                self.shutdowns.fetch_add(1, Ordering::SeqCst);
            }
        }

        /// An `InboundService` test double that holds a REAL bound listener until
        /// `request_shutdown` releases it (mirrors the accept-loop-exits-on-flag contract:
        /// dropping the Arc alone never frees the port; only request_shutdown does).
        #[derive(Debug)]
        struct PortHoldingInbound {
            listener: Mutex<Option<std::net::TcpListener>>,
        }

        impl InboundService for PortHoldingInbound {
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

        /// A `V2RayServer` test double that records `close()` calls.
        #[derive(Debug)]
        struct CloseCountingV2Ray {
            closes: Arc<AtomicUsize>,
        }

        impl V2RayServer for CloseCountingV2Ray {
            fn start(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) -> anyhow::Result<()> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        fn counting_v2ray() -> (Arc<dyn V2RayServer>, Arc<AtomicUsize>) {
            let closes = Arc::new(AtomicUsize::new(0));
            let server: Arc<dyn V2RayServer> = Arc::new(CloseCountingV2Ray {
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
            let inbound: Arc<dyn InboundService> = inbound_impl.clone();
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
            let inbound: Arc<dyn InboundService> = Arc::new(PortHoldingInbound {
                listener: Mutex::new(Some(listener)),
            });

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

        // ── real-listener coverage (binds actual gRPC listeners; all released in-test) ──
        #[cfg(feature = "service_v2ray_api")]
        mod real_listener {
            use super::super::super::{
                build_context_from_ir, reusable_v2ray_server, same_v2ray_server, shutdown_context,
                shutdown_failed_reload_context,
            };
            use super::counting_v2ray;
            use crate::context::Context;
            use sb_config::ir::{ConfigIR, ExperimentalIR, StatsIR, V2RayApiIR};
            use std::sync::atomic::Ordering;

            fn v2ray_ir(listen: &str) -> ConfigIR {
                ConfigIR {
                    experimental: Some(ExperimentalIR {
                        v2ray_api: Some(V2RayApiIR {
                            listen: Some(listen.to_string()),
                            stats: Some(StatsIR {
                                enabled: true,
                                ..Default::default()
                            }),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }
            }

            fn reserve_port() -> Option<u16> {
                match std::net::TcpListener::bind("127.0.0.1:0") {
                    Ok(l) => {
                        let p = l.local_addr().ok()?.port();
                        drop(l);
                        Some(p)
                    }
                    Err(e) => {
                        eprintln!("skip rollback real-listener test (cannot reserve port): {e}");
                        None
                    }
                }
            }

            async fn connect_ok(addr: &str) -> bool {
                for _ in 0..40 {
                    if tokio::net::TcpStream::connect(addr).await.is_ok() {
                        return true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                false
            }

            /// `V2RayApiServer::close()` only signals shutdown; the serve task releases the
            /// listener asynchronously — so port-release assertions must retry.
            async fn bindable_ok(addr: &str) -> bool {
                for _ in 0..80 {
                    if std::net::TcpListener::bind(addr).is_ok() {
                        return true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
                false
            }

            // ── A/Q. fresh V2Ray rollback: listener B closed, port re-bindable ──
            #[tokio::test]
            async fn a_rollback_closes_fresh_v2ray_and_releases_port() {
                let Some(port) = reserve_port() else { return };
                let listen = format!("127.0.0.1:{port}");

                let new_ctx = build_context_from_ir(&v2ray_ir(&listen), None);
                assert!(new_ctx.v2ray_server.is_some(), "fresh v2ray must be wired");
                assert!(connect_ok(&listen).await, "fresh listener must be bound");

                // Old context has no v2ray server → same_v2ray_server == false → close fresh.
                shutdown_failed_reload_context(&Context::new(), &new_ctx, &[], &[], &[]);

                assert!(
                    bindable_ok(&listen).await,
                    "fresh v2ray port must be re-bindable after rollback"
                );
            }

            // ── B/R. inherited V2Ray rollback: old listener A keeps serving; released only
            // at the old context's final shutdown ──
            #[tokio::test]
            async fn b_rollback_preserves_inherited_v2ray_listener() {
                let Some(port) = reserve_port() else { return };
                let listen = format!("127.0.0.1:{port}");
                let ir = v2ray_ir(&listen);

                let old_ctx = build_context_from_ir(&ir, None);
                assert!(connect_ok(&listen).await, "old listener A must be bound");

                let v2 = ir.experimental.as_ref().and_then(|e| e.v2ray_api.as_ref());
                let inherited = reusable_v2ray_server(v2, v2, old_ctx.v2ray_server.as_ref())
                    .expect("running equivalent server must be reusable");
                let new_ctx = build_context_from_ir(&ir, Some(inherited));
                assert!(same_v2ray_server(&old_ctx, &new_ctx));

                // Pre-swap failure → rollback must NOT close the inherited (shared) server.
                shutdown_failed_reload_context(&old_ctx, &new_ctx, &[], &[], &[]);
                assert!(
                    connect_ok(&listen).await,
                    "inherited listener A must survive rollback"
                );

                // Dropping the new context's borrowed Arc leaves the old owner serving.
                drop(new_ctx);
                assert!(
                    connect_ok(&listen).await,
                    "old context must keep serving after the new context drops"
                );

                // Final shutdown of the owning (old) context releases A.
                shutdown_context(&old_ctx);
                assert!(
                    bindable_ok(&listen).await,
                    "old final shutdown must release listener A"
                );
            }

            // ── C. bind failure (port externally occupied) → warn+skip → rollback is a
            // no-op for v2ray and never touches the old context's server ──
            #[tokio::test]
            async fn c_bind_failure_skip_rollback_is_noop_and_keeps_old() {
                let holder = match std::net::TcpListener::bind("127.0.0.1:0") {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("skip c_bind_failure (cannot bind holder): {e}");
                        return;
                    }
                };
                let listen = format!("127.0.0.1:{}", holder.local_addr().unwrap().port());

                // External occupation → fresh start fails → visible-but-nonfatal skip.
                let new_ctx = build_context_from_ir(&v2ray_ir(&listen), None);
                assert!(
                    new_ctx.v2ray_server.is_none(),
                    "bind failure must warn+skip, leaving no v2ray in the new context"
                );

                let (old_server, old_closes) = counting_v2ray();
                let old_ctx = Context::new().with_v2ray_server(old_server);
                shutdown_failed_reload_context(&old_ctx, &new_ctx, &[], &[], &[]);

                assert_eq!(
                    old_closes.load(Ordering::SeqCst),
                    0,
                    "rollback must never close the old context's server"
                );
                assert!(
                    std::net::TcpListener::bind(listen.as_str()).is_err(),
                    "the external holder must still own the port (rollback touched nothing)"
                );
                drop(holder);
            }

            // ── E/T. repeated failed reloads: each rollback fully releases the fresh port ──
            #[tokio::test]
            async fn e_repeated_failed_reloads_do_not_accumulate_leaks() {
                let Some(port) = reserve_port() else { return };
                let listen = format!("127.0.0.1:{port}");

                for round in 0..3 {
                    let new_ctx = build_context_from_ir(&v2ray_ir(&listen), None);
                    assert!(
                        new_ctx.v2ray_server.is_some(),
                        "round {round}: fresh v2ray must bind (port released by prior rollback)"
                    );
                    assert!(
                        connect_ok(&listen).await,
                        "round {round}: fresh listener must serve"
                    );
                    shutdown_failed_reload_context(&Context::new(), &new_ctx, &[], &[], &[]);
                    assert!(
                        bindable_ok(&listen).await,
                        "round {round}: port must be re-bindable after rollback"
                    );
                }
            }

            // ── Arc lifecycle sanity: rollback closes the fresh server exactly once ──
            #[tokio::test]
            async fn fresh_rollback_closes_exactly_once() {
                let Some(port) = reserve_port() else { return };
                let listen = format!("127.0.0.1:{port}");
                let new_ctx = build_context_from_ir(&v2ray_ir(&listen), None);
                let server = new_ctx.v2ray_server.clone().expect("fresh server wired");

                shutdown_failed_reload_context(&Context::new(), &new_ctx, &[], &[], &[]);
                assert!(bindable_ok(&listen).await);

                // A second close on an already-shut-down server is an idempotent no-op.
                server.close().expect("idempotent close");
                drop(new_ctx);
                assert!(bindable_ok(&listen).await, "no resurrection after drop");
            }
        }
    }
}
