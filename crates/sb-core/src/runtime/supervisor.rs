//! Runtime supervisor for hot reload and graceful shutdown.
//!
//! Manages engine/bridge lifecycle and handles reload/shutdown messages
//! via async channels while maintaining service availability.

use crate::adapter::Bridge;
#[cfg(feature = "router")]
use crate::routing::engine::Engine;
use anyhow::{Context, Result};
use sb_config::ir::diff::Diff;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;

/// Messages sent to supervisor event loop
#[derive(Debug)]
pub enum ReloadMsg {
    /// Apply new configuration with hot reload
    Apply(sb_config::ir::ConfigIR),
    /// Begin graceful shutdown with deadline
    Shutdown { deadline: Instant },
}

/// Runtime state managed by supervisor
#[cfg(feature = "router")]
#[derive(Debug)]
pub struct State {
    pub engine: Engine<'static>,
    pub bridge: Arc<Bridge>,
    pub health: Option<tokio::task::JoinHandle<()>>,
    #[cfg(feature = "service_ntp")]
    pub ntp: Option<tokio::task::JoinHandle<()>>,
    pub started_at: Instant,
    /// Current configuration IR for diff computation during reload
    pub current_ir: sb_config::ir::ConfigIR,
}

#[cfg(not(feature = "router"))]
#[derive(Debug)]
pub struct State {
    pub bridge: Arc<Bridge>,
    pub health: Option<tokio::task::JoinHandle<()>>,
    pub started_at: Instant,
    /// Current configuration IR for diff computation during reload
    pub current_ir: sb_config::ir::ConfigIR,
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
    pub fn new(engine: Engine<'static>, bridge: Bridge, ir: sb_config::ir::ConfigIR) -> Self {
        Self {
            engine,
            bridge: Arc::new(bridge),
            health: None,
            #[cfg(feature = "service_ntp")]
            ntp: None,
            started_at: Instant::now(),
            current_ir: ir,
        }
    }
}

#[cfg(not(feature = "router"))]
impl State {
    pub fn new(_engine: (), bridge: Bridge, ir: sb_config::ir::ConfigIR) -> Self {
        Self {
            bridge: Arc::new(bridge),
            health: None,
            started_at: Instant::now(),
            current_ir: ir,
        }
    }
}

impl Supervisor {
    /// Start supervisor with initial configuration
    #[cfg(feature = "router")]
    pub async fn start(ir: sb_config::ir::ConfigIR) -> Result<Self> {
        let (tx, mut rx) = mpsc::channel::<ReloadMsg>(32);
        let cancel = CancellationToken::new();

        // Build initial engine and bridge
        let engine = Engine::from_ir(&ir).context("failed to build engine from initial config")?;
        let engine_static = engine.clone_as_static();

        // Build bridge via adapter bridge to enable routed inbounds/outbounds
        let bridge = crate::adapter::bridge::build_bridge(&ir, engine.clone());

        // Configure DNS resolver from IR (if provided)
        if let Some(dns_ir) = ir.dns.as_ref() {
            if let Ok(resolver) = crate::dns::config_builder::resolver_from_ir(dns_ir) {
                crate::dns::global::set(resolver);
            }
        }
        // Apply TLS certificate configuration (global trust augmentation)
        crate::tls::global::apply_from_ir(ir.certificate.as_ref());

        let initial_state = State::new(engine_static, bridge, ir);
        let state = Arc::new(RwLock::new(initial_state));

        // Start inbound listeners
        {
            let state_guard = state.read().await;
            for inbound in &state_guard.bridge.inbounds {
                let ib = inbound.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = ib.serve() {
                        tracing::error!(target: "sb_core::runtime", error = %e, "inbound serve failed");
                    }
                });
            }

            // Optional health task
            if std::env::var("SB_HEALTH_ENABLE").is_ok() {
                let health_bridge = state_guard.bridge.clone();
                let tok = cancel.clone();
                let health_handle = tokio::spawn(async move {
                    spawn_health_task_async(health_bridge, tok).await;
                });
                drop(state_guard);
                state.write().await.health = Some(health_handle);
            }
            #[cfg(feature = "service_ntp")]
            {
                // Spawn NTP service if enabled in config
                let mut sw = state.write().await;
                if let Some(ntp_cfg) = &sw.current_ir.ntp {
                    if ntp_cfg.enabled {
                        let server = match (&ntp_cfg.server, ntp_cfg.server_port) {
                            (Some(s), Some(p)) => format!("{s}:{p}"),
                            (Some(s), None) => {
                                if s.contains(':') { s.clone() } else { format!("{s}:123") }
                            }
                            (None, Some(p)) => format!("time.google.com:{p}"),
                            (None, None) => crate::services::ntp::NtpConfig::default().server,
                        };
                        let interval = std::time::Duration::from_millis(
                            ntp_cfg.interval_ms.unwrap_or(30 * 60 * 1000),
                        );
                        let timeout = std::time::Duration::from_millis(
                            ntp_cfg.timeout_ms.unwrap_or(1500),
                        );
                        let ntp = crate::services::ntp::NtpService::new(
                            crate::services::ntp::NtpConfig {
                                enabled: true,
                                server,
                                interval,
                                timeout,
                            },
                        )
                        .spawn();
                        sw.ntp = ntp;
                    }
                }
            }
        }

        let state_clone = Arc::clone(&state);

        // Event loop
        let cancel_ev = cancel.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    ReloadMsg::Apply(new_ir) => {
                        if let Err(e) = Self::handle_reload(&state_clone, new_ir).await {
                            tracing::error!(target: "sb_core::runtime", error = %e, "reload failed");
                        }
                    }
                    ReloadMsg::Shutdown { deadline } => {
                        // 广播取消信号
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
        let (tx, mut rx) = mpsc::channel::<ReloadMsg>(32);
        let cancel = CancellationToken::new();

        let bridge = Bridge::from_ir(&ir).context("failed to build bridge from initial config")?;
        let initial_state = State::new((), bridge, ir);
        let state = Arc::new(RwLock::new(initial_state));

        // Start inbound listeners
        {
            let state_guard = state.read().await;
            for inbound in &state_guard.bridge.inbounds {
                let ib = inbound.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = ib.serve() {
                        tracing::error!(target: "sb_core::runtime", error = %e, "inbound serve failed");
                    }
                });
            }

            // Optional health task
            // (implementation would be similar to router version but without engine)
        }

        // Event loop (simplified for non-router case)
        let state_clone = Arc::clone(&state);
        let cancel_ev = cancel.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    ReloadMsg::Apply(new_ir) => {
                        if let Err(e) = Self::handle_reload_no_router(&state_clone, new_ir).await {
                            tracing::error!(target: "sb_core::runtime", error = %e, "reload failed");
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
            .send(ReloadMsg::Apply(new_ir.clone()))
            .await
            .context("failed to send reload message")?;

        // Compute diff between old and new configuration
        if std::env::var("SB_RUNTIME_DIFF").ok().as_deref() == Some("1") {
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

        // 广播取消信号（幂等）
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
        // Step 0: Ask old inbounds to stop accepting (best-effort)
        {
            let state_guard = state.read().await;
            for ib in &state_guard.bridge.inbounds {
                ib.request_shutdown();
            }
        }

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
        let new_engine_static = new_engine.clone_as_static();

        // Build new bridge via adapter bridge
        let new_bridge = crate::adapter::bridge::build_bridge(&new_ir, new_engine.clone());

        // Update DNS resolver from IR if present
        if let Some(dns_ir) = new_ir.dns.as_ref() {
            if let Ok(resolver) = crate::dns::config_builder::resolver_from_ir(dns_ir) {
                crate::dns::global::set(resolver);
            }
        }
        // Refresh global TLS trust configuration from IR
        crate::tls::global::apply_from_ir(new_ir.certificate.as_ref());

        // Start new inbound listeners
        let new_bridge_arc = Arc::new(new_bridge);
        for inbound in &new_bridge_arc.inbounds {
            let ib = inbound.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = ib.serve() {
                    tracing::error!(target: "sb_core::runtime", error = %e, "new inbound serve failed");
                }
            });
        }

        // Update state atomically
        {
            let mut state_guard = state.write().await;

            // Stop old health task if any
            if let Some(old_health) = state_guard.health.take() {
                old_health.abort();
            }
            #[cfg(feature = "service_ntp")]
            {
                if let Some(h) = state_guard.ntp.take() {
                    h.abort();
                }
            }

            // Replace engine, bridge, and current IR
            state_guard.engine = new_engine_static;
            state_guard.bridge = new_bridge_arc;
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
            #[cfg(feature = "service_ntp")]
            {
                if let Some(ntp_cfg) = &state_guard.current_ir.ntp {
                    if ntp_cfg.enabled {
                        let server = match (&ntp_cfg.server, ntp_cfg.server_port) {
                            (Some(s), Some(p)) => format!("{s}:{p}"),
                            (Some(s), None) => {
                                if s.contains(':') { s.clone() } else { format!("{s}:123") }
                            }
                            (None, Some(p)) => format!("time.google.com:{p}"),
                            (None, None) => crate::services::ntp::NtpConfig::default().server,
                        };
                        let interval = std::time::Duration::from_millis(
                            ntp_cfg.interval_ms.unwrap_or(30 * 60 * 1000),
                        );
                        let timeout = std::time::Duration::from_millis(
                            ntp_cfg.timeout_ms.unwrap_or(1500),
                        );
                        let ntp = crate::services::ntp::NtpService::new(
                            crate::services::ntp::NtpConfig {
                                enabled: true,
                                server,
                                interval,
                                timeout,
                            },
                        )
                        .spawn();
                        state_guard.ntp = ntp;
                    }
                }
            }
        }

        tracing::info!(target: "sb_core::runtime", "configuration reloaded successfully");

        Ok(())
    }

    // Internal: handle reload in event loop (router feature disabled)
    #[cfg(not(feature = "router"))]
    async fn handle_reload_no_router(
        state: &Arc<RwLock<State>>,
        new_ir: sb_config::ir::ConfigIR,
    ) -> Result<()> {
        // Step 0: Ask old inbounds to stop accepting (best-effort)
        {
            let state_guard = state.read().await;
            for ib in &state_guard.bridge.inbounds {
                ib.request_shutdown();
            }
        }

        // Give old listeners a short grace to release ports
        let grace_ms = std::env::var("SB_INBOUND_RELOAD_GRACE_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1200);
        if grace_ms > 0 {
            tokio::time::sleep(Duration::from_millis(grace_ms)).await;
        }

        // Build new bridge (no engine needed)
        let new_bridge = Bridge::from_ir(&new_ir).context("failed to build new bridge")?;

        // Start new inbound listeners
        let new_bridge_arc = Arc::new(new_bridge);
        for inbound in &new_bridge_arc.inbounds {
            let ib = inbound.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = ib.serve() {
                    tracing::error!(target: "sb_core::runtime", error = %e, "new inbound serve failed");
                }
            });
        }

        // Update state atomically
        {
            let mut state_guard = state.write().await;

            // Stop old health task if any
            if let Some(old_health) = state_guard.health.take() {
                old_health.abort();
            }

            // Replace bridge and current IR (no engine field in non-router State)
            state_guard.bridge = new_bridge_arc;
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

        tracing::info!(target: "sb_core::runtime", "configuration reloaded successfully (no router)");

        Ok(())
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

            // Safety valve: don't wait extremely short — allow minimal drain window
            if now.duration_since(wait_start) > Duration::from_millis(500) && active_total == 0 {
                break;
            }
        }

        let wait_ms = Instant::now()
            .saturating_duration_since(wait_start)
            .as_millis();
        let shutdown_success = Instant::now() < deadline;

        // Cleanup state
        {
            let mut state_guard = state.write().await;
            if let Some(health) = state_guard.health.take() {
                health.abort();
            }
        }

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
            .send(ReloadMsg::Apply(new_ir.clone()))
            .await
            .context("failed to send reload message")?;

        if std::env::var("SB_RUNTIME_DIFF").ok().as_deref() == Some("1") {
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

#[cfg(feature = "router")]
impl Engine<'_> {
    /// Create engine from IR configuration
    pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Engine<'static>> {
        // This should use existing engine construction logic
        // For now, create a minimal engine
        Ok(Engine::new(Box::leak(Box::new(ir.clone()))))
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
        Self::new_from_config(ir).context("failed to create bridge from config")
    }
}
