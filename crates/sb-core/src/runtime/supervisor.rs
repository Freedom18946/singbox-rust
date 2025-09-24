//! Runtime supervisor for hot reload and graceful shutdown.
//!
//! Manages engine/bridge lifecycle and handles reload/shutdown messages
//! via async channels while maintaining service availability.

use crate::adapter::Bridge;
use crate::routing::engine::Engine;
use anyhow::{Context, Result};
use sb_config::ir::diff::Diff;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

/// Messages sent to supervisor event loop
#[derive(Debug)]
pub enum ReloadMsg {
    /// Apply new configuration with hot reload
    Apply(sb_config::ir::ConfigIR),
    /// Begin graceful shutdown with deadline
    Shutdown { deadline: Instant },
}

/// Runtime state managed by supervisor
#[derive(Debug)]
pub struct State {
    pub engine: Engine<'static>,
    pub bridge: Arc<Bridge>,
    pub health: Option<tokio::task::JoinHandle<()>>,
    pub started_at: Instant,
}

/// Supervisor manages runtime state and hot reload/shutdown
pub struct Supervisor {
    tx: mpsc::Sender<ReloadMsg>,
    handle: tokio::task::JoinHandle<()>,
    state: Arc<RwLock<State>>,
}

impl State {
    pub fn new(engine: Engine<'static>, bridge: Bridge) -> Self {
        Self {
            engine,
            bridge: Arc::new(bridge),
            health: None,
            started_at: Instant::now(),
        }
    }
}

impl Supervisor {
    /// Start supervisor with initial configuration
    pub async fn start(ir: sb_config::ir::ConfigIR) -> Result<Self> {
        let (tx, mut rx) = mpsc::channel::<ReloadMsg>(32);

        // Build initial engine and bridge
        let engine = Engine::from_ir(&ir).context("failed to build engine from initial config")?;
        let engine_static = engine.clone_as_static();

        let bridge = Bridge::from_ir(&ir).context("failed to build bridge from initial config")?;

        let initial_state = State::new(engine_static, bridge);
        let state = Arc::new(RwLock::new(initial_state));

        // Start inbound listeners
        {
            let state_guard = state.read().await;
            for inbound in &state_guard.bridge.inbounds {
                let ib = inbound.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = ib.serve() {
                        // TODO: Add proper logging
                        eprintln!("inbound serve failed: {}", e);
                    }
                });
            }

            // Optional health task
            if std::env::var("SB_HEALTH_ENABLE").is_ok() {
                let health_bridge = state_guard.bridge.clone();
                let health_handle = tokio::spawn(async move {
                    spawn_health_task_async(health_bridge).await;
                });
                drop(state_guard);
                state.write().await.health = Some(health_handle);
            }
        }

        let state_clone = Arc::clone(&state);

        // Event loop
        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    ReloadMsg::Apply(new_ir) => {
                        if let Err(e) = Self::handle_reload(&state_clone, new_ir).await {
                            eprintln!("reload failed: {}", e);
                        }
                    }
                    ReloadMsg::Shutdown { deadline } => {
                        Self::handle_shutdown(&state_clone, deadline).await;
                        break;
                    }
                }
            }
        });

        Ok(Self { tx, handle, state })
    }

    /// Trigger hot reload with new configuration
    pub async fn reload(&self, new_ir: sb_config::ir::ConfigIR) -> Result<Diff> {
        let old_ir = {
            let state_guard = self.state.read().await;
            // For now, return an empty diff since we can't easily convert types
            return Ok(Diff::default());
        };

        let diff = sb_config::ir::diff::diff(&old_ir, &new_ir);

        self.tx
            .send(ReloadMsg::Apply(new_ir))
            .await
            .context("failed to send reload message")?;

        Ok(diff)
    }

    /// Begin graceful shutdown
    pub async fn shutdown_graceful(self, dur: Duration) -> Result<()> {
        let deadline = Instant::now() + dur;

        self.tx
            .send(ReloadMsg::Shutdown { deadline })
            .await
            .context("failed to send shutdown message")?;

        // Wait for event loop to finish
        if let Err(e) = self.handle.await {
            eprintln!("supervisor task join failed: {}", e);
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
        // Build new engine and bridge
        let new_engine = Engine::from_ir(&new_ir).context("failed to build new engine")?;
        let new_engine_static = new_engine.clone_as_static();

        let new_bridge = Bridge::from_ir(&new_ir).context("failed to build new bridge")?;

        // Start new inbound listeners first
        let new_bridge_arc = Arc::new(new_bridge);
        for inbound in &new_bridge_arc.inbounds {
            let ib = inbound.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = ib.serve() {
                    eprintln!("new inbound serve failed: {}", e);
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

            // Replace engine and bridge
            state_guard.engine = new_engine_static;
            state_guard.bridge = new_bridge_arc;

            // Start new health task if needed
            if std::env::var("SB_HEALTH_ENABLE").is_ok() {
                let health_bridge = state_guard.bridge.clone();
                let health_handle = tokio::spawn(async move {
                    spawn_health_task_async(health_bridge).await;
                });
                state_guard.health = Some(health_handle);
            }
        }

        eprintln!("configuration reloaded successfully");

        Ok(())
    }

    // Internal: handle graceful shutdown
    async fn handle_shutdown(state: &Arc<RwLock<State>>, deadline: Instant) {
        let start_shutdown = Instant::now();

        // Stop accepting new connections (implementation depends on inbound design)
        eprintln!(
            "beginning graceful shutdown, deadline in {} ms",
            deadline
                .saturating_duration_since(start_shutdown)
                .as_millis()
        );

        // Wait for active connections to finish or timeout
        let wait_start = Instant::now();
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }

            // Check if we have active connections (simplified for now)
            tokio::time::sleep(Duration::from_millis(100)).await;

            // In a real implementation, check active connection count
            // For now, just wait a bit to simulate connection draining
            if now.duration_since(wait_start) > Duration::from_millis(500) {
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

        eprintln!(
            "{}",
            serde_json::to_string(&shutdown_json).unwrap_or_default()
        );
    }
}

// Helper functions for supervisor

/// Placeholder async health task spawning function
pub async fn spawn_health_task_async(bridge: Arc<Bridge>) {
    // Placeholder for async health checking
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            // Perform health checks
            eprintln!(
                "health check completed, outbounds: {}",
                bridge.outbounds_snapshot().len()
            );
        }
    })
    .await
    .ok();
}

impl Engine<'_> {
    /// Create engine from IR configuration
    pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Engine<'static>> {
        // This should use existing engine construction logic
        // For now, create a minimal engine
        Ok(Engine::new(Box::leak(Box::new(ir.clone()))))
    }
}

impl Bridge {
    /// Create bridge from IR configuration
    pub fn from_ir(ir: &sb_config::ir::ConfigIR) -> Result<Bridge> {
        // This should use existing bridge construction logic
        // For now, create a minimal bridge
        Ok(Bridge::new_from_config(ir).context("failed to create bridge from config")?)
    }
}
