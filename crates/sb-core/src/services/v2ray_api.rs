//! V2Ray API Server Implementation
//!
//! Provides V2Ray-compatible API for statistics and management via gRPC.
//! This module bridges the sb-core context with sb-api's V2Ray implementation.
//!
//! ## Services
//! - Stats Service: Query traffic statistics
//!
//! ## Endpoints
//! Exposed via gRPC on the configured listen address.

use crate::context::{
    V2RayServer, V2RayServerActiveGeneration, V2RayServerActivePhase, V2RayServerExit,
    V2RayServerExitRecord, V2RayServerRuntimeSnapshot,
};
use parking_lot::{Mutex, RwLock};
use sb_config::ir::{StatsIR, V2RayApiIR};
use std::collections::{HashMap, HashSet};
#[cfg(any(feature = "service_v2ray_api", test))]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{oneshot, watch};

#[cfg(feature = "service_v2ray_api")]
use tonic::{transport::Server, Request, Response, Status};

#[cfg(feature = "service_v2ray_api")]
use crate::services::v2ray::stats::command::{
    stats_service_server::{StatsService, StatsServiceServer},
    GetStatsRequest, GetStatsResponse, QueryStatsRequest, QueryStatsResponse, Stat,
    SysStatsRequest, SysStatsResponse,
};

/// Statistics counter
#[derive(Debug, Default)]
pub struct StatCounter {
    value: AtomicU64,
}

impl StatCounter {
    /// Create a new counter with initial value
    pub fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }

    /// Get current value
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Add to counter
    pub fn add(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::SeqCst);
    }

    /// Reset counter and return previous value
    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::SeqCst)
    }
}

/// Statistics manager
#[derive(Debug)]
pub struct StatsManager {
    enabled: bool,
    created_at: Instant,
    inbounds: HashSet<String>,
    outbounds: HashSet<String>,
    users: HashSet<String>,
    track_all_inbounds: bool,
    track_all_outbounds: bool,
    counters: RwLock<HashMap<String, Arc<StatCounter>>>,
}

impl StatsManager {
    /// Create a new stats manager from config.
    pub fn new(cfg: Option<StatsIR>) -> Self {
        let cfg = cfg.unwrap_or_default();
        let track_all_inbounds = cfg.inbound.unwrap_or(false);
        let track_all_outbounds = cfg.outbound.unwrap_or(false);
        let inbounds = cfg.inbounds.into_iter().collect();
        let outbounds = cfg.outbounds.into_iter().collect();
        let users = cfg.users.into_iter().collect();

        Self {
            enabled: cfg.enabled,
            created_at: Instant::now(),
            inbounds,
            outbounds,
            users,
            track_all_inbounds,
            track_all_outbounds,
            counters: RwLock::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get or create a counter.
    pub fn get_counter(&self, name: &str) -> Arc<StatCounter> {
        if let Some(counter) = self.counters.read().get(name) {
            return counter.clone();
        }
        let mut counters = self.counters.write();
        counters
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(StatCounter::new(0)))
            .clone()
    }

    /// Get counter value by name.
    pub fn get_stat(&self, name: &str) -> Option<u64> {
        self.counters.read().get(name).map(|c| c.get())
    }

    /// Query stats matching patterns.
    pub fn query_stats(&self, patterns: &[String], regex: bool, reset: bool) -> Vec<(String, u64)> {
        let counters = self.counters.read();
        let mut out = Vec::new();

        let mut matchers = Vec::new();
        if regex {
            for pattern in patterns {
                if let Ok(re) = regex::Regex::new(pattern) {
                    matchers.push(re);
                }
            }
        }

        for (name, counter) in counters.iter() {
            let matched = if patterns.is_empty() {
                true
            } else if regex {
                matchers.iter().any(|re| re.is_match(name))
            } else {
                patterns.iter().any(|pat| name.contains(pat))
            };

            if matched {
                let value = if reset {
                    counter.reset()
                } else {
                    counter.get()
                };
                out.push((name.clone(), value));
            }
        }

        out
    }

    fn should_track_inbound(&self, inbound: &str) -> bool {
        if !self.enabled || inbound.is_empty() {
            return false;
        }
        if self.track_all_inbounds {
            return true;
        }
        if self.inbounds.is_empty() {
            return false;
        }
        self.inbounds.contains(inbound)
    }

    fn should_track_outbound(&self, outbound: &str) -> bool {
        if !self.enabled || outbound.is_empty() {
            return false;
        }
        if self.track_all_outbounds {
            return true;
        }
        if self.outbounds.is_empty() {
            return false;
        }
        self.outbounds.contains(outbound)
    }

    fn should_track_user(&self, user: &str) -> bool {
        if !self.enabled || user.is_empty() {
            return false;
        }
        if self.users.is_empty() {
            return false;
        }
        self.users.contains(user)
    }

    pub fn traffic_recorder(
        &self,
        inbound: Option<&str>,
        outbound: Option<&str>,
        user: Option<&str>,
    ) -> Option<Arc<dyn crate::net::metered::TrafficRecorder>> {
        if !self.enabled {
            return None;
        }

        let mut uplink = Vec::new();
        let mut downlink = Vec::new();
        let mut uplink_packets = Vec::new();
        let mut downlink_packets = Vec::new();

        if let Some(tag) = inbound {
            if self.should_track_inbound(tag) {
                uplink.push(self.get_counter(&format!("inbound>>>{}>>>traffic>>>uplink", tag)));
                downlink.push(self.get_counter(&format!("inbound>>>{}>>>traffic>>>downlink", tag)));
                uplink_packets
                    .push(self.get_counter(&format!("inbound>>>{}>>>packet>>>uplink", tag)));
                downlink_packets
                    .push(self.get_counter(&format!("inbound>>>{}>>>packet>>>downlink", tag)));
            }
        }

        if let Some(tag) = outbound {
            if self.should_track_outbound(tag) {
                uplink.push(self.get_counter(&format!("outbound>>>{}>>>traffic>>>uplink", tag)));
                downlink
                    .push(self.get_counter(&format!("outbound>>>{}>>>traffic>>>downlink", tag)));
                uplink_packets
                    .push(self.get_counter(&format!("outbound>>>{}>>>packet>>>uplink", tag)));
                downlink_packets
                    .push(self.get_counter(&format!("outbound>>>{}>>>packet>>>downlink", tag)));
            }
        }

        if let Some(name) = user {
            if self.should_track_user(name) {
                uplink.push(self.get_counter(&format!("user>>>{}>>>traffic>>>uplink", name)));
                downlink.push(self.get_counter(&format!("user>>>{}>>>traffic>>>downlink", name)));
                uplink_packets
                    .push(self.get_counter(&format!("user>>>{}>>>packet>>>uplink", name)));
                downlink_packets
                    .push(self.get_counter(&format!("user>>>{}>>>packet>>>downlink", name)));
            }
        }

        if uplink.is_empty() && downlink.is_empty() {
            return None;
        }

        Some(Arc::new(TrafficCounters {
            uplink,
            downlink,
            uplink_packets,
            downlink_packets,
        }))
    }

    /// Initialize standard V2Ray counters
    pub fn init_standard_counters(&self) {
        let counters = [
            "inbound>>>api>>>traffic>>>uplink",
            "inbound>>>api>>>traffic>>>downlink",
            "outbound>>>direct>>>traffic>>>uplink",
            "outbound>>>direct>>>traffic>>>downlink",
            "outbound>>>proxy>>>traffic>>>uplink",
            "outbound>>>proxy>>>traffic>>>downlink",
            "inbound>>>api>>>packet>>>uplink",
            "inbound>>>api>>>packet>>>downlink",
            "outbound>>>direct>>>packet>>>uplink",
            "outbound>>>direct>>>packet>>>downlink",
            "outbound>>>proxy>>>packet>>>uplink",
            "outbound>>>proxy>>>packet>>>downlink",
        ];

        for name in counters {
            self.get_counter(name);
        }
    }
}

#[derive(Debug)]
pub struct TrafficCounters {
    uplink: Vec<Arc<StatCounter>>,
    downlink: Vec<Arc<StatCounter>>,
    uplink_packets: Vec<Arc<StatCounter>>,
    downlink_packets: Vec<Arc<StatCounter>>,
}

impl crate::net::metered::TrafficRecorder for TrafficCounters {
    fn record_up(&self, bytes: u64) {
        for counter in &self.uplink {
            counter.add(bytes);
        }
    }

    fn record_down(&self, bytes: u64) {
        for counter in &self.downlink {
            counter.add(bytes);
        }
    }

    fn record_up_packet(&self, packets: u64) {
        for counter in &self.uplink_packets {
            counter.add(packets);
        }
    }

    fn record_down_packet(&self, packets: u64) {
        for counter in &self.downlink_packets {
            counter.add(packets);
        }
    }
}

/// V2Ray API server state
#[derive(Clone)]
pub struct V2RayApiState {
    stats: Arc<StatsManager>,
    enabled: bool,
}

impl std::fmt::Debug for V2RayApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2RayApiState")
            .field("enabled", &self.enabled)
            .finish()
    }
}

/// One active (running or draining) V2Ray server generation.
///
/// The shutdown sender and the generation-local `shutdown_requested` marker are bound to *this*
/// generation, so `close()` can only stop the generation it read and a monitor can only classify
/// its own generation's terminal — no generation-blind shared flag.
#[derive(Debug)]
struct RunningGeneration {
    generation: u64,
    phase: V2RayServerActivePhase,
    /// Set by `close()` when a shutdown is requested for this generation; read by this
    /// generation's monitor to distinguish `CleanShutdown` from `UnexpectedCompletion`.
    #[allow(dead_code)]
    shutdown_requested: Arc<AtomicBool>,
    /// This generation's shutdown signal sender (always `None` in the no-feature stub build).
    #[allow(dead_code)]
    shutdown_tx: Option<oneshot::Sender<()>>,
}

/// The single arbiter of V2Ray server lifecycle state, guarded by one mutex.
///
/// `next_generation`, `current`, and `last_exit` are all mutated only under that mutex; the
/// `watch` sender publishes the resulting snapshot. No `.await` is ever held across the mutex.
#[derive(Debug)]
struct V2RayLifecycle {
    /// Next generation id to hand out; the first successful start consumes `1`.
    next_generation: u64,
    /// The newest active generation, if any.
    current: Option<RunningGeneration>,
    /// Highest-generation terminal outcome seen so far (monotonic, never regresses).
    last_exit: Option<V2RayServerExitRecord>,
}

impl V2RayLifecycle {
    fn new() -> Self {
        Self {
            next_generation: 1,
            current: None,
            last_exit: None,
        }
    }

    /// Build the public snapshot from the current control state.
    fn snapshot(&self) -> V2RayServerRuntimeSnapshot {
        V2RayServerRuntimeSnapshot {
            current: self.current.as_ref().map(|g| V2RayServerActiveGeneration {
                generation: g.generation,
                phase: g.phase.clone(),
            }),
            last_exit: self.last_exit.clone(),
        }
    }
}

/// V2Ray API server
#[derive(Debug)]
pub struct V2RayApiServer {
    cfg: V2RayApiIR,
    state: V2RayApiState,
    /// The single lifecycle arbiter; shared with each generation's monitor task so it can commit
    /// its terminal under the same mutex.
    lifecycle: Arc<Mutex<V2RayLifecycle>>,
    /// Publishes the latest runtime snapshot to late subscribers. Outlives every serve task.
    runtime_tx: watch::Sender<V2RayServerRuntimeSnapshot>,
}

impl V2RayApiServer {
    /// Create a new V2Ray API server
    pub fn new(cfg: V2RayApiIR) -> Self {
        let stats = Arc::new(StatsManager::new(cfg.stats.clone()));
        let enabled = stats.enabled();
        let (runtime_tx, _) = watch::channel(V2RayServerRuntimeSnapshot::default());

        Self {
            cfg,
            state: V2RayApiState { stats, enabled },
            lifecycle: Arc::new(Mutex::new(V2RayLifecycle::new())),
            runtime_tx,
        }
    }

    /// Hand out the next monotonic generation id under the lifecycle mutex.
    ///
    /// Advances `next_generation` only on success; never wraps. Returns `Err` (consuming no
    /// generation) when the counter would overflow `u64`.
    fn allocate_generation(lifecycle: &mut V2RayLifecycle) -> anyhow::Result<u64> {
        let generation = lifecycle.next_generation;
        let advanced = generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("V2Ray API generation counter overflow"))?;
        lifecycle.next_generation = advanced;
        Ok(generation)
    }

    /// Map a monitored serve task's join outcome to a terminal exit.
    ///
    /// Generic over the serve error type so tests can synthesize outcomes without a tonic error.
    #[allow(dead_code)]
    fn classify_exit<E: std::fmt::Display>(
        outcome: Result<Result<(), E>, tokio::task::JoinError>,
        shutdown_requested: bool,
    ) -> V2RayServerExit {
        match outcome {
            Ok(Ok(())) => {
                if shutdown_requested {
                    V2RayServerExit::CleanShutdown
                } else {
                    V2RayServerExit::UnexpectedCompletion
                }
            }
            Ok(Err(e)) => V2RayServerExit::ServeError(e.to_string()),
            Err(join_err) => {
                if join_err.is_panic() {
                    let payload = join_err.into_panic();
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "panic with non-string payload".to_string());
                    V2RayServerExit::Panicked(msg)
                } else if join_err.is_cancelled() {
                    V2RayServerExit::Cancelled
                } else {
                    // No other JoinError kind exists today; map to the nearest defined terminal.
                    V2RayServerExit::Cancelled
                }
            }
        }
    }

    /// Publish the current lifecycle snapshot to the watch channel **while the lifecycle mutex is
    /// held**.
    ///
    /// `send_replace` is synchronous (no `.await`), so it is safe — and required — to call it inside
    /// the critical section. Capturing the snapshot under the lock but sending it after unlocking
    /// would open a backflow window: a stale snapshot could overwrite a newer one published by a
    /// concurrent generation (e.g. an older `commit_terminal` racing a newer `start`). Serializing
    /// mutation → capture → send under one mutex makes watch ordering match lifecycle ordering.
    fn publish_snapshot_locked(
        lifecycle: &V2RayLifecycle,
        runtime_tx: &watch::Sender<V2RayServerRuntimeSnapshot>,
    ) {
        let _ = runtime_tx.send_replace(lifecycle.snapshot());
    }

    /// Commit a generation's terminal outcome under the lifecycle mutex, then publish.
    ///
    /// Generation-checked so an older generation's late exit can never clear a newer `current`
    /// nor regress `last_exit`:
    /// - clears `current` only if it still owns this generation;
    /// - updates `last_exit` only if this generation id is the highest terminal seen so far.
    #[allow(dead_code)]
    fn commit_terminal(
        lifecycle: &Arc<Mutex<V2RayLifecycle>>,
        runtime_tx: &watch::Sender<V2RayServerRuntimeSnapshot>,
        generation: u64,
        exit: V2RayServerExit,
    ) {
        let mut lc = lifecycle.lock();
        if lc.current.as_ref().map(|g| g.generation) == Some(generation) {
            lc.current = None;
        }
        let replace = match &lc.last_exit {
            None => true,
            Some(rec) => generation > rec.generation,
        };
        if replace {
            lc.last_exit = Some(V2RayServerExitRecord { generation, exit });
        }
        // Capture + send under the lock (see publish_snapshot_locked).
        Self::publish_snapshot_locked(&lc, runtime_tx);
    }

    /// Get reference to stats manager
    pub fn stats(&self) -> &Arc<StatsManager> {
        &self.state.stats
    }

    /// Check if stats are enabled
    pub fn stats_enabled(&self) -> bool {
        self.state.enabled
    }

    /// Get listen address
    #[cfg(any(feature = "service_v2ray_api", test))]
    fn listen_addr(&self) -> Option<SocketAddr> {
        self.cfg.listen.as_ref().and_then(|addr| addr.parse().ok())
    }

    /// Synchronously bind the gRPC TCP listener so a bind failure (e.g. address
    /// already in use) surfaces as `Err` from `start()` — instead of a detached
    /// tonic task logging-and-exiting while the sidecar still reports started.
    /// Mirrors the dns_forwarder / DERP / SSM-API std-bind -> `from_std` pattern;
    /// tonic then serves over the pre-bound listener via `serve_with_incoming_shutdown`.
    #[cfg(feature = "service_v2ray_api")]
    fn pre_bind(addr: SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
        let std_listener = Self::bind_std_listener_with_retry(addr)?;
        std_listener.set_nonblocking(true).map_err(|e| {
            anyhow::anyhow!("V2Ray API failed to set non-blocking on {}: {}", addr, e)
        })?;
        tokio::net::TcpListener::from_std(std_listener).map_err(|e| {
            anyhow::anyhow!("V2Ray API failed to register listener on {}: {}", addr, e)
        })
    }

    #[cfg(feature = "service_v2ray_api")]
    fn bind_std_listener_with_retry(addr: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
        const RETRY_BUDGET: std::time::Duration = std::time::Duration::from_millis(1_000);
        const RETRY_STEP: std::time::Duration = std::time::Duration::from_millis(25);

        let started = Instant::now();
        let mut attempts = 0u32;
        loop {
            match std::net::TcpListener::bind(addr) {
                Ok(listener) => {
                    if attempts > 0 {
                        tracing::info!(
                            target: "sb_core::services::v2ray",
                            listen = %addr,
                            attempts,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "V2Ray API listener acquired after same-port release retry"
                        );
                    }
                    return Ok(listener);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::AddrInUse
                        && started.elapsed() < RETRY_BUDGET =>
                {
                    attempts = attempts.saturating_add(1);
                    let remaining = RETRY_BUDGET.saturating_sub(started.elapsed());
                    let sleep_for = remaining.min(RETRY_STEP);
                    tracing::debug!(
                        target: "sb_core::services::v2ray",
                        listen = %addr,
                        attempts,
                        backoff_ms = sleep_for.as_millis() as u64,
                        "V2Ray API listener still busy; retrying same-port release"
                    );
                    std::thread::sleep(sleep_for);
                }
                Err(error) => {
                    return Err(anyhow::anyhow!(
                        "V2Ray API failed to bind {}: {}",
                        addr,
                        error
                    ));
                }
            }
        }
    }
}

impl V2RayServer for V2RayApiServer {
    #[cfg(not(feature = "service_v2ray_api"))]
    fn start(&self) -> anyhow::Result<()> {
        // Stub build: no real serve task. The lifecycle is purely synchronous — a successful
        // start publishes Running(g); there is no monitor, so close() commits the terminal.
        {
            let mut lc = self.lifecycle.lock();
            if let Some(cur) = &lc.current {
                if cur.phase == V2RayServerActivePhase::Running {
                    return Ok(());
                }
            }
            let generation = Self::allocate_generation(&mut lc)?;
            lc.current = Some(RunningGeneration {
                generation,
                phase: V2RayServerActivePhase::Running,
                shutdown_requested: Arc::new(AtomicBool::new(false)),
                shutdown_tx: None,
            });
            // Publish under the lock (see publish_snapshot_locked).
            Self::publish_snapshot_locked(&lc, &self.runtime_tx);
        }
        tracing::info!(
            target: "sb_core::services::v2ray",
            listen = ?self.cfg.listen,
            stats_enabled = self.state.enabled,
            "V2Ray API server start requested (stub - enable 'service_v2ray_api' feature)"
        );
        Ok(())
    }

    #[cfg(feature = "service_v2ray_api")]
    fn start(&self) -> anyhow::Result<()> {
        let listen_addr = match self.listen_addr() {
            Some(addr) => addr,
            None => {
                tracing::warn!(
                    target: "sb_core::services::v2ray",
                    "V2Ray API listen address not configured, server not started"
                );
                return Ok(());
            }
        };

        // Single critical section: admission + synchronous pre-bind + generation allocation +
        // shutdown-sender install + snapshot publish. Because `pre_bind` is synchronous (no
        // `.await`), holding the lifecycle mutex across it is safe and closes the
        // close-during-start window: `close()` can never observe `current == None` between a
        // start's admission and its Running publish. The serve task is spawned AFTER the lock is
        // released.
        let (listener, shutdown_rx, shutdown_requested, generation) = {
            let mut lc = self.lifecycle.lock();

            // A second start() while already Running is an idempotent no-op; it must NOT bind a
            // second listener nor consume a generation.
            if let Some(cur) = &lc.current {
                if cur.phase == V2RayServerActivePhase::Running {
                    tracing::debug!(
                        target: "sb_core::services::v2ray",
                        "V2Ray API server already started; ignoring duplicate start"
                    );
                    return Ok(());
                }
                // ShutdownRequested: the previous generation is draining; a fresh generation may
                // start once its listener frees (transient EADDRINUSE rolls back below).
            }

            // Pre-bind synchronously so a bind failure surfaces as Err here, before any
            // generation is allocated or any Running snapshot is published.
            let listener = Self::pre_bind(listen_addr)?;

            // Allocate the generation only after a successful bind. On overflow, release the
            // listener and fail without consuming a generation.
            let generation = match Self::allocate_generation(&mut lc) {
                Ok(g) => g,
                Err(e) => {
                    drop(listener);
                    return Err(e);
                }
            };

            let shutdown_requested = Arc::new(AtomicBool::new(false));
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            lc.current = Some(RunningGeneration {
                generation,
                phase: V2RayServerActivePhase::Running,
                shutdown_requested: shutdown_requested.clone(),
                shutdown_tx: Some(shutdown_tx),
            });
            // Publish Running under the lock (see publish_snapshot_locked).
            Self::publish_snapshot_locked(&lc, &self.runtime_tx);

            (listener, shutdown_rx, shutdown_requested, generation)
        };

        // Initialize standard counters (unchanged; stats identity stays instance-scoped — see H5).
        let stats_manager = self.state.stats.clone();
        tokio::spawn(async move {
            stats_manager.init_standard_counters();
        });

        tracing::info!(
            target: "sb_core::services::v2ray",
            listen = %listen_addr,
            generation,
            stats_enabled = self.state.enabled,
            "Starting V2Ray API gRPC server"
        );

        let stats_service = StatsServiceImpl {
            stats: self.state.stats.clone(),
        };
        let lifecycle = self.lifecycle.clone();
        let runtime_tx = self.runtime_tx.clone();

        // Outer monitor is the SOLE terminal writer for this generation. It owns the inner tonic
        // serve task's JoinHandle, maps its outcome, and commits the generation-scoped terminal.
        tokio::spawn(async move {
            let inner = tokio::spawn(async move {
                // The incoming stream is built dep-free from the pre-bound TcpListener
                // (futures::stream::unfold; no tokio-stream dependency).
                let incoming = Box::pin(futures::stream::unfold(listener, |listener| async move {
                    let conn = listener.accept().await.map(|(stream, _)| stream);
                    Some((conn, listener))
                }));
                Server::builder()
                    .add_service(StatsServiceServer::new(stats_service))
                    .serve_with_incoming_shutdown(incoming, async {
                        let _ = shutdown_rx.await;
                        tracing::info!(target: "sb_core::services::v2ray", "Received shutdown signal");
                    })
                    .await
            });

            let outcome = inner.await;
            let exit = Self::classify_exit(outcome, shutdown_requested.load(Ordering::SeqCst));

            // The monitor is the single terminal logger for this generation. A stale terminal
            // that does not enter the snapshot (lower generation) is still logged once here.
            match &exit {
                V2RayServerExit::CleanShutdown => tracing::info!(
                    target: "sb_core::services::v2ray", generation,
                    "V2Ray API server generation stopped (clean shutdown)"
                ),
                V2RayServerExit::UnexpectedCompletion => tracing::warn!(
                    target: "sb_core::services::v2ray", generation,
                    "V2Ray API server generation completed without a shutdown request"
                ),
                V2RayServerExit::ServeError(e) => tracing::error!(
                    target: "sb_core::services::v2ray", generation, error = %e,
                    "V2Ray API server generation serve error"
                ),
                V2RayServerExit::Panicked(p) => tracing::error!(
                    target: "sb_core::services::v2ray", generation, panic = %p,
                    "V2Ray API server generation panicked"
                ),
                V2RayServerExit::Cancelled => tracing::warn!(
                    target: "sb_core::services::v2ray", generation,
                    "V2Ray API server generation cancelled"
                ),
            }

            Self::commit_terminal(&lifecycle, &runtime_tx, generation, exit);
        });

        Ok(())
    }

    #[cfg(not(feature = "service_v2ray_api"))]
    fn close(&self) -> anyhow::Result<()> {
        // Stub build: shutdown is synchronous and clean; there is no monitor, so close() itself
        // commits the terminal (generation-checked, mirroring commit_terminal).
        {
            let mut lc = self.lifecycle.lock();
            let generation = match lc.current.as_ref() {
                None => return Ok(()),
                Some(cur) => cur.generation,
            };
            lc.current = None;
            let replace = match &lc.last_exit {
                None => true,
                Some(rec) => generation > rec.generation,
            };
            if replace {
                lc.last_exit = Some(V2RayServerExitRecord {
                    generation,
                    exit: V2RayServerExit::CleanShutdown,
                });
            }
            // Publish under the lock (see publish_snapshot_locked).
            Self::publish_snapshot_locked(&lc, &self.runtime_tx);
        }
        Ok(())
    }

    #[cfg(feature = "service_v2ray_api")]
    fn close(&self) -> anyhow::Result<()> {
        // Synchronous, idempotent, non-blocking. Only marks the target generation as
        // ShutdownRequested and signals it; the terminal is committed later by that generation's
        // monitor. Never waits, never fabricates CleanShutdown, never clears current/last_exit.
        let shutdown_tx;
        {
            let mut lc = self.lifecycle.lock();
            match lc.current.as_mut() {
                None => return Ok(()),
                Some(cur) => {
                    if cur.phase == V2RayServerActivePhase::ShutdownRequested {
                        // Already requested for this generation; do not resend.
                        return Ok(());
                    }
                    cur.phase = V2RayServerActivePhase::ShutdownRequested;
                    cur.shutdown_requested.store(true, Ordering::SeqCst);
                    shutdown_tx = cur.shutdown_tx.take();
                }
            }
            // Publish ShutdownRequested under the lock (see publish_snapshot_locked).
            Self::publish_snapshot_locked(&lc, &self.runtime_tx);
        }
        // The shutdown signal is sent outside the lock — only the snapshot publication must be
        // serialized; the oneshot send is generation-bound and cannot reorder snapshots.
        if let Some(tx) = shutdown_tx {
            let _ = tx.send(());
        }
        Ok(())
    }

    fn stats(&self) -> Option<Arc<StatsManager>> {
        Some(self.state.stats.clone())
    }

    fn subscribe_runtime_state(&self) -> Option<watch::Receiver<V2RayServerRuntimeSnapshot>> {
        Some(self.runtime_tx.subscribe())
    }
}

// ─────────────────────────────────────────────────────────────────────────
// gRPC Handler Implementation
// ─────────────────────────────────────────────────────────────────────────

#[cfg(feature = "service_v2ray_api")]
#[derive(Debug)]
pub struct StatsServiceImpl {
    stats: Arc<StatsManager>,
}

#[cfg(feature = "service_v2ray_api")]
#[tonic::async_trait]
impl StatsService for StatsServiceImpl {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let req = request.into_inner();
        let name = req.name;
        let reset = req.reset;
        let value = match self.stats.get_stat(&name) {
            Some(v) => v,
            None => {
                return Err(Status::not_found(format!("stat '{}' not found", name)));
            }
        };
        if reset {
            let counter = self.stats.get_counter(&name);
            counter.reset();
        }

        Ok(Response::new(GetStatsResponse {
            stat: Some(Stat {
                name,
                value: value as i64,
            }),
        }))
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let req = request.into_inner();
        let reset = req.reset;
        let mut patterns = req.patterns;
        if patterns.is_empty() && !req.pattern.is_empty() {
            patterns.push(req.pattern);
        }

        let stats = self.stats.query_stats(&patterns, req.regexp, reset);
        let stat_list = stats
            .into_iter()
            .map(|(name, value)| Stat {
                name,
                value: value as i64,
            })
            .collect();

        Ok(Response::new(QueryStatsResponse { stat: stat_list }))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        // Best-effort runtime stats; Rust does not expose Go-equivalent counters.
        let uptime = self
            .stats
            .created_at()
            .elapsed()
            .as_secs()
            .try_into()
            .unwrap_or(u32::MAX);
        let resp = SysStatsResponse {
            num_goroutine: tokio::runtime::Handle::current().metrics().num_workers() as u32,
            num_gc: 0,
            alloc: 0,
            total_alloc: 0,
            sys: 0,
            mallocs: 0,
            frees: 0,
            live_objects: 0,
            pause_total_ns: 0,
            uptime,
        };
        Ok(Response::new(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stats_manager() {
        let manager = StatsManager::new(Some(StatsIR {
            enabled: true,
            ..Default::default()
        }));

        // Get counter
        let counter = manager.get_counter("test>>>traffic>>>uplink");
        assert_eq!(counter.get(), 0);

        // Add traffic
        counter.add(1024);
        assert_eq!(counter.get(), 1024);

        // Query stats
        let stats = manager.query_stats(&["traffic".to_string()], false, false);
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "test>>>traffic>>>uplink");
        assert_eq!(stats[0].1, 1024);

        // Reset
        let old = counter.reset();
        assert_eq!(old, 1024);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_server_creation() {
        let cfg = V2RayApiIR {
            listen: Some("127.0.0.1:10085".to_string()),
            stats: Some(sb_config::ir::StatsIR {
                enabled: true,
                inbounds: vec![],
                outbounds: vec![],
                users: vec![],
                inbound: Some(true),
                outbound: Some(true),
            }),
        };

        let server = V2RayApiServer::new(cfg);
        assert!(server.stats_enabled());
        assert_eq!(
            server.listen_addr(),
            Some("127.0.0.1:10085".parse().unwrap())
        );
    }

    #[test]
    fn test_packet_counters_from_recorder() {
        let manager = StatsManager::new(Some(StatsIR {
            enabled: true,
            inbounds: vec!["dns".to_string()],
            outbounds: vec!["direct".to_string()],
            users: vec!["alice".to_string()],
            inbound: None,
            outbound: None,
        }));

        let recorder = manager
            .traffic_recorder(Some("dns"), Some("direct"), Some("alice"))
            .expect("traffic recorder expected");

        recorder.record_up(10);
        recorder.record_down(20);
        recorder.record_up_packet(2);
        recorder.record_down_packet(3);

        let uplink = 10;
        let downlink = 20;
        let up_packets = 2;
        let down_packets = 3;

        let checks = [
            ("inbound>>>dns>>>traffic>>>uplink", uplink),
            ("inbound>>>dns>>>traffic>>>downlink", downlink),
            ("outbound>>>direct>>>traffic>>>uplink", uplink),
            ("outbound>>>direct>>>traffic>>>downlink", downlink),
            ("user>>>alice>>>traffic>>>uplink", uplink),
            ("user>>>alice>>>traffic>>>downlink", downlink),
            ("inbound>>>dns>>>packet>>>uplink", up_packets),
            ("inbound>>>dns>>>packet>>>downlink", down_packets),
            ("outbound>>>direct>>>packet>>>uplink", up_packets),
            ("outbound>>>direct>>>packet>>>downlink", down_packets),
            ("user>>>alice>>>packet>>>uplink", up_packets),
            ("user>>>alice>>>packet>>>downlink", down_packets),
        ];

        for (name, expected) in checks {
            let value = manager.get_stat(name).unwrap_or(0);
            assert_eq!(value, expected, "stat mismatch for {name}");
        }
    }

    // ── SVC-V2RAY-API-01A + APP-SIDECAR-LIVENESS-01E lifecycle regression tests ──
    // The V2Ray gRPC sidecar must return Err (and publish NO running generation) when its
    // listener does not bind, and must expose a generation-aware runtime snapshot across
    // repeated start/close/start. Driven directly on V2RayApiServer (it is NOT a ServiceManager
    // service). Tests that need a real bound listener are feature-gated; pure snapshot-contract
    // tests run in both builds.

    fn test_server(port: u16) -> V2RayApiServer {
        V2RayApiServer::new(V2RayApiIR {
            listen: Some(format!("127.0.0.1:{port}")),
            stats: Some(StatsIR {
                enabled: true,
                inbounds: vec![],
                outbounds: vec![],
                users: vec![],
                inbound: Some(true),
                outbound: Some(true),
            }),
        })
    }

    /// Read the latest published runtime snapshot via the public trait surface.
    fn snap(server: &V2RayApiServer) -> V2RayServerRuntimeSnapshot {
        server
            .subscribe_runtime_state()
            .expect("real V2RayApiServer exposes a runtime snapshot")
            .borrow()
            .clone()
    }

    #[cfg(feature = "service_v2ray_api")]
    fn current_generation(server: &V2RayApiServer) -> Option<u64> {
        snap(server).current.map(|g| g.generation)
    }

    #[cfg(feature = "service_v2ray_api")]
    fn reserve_port() -> Option<u16> {
        std::net::TcpListener::bind("127.0.0.1:0")
            .ok()
            .map(|l| l.local_addr().unwrap().port())
    }

    #[cfg(feature = "service_v2ray_api")]
    async fn wait_until_no_current(server: &V2RayApiServer) -> bool {
        for _ in 0..80 {
            if snap(server).current.is_none() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    #[cfg(feature = "service_v2ray_api")]
    async fn restart_with_retry(server: &V2RayApiServer) -> bool {
        for _ in 0..80 {
            if server.start().is_ok() && snap(server).current.is_some() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        false
    }

    /// Simulate the serve task ending WITHOUT a `close()` (no shutdown requested) by taking the
    /// current generation's shutdown sender directly and firing it. The monitor then sees the
    /// serve future return `Ok` with `shutdown_requested == false` → `UnexpectedCompletion`.
    #[cfg(feature = "service_v2ray_api")]
    fn signal_shutdown_without_close(server: &V2RayApiServer) {
        let tx = server
            .lifecycle
            .lock()
            .current
            .as_mut()
            .and_then(|c| c.shutdown_tx.take());
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
    }

    // ── A. Initial snapshot is empty (both builds) ──
    #[test]
    fn initial_snapshot_is_empty() {
        let server = test_server(0);
        let s = snap(&server);
        assert!(
            s.current.is_none(),
            "fresh server has no current generation"
        );
        assert!(s.last_exit.is_none(), "fresh server has no terminal");
    }

    // ── N. Trait default returns None for a non-overriding implementor ──
    #[test]
    fn trait_default_subscribe_returns_none() {
        #[derive(Debug)]
        struct MockV2Ray;
        impl V2RayServer for MockV2Ray {
            fn start(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }
        let m = MockV2Ray;
        assert!(
            m.subscribe_runtime_state().is_none(),
            "additive default must return None"
        );
    }

    // ── O. Generation counter must not wrap on overflow ──
    #[test]
    fn generation_overflow_does_not_wrap() {
        let mut lc = V2RayLifecycle::new();
        lc.next_generation = u64::MAX;
        let res = V2RayApiServer::allocate_generation(&mut lc);
        assert!(res.is_err(), "allocation at u64::MAX must fail, not wrap");
        assert_eq!(
            lc.next_generation,
            u64::MAX,
            "failed allocation must not advance/wrap the counter"
        );
    }

    // ── G. A stale (older) terminal must not clear a newer current ──
    #[test]
    fn stale_terminal_does_not_clear_newer_current() {
        let server = test_server(0);
        server.lifecycle.lock().current = Some(RunningGeneration {
            generation: 2,
            phase: V2RayServerActivePhase::Running,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_tx: None,
        });

        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            1,
            V2RayServerExit::UnexpectedCompletion,
        );

        let s = snap(&server);
        assert_eq!(
            s.current.map(|g| g.generation),
            Some(2),
            "current generation 2 must survive a generation-1 terminal"
        );
        assert_eq!(s.last_exit.map(|r| r.generation), Some(1));
    }

    // ── H. last_exit only advances by generation (monotonic, no regression) ──
    #[test]
    fn last_exit_only_advances_by_generation() {
        let server = test_server(0);
        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            2,
            V2RayServerExit::CleanShutdown,
        );
        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            1,
            V2RayServerExit::ServeError("late".into()),
        );

        let s = snap(&server);
        assert_eq!(
            s.last_exit,
            Some(V2RayServerExitRecord {
                generation: 2,
                exit: V2RayServerExit::CleanShutdown,
            }),
            "an older generation's terminal must never overwrite a newer one"
        );
    }

    // ── I. Arbitrary stale monitor order still preserves current + highest last_exit ──
    #[test]
    fn arbitrary_stale_monitor_order_preserves_state() {
        let server = test_server(0);
        server.lifecycle.lock().current = Some(RunningGeneration {
            generation: 3,
            phase: V2RayServerActivePhase::Running,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_tx: None,
        });

        // terminal(2) then terminal(1) arrive after generation 3 is already running.
        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            2,
            V2RayServerExit::CleanShutdown,
        );
        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            1,
            V2RayServerExit::Cancelled,
        );

        let s = snap(&server);
        assert_eq!(s.current.map(|g| g.generation), Some(3));
        assert_eq!(s.last_exit.map(|r| r.generation), Some(2));
    }

    // ── M. Late subscriber reads the latest terminal ──
    #[test]
    fn late_subscriber_reads_terminal() {
        let server = test_server(0);
        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            1,
            V2RayServerExit::CleanShutdown,
        );
        // Subscribe AFTER the terminal was committed.
        let late = server.subscribe_runtime_state().expect("snapshot exposed");
        assert_eq!(
            late.borrow().last_exit,
            Some(V2RayServerExitRecord {
                generation: 1,
                exit: V2RayServerExit::CleanShutdown,
            })
        );
    }

    // ── R1-A/B. Publication helper sends the CURRENT (post-mutation) state, in-lock ──
    // Guards against the "capture-under-lock, send-after-unlock" backflow shape: the single
    // publish site is publish_snapshot_locked, which captures + sends while the mutex is held, so
    // the published snapshot always reflects the lifecycle state at send time.
    #[test]
    fn publish_snapshot_locked_sends_current_state() {
        let server = test_server(0);
        {
            let mut lc = server.lifecycle.lock();
            lc.next_generation = 3;
            lc.current = Some(RunningGeneration {
                generation: 2,
                phase: V2RayServerActivePhase::Running,
                shutdown_requested: Arc::new(AtomicBool::new(false)),
                shutdown_tx: None,
            });
            V2RayApiServer::publish_snapshot_locked(&lc, &server.runtime_tx);
        }
        let s = snap(&server);
        assert_eq!(
            s.current.map(|g| (g.generation, g.phase)),
            Some((2, V2RayServerActivePhase::Running)),
            "helper must publish the state present at send time"
        );
    }

    // ── R1-B. A stale terminal arriving AFTER a newer generation is Running must not backflow ──
    // current must stay on the newer generation and last_exit must not regress.
    #[test]
    fn stale_terminal_after_newer_running_does_not_backflow() {
        let server = test_server(0);

        // gen 1 runs then exits cleanly (current cleared, last_exit = 1).
        {
            let mut lc = server.lifecycle.lock();
            lc.next_generation = 2;
            lc.current = Some(RunningGeneration {
                generation: 1,
                phase: V2RayServerActivePhase::Running,
                shutdown_requested: Arc::new(AtomicBool::new(true)),
                shutdown_tx: None,
            });
            V2RayApiServer::publish_snapshot_locked(&lc, &server.runtime_tx);
        }
        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            1,
            V2RayServerExit::CleanShutdown,
        );

        // gen 2 starts running.
        {
            let mut lc = server.lifecycle.lock();
            lc.next_generation = 3;
            lc.current = Some(RunningGeneration {
                generation: 2,
                phase: V2RayServerActivePhase::Running,
                shutdown_requested: Arc::new(AtomicBool::new(false)),
                shutdown_tx: None,
            });
            V2RayApiServer::publish_snapshot_locked(&lc, &server.runtime_tx);
        }

        // A late, stale terminal for gen 1 arrives — it must not clear current(2) nor regress.
        V2RayApiServer::commit_terminal(
            &server.lifecycle,
            &server.runtime_tx,
            1,
            V2RayServerExit::CleanShutdown,
        );

        let s = snap(&server);
        assert_eq!(
            s.current.map(|g| g.generation),
            Some(2),
            "a stale gen-1 terminal must not clear the running gen-2"
        );
        assert_eq!(s.last_exit.map(|r| r.generation), Some(1));
    }

    // ── J. classify_exit: completion + serve error ──
    #[test]
    fn classify_exit_maps_completion_and_error() {
        assert_eq!(
            V2RayApiServer::classify_exit::<String>(Ok(Ok(())), true),
            V2RayServerExit::CleanShutdown
        );
        assert_eq!(
            V2RayApiServer::classify_exit::<String>(Ok(Ok(())), false),
            V2RayServerExit::UnexpectedCompletion
        );
        assert_eq!(
            V2RayApiServer::classify_exit(Ok(Err("boom".to_string())), false),
            V2RayServerExit::ServeError("boom".to_string())
        );
    }

    // ── K. classify_exit: panic ──
    #[tokio::test]
    async fn classify_exit_maps_panic() {
        let handle = tokio::spawn(async {
            panic!("kaboom");
        });
        let outcome = handle.await.map(|()| Ok::<(), String>(()));
        match V2RayApiServer::classify_exit(outcome, false) {
            V2RayServerExit::Panicked(msg) => {
                assert!(msg.contains("kaboom"), "panic payload preserved: {msg}");
            }
            other => panic!("expected Panicked, got {other:?}"),
        }
    }

    // ── L. classify_exit: cancellation ──
    #[tokio::test]
    async fn classify_exit_maps_cancelled() {
        let handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });
        handle.abort();
        let outcome = handle.await.map(|()| Ok::<(), String>(()));
        assert_eq!(
            V2RayApiServer::classify_exit(outcome, false),
            V2RayServerExit::Cancelled
        );
    }

    // ── D. Bind failure returns Err and publishes no phantom generation ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test]
    async fn bind_conflict_returns_error_and_no_phantom_generation() {
        // Occupy a TCP port so the sidecar's synchronous pre-bind must fail.
        let occupier = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping bind_conflict test (cannot bind): {e}");
                return;
            }
        };
        let addr = occupier.local_addr().unwrap();
        let server = test_server(addr.port());

        let res = server.start();
        assert!(res.is_err(), "bind conflict must return Err, got Ok");
        let msg = format!("{}", res.unwrap_err()).to_lowercase();
        assert!(
            msg.contains("bind")
                || msg.contains("address")
                || msg.contains("in use")
                || msg.contains("addrinuse"),
            "err must carry bind/address-in-use semantics, got: {msg}"
        );
        assert!(
            snap(&server).current.is_none(),
            "a failed bind must publish no running generation"
        );
        assert_eq!(
            server.lifecycle.lock().next_generation,
            1,
            "a failed bind must consume no generation (reservation recoverable)"
        );
        drop(occupier);
    }

    // ── B + M. Successful bind publishes Running(1); late subscriber observes it ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test]
    async fn successful_bind_publishes_running() {
        let port = match reserve_port() {
            Some(p) => p,
            None => {
                eprintln!("Skipping successful_bind test (cannot bind)");
                return;
            }
        };
        let server = test_server(port);

        assert!(server.start().is_ok(), "successful bind must return Ok");
        let s = snap(&server);
        assert_eq!(s.current.as_ref().map(|g| g.generation), Some(1));
        assert_eq!(
            s.current.as_ref().map(|g| g.phase.clone()),
            Some(V2RayServerActivePhase::Running)
        );
        // Late subscriber sees the live generation.
        let late = server.subscribe_runtime_state().expect("snapshot exposed");
        assert_eq!(
            late.borrow().current.as_ref().map(|g| g.generation),
            Some(1)
        );
        server.close().unwrap();
    }

    // ── (regression) restart after a failed bind; first success is generation 1 ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test]
    async fn restart_after_failed_bind() {
        let occupier = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Skipping restart test (cannot bind): {e}");
                return;
            }
        };
        let addr = occupier.local_addr().unwrap();
        let server = test_server(addr.port());

        // First attempt: port occupied → Err, no generation consumed.
        assert!(
            server.start().is_err(),
            "first start must fail (port occupied)"
        );
        assert!(
            snap(&server).current.is_none(),
            "no running generation after a failed bind"
        );

        // Release the port; a retry must recover (failure must not be permanent).
        drop(occupier);
        assert!(
            server.start().is_ok(),
            "restart after releasing the port must succeed"
        );
        assert_eq!(
            current_generation(&server),
            Some(1),
            "the first successful start is generation 1 (failed bind consumed none)"
        );
        server.close().unwrap();
    }

    // ── C. Duplicate running start keeps the same generation, no second listener ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test]
    async fn duplicate_start_keeps_same_generation() {
        let port = match reserve_port() {
            Some(p) => p,
            None => {
                eprintln!("Skipping duplicate_start test (cannot bind)");
                return;
            }
        };
        let server = test_server(port);

        assert!(server.start().is_ok(), "first start must bind");
        assert_eq!(current_generation(&server), Some(1));

        // A second start() is an idempotent no-op: Ok WITHOUT a second bind and WITHOUT a new
        // generation. (A second bind on the held port would Err — Ok here proves no new listener.)
        assert!(
            server.start().is_ok(),
            "duplicate start must be an idempotent Ok"
        );
        assert_eq!(
            current_generation(&server),
            Some(1),
            "duplicate start must not mint a new generation"
        );
        assert_eq!(
            server.lifecycle.lock().next_generation,
            2,
            "only one generation consumed across duplicate starts"
        );
        server.close().unwrap();
    }

    // ── E. Normal close: ShutdownRequested(1) then clean terminal ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test]
    async fn normal_close_publishes_shutdown_then_clean_exit() {
        let port = match reserve_port() {
            Some(p) => p,
            None => {
                eprintln!("Skipping normal_close test (cannot bind)");
                return;
            }
        };
        let server = test_server(port);

        assert!(server.start().is_ok(), "first start must bind");
        server.close().unwrap();

        // close() publishes ShutdownRequested synchronously (before the monitor commits).
        let s = snap(&server);
        assert_eq!(
            s.current.map(|g| (g.generation, g.phase)),
            Some((1, V2RayServerActivePhase::ShutdownRequested))
        );

        // The monitor eventually commits the clean terminal.
        assert!(
            wait_until_no_current(&server).await,
            "serve task must terminate after close"
        );
        let s2 = snap(&server);
        assert!(s2.current.is_none());
        assert_eq!(
            s2.last_exit,
            Some(V2RayServerExitRecord {
                generation: 1,
                exit: V2RayServerExit::CleanShutdown,
            })
        );
    }

    // ── F. Bounded same-port release retry reaches generation 2 without caller-side retry ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_same_port_release_retry_reaches_generation_two() {
        let port = match reserve_port() {
            Some(p) => p,
            None => {
                eprintln!("Skipping bounded_same_port_release_retry test (cannot bind)");
                return;
            }
        };
        let server = test_server(port);

        assert!(server.start().is_ok(), "first start must bind");
        assert_eq!(current_generation(&server), Some(1));
        server.close().unwrap();

        // The previous serve task releases the port asynchronously after close(); start() itself
        // must absorb the transient AddrInUse window with a bounded retry.
        assert!(
            server.start().is_ok(),
            "same-port rapid re-enable must succeed inside V2RayApiServer::start()"
        );
        assert_eq!(
            current_generation(&server),
            Some(2),
            "the restart must be a new generation"
        );
        server.close().unwrap();
    }

    // ── Task exit WITHOUT close() → UnexpectedCompletion; restart still works ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test]
    async fn task_exit_without_close_is_unexpected_completion() {
        let port = match reserve_port() {
            Some(p) => p,
            None => {
                eprintln!("Skipping task_exit test (cannot bind)");
                return;
            }
        };
        let server = test_server(port);

        assert!(
            server.start().is_ok(),
            "server must bind before task-exit test"
        );
        assert_eq!(current_generation(&server), Some(1));

        // Fire the shutdown signal directly (no close → no shutdown request recorded).
        signal_shutdown_without_close(&server);
        assert!(
            wait_until_no_current(&server).await,
            "serve task exit must clear the current generation"
        );
        assert_eq!(
            snap(&server).last_exit.map(|r| (r.generation, r.exit)),
            Some((1, V2RayServerExit::UnexpectedCompletion)),
            "an exit with no shutdown request is UnexpectedCompletion"
        );

        // A later restart still works and mints generation 2.
        assert!(restart_with_retry(&server).await);
        assert_eq!(current_generation(&server), Some(2));
        server.close().unwrap();
    }

    // ── P. start() publishes Running synchronously; no sneaky start-after-close window ──
    #[cfg(feature = "service_v2ray_api")]
    #[tokio::test]
    async fn start_publishes_running_synchronously() {
        let port = match reserve_port() {
            Some(p) => p,
            None => {
                eprintln!("Skipping start_publishes_running test (cannot bind)");
                return;
            }
        };
        let server = test_server(port);

        // Running is published WITHIN start()'s critical section, observable immediately with no
        // await — so close(), taking the same lifecycle mutex, can never miss it (no
        // close-observes-None-then-start-publishes-Running window).
        assert!(server.start().is_ok());
        assert_eq!(
            snap(&server).current.map(|g| (g.generation, g.phase)),
            Some((1, V2RayServerActivePhase::Running))
        );
        server.close().unwrap();
        assert_eq!(
            snap(&server).current.map(|g| g.phase),
            Some(V2RayServerActivePhase::ShutdownRequested)
        );

        // close() with genuinely no current is a clean Ok and publishes no Running.
        let fresh = test_server(0);
        assert!(fresh.close().is_ok());
        assert!(snap(&fresh).current.is_none());
    }
}
