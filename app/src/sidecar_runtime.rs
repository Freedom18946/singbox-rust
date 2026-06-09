//! App-level sidecar runtime snapshot adapter + run-engine event bridge
//! (APP-SIDECAR-LIVENESS-01F / 01G-B / 01H-B).
//!
//! A thin, read-only projection of a sidecar's source-of-truth runtime snapshot into an
//! app-internal liveness model. Two source kinds:
//! - **`V2Ray`**: maps `sb_core::context::V2RayServerRuntimeSnapshot` (published by sb-core).
//! - **Clash**: the app task owner publishes the app-level `SidecarRuntimeSnapshot` directly, so the
//!   Clash arm is an identity read (no second mapping).
//!
//! Design discipline:
//! - There is exactly ONE source `watch::Receiver` per subscription. This adapter borrows + reads on
//!   demand; it never spawns a forwarding task and never creates a second `watch` channel.
//! - The `V2Ray` mapping is pure: generations, phases, exit records, and error strings cross verbatim;
//!   no timestamps are fabricated; no app failure policy is applied; no full terminal history kept.
//! - sb-core's source enums are `#[non_exhaustive]`; every mapping keeps a wildcard arm that degrades
//!   unknown future variants to `Unknown` — never `panic!`/`unreachable!()`, never a silent collapse.
//!
//! The run-engine event bridge (bottom of this file) projects ONLY terminal / projection-closed into
//! an app-local mpsc consumed log-only; the source outer monitors stay the sole terminal loggers.

#[cfg(feature = "v2ray_api")]
use sb_core::context::{
    V2RayServer, V2RayServerActivePhase, V2RayServerExit, V2RayServerRuntimeSnapshot,
};
use tokio::sync::watch;

/// App-internal liveness snapshot for a sidecar runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SidecarRuntimeSnapshot {
    /// The newest active generation, if any is running or shutting down.
    pub current: Option<SidecarActiveGeneration>,
    /// The terminal outcome of the highest generation that has exited so far.
    pub last_exit: Option<SidecarExitRecord>,
}

/// An active (running or draining) sidecar generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarActiveGeneration {
    pub generation: u64,
    pub phase: SidecarActivePhase,
}

/// Active-phase of a sidecar generation. `Unknown` absorbs future source variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarActivePhase {
    Running,
    ShutdownRequested,
    Unknown,
}

/// A terminal outcome bound to the generation that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarExitRecord {
    pub generation: u64,
    pub exit: SidecarExit,
}

/// Terminal outcome of a sidecar generation. `Unknown` absorbs future source variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarExit {
    CleanShutdown,
    UnexpectedCompletion,
    ServeError(String),
    Panicked(String),
    Cancelled,
    Unknown,
}

/// The source a subscription projects from.
enum SidecarRuntimeSource {
    #[cfg(feature = "v2ray_api")]
    V2Ray(watch::Receiver<V2RayServerRuntimeSnapshot>),
    #[cfg(feature = "clash_api")]
    Clash(watch::Receiver<SidecarRuntimeSnapshot>),
}

/// A thin, named subscription that reads a sidecar's source runtime snapshot into the app model.
///
/// Holds the single source `watch::Receiver` directly — no forwarding task, no second channel.
pub struct SidecarRuntimeSubscription {
    name: String,
    source: SidecarRuntimeSource,
}

impl SidecarRuntimeSubscription {
    /// Build a subscription from a `V2Ray` server's runtime-state capability.
    ///
    /// Returns `None` when the server does not expose a runtime snapshot (the `V2RayServer` trait
    /// default returns `None`). `None` means "capability absent", NOT "exited" — callers must not
    /// treat it as a terminal state.
    #[cfg(feature = "v2ray_api")]
    pub fn from_v2ray_server(name: impl Into<String>, server: &dyn V2RayServer) -> Option<Self> {
        let receiver = server.subscribe_runtime_state()?;
        Some(Self {
            name: name.into(),
            source: SidecarRuntimeSource::V2Ray(receiver),
        })
    }

    /// Build a subscription from a Clash runtime source.
    ///
    /// Unlike `from_v2ray_server`, this is infallible: the Clash task owner always publishes an
    /// app-level snapshot, so the source is always present. The Clash arm is an identity read.
    #[cfg(feature = "clash_api")]
    pub fn from_clash(
        name: impl Into<String>,
        receiver: watch::Receiver<SidecarRuntimeSnapshot>,
    ) -> Self {
        Self {
            name: name.into(),
            source: SidecarRuntimeSource::Clash(receiver),
        }
    }

    /// The sidecar name this subscription was created for.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read the current snapshot and mark this version as seen.
    ///
    /// Uses `borrow_and_update()` (not `borrow()`): an observer that reads the initial snapshot on
    /// startup should mark the current version seen so a subsequent `changed()` only resolves on a
    /// genuinely newer version, never re-consuming the same one.
    pub fn snapshot_and_mark_seen(&mut self) -> SidecarRuntimeSnapshot {
        match &mut self.source {
            #[cfg(feature = "v2ray_api")]
            SidecarRuntimeSource::V2Ray(rx) => map_v2ray_snapshot(&rx.borrow_and_update()),
            #[cfg(feature = "clash_api")]
            SidecarRuntimeSource::Clash(rx) => rx.borrow_and_update().clone(),
        }
    }

    /// Await the next snapshot change, then read and return it.
    ///
    /// Propagates `watch::error::RecvError` on a closed source channel — channel closure is left
    /// for a later consumer-policy layer and is NOT disguised as a terminal exit.
    pub async fn changed(&mut self) -> Result<SidecarRuntimeSnapshot, watch::error::RecvError> {
        match &mut self.source {
            #[cfg(feature = "v2ray_api")]
            SidecarRuntimeSource::V2Ray(rx) => {
                rx.changed().await?;
                Ok(map_v2ray_snapshot(&rx.borrow_and_update()))
            }
            #[cfg(feature = "clash_api")]
            SidecarRuntimeSource::Clash(rx) => {
                rx.changed().await?;
                Ok(rx.borrow_and_update().clone())
            }
        }
    }
}

/// Pure projection of a `V2Ray` source snapshot into the app model.
#[cfg(feature = "v2ray_api")]
fn map_v2ray_snapshot(source: &V2RayServerRuntimeSnapshot) -> SidecarRuntimeSnapshot {
    SidecarRuntimeSnapshot {
        current: source.current.as_ref().map(|g| SidecarActiveGeneration {
            generation: g.generation,
            phase: map_v2ray_phase(&g.phase),
        }),
        last_exit: source.last_exit.as_ref().map(|r| SidecarExitRecord {
            generation: r.generation,
            exit: map_v2ray_exit(&r.exit),
        }),
    }
}

/// Map a source active-phase; unknown future variants degrade to `Unknown`.
#[cfg(feature = "v2ray_api")]
const fn map_v2ray_phase(phase: &V2RayServerActivePhase) -> SidecarActivePhase {
    match phase {
        V2RayServerActivePhase::Running => SidecarActivePhase::Running,
        V2RayServerActivePhase::ShutdownRequested => SidecarActivePhase::ShutdownRequested,
        // sb-core's enum is #[non_exhaustive]: never panic, never collapse to a real phase.
        _ => SidecarActivePhase::Unknown,
    }
}

/// Map a source terminal exit; unknown future variants degrade to `Unknown`.
#[cfg(feature = "v2ray_api")]
fn map_v2ray_exit(exit: &V2RayServerExit) -> SidecarExit {
    match exit {
        V2RayServerExit::CleanShutdown => SidecarExit::CleanShutdown,
        V2RayServerExit::UnexpectedCompletion => SidecarExit::UnexpectedCompletion,
        V2RayServerExit::ServeError(e) => SidecarExit::ServeError(e.clone()),
        V2RayServerExit::Panicked(p) => SidecarExit::Panicked(p.clone()),
        V2RayServerExit::Cancelled => SidecarExit::Cancelled,
        // sb-core's enum is #[non_exhaustive]: never panic, never collapse to CleanShutdown.
        _ => SidecarExit::Unknown,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Run-engine sidecar runtime event bridge (APP-SIDECAR-LIVENESS-01H-B)
//
// One observer task per subscription reads the source snapshot and projects ONLY terminal /
// projection-closed into an app-local unbounded mpsc, consumed log-only. `Running` /
// `ShutdownRequested` stay in the snapshot and never cross the bridge. The source outer monitors
// remain the sole terminal loggers; the consumer adds only a low-noise breadcrumb. No product
// policy (no hard-fail / restart / degrade / health probe).
// ─────────────────────────────────────────────────────────────────────────

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Minimal consumer-layer event. `generation` lives in `SidecarExitRecord`; error text lives in
/// `SidecarExit`. No timestamp / restart counter / health / snapshot / history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SidecarRuntimeEvent {
    /// The sidecar's current generation has terminated (carries the highest-generation terminal).
    Exited {
        name: String,
        exit: SidecarExitRecord,
    },
    /// The source `watch` channel closed before this observer saw a terminal.
    ProjectionClosed { name: String },
}

/// What the consumer decides after an event. Log-only today — always `Continue` (no hard-fail /
/// restart / degrade). Kept as an explicit, testable return rather than an implicit `()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidecarRuntimeAction {
    Continue,
}

/// Project a snapshot to a terminal event, or `None` if there is no terminal to report.
///
/// An active `current` (`Running` / `ShutdownRequested`) always wins: even if a historical `last_exit`
/// is present (e.g. `V2Ray` `current = Running(2)` with `last_exit = CleanShutdown(1)`), the live
/// generation is NOT reported as dead.
fn terminal_event_from_snapshot(
    name: &str,
    snapshot: &SidecarRuntimeSnapshot,
) -> Option<SidecarRuntimeEvent> {
    if snapshot.current.is_some() {
        return None;
    }
    snapshot
        .last_exit
        .as_ref()
        .map(|exit| SidecarRuntimeEvent::Exited {
            name: name.to_string(),
            exit: exit.clone(),
        })
}

/// Observe one sidecar runtime subscription, emitting AT MOST one event, then exit.
///
/// Reads the initial snapshot first (a sidecar may already be terminal at subscribe time and
/// `watch` will not re-emit the seen version). A send failure (consumer gone) is not retried and is
/// not a panic — the observer simply exits.
async fn observe_sidecar_runtime(
    mut subscription: SidecarRuntimeSubscription,
    event_tx: mpsc::UnboundedSender<SidecarRuntimeEvent>,
) {
    let name = subscription.name().to_string();
    let initial = subscription.snapshot_and_mark_seen();
    if let Some(event) = terminal_event_from_snapshot(&name, &initial) {
        let _ = event_tx.send(event);
        return;
    }
    loop {
        match subscription.changed().await {
            Ok(snapshot) => {
                if let Some(event) = terminal_event_from_snapshot(&name, &snapshot) {
                    let _ = event_tx.send(event);
                    return;
                }
                // Running / ShutdownRequested → keep waiting for a terminal.
            }
            Err(_recv_error) => {
                // Projection channel closed (source sender dropped) — NOT a CleanShutdown.
                let _ = event_tx.send(SidecarRuntimeEvent::ProjectionClosed { name: name.clone() });
                return;
            }
        }
    }
}

/// Log-only handling of a single event. Returns the (currently always `Continue`) action so the
/// policy decision is explicit and testable. Does NOT re-log the terminal (the source monitor
/// already did); only a low-noise breadcrumb / a projection-closed warning.
fn handle_sidecar_runtime_event(event: &SidecarRuntimeEvent) -> SidecarRuntimeAction {
    match event {
        SidecarRuntimeEvent::Exited { name, exit } => {
            tracing::debug!(
                target: "app::sidecar_runtime",
                sidecar = %name,
                generation = exit.generation,
                exit = ?exit.exit,
                "run-engine observed sidecar runtime exit"
            );
        }
        SidecarRuntimeEvent::ProjectionClosed { name } => {
            tracing::warn!(
                target: "app::sidecar_runtime",
                sidecar = %name,
                "sidecar runtime projection channel closed"
            );
        }
    }
    SidecarRuntimeAction::Continue
}

/// Drain events until all observers' senders drop (channel closed), handling each log-only.
async fn consume_sidecar_runtime_events(
    mut event_rx: mpsc::UnboundedReceiver<SidecarRuntimeEvent>,
) {
    while let Some(event) = event_rx.recv().await {
        let _ = handle_sidecar_runtime_event(&event);
    }
}

/// Owns the run-engine sidecar runtime observers + the single log-only consumer.
pub struct SidecarRuntimeEventBridge {
    observer_joins: Vec<JoinHandle<()>>,
    consumer_join: JoinHandle<()>,
}

impl SidecarRuntimeEventBridge {
    /// Spawn one observer per subscription plus a single consumer. Returns `None` for an empty set
    /// (no empty consumer task is created). The root sender is dropped so the consumer exits
    /// naturally once every observer has finished.
    pub fn spawn(subscriptions: Vec<SidecarRuntimeSubscription>) -> Option<Self> {
        if subscriptions.is_empty() {
            return None;
        }
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let observer_joins = subscriptions
            .into_iter()
            .map(|subscription| {
                let event_tx = event_tx.clone();
                tokio::spawn(observe_sidecar_runtime(subscription, event_tx))
            })
            .collect();
        drop(event_tx); // only observer clones remain → consumer ends when they all finish
        let consumer_join = tokio::spawn(consume_sidecar_runtime_events(event_rx));
        Some(Self {
            observer_joins,
            consumer_join,
        })
    }

    /// Abort any still-waiting observers and await everything. Does NOT wait for the sidecar's own
    /// terminal (`V2Ray` close may happen later in outer context shutdown); a bounded teardown.
    pub async fn shutdown(self) {
        for join in &self.observer_joins {
            join.abort();
        }
        for join in self.observer_joins {
            let _ = join.await;
        }
        // Observer sender clones are now dropped → consumer's receiver closes → consumer exits.
        let _ = self.consumer_join.await;
    }
}

#[cfg(test)]
mod tests {
    // ── V2Ray adapter tests (require the V2Ray source / sb-core) ──
    #[cfg(feature = "v2ray_api")]
    mod v2ray {
        use super::super::*;
        use sb_core::context::{
            V2RayServerActiveGeneration, V2RayServerExitRecord, V2RayServerRuntimeSnapshot,
        };

        /// Minimal V2RayServer that publishes through a test-owned watch sender.
        #[derive(Debug)]
        struct MockV2Ray {
            tx: watch::Sender<V2RayServerRuntimeSnapshot>,
        }

        impl MockV2Ray {
            fn new() -> Self {
                let (tx, _) = watch::channel(V2RayServerRuntimeSnapshot::default());
                Self { tx }
            }
        }

        impl V2RayServer for MockV2Ray {
            fn start(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn subscribe_runtime_state(
                &self,
            ) -> Option<watch::Receiver<V2RayServerRuntimeSnapshot>> {
                Some(self.tx.subscribe())
            }
        }

        /// V2RayServer that does NOT expose runtime state (uses the trait default None).
        #[derive(Debug)]
        struct MockNoRuntime;

        impl V2RayServer for MockNoRuntime {
            fn start(&self) -> anyhow::Result<()> {
                Ok(())
            }
            fn close(&self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        fn running(generation: u64) -> V2RayServerRuntimeSnapshot {
            V2RayServerRuntimeSnapshot {
                current: Some(V2RayServerActiveGeneration {
                    generation,
                    phase: V2RayServerActivePhase::Running,
                }),
                last_exit: None,
            }
        }

        // ── A. Empty snapshot ──
        #[test]
        fn maps_empty_snapshot() {
            let mapped = map_v2ray_snapshot(&V2RayServerRuntimeSnapshot::default());
            assert_eq!(mapped, SidecarRuntimeSnapshot::default());
            assert!(mapped.current.is_none());
            assert!(mapped.last_exit.is_none());
        }

        // ── B. Running ──
        #[test]
        fn maps_running_generation() {
            let mapped = map_v2ray_snapshot(&running(7));
            assert_eq!(
                mapped.current,
                Some(SidecarActiveGeneration {
                    generation: 7,
                    phase: SidecarActivePhase::Running,
                })
            );
        }

        // ── C. ShutdownRequested ──
        #[test]
        fn maps_shutdown_requested_generation() {
            let source = V2RayServerRuntimeSnapshot {
                current: Some(V2RayServerActiveGeneration {
                    generation: 8,
                    phase: V2RayServerActivePhase::ShutdownRequested,
                }),
                last_exit: None,
            };
            let mapped = map_v2ray_snapshot(&source);
            assert_eq!(
                mapped.current,
                Some(SidecarActiveGeneration {
                    generation: 8,
                    phase: SidecarActivePhase::ShutdownRequested,
                })
            );
        }

        // ── D. Each exit variant, preserving generation + error strings ──
        #[test]
        fn maps_each_exit_variant() {
            let cases = [
                (V2RayServerExit::CleanShutdown, SidecarExit::CleanShutdown),
                (
                    V2RayServerExit::UnexpectedCompletion,
                    SidecarExit::UnexpectedCompletion,
                ),
                (
                    V2RayServerExit::ServeError("boom".to_string()),
                    SidecarExit::ServeError("boom".to_string()),
                ),
                (
                    V2RayServerExit::Panicked("kaboom".to_string()),
                    SidecarExit::Panicked("kaboom".to_string()),
                ),
                (V2RayServerExit::Cancelled, SidecarExit::Cancelled),
            ];
            for (source_exit, want) in cases {
                let source = V2RayServerRuntimeSnapshot {
                    current: None,
                    last_exit: Some(V2RayServerExitRecord {
                        generation: 5,
                        exit: source_exit,
                    }),
                };
                let mapped = map_v2ray_snapshot(&source);
                assert_eq!(
                    mapped.last_exit,
                    Some(SidecarExitRecord {
                        generation: 5,
                        exit: want,
                    })
                );
            }
        }

        // ── E. Late subscriber reads the terminal published before subscribing ──
        #[tokio::test]
        async fn late_subscriber_reads_terminal() {
            let mock = MockV2Ray::new();
            // Publish a terminal BEFORE the adapter subscribes.
            mock.tx.send_replace(V2RayServerRuntimeSnapshot {
                current: None,
                last_exit: Some(V2RayServerExitRecord {
                    generation: 3,
                    exit: V2RayServerExit::CleanShutdown,
                }),
            });
            let mut sub = SidecarRuntimeSubscription::from_v2ray_server("v2ray", &mock)
                .expect("runtime state exposed");
            let snap = sub.snapshot_and_mark_seen();
            assert_eq!(
                snap.last_exit,
                Some(SidecarExitRecord {
                    generation: 3,
                    exit: SidecarExit::CleanShutdown,
                })
            );
        }

        // ── F. After mark-seen, changed() does not re-consume the same version ──
        #[tokio::test]
        async fn changed_does_not_reconsume_seen_version() {
            let mock = MockV2Ray::new();
            mock.tx.send_replace(running(1));
            let mut sub = SidecarRuntimeSubscription::from_v2ray_server("v2ray", &mock)
                .expect("runtime state exposed");
            assert_eq!(sub.name(), "v2ray");
            let _ = sub.snapshot_and_mark_seen();

            // No new send: changed() must NOT resolve. Bounded timeout, no flaky sleep.
            let res =
                tokio::time::timeout(std::time::Duration::from_millis(50), sub.changed()).await;
            assert!(
                res.is_err(),
                "changed() must block until a newer version arrives"
            );
        }

        // ── G. changed() maps the next published version ──
        #[tokio::test]
        async fn changed_maps_new_version() {
            let mock = MockV2Ray::new();
            let mut sub = SidecarRuntimeSubscription::from_v2ray_server("v2ray", &mock)
                .expect("runtime state exposed");
            let _ = sub.snapshot_and_mark_seen();

            mock.tx.send_replace(running(2));
            let snap = sub.changed().await.expect("a new version was sent");
            assert_eq!(
                snap.current,
                Some(SidecarActiveGeneration {
                    generation: 2,
                    phase: SidecarActivePhase::Running,
                })
            );
        }

        // ── H. Source closed → RecvError, never mapped to an exit ──
        #[tokio::test]
        async fn source_closed_propagates_recv_error() {
            let mock = MockV2Ray::new();
            let mut sub = SidecarRuntimeSubscription::from_v2ray_server("v2ray", &mock)
                .expect("runtime state exposed");
            let _ = sub.snapshot_and_mark_seen();

            drop(mock); // drops the only sender → channel closed
            let res = sub.changed().await;
            assert!(
                res.is_err(),
                "closed source must surface RecvError, not a synthesized exit"
            );
        }

        // ── I. Trait default → capability absent → None ──
        #[test]
        fn capability_absent_yields_none() {
            let sub = SidecarRuntimeSubscription::from_v2ray_server("v2ray", &MockNoRuntime);
            assert!(
                sub.is_none(),
                "trait default None must yield no subscription"
            );
        }

        // ── J. Real V2RayApiServer exposes a receiver → Some (no port bind needed) ──
        #[test]
        fn real_v2ray_server_yields_some() {
            let server =
                sb_core::services::v2ray_api::V2RayApiServer::new(sb_config::ir::V2RayApiIR {
                    listen: Some("127.0.0.1:0".to_string()),
                    stats: None,
                });
            let sub = SidecarRuntimeSubscription::from_v2ray_server("v2ray", &server);
            assert!(
                sub.is_some(),
                "real server exposes a runtime snapshot receiver"
            );
        }
    }

    // ── Clash adapter tests (identity read; no sb-core) ──
    #[cfg(feature = "clash_api")]
    mod clash {
        use super::super::*;
        use tokio::sync::watch;

        fn running(generation: u64) -> SidecarRuntimeSnapshot {
            SidecarRuntimeSnapshot {
                current: Some(SidecarActiveGeneration {
                    generation,
                    phase: SidecarActivePhase::Running,
                }),
                last_exit: None,
            }
        }

        // ── I. App adapter identity: Clash source returns the snapshot verbatim ──
        #[test]
        fn clash_source_is_identity() {
            let snapshot = SidecarRuntimeSnapshot {
                current: Some(SidecarActiveGeneration {
                    generation: 1,
                    phase: SidecarActivePhase::ShutdownRequested,
                }),
                last_exit: Some(SidecarExitRecord {
                    generation: 1,
                    exit: SidecarExit::ServeError("boom".to_string()),
                }),
            };
            let (tx, rx) = watch::channel(snapshot.clone());
            let mut sub = SidecarRuntimeSubscription::from_clash("clash", rx);
            assert_eq!(sub.name(), "clash");
            assert_eq!(sub.snapshot_and_mark_seen(), snapshot);
            let _ = tx; // keep sender alive
        }

        // ── L. Late subscriber reads the terminal published before subscribing ──
        #[test]
        fn clash_late_subscriber_reads_terminal() {
            let (tx, _rx) = watch::channel(SidecarRuntimeSnapshot::default());
            let terminal = SidecarRuntimeSnapshot {
                current: None,
                last_exit: Some(SidecarExitRecord {
                    generation: 1,
                    exit: SidecarExit::CleanShutdown,
                }),
            };
            tx.send_replace(terminal.clone());
            let mut sub = SidecarRuntimeSubscription::from_clash("clash", tx.subscribe());
            assert_eq!(sub.snapshot_and_mark_seen(), terminal);
        }

        // ── J. After mark-seen, changed() does not re-consume the same version ──
        #[tokio::test]
        async fn clash_changed_does_not_reconsume_seen_version() {
            let (tx, rx) = watch::channel(running(1));
            let mut sub = SidecarRuntimeSubscription::from_clash("clash", rx);
            let _ = sub.snapshot_and_mark_seen();

            let res =
                tokio::time::timeout(std::time::Duration::from_millis(50), sub.changed()).await;
            assert!(
                res.is_err(),
                "changed() must block until a newer version arrives"
            );
            let _ = tx;
        }

        // ── K. changed() returns the next published version ──
        #[tokio::test]
        async fn clash_changed_returns_new_version() {
            let (tx, rx) = watch::channel(running(1));
            let mut sub = SidecarRuntimeSubscription::from_clash("clash", rx);
            let _ = sub.snapshot_and_mark_seen();

            let next = SidecarRuntimeSnapshot {
                current: Some(SidecarActiveGeneration {
                    generation: 1,
                    phase: SidecarActivePhase::ShutdownRequested,
                }),
                last_exit: None,
            };
            tx.send_replace(next.clone());
            assert_eq!(sub.changed().await.expect("a new version was sent"), next);
        }

        // ── Source closed → RecvError, never mapped to an exit ──
        #[tokio::test]
        async fn clash_source_closed_propagates_recv_error() {
            let (tx, rx) = watch::channel(running(1));
            let mut sub = SidecarRuntimeSubscription::from_clash("clash", rx);
            let _ = sub.snapshot_and_mark_seen();

            drop(tx);
            assert!(
                sub.changed().await.is_err(),
                "closed source must surface RecvError, not a synthesized exit"
            );
        }
    }

    // ── Run-engine event bridge tests (Clash-style sources; identity adapter, no sb-core) ──
    #[cfg(feature = "clash_api")]
    mod bridge {
        use super::super::*;
        use tokio::sync::{mpsc, watch};

        fn running(generation: u64) -> SidecarRuntimeSnapshot {
            SidecarRuntimeSnapshot {
                current: Some(SidecarActiveGeneration {
                    generation,
                    phase: SidecarActivePhase::Running,
                }),
                last_exit: None,
            }
        }

        fn clean_exit(generation: u64) -> SidecarRuntimeSnapshot {
            SidecarRuntimeSnapshot {
                current: None,
                last_exit: Some(SidecarExitRecord {
                    generation,
                    exit: SidecarExit::CleanShutdown,
                }),
            }
        }

        // ── E. Active generation wins over a historical exit (pure rule) ──
        #[test]
        fn active_generation_outranks_historical_exit() {
            let snapshot = SidecarRuntimeSnapshot {
                current: Some(SidecarActiveGeneration {
                    generation: 2,
                    phase: SidecarActivePhase::Running,
                }),
                last_exit: Some(SidecarExitRecord {
                    generation: 1,
                    exit: SidecarExit::CleanShutdown,
                }),
            };
            assert!(terminal_event_from_snapshot("v2ray", &snapshot).is_none());
        }

        // ── K. Consumer is log-only: every event returns Continue ──
        #[test]
        fn consumer_is_log_only() {
            assert_eq!(
                handle_sidecar_runtime_event(&SidecarRuntimeEvent::Exited {
                    name: "clash".into(),
                    exit: SidecarExitRecord {
                        generation: 1,
                        exit: SidecarExit::ServeError("boom".into()),
                    },
                }),
                SidecarRuntimeAction::Continue
            );
            assert_eq!(
                handle_sidecar_runtime_event(&SidecarRuntimeEvent::ProjectionClosed {
                    name: "clash".into(),
                }),
                SidecarRuntimeAction::Continue
            );
        }

        // ── A. Initial terminal is not missed (terminal published before observer spawns) ──
        #[tokio::test]
        async fn initial_terminal_is_reported() {
            let (tx, rx) = watch::channel(clean_exit(1));
            let (event_tx, mut event_rx) = mpsc::unbounded_channel();
            let observer = tokio::spawn(observe_sidecar_runtime(
                SidecarRuntimeSubscription::from_clash("clash", rx),
                event_tx,
            ));
            assert_eq!(
                event_rx.recv().await,
                Some(SidecarRuntimeEvent::Exited {
                    name: "clash".into(),
                    exit: SidecarExitRecord {
                        generation: 1,
                        exit: SidecarExit::CleanShutdown,
                    },
                })
            );
            let _ = observer.await;
            let _ = tx;
        }

        // ── B/C. Running and ShutdownRequested emit no event ──
        #[tokio::test]
        async fn running_and_shutdown_requested_emit_no_event() {
            let (tx, rx) = watch::channel(running(1));
            let (event_tx, mut event_rx) = mpsc::unbounded_channel();
            let _observer = tokio::spawn(observe_sidecar_runtime(
                SidecarRuntimeSubscription::from_clash("clash", rx),
                event_tx,
            ));
            // Running → no event.
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv())
                    .await
                    .is_err()
            );
            // ShutdownRequested → still no event.
            tx.send_replace(SidecarRuntimeSnapshot {
                current: Some(SidecarActiveGeneration {
                    generation: 1,
                    phase: SidecarActivePhase::ShutdownRequested,
                }),
                last_exit: None,
            });
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), event_rx.recv())
                    .await
                    .is_err()
            );
        }

        // ── D. One Exited after Running → ShutdownRequested → CleanShutdown ──
        #[tokio::test]
        async fn terminal_after_transitions_emits_once() {
            let (tx, rx) = watch::channel(running(1));
            let (event_tx, mut event_rx) = mpsc::unbounded_channel();
            let observer = tokio::spawn(observe_sidecar_runtime(
                SidecarRuntimeSubscription::from_clash("clash", rx),
                event_tx,
            ));
            tx.send_replace(SidecarRuntimeSnapshot {
                current: Some(SidecarActiveGeneration {
                    generation: 1,
                    phase: SidecarActivePhase::ShutdownRequested,
                }),
                last_exit: None,
            });
            tx.send_replace(clean_exit(1));
            assert_eq!(
                event_rx.recv().await,
                Some(SidecarRuntimeEvent::Exited {
                    name: "clash".into(),
                    exit: SidecarExitRecord {
                        generation: 1,
                        exit: SidecarExit::CleanShutdown,
                    },
                })
            );
            // Observer ended after the single terminal; channel closes (all senders gone).
            let _ = observer.await;
            assert_eq!(event_rx.recv().await, None);
        }

        // ── F. Projection closed → ProjectionClosed (not an exit) ──
        #[tokio::test]
        async fn projection_closed_is_reported() {
            let (tx, rx) = watch::channel(running(1));
            let (event_tx, mut event_rx) = mpsc::unbounded_channel();
            let observer = tokio::spawn(observe_sidecar_runtime(
                SidecarRuntimeSubscription::from_clash("clash", rx),
                event_tx,
            ));
            drop(tx); // close the source projection
            assert_eq!(
                event_rx.recv().await,
                Some(SidecarRuntimeEvent::ProjectionClosed {
                    name: "clash".into(),
                })
            );
            let _ = observer.await;
        }

        // ── G. A dropped receiver does not block the observer ──
        #[tokio::test]
        async fn dropped_receiver_does_not_block_observer() {
            let (tx, rx) = watch::channel(running(1));
            let (event_tx, event_rx) = mpsc::unbounded_channel();
            drop(event_rx); // consumer gone
            let observer = tokio::spawn(observe_sidecar_runtime(
                SidecarRuntimeSubscription::from_clash("clash", rx),
                event_tx,
            ));
            tx.send_replace(clean_exit(1));
            // The observer's send fails silently and it exits; the join must complete.
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(1), observer)
                    .await
                    .is_ok()
            );
            let _ = tx;
        }

        // ── H. Empty subscription set → no bridge ──
        #[test]
        fn empty_subscriptions_yield_no_bridge() {
            assert!(SidecarRuntimeEventBridge::spawn(Vec::new()).is_none());
        }

        // ── I. Bridge shutdown does not wait for the source terminal ──
        #[tokio::test]
        async fn bridge_shutdown_does_not_wait_for_terminal() {
            let (tx, rx) = watch::channel(running(1)); // stays Running forever
            let bridge =
                SidecarRuntimeEventBridge::spawn(vec![SidecarRuntimeSubscription::from_clash(
                    "clash", rx,
                )])
                .expect("non-empty bridge");
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(2), bridge.shutdown())
                    .await
                    .is_ok(),
                "shutdown must abort the still-Running observer, not block on a terminal"
            );
            let _ = tx;
        }

        // ── J. Multiple observers each project their terminal; bridge shuts down cleanly ──
        #[tokio::test]
        async fn multiple_observers_then_shutdown() {
            let (tx_a, rx_a) = watch::channel(clean_exit(1));
            let (tx_b, rx_b) = watch::channel(running(1));
            let bridge = SidecarRuntimeEventBridge::spawn(vec![
                SidecarRuntimeSubscription::from_clash("clash-api", rx_a),
                SidecarRuntimeSubscription::from_clash("v2ray-api", rx_b),
            ])
            .expect("non-empty bridge");
            // tx_a already terminal; tx_b stays Running until shutdown aborts its observer.
            assert!(
                tokio::time::timeout(std::time::Duration::from_secs(2), bridge.shutdown())
                    .await
                    .is_ok()
            );
            let _ = (tx_a, tx_b);
        }
    }
}
