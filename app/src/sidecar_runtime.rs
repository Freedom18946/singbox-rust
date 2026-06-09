//! App-level sidecar runtime snapshot adapter (APP-SIDECAR-LIVENESS-01F / 01G-B).
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
//! The consumer (bootstrap observer / run-engine supervisor) is intentionally deferred to a later
//! card, so this adapter surface is currently unused outside its own tests.

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
}
