# APP-SIDECAR-LIVENESS-01C - cross-crate runtime completion contract

## Scope Result

Implementation stopped before Rust edits.

Reason: the existing `sb-core` V2Ray API server explicitly supports multiple lifecycles on the same
server instance:

```text
start
-> close or task exit
-> start again
```

That is one of this card's stop conditions. A single unversioned `watch` state would mix terminal
state from generation N with `Running` / terminal state from generation N+1. Implementing it anyway
would make late-subscriber semantics ambiguous and would hide lifecycle races instead of projecting
them.

No Rust code, app code, sb-api code, Cargo files, supervisor events, hard-fail policy, restart
policy, health probes, fixtures, CI files, or `agents-only/a0_reality_spike/` were changed.

## Baseline

Initial status:

- `## main...origin/main`
- `?? agents-only/a0_reality_spike/`

Recent synced commits confirmed:

- `90562381 checkpoint: propose sidecar runtime completion projection`
- `ab7f19db checkpoint: audit app sidecar runtime liveness`

## Audit Evidence

`V2RayServer` is a public trait in `crates/sb-core/src/context.rs`.

Current methods:

```rust
pub trait V2RayServer: Send + Sync + std::fmt::Debug {
    fn start(&self) -> anyhow::Result<()>;
    fn close(&self) -> anyhow::Result<()>;
    fn stats(&self) -> Option<Arc<StatsManager>> {
        None
    }
}
```

Workspace implementors found:

| Implementor | Location | Count |
| --- | --- | ---: |
| `V2RayApiServer` | `crates/sb-core/src/services/v2ray_api.rs` | 1 |

The real tonic serve future is spawned in `V2RayApiServer::start()` under the
`service_v2ray_api` feature. The current task body owns:

- pre-bound `tokio::net::TcpListener`;
- `oneshot` shutdown receiver;
- `StatsServiceImpl`;
- `ResetStartedOnDrop`.

The current implementation does not retain the real serve `JoinHandle`.

`tokio::sync::watch` is available without Cargo changes because `sb-core` depends on
`tokio = { version = "1.47", features = ["full"] }`.

## Repeated-start Stop Condition

The implementation itself documents duplicate-running protection:

```text
compare_exchange(false, true)
-> duplicate start while running is an idempotent no-op
```

That only prevents two simultaneous listeners. It does not make the instance single-lifecycle.

Existing tests explicitly require repeat lifecycle support:

| Evidence | Meaning |
| --- | --- |
| `restart_after_failed_bind` | a failed `start()` must be retryable on the same instance |
| `shutdown_allows_restart` | `start -> close -> start` is accepted on the same instance |
| `task_exit_resets_started` | task exit without `close()` resets `started`, then same instance can `start()` again |
| `restart_with_retry(&server)` helper | bounded retry is part of the accepted behavior |

Therefore 01C cannot add a single `watch::Sender<V2RayServerRuntimeState>` with states like
`NotStarted`, `Running`, `ShutdownRequested`, `Exited(_)` and call the contract complete. A late
subscriber after a restart would not know whether `Exited(CleanShutdown)` belongs to the current
generation, the previous generation, or a race with a new `Running`.

## Current Behavior Answers

| Question | Answer |
| --- | --- |
| Is `V2RayServer` public? | Yes, through public `sb_core::context`. |
| Workspace trait implementors | One: `V2RayApiServer`. |
| Can `V2RayApiServer` be started repeatedly? | Yes, current tests require retry after failed bind, restart after close, and restart after task exit. |
| Is `close()` idempotent? | Effectively yes: it stores `started=false`, takes optional shutdown sender, and returns `Ok(())` when no sender exists. |
| Where is the tonic future spawned? | Inside `V2RayApiServer::start()` under `service_v2ray_api`. |
| Is the real serve `JoinHandle` retained? | No. The spawned task is detached. |
| Is `watch` available? | Yes, via existing Tokio `full` feature. |

## Why A Single State Is Insufficient

The 01B proposal assumed a single lifecycle:

```text
NotStarted -> Running -> ShutdownRequested -> Exited(...)
```

That model is valid only if a server instance is consumed after terminal state. The current V2Ray
server instance is not consumed; it can return to a startable state. Resetting `Exited(_)` back to
`Running` would violate late-subscriber terminal retention. Keeping `Exited(_)` forever would make a
valid later `start()` unable to publish `Running`.

The contract needs generation identity before implementation.

## Minimum Generation-aware Contract

Recommended source-local model:

```rust
pub type V2RayServerGeneration = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct V2RayServerRuntimeSnapshot {
    pub generation: V2RayServerGeneration,
    pub state: V2RayServerRuntimeState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2RayServerRuntimeState {
    NotStarted,
    Starting,
    Running,
    ShutdownRequested,
    Exited(V2RayServerExit),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum V2RayServerExit {
    CleanShutdown,
    UnexpectedCompletion,
    ServeError(String),
    Panicked(String),
    Cancelled,
}
```

Generation semantics:

- Generation `0` starts as `NotStarted`.
- A successful `start()` claim creates generation `N+1`.
- Startup bind failure does not publish `Running`; it can either leave generation unchanged or
  publish a generation-scoped startup failure only if a later policy explicitly wants startup
  state in this channel. Current startup errors are already projected by `Result`.
- `Running`, `ShutdownRequested`, and `Exited(_)` are scoped to one generation.
- `Exited(_)` for generation N must never be overwritten by another terminal state for N.
- A later start may publish generation N+1 `Running` without erasing the historical fact that
  generation N exited.

Late subscriber semantics:

- `subscribe_runtime_state()` returns the latest snapshot.
- The latest snapshot is enough to observe the current generation.
- If consumers need historical terminal state for a previous generation after a restart, the source
  must either retain `last_exit: Option<(generation, exit)>` or expose a small snapshot containing
  both current state and last terminal state.

Minimum late-subscriber-safe shape:

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct V2RayServerRuntimeSnapshot {
    pub generation: u64,
    pub state: V2RayServerRuntimeState,
    pub last_exit: Option<V2RayServerGenerationExit>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct V2RayServerGenerationExit {
    pub generation: u64,
    pub exit: V2RayServerExit,
}
```

This keeps the current-generation state clear while still letting late subscribers see the most
recent terminal outcome after a restart.

## Trait Shape Still Looks Additive

After generation is accepted, the trait method can remain an additive default:

```rust
fn subscribe_runtime_state(
    &self,
) -> Option<tokio::sync::watch::Receiver<V2RayServerRuntimeSnapshot>> {
    None
}
```

`V2RayApiServer` would override it:

```rust
fn subscribe_runtime_state(
    &self,
) -> Option<tokio::sync::watch::Receiver<V2RayServerRuntimeSnapshot>> {
    Some(self.runtime_state.subscribe())
}
```

This remains object-safe and does not require app types or supervisor callbacks in `sb-core`.

## Revised Implementation Requirements

Before implementing:

1. Decide whether the state snapshot includes `last_exit`.
2. Decide whether a successful new generation may replace `state=Exited(_)` with `state=Running`
   while preserving prior terminal state in `last_exit`.
3. Define generation claim ordering around `compare_exchange(false, true)`.
4. Define whether duplicate `start()` while already running returns the existing generation or only
   leaves state untouched.
5. Define whether direct shutdown signal without `close()` maps to `CleanShutdown` or
   `UnexpectedCompletion` with no shutdown request. Current test `task_exit_resets_started` can
   trigger this path.

## Monitor Design Once Generation Exists

Recommended shape remains an outer monitor task:

```text
start() claims generation N
-> publish generation N Running after pre-bind succeeds
-> monitor owns inner tonic serve JoinHandle
-> monitor maps Ok / Err / panic / cancellation to generation N terminal exit
-> terminal submit for generation N succeeds once
```

Panic/cancelled mapping remains:

| Inner result | Terminal |
| --- | --- |
| `Ok(Ok(()))` with shutdown requested for generation N | `Exited(CleanShutdown)` |
| `Ok(Ok(()))` without shutdown requested for generation N | `Exited(UnexpectedCompletion)` |
| `Ok(Err(e))` | `Exited(ServeError(e.to_string()))` |
| `Err(join_error)` where `is_panic()` | `Exited(Panicked(...))` |
| `Err(join_error)` where `is_cancelled()` | `Exited(Cancelled)` |

## Logging Discipline Proposal

Current owner:

- serve task logs `Received shutdown signal`;
- serve task logs `V2Ray API server error`;
- serve task logs `V2Ray API server stopped`;
- `close()` does not log terminal outcome.

Future owner:

- terminal log should happen only from the generation terminal submit winner;
- shutdown signal receipt can stay informational if it does not duplicate terminal outcome;
- `close()` should request shutdown but not log clean terminal completion;
- duplicate `start()` should keep current debug behavior.

## Next Card

`APP-SIDECAR-LIVENESS-01C-GEN - generation-aware V2Ray runtime completion contract`

Minimum scope:

- Define generation-aware `V2RayServerRuntimeSnapshot`.
- Add additive default `subscribe_runtime_state()` to `V2RayServer`.
- Add generation-aware watch sender to `V2RayApiServer`.
- Add deterministic helper tests for generation monotonicity, late subscriber, and repeated
  lifecycle behavior.
- Do not modify app, Clash, sb-api, supervisor, hard-fail policy, restart policy, or health probes.

## Verification

Because Rust implementation stopped before edits, code validation commands were not run. Required
documentation hygiene for this checkpoint:

- `git diff --check`
- `bash agents-only/06-scripts/verify-consistency.sh`
- `bash agents-only/06-scripts/check-boundaries.sh`
- `git status --short --branch`

## State

`APP-SIDECAR-LIVENESS-01C` is stopped by repeated-lifecycle evidence.

`SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`.
