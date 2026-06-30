# APP-SIDECAR-LIVENESS-01B - ServiceHandle runtime completion projection proposal

## Scope

Proposal only. No Rust code, tests, channels, watcher tasks, supervisor events, restart behavior,
health probes, Cargo files, fixtures, REALITY artifacts, CI files, or `agents-only/a0_reality_spike/`
were changed.

Goal: design the smallest mechanism that lets callers observe a sidecar's terminal runtime state
after startup succeeds. Observing completion is separate from deciding whether that completion should
hard-fail, degrade, restart, or remain log-only.

Non-goals:

- Readiness probing beyond the existing pre-bind startup fixes.
- Request-level health probes.
- Automatic restart.
- Global hard-fail policy.
- `SVC-V2RAY-API-01B`.

## Baseline

Initial status:

- `## main...origin/main`
- `?? agents-only/a0_reality_spike/`

Recent synced commits confirmed:

- `ab7f19db checkpoint: audit app sidecar runtime liveness`
- `44d2c4fa checkpoint: record sb-api v2ray alias deprecation`
- `60b88414 feat(sb-api): deprecate generic v2ray server aliases`

`APP-SIDECAR-LIVENESS-01A` established:

- Startup readiness is honest for Clash and V2Ray pre-bound paths.
- Runtime liveness/completion is not projected to bootstrap or run-engine callers.
- Bootstrap V2Ray's app `ServiceHandle.join` is not the actual tonic serve task.
- Run-engine V2Ray uses `Arc<dyn V2RayServer>` whose trait exposes only `start`, `close`, and `stats`.

## Task-owner Matrix

| Sidecar | True owner of serve future | Current saved join handle | Current shutdown owner | Current log owner | Current projection layer |
| --- | --- | --- | --- | --- | --- |
| bootstrap Clash | `app/src/run_engine_runtime/admin_start.rs::spawn_prebound_clash_api_server` owns the spawned axum serve future | `PreboundClashApiHandle.join`, wrapped into bootstrap `ServiceHandle.join` | bootstrap `ServiceHandle::shutdown()` sends the pre-bound shutdown oneshot | the spawned task in `admin_start.rs` logs `Clash API server error` | app layer can project through `ServiceHandle` because it owns the real join handle |
| run-engine Clash | same `spawn_prebound_clash_api_server` helper | private `ClashApiHandle.join` inside `AdminServices` | `AdminServices::shutdown()` -> `ClashApiHandle::shutdown()` | the spawned task in `admin_start.rs` | app run-engine adapter can project through `AdminServices` or a shared app sidecar handle |
| bootstrap V2Ray | `crates/sb-core/src/services/v2ray_api.rs::V2RayApiServer::start()` owns the tonic serve future | no app-visible join for the serve task; app `ServiceHandle.join` is only a shutdown waiter | bootstrap `ServiceHandle` wakes a waiter which calls `server.close()` | sb-core V2Ray serve task logs `V2Ray API server error` / stopped | sb-core must publish source-local terminal state; app can only adapt it |
| run-engine V2Ray | same sb-core `V2RayApiServer::start()` task inside `wire_experimental_sidecars` | no join handle exposed; only `Context.v2ray_server: Option<Arc<dyn V2RayServer>>` | `shutdown_context()` calls `v2ray.close()` | sb-core V2Ray serve task | sb-core trait/service boundary must expose completion state before app/run-engine can consume it |

Conclusion:

- Clash can be projected locally in app without changing sb-api public API.
- V2Ray cannot be fully covered by app-only handle changes because the true task owner is sb-core.
- A unified design needs source-owner terminal state plus app-level mapping.

## Proposed Data Model

Keep the contract small and terminal-focused.

Source-local model, defined near the owner:

```rust
pub enum RuntimeTaskState {
    Running,
    ShutdownRequested,
    Exited(RuntimeTaskExit),
}

pub enum RuntimeTaskExit {
    CleanShutdown,
    ServeError(String),
    Panicked(String),
    Cancelled,
    ShutdownSignalDropped,
    Unknown(String),
}
```

App-level adapter model:

```rust
pub struct SidecarCompletion {
    pub name: SidecarName,
    pub phase: SidecarPhase,
    pub exit: SidecarExit,
    pub occurred_at: std::time::SystemTime,
}

pub enum SidecarPhase {
    BeforeShutdownRequested,
    AfterShutdownRequested,
}

pub enum SidecarExit {
    CleanShutdown,
    ServeError(String),
    Panicked(String),
    Cancelled,
    ShutdownSignalDropped,
    Unknown(String),
}
```

Model decisions:

- `Running` and `ShutdownRequested` are useful for monotonic state, but consumers primarily care
  about the first terminal `Exited`.
- `CleanShutdown` is only clean when shutdown was requested and the serve task returns normally.
- A normal serve-future return before shutdown is not necessarily clean. If the server future can
  return `Ok(())` before shutdown, map it to `Unknown("serve returned before shutdown")` or a later
  explicit `EndedUnexpectedly` variant. Do not silently call it clean.
- Error types should be downgraded to strings across crate boundaries. This avoids leaking axum,
  tonic, or anyhow internals through public app/sb-core contracts.
- Panic payload is worth preserving as a string when available; otherwise use the `JoinError`
  display string.
- Include sidecar name at the app adapter layer. Source-local sb-core V2Ray does not need to know app
  sidecar names.
- Include occurrence time at the app adapter layer for diagnostics and late subscribers.
- Include whether shutdown had been requested before terminal state. This prevents a shutdown race
  from being misclassified as unexpected.

## Signal Mechanism Comparison

### Route A: `JoinHandle::is_finished()`

Useful only as an auxiliary passive query.

Pros:

- Very small for handles that already own a `JoinHandle`.
- Can answer "has this task stopped?" without awaiting.

Cons:

- No active notification.
- No stable poll point exists today in bootstrap or run-engine.
- No exit reason.
- Does not cover V2Ray because the task is hidden inside sb-core.
- Does not support late subscriber semantics beyond a boolean with no terminal payload.

Judgment: not sufficient as the primary completion projection mechanism.

### Route B: `oneshot` terminal completion

Model: owner sends once when terminal state occurs; one observer awaits a receiver.

Pros:

- Natural exactly-once behavior.
- Small implementation surface.
- Good fit when there is exactly one consumer.

Cons:

- Not cloneable; multiple observers require fan-out.
- Late subscribers cannot read the terminal event after the receiver is consumed or dropped.
- Receiver ownership is awkward for both bootstrap and run-engine if a handle also needs a shutdown
  path and maybe a supervisor consumer.

Judgment: useful internally as an implementation detail, but not sufficient as the shared
source-of-truth state for this repo.

### Route C: `watch` runtime state

Model: owner holds a `watch::Sender<RuntimeTaskState>`; observers clone receivers and can read the
latest state.

Pros:

- Supports multiple observers.
- Supports late subscribers: terminal state remains readable from `borrow()` / latest value.
- Fits a small monotonic state machine: `Running -> ShutdownRequested -> Exited`.
- Cloneable receiver can be returned from a trait object without moving ownership.
- App can map source-local state to app-level `SidecarCompletion`.

Cons:

- Sender drop must have defined semantics. If sender drops before a terminal state, consumers should
  map that to `Unknown("runtime state sender dropped")` or treat channel closure as a contract bug.
- Requires monotonic update discipline so `ShutdownRequested` does not overwrite `Exited`.
- Slightly heavier than oneshot, but still small.

Judgment: preferred source-of-truth mechanism.

### Route D: `broadcast` event

Pros:

- Multiple observers.
- Event-shaped API.

Cons:

- Late subscribers can miss terminal events.
- Lagged receivers can miss terminal events.
- Requires separate storage to satisfy this card's late-subscriber invariant.

Judgment: not suitable as the only mechanism. It can be a consumer-facing event bus only if backed
by watch/state storage.

### Route E: direct run-engine supervisor `mpsc` event

Pros:

- Natural for run-engine policy decisions.
- Can feed existing supervision/reload loop in a later card.

Cons:

- Couples source owner to app policy if used as the source of truth.
- Does not help bootstrap unless another path is added.
- Does not provide late-subscriber state without additional storage.
- sb-core should not send app-specific supervisor events directly.

Judgment: valid consumer-facing projection after source state exists. It should not be the
source-of-truth completion mechanism.

## Panic Projection

Recommended: outer monitor task.

Shape:

```text
source owner starts monitor task
  monitor spawns or owns inner serve task
  monitor awaits inner JoinHandle
  monitor maps:
    Ok(Ok(())) after shutdown -> CleanShutdown
    Ok(Ok(())) before shutdown -> Unknown/UnexpectedEnd
    Ok(Err(e)) -> ServeError(e.to_string())
    Err(join_error) if panic -> Panicked(join_error.to_string())
    Err(join_error) if cancelled -> Cancelled
  monitor publishes terminal state exactly once
```

Why this is preferred:

- Panic cannot reliably publish from inside the panicking future.
- Awaiting the inner `JoinHandle` is already the Tokio-native way to observe panic/cancellation.
- No new dependency is required.

Rejected for now:

- `catch_unwind`: would add awkward future wrapping and likely require `FutureExt`/unwind-safety
  considerations for little benefit.
- No panic projection: fails the goal because unexpected task death would still be invisible until a
  later join, and V2Ray has no retained join at all.

## Exactly-once And Monotonic State

Use an internal terminal submit helper around the `watch::Sender`.

Semantics:

- Initial state: `Running`.
- Shutdown request attempts `Running -> ShutdownRequested`.
- Terminal submit attempts `Running|ShutdownRequested -> Exited(exit)`.
- Once state is `Exited(_)`, later updates are ignored.
- The submit helper returns whether it won; only the winner logs terminal state.

Implementation options:

- Simple lock-protected state around `watch::Sender` for exact compare-and-set semantics.
- Or an atomic terminal flag plus watch state update. The lock is clearer and less error-prone
  because watch state and terminal flag stay consistent.

Avoid:

- Task body logging serve error and monitor logging it again.
- `close()` overwriting an existing serve error with clean shutdown.
- Join wrapper overwriting a serve-error state with `Panicked` or `Cancelled`.

## Required Timelines

### A. Normal shutdown

```text
caller requests shutdown
-> state: Running -> ShutdownRequested
-> shutdown signal sent
-> serve future exits Ok after seeing shutdown
-> monitor submits Exited(CleanShutdown), phase=AfterShutdownRequested
-> join completes
```

Policy: not unexpected; caller can ignore, log debug, or record clean termination.

### B. Serve error before shutdown

```text
serve future returns Err(e)
-> monitor submits Exited(ServeError(e.to_string())), phase=BeforeShutdownRequested
-> caller later requests shutdown
-> close/shutdown sees terminal state and must not overwrite it
```

Policy: unexpected completion; bootstrap may log; run-engine may later raise an event.

### C. Panic

```text
inner serve task panics
-> monitor awaits JoinHandle
-> JoinError reports panic
-> monitor submits Exited(Panicked(display)), phase depends on shutdown flag
```

Policy: unexpected unless there is a documented cancellation path; no hard-fail decision in this card.

### D. Shutdown/failure race

```text
caller requests shutdown  -----------------+
-> state maybe ShutdownRequested            |
                                            +-> terminal submit races
serve error / panic happens ---------------+
```

Rules:

- First terminal submit wins.
- `ShutdownRequested` is nonterminal and can be followed by any terminal exit.
- If error/panic wins after shutdown was requested, preserve the error/panic with
  `AfterShutdownRequested`; do not collapse to `CleanShutdown`.
- `close()` is idempotent and should only request shutdown, not claim terminal state.
- Join must not be awaited twice; one monitor owns the inner join. Consumer handles observe state,
  not the raw inner join.

## Cross-crate Design

### Clash

`PreboundClashApiHandle` can add a cloneable completion receiver locally:

- The true serve owner is app `spawn_prebound_clash_api_server`.
- Bootstrap and run-engine already share this helper.
- No sb-api public API change is needed; `sb_api::clash::ClashApiServer` still supplies the serve
  future.
- The app helper can wrap `server.serve_with_listener_and_shutdown(...)` in a monitor and publish
  app-level sidecar completion.

Preferred shape:

```text
PreboundClashApiHandle {
  listen_addr,
  shutdown,
  completion_rx,
  monitor_join,
}
```

Open implementation detail:

- Preserve a shutdown await path without exposing or double-awaiting the inner serve task. The handle
  should await the monitor task, not the inner serve task directly.

### V2Ray

V2Ray requires a cross-crate contract because the real task is owned by sb-core.

Recommended layering:

```text
sb-core V2Ray task owner
  -> publishes source-local RuntimeTaskState via watch

V2RayServer trait
  -> exposes cloneable runtime_state receiver or snapshot+subscribe method

app adapter
  -> maps source-local RuntimeTaskState into SidecarCompletion

bootstrap consumer
  -> log-only observation for unexpected terminal states

run-engine consumer
  -> later supervisor-side event/policy integration
```

Trait direction:

```rust
pub trait V2RayServer: Send + Sync + std::fmt::Debug {
    fn start(&self) -> anyhow::Result<()>;
    fn close(&self) -> anyhow::Result<()>;
    fn stats(&self) -> Option<Arc<StatsManager>> { None }
    fn runtime_state(&self) -> Option<V2RayRuntimeStateReceiver> { None }
}
```

The exact type name can change, but it should live in sb-core or an sb-types-style neutral crate,
not in app.

Avoid:

- App types in sb-core.
- sb-core sending app supervisor events directly.
- A Clash-only API that cannot map to V2Ray.
- A V2Ray-only trait that forces Clash into a separate semantic model.

## Consumer Strategy

### Bootstrap

Mechanism:

- `ServiceHandle` exposes `subscribe_runtime_state()` or `completion_state()`.
- Bootstrap can spawn a small observer task per sidecar, or `Runtime` can own observer handles.
- Observer logs unexpected exits only. It does not restart and does not hard-fail.

Lifecycle:

- Observer should stop on normal shutdown or after terminal state.
- If `ServiceHandle` is dropped without shutdown, the observer must not leak indefinitely; it should
  watch both completion and a cancellation token / handle-owned shutdown path.

### Run-engine

Mechanism:

- `AdminServices` or a shared sidecar registry subscribes to sidecar terminal state.
- Later, run-engine can map unexpected exits into a `SidecarExited` supervisor-facing event.

Policy boundary:

- 01C should define contract and state plumbing.
- A later policy card should decide whether run-engine only logs, degrades, restarts, or exits.
- Do not introduce hard-fail in the mechanism card.

Existing supervisor:

- There is a run-engine loop around signal/reload and a sb-core supervisor handle, but no current
  sidecar completion input. A consumer event can be added later without making sb-core aware of app
  policy.

## Implementation Route Comparison

| Route | Summary | Assessment |
| --- | --- | --- |
| 1. Keep log-only | Rely on existing task logs and shutdown joins | Leaves 01A gap open. Runtime task can die while handles remain live-looking. V2Ray remains opaque. |
| 2. App `ServiceHandle` passive query only | Add `is_finished()` / `try_take_exit()` to app handle | Incomplete. No active notification, no stable poll point, and cannot cover V2Ray actual serve task. |
| 3. App-local active projection for Clash only | Add completion receiver around `PreboundClashApiHandle` first | Technically feasible and small, but risks creating a Clash-specific API unless the V2Ray contract is designed first. Acceptable only after 01C defines shared app-level semantics. |
| 4. Source-owner terminal state + app adapter | Owner publishes source-local state; app maps to `SidecarCompletion`; consumers choose policy | Recommended. It satisfies late subscribers, exactly-once terminal state, panic projection, and cross-crate ownership. It is the smallest complete long-term direction. |
| 5. Direct supervisor hard-fail | Send sidecar death directly to run-engine supervisor and exit | Rejected for this phase. It mixes mechanism and product policy, does not help bootstrap, and couples sb-core/app boundaries too early. |

## Staged Implementation Plan

### Phase 0: terminal state contract

Goal:

- Define minimal source-local runtime state and app-level completion mapping.
- Choose `watch` as source-of-truth mechanism.
- Specify monitor-task panic mapping and exactly-once terminal submit semantics.

Modify crates:

- likely `app` for app-level sidecar completion types;
- likely `sb-core` or neutral shared crate for V2Ray source-local state.

New types/methods:

- source-local `RuntimeTaskState` / `RuntimeTaskExit`;
- app `SidecarCompletion` / `SidecarExit`;
- terminal submit helper.

Caller behavior:

- none beyond compile-time plumbing.

Test strategy:

- unit tests for monotonic state transitions;
- late-subscriber reads terminal state;
- double terminal submit preserves first exit.

Product policy change:

- none.

Stop conditions:

- if watch cannot cross the needed trait/object boundaries without leaking app types into sb-core,
  stop and re-evaluate type placement.

### Phase 1: Clash projection

Goal:

- Add terminal projection for the shared pre-bound Clash serve task.

Modify crates:

- `app` only, likely `run_engine_runtime/admin_start.rs` plus bootstrap/run-engine handle plumbing.

New types/methods:

- completion receiver on `PreboundClashApiHandle` / shared app sidecar handle;
- monitor task around the axum serve future;
- bootstrap/run-engine adapter mapping to app `SidecarCompletion`.

Caller behavior:

- visible-but-nonfatal;
- unexpected terminal state logged once.

Test strategy:

- serve error maps to terminal state;
- shutdown maps to clean terminal state;
- panic in inner task maps to panic terminal state;
- late subscriber sees terminal state.

Product policy change:

- none.

Stop conditions:

- if adding projection requires changing sb-api public API or double-awaiting a join handle.

### Phase 2: V2Ray projection

Goal:

- Publish terminal state from the true sb-core V2Ray serve-task owner.

Modify crates:

- `sb-core` for `V2RayApiServer`;
- app adapter code that consumes `Arc<dyn V2RayServer>`.

New types/methods:

- V2Ray source-local runtime state receiver;
- `V2RayServer::runtime_state()` or equivalent snapshot+subscribe method;
- monitor task wrapping the tonic serve future.

Caller behavior:

- bootstrap observes unexpected exits and logs;
- run-engine can store/forward terminal state, but policy remains nonfatal until a later card.

Test strategy:

- bind success starts in `Running`;
- close transitions to clean exit;
- serve error / synthetic panic maps terminally;
- late subscriber sees terminal state;
- trait object can return a cloneable receiver.

Product policy change:

- none.

Stop conditions:

- if trait changes pull app-specific policy or supervisor events into sb-core.

### Phase 3: consumer policy

Goal:

- Decide what consumers do with completion events.

Modify crates:

- app run-engine supervisor-facing code;
- maybe bootstrap runtime for observer lifecycle.

New types/methods:

- optional `SidecarExited` run-engine event;
- observer task lifecycle owner.

Caller behavior:

- bootstrap remains log-only unless policy changes.
- run-engine may log, degrade, restart, or hard-fail only after explicit policy review.

Test strategy:

- event delivery without hard-fail;
- shutdown does not emit unexpected-exit warning;
- observer does not leak after runtime shutdown.

Product policy change:

- yes, only if this phase explicitly chooses one.

Stop conditions:

- if the proposed behavior changes global process exit semantics without explicit approval.

## Classification

`C. CROSS_CRATE_LIVENESS_CONTRACT_REQUIRED`

Reason: app-local handle extension can cover Clash but cannot cover V2Ray, because both bootstrap
and run-engine V2Ray hide the true tonic serve task inside sb-core behind `V2RayServer`. A complete
solution needs a source-owner terminal-state contract across the sb-core/app boundary, but does not
require redesigning the whole supervisor boundary first.

## Recommended Next Card

`APP-SIDECAR-LIVENESS-01C - cross-crate runtime completion contract`

Minimum scope:

- Define the source-local runtime completion contract and app mapping.
- Choose `watch`-backed terminal state with exactly-once semantics.
- Do not add hard-fail, restart, health probes, or broad supervisor policy.
- Prefer contract and one narrow proof path over all sidecars in one oversized card.

## Verification

Required after this proposal:

- `git diff --check`
- `bash agents-only/06-scripts/verify-consistency.sh`
- `bash agents-only/06-scripts/check-boundaries.sh`
- `git status --short --branch`

## State

`APP-SIDECAR-LIVENESS-01B` is DONE.

`SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`.
