# APP-SIDECAR-LIVENESS-01A - runtime liveness projection audit

## Scope

Audit-only. No Rust code, tests, Cargo files, fixtures, REALITY artifacts, CI files, or
`agents-only/a0_reality_spike/` were changed.

This audit separates three meanings:

- Startup readiness: whether bind/start succeeded before a live-looking handle is returned.
- Runtime liveness: whether the background task is still running after startup.
- Service health: whether a live task correctly handles requests.

This card audits runtime liveness only. Startup readiness is already covered by the earlier
pre-bind work; request-level health is left as a separate boundary.

## Baseline

Before the audit, accepted commits were pushed:

- `44d2c4fa checkpoint: record sb-api v2ray alias deprecation`
- `60b88414 feat(sb-api): deprecate generic v2ray server aliases`
- `79e3b1bd checkpoint: audit sb-api v2ray deprecation impact`

Post-push baseline:

- `## main...origin/main`
- `?? agents-only/a0_reality_spike/`

Relevant closed baseline:

- `APP-SIDECAR-BIND-01`: Clash API uses `spawn_prebound_clash_api_server`; bind failure no longer
  returns a live-looking handle.
- `APP-V2RAY-SIMPLE-01A`: bootstrap V2Ray API uses the sb-core real listener; bind failure no
  longer returns a live-looking handle.
- `APP-V2RAY-SURFACE-02D`: generic public V2Ray aliases deprecated; breaking cleanup remains
  `DEFER / FUTURE MAJOR WINDOW`.
- `SVC-V2RAY-API-01B`: still `DEFER / POLICY REVIEW`.

## Files Reviewed

Primary review set:

- `app/src/bootstrap.rs`
- `app/src/bootstrap_runtime/api_services.rs`
- `app/src/bootstrap_runtime/runtime_shell.rs`
- `app/src/run_engine_runtime/admin_start.rs`
- `app/src/run_engine_runtime/context.rs`
- `app/src/run_engine_runtime/supervisor.rs`
- `crates/sb-core/src/services/v2ray_api.rs`
- `crates/sb-core/src/context.rs`
- `crates/sb-api/src/clash/server.rs`
- `crates/sb-api/src/v2ray/`

Additional sidecar-adjacent review:

- `app/src/tracing_init.rs`
- `app/src/admin_debug/http_server.rs`
- `app/src/admin_debug/mod.rs`
- `app/src/admin_debug/reloadable.rs`
- `app/src/util.rs`
- `crates/sb-core/src/admin/http.rs`
- `crates/sb-metrics/src/lib.rs`
- `crates/sb-api/src/managers.rs`

## ServiceHandle

Definition: `app/src/bootstrap_runtime/api_services.rs`.

```rust
pub(crate) struct ServiceHandle {
    pub(crate) name: &'static str,
    pub(crate) shutdown: tokio::sync::oneshot::Sender<()>,
    pub(crate) join: tokio::task::JoinHandle<()>,
}
```

Construction points:

- bootstrap Clash API: wraps `PreboundClashApiHandle` from `spawn_prebound_clash_api_server`.
- bootstrap V2Ray API: wraps a shutdown waiter task that calls `server.close()` on the sb-core
  V2Ray server.
- tests construct synthetic handles for shutdown behavior.

Answers:

1. Fields: `name`, shutdown sender, `JoinHandle<()>`.
2. It saves a `JoinHandle`, but the meaning differs by sidecar.
3. It saves shutdown sender.
4. It saves no completion state.
5. It cannot return task exit reason; `shutdown()` ignores the join result.
6. `join()` is only awaited through explicit runtime shutdown.
7. No watcher, poller, or supervisor actively reads task state after startup.
8. Drop has no custom behavior. Dropping the shutdown sender can wake tasks that await the receiver;
   dropping the `JoinHandle` detaches the task without awaiting outcome.
9. Yes: task can exit while handle remains; caller may not observe it; started logs can remain as
   the last visible lifecycle statement.

Important nuance: bootstrap V2Ray's `ServiceHandle.join` is not the actual gRPC serve task. The
actual serve task is spawned inside `crates/sb-core/src/services/v2ray_api.rs` and no join handle is
exposed to app.

## Sidecar Matrix

| Sidecar | Startup entry | Underlying listener / task | Pre-bind | Returned handle type | Shutdown path | Join path | Unexpected task exit observable |
| --- | --- | --- | ---: | --- | --- | --- | ---: |
| bootstrap Clash API | `bootstrap.rs` -> `start_clash_api_server` | `spawn_prebound_clash_api_server` -> axum `serve_with_listener_and_shutdown` task | Yes | `ServiceHandle` wrapping `PreboundClashApiHandle` | Runtime shutdown sends oneshot | `ServiceHandle::shutdown()` awaits `JoinHandle<()>` and discards result | No active projection; serve errors are logged in task; panic only visible if later join result were inspected, but it is discarded |
| run-engine Clash API | `RuntimeContext::start_admin_services` -> `start_clash_api_from_supervisor` | Same pre-bound axum serve task | Yes | private `ClashApiHandle` inside `AdminServices` | `AdminServices::shutdown()` sends oneshot | `ClashApiHandle::shutdown()` awaits join and logs only join failure during shutdown | No active projection; not wired into supervisor event loop |
| bootstrap V2Ray API | `bootstrap.rs` -> `start_v2ray_api_server` | `sb_core::services::v2ray_api::V2RayApiServer::start()` pre-binds and spawns tonic serve task; outer app task only waits for shutdown then calls `close()` | Yes | `ServiceHandle`, but its join is shutdown waiter, not serve task | Runtime shutdown wakes outer waiter, then calls `server.close()` | Outer shutdown waiter is awaited; actual serve task is not joined | No active projection; sb-core private `started` flag resets on task exit, but app cannot observe it |
| run-engine V2Ray API | `sb-core runtime::supervisor::wire_experimental_sidecars` | sb-core V2Ray server pre-binds and spawns tonic serve task | Yes | `Context.v2ray_server: Option<Arc<dyn V2RayServer>>`, not app `ServiceHandle` | `shutdown_context()` calls `v2ray.close()` | No join handle exposed | No active projection; trait exposes `start/close/stats`, no liveness or completion event |

Other sidecar-adjacent handles:

- Metrics exporter: `MetricsExporterHandle` owns a `JoinHandle<()>`; shutdown aborts and awaits it.
  No runtime liveness projection before shutdown.
- Admin debug server: `AdminDebugHandle` owns `CancellationToken` + `JoinHandle<()>`; startup bind
  errors return before handle in async path. Runtime death is not projected unless shutdown awaits
  the join. Drop cancels but does not await.
- Core admin (`admin_impl=core`): `spawn_core_admin_from_supervisor` calls
  `sb_core::admin::http::spawn_admin`, which returns a thread handle, but app discards it. Runtime
  death is not projected at app level.
- ProviderManager background updates: owns a task handle internally, but this is not one of the app
  sidecar start entries audited as Clash/V2Ray.

## Exit Source Matrix

| Sidecar | Exit source | Logs | Projects to caller | Changes process state | Only discoverable on later join |
| --- | --- | ---: | ---: | ---: | ---: |
| bootstrap Clash | Normal shutdown | Axum path normally quiet; shutdown path awaited | No status projection; caller initiated it | No | Join awaited, result discarded |
| bootstrap Clash | Listener/serve error | Yes: `Clash API server error` | No | No | No; task maps error to log then returns `()` |
| bootstrap Clash | Panic | Tokio join would carry `JoinError` | No active projection | No | Only if joined, but `ServiceHandle::shutdown` discards it |
| bootstrap Clash | Shutdown sender dropped early | Graceful shutdown future completes | No | No | Join may complete detached |
| bootstrap Clash | Dependency resource closes | If axum serve returns error, task logs | No | No | No |
| bootstrap Clash | Task abort | N/A in product path | N/A | N/A | N/A |
| run-engine Clash | Normal shutdown | Shutdown path may log join failure only | No status projection; caller initiated it | No | Join awaited during `AdminServices::shutdown()` |
| run-engine Clash | Listener/serve error | Yes: `Clash API server error` | No | No | No |
| run-engine Clash | Panic | Join failure logged only if later shutdown awaits it | No active projection | No | Yes |
| run-engine Clash | Shutdown sender dropped early | Graceful shutdown future completes | No | No | Join may complete detached |
| run-engine Clash | Dependency resource closes | If axum serve returns error, task logs | No | No | No |
| run-engine Clash | Task abort | N/A in product path | N/A | N/A | N/A |
| bootstrap V2Ray | Normal shutdown | sb-core logs shutdown/stopped; app waits bind release | No service completion status | No | Actual serve task not joined |
| bootstrap V2Ray | Tonic serve error | Yes: `V2Ray API server error` | No | No | No |
| bootstrap V2Ray | Panic | Internal join handle is not retained | No | No | No |
| bootstrap V2Ray | Shutdown sender dropped early | Internal graceful shutdown can complete | No | No | No |
| bootstrap V2Ray | Dependency resource closes | If tonic serve returns error, task logs | No | No | No |
| bootstrap V2Ray | Task abort | N/A in product path | N/A | N/A | N/A |
| run-engine V2Ray | Normal shutdown | sb-core logs shutdown/stopped | No service completion status | No | No join handle |
| run-engine V2Ray | Tonic serve error | Yes: `V2Ray API server error` | No | No | No |
| run-engine V2Ray | Panic | Internal join handle is not retained | No | No | No |
| run-engine V2Ray | Shutdown sender dropped early | Internal graceful shutdown can complete | No | No | No |
| run-engine V2Ray | Dependency resource closes | If tonic serve returns error, task logs | No | No | No |
| run-engine V2Ray | Task abort | N/A in product path | N/A | N/A | N/A |

## Bootstrap Versus Run-engine Policy

Bootstrap:

- Startup sidecar failure is visible but nonfatal: invalid config or bind failure logs and returns
  `None`; main bootstrap continues.
- Runtime sidecar death is not restarted and not escalated.
- Clash runtime errors are log-only from the spawned task.
- V2Ray runtime errors are log-only from sb-core. The private `started` flag resets when the serve
  task exits, but bootstrap has no path to query it.

Run-engine:

- Clash startup failure logs and stores `None`; main engine continues.
- V2Ray startup failure logs in sb-core and does not wire `Context.v2ray_server`; main engine
  continues.
- Runtime sidecar death does not enter the run-engine supervisor signal/reload loop.
- Shutdown later calls the owned handle or trait close, but this is not active liveness projection.

No evidence supports silently upgrading sidecar runtime death to a global hard-fail in this card.
That would be a product policy change, not a technical cleanup.

## Local Fixability

No scratch code was needed. The repository evidence is enough:

- `JoinHandle` supports await and `is_finished()`, and the code already stores a `JoinHandle` for
  bootstrap/run-engine Clash and admin-debug/metrics handles.
- `ServiceHandle` can add passive state methods for the tasks it truly owns.
- Bootstrap V2Ray's app-level `ServiceHandle` does not own the actual serve task, so a
  ServiceHandle-only fix would be incomplete.
- sb-core V2Ray already keeps a private `started: Arc<AtomicBool>` that resets on serve-task exit,
  but the `V2RayServer` trait exposes no liveness method or completion event.
- run-engine already has a supervisor loop, but sidecar task completion is not currently an input to
  that loop.

Therefore the repo has local additive building blocks, but the event model must be decided before
implementation.

## Route Evaluation

| Route | Summary | Assessment |
| --- | --- | --- |
| 1. Keep current | Startup honesty only; runtime death remains log-only or shutdown-join-only | Lowest churn, but handles can remain live-looking after task death; run-engine cannot react; V2Ray death is especially opaque because no join handle is exposed |
| 2. Passive `ServiceHandle` liveness query | Add `is_finished()`, `state()`, or `try_take_exit()` to handles that own real tasks | Additive for Clash and admin-debug/metrics style handles; improves observability only if callers poll; incomplete for bootstrap/run-engine V2Ray unless sb-core exposes actual serve-task state |
| 3. Active completion projection | Add watch/oneshot completion signal or supervisor event | Best semantic fit for runtime liveness; can distinguish bootstrap log-only policy from run-engine reactions; requires touching all sidecar construction paths and defining exit-event payload |
| 4. Run-engine supervisor integration, bootstrap log-only | Route run-engine sidecar death into supervisor/event handling while bootstrap remains diagnostic | Fits existing run-engine ownership better, but creates intentionally different bootstrap/run-engine semantics; should be proposed explicitly and split from implementation |
| 5. Sidecar death hard-fails process | Treat sidecar death as global fatal | Not recommended as a hidden fix. This is product policy and must not be introduced without explicit decision |

## Classification

`C. MISSING_RUNTIME_LIVENESS_PROJECTION`

Reason: startup readiness is fixed, but runtime task completion is not reliably projected to
bootstrap or run-engine callers. The repo has local additive primitives (`JoinHandle` on several
handles, private sb-core V2Ray `started` state, and an existing run-engine supervisor loop), so this
does not yet require a full lifecycle boundary redesign. It does require a proposal to define the
completion event model and caller policy before implementation.

## Recommended Next Card

`APP-SIDECAR-LIVENESS-01B - ServiceHandle runtime completion projection proposal`

Scope for the proposal:

- Define passive versus active completion projection.
- Define a sidecar exit event payload, including normal shutdown, serve error, panic/join error, and
  unknown internal exit.
- Decide bootstrap policy separately from run-engine policy.
- Decide how sb-core V2Ray exposes runtime completion without folding it into
  `SVC-V2RAY-API-01B`.
- Confirm no global hard-fail is introduced without explicit product policy.

## Verification

Audit-only verification commands required after writing this document:

- `git diff --check`
- `bash agents-only/06-scripts/verify-consistency.sh`
- `bash agents-only/06-scripts/check-boundaries.sh`
- `git status --short --branch`

## State

`APP-SIDECAR-LIVENESS-01A` is DONE.

`SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`.
