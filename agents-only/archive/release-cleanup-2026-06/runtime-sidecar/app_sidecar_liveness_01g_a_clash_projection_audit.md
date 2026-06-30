<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01G-A — Clash runtime completion projection boundary audit

> Audit only. No Rust changed. Determines whether the Clash API background task can carry a
> runtime-completion projection compatible with the V2Ray adapter, and the minimal implementation
> card. No consumer policy.

## A. Accepted-commits push result

`git push origin main` → `ae5898d9..84cea4dd main -> main` (01F adapter + checkpoint now on remote).
Post-push: `## main...origin/main` + untracked `agents-only/a0_reality_spike/`.

## B. Baseline git status

`## main...origin/main` + untracked `a0_reality_spike/`. Chain `84cea4dd`/`24323c02`/`ae5898d9`/
`3f09a338` confirmed.

## C. Clash task-owner matrix

Both paths funnel through the **single shared helper** `spawn_prebound_clash_api_server`
(`app/src/run_engine_runtime/admin_start.rs:105`).

| Path | Entry | pre-bind site | real serve-task owner | shutdown sender owner | join owner | current log owner |
| --- | --- | --- | --- | --- | --- | --- |
| bootstrap Clash | `bootstrap_runtime/api_services.rs::start_clash_api_server` (:24) → `spawn_prebound_clash_api_server` | `pre_bind_clash_api_listener` (admin_start.rs:91, **app, sync**) | `tokio::spawn` in `spawn_prebound_clash_api_server` (admin_start.rs:116) running sb-api `serve_with_listener_and_shutdown` | `ServiceHandle.shutdown` (oneshot, moved out of `PreboundClashApiHandle`) | `ServiceHandle.join` (moved out) | the spawned task logs `"Clash API server error"` (admin_start.rs:121) |
| run-engine Clash | `admin_start.rs::start_clash_api_from_supervisor` (:156) → same helper | same `pre_bind_clash_api_listener` | same `tokio::spawn` helper | `ClashApiHandle.shutdown` (oneshot, moved out) | `ClashApiHandle.join` (moved out) | same in-task `"Clash API server error"` log |

Key: the **true task owner is app** (`spawn_prebound_clash_api_server`), not sb-api. sb-api owns only
the serve *future* (`ClashApiServer::serve_with_listener_and_shutdown` → `ApiResult<()>`). This differs
from V2Ray (where the task lived inside sb-core) and is **more favorable**: the whole projection can
be built app-local at the single shared helper.

## D. `PreboundClashApiHandle` fields + destructuring

`admin_start.rs:58` — `pub struct PreboundClashApiHandle { pub listen_addr: SocketAddr, pub shutdown:
oneshot::Sender<()>, pub join: JoinHandle<()> }`. It **is destructured at both call sites**, moving
`shutdown` + `join` into wrapper handles and discarding `listen_addr` (bootstrap) / re-storing it
(run-engine):
- bootstrap (`api_services.rs:77`): `ServiceHandle { name:"clash_api", shutdown: handle.shutdown, join: handle.join }`.
- run-engine (`admin_start.rs:222`): `ClashApiHandle { listen_addr, shutdown: handle.shutdown, join: handle.join }`.

## E. `ServiceHandle` / `AdminServices` holding

- `ServiceHandle` (`api_services.rs:9`): `{ name:&'static str, shutdown: oneshot::Sender<()>, join:
  JoinHandle<()> }`; stored in `runtime_shell.rs` as `Vec<ServiceHandle>`, consumed once at shutdown
  (`runtime_shell.rs:46` `service.shutdown().await`).
- `AdminServices` (`admin_start.rs:8`): holds `Option<ClashApiHandle>` (private, admin_start.rs:51) +
  optional admin_debug; `shutdown(self)` (admin_start.rs:16) awaits each.

## F. Shutdown-sender ownership

A bare `oneshot::Sender<()>`, created in the helper (admin_start.rs:115), returned in
`PreboundClashApiHandle`, then **moved out** into `ServiceHandle.shutdown` / `ClashApiHandle.shutdown`.
`shutdown()` (both wrappers) sends `()` then awaits join. **No `ShutdownRequested` is published by
anyone today** — there is no runtime publisher. Sender behavior: sb-api's graceful closure does
`let _ = shutdown.await` (server.rs:267), so **dropping the sender also triggers graceful shutdown**
(oneshot recv resolves `Err` on drop, ignored) — i.e. both send and drop end the serve future
`Ok(())`.

## G. Join ownership

`JoinHandle<()>` created in the helper, moved into the wrapper, awaited by `shutdown()`
(`ServiceHandle::shutdown` api_services.rs:19; `ClashApiHandle::shutdown` admin_start.rs:70). **The
serve `ApiResult` is swallowed inside the task** (logged then dropped), so the join outcome is
`()` and currently carries only panic/cancel — never the serve error or clean/unexpected distinction.

## H. Handle single-lifecycle?

**Yes, strictly single-lifecycle.** Evidence:
1. `spawn_prebound_clash_api_server` creates a fresh listener + fresh oneshot + fresh task per call.
2. Both `shutdown(self)` methods consume `self` (no restart on the same handle).
3. `start_admin_services` is called **once** at run startup (`supervisor.rs:249`), *before* the
   watch/reload loop; reload updates router/config through shared `Arc`s and does **not** re-invoke
   it. Bootstrap creates its `ServiceHandle` once, consumed once at shutdown.
4. No path rebinds the same listener with a second handle (bootstrap and run-engine paths are
   mutually exclusive runtimes; each makes one handle).

## I. Generation model

**Handle-local generation = 1, single source per handle.** Each `PreboundClashApiHandle` ⇔ exactly
one serve generation. There is no `start→shutdown→restart` on the same handle, no per-reload restart,
and no two handles contending one listener. Therefore:
- runtime snapshot uses `generation = 1` (handle-local constant).
- a new handle naturally creates a new independent snapshot source.
- consumers do **not** compare generations across handles; **no global counter** is introduced.

This is strictly simpler than V2Ray's multi-generation model — Clash needs no `next_generation`
counter, no `last_exit` cross-generation ratchet (there is only generation 1 and at most its single
terminal). The app-level `SidecarRuntimeSnapshot` still fits: `current = Running/ShutdownRequested(1)`,
`last_exit = (1, exit)`.

## J. Source-of-truth recommended location

**Route A — own the `watch` sender inside `spawn_prebound_clash_api_server` / `PreboundClashApiHandle`.**
It is the single shared task owner; bootstrap and run-engine both go through it, so one implementation
covers both with zero duplication and **no sb-api change**. Route B (wrapping separately in
`ServiceHandle` and `AdminServices`) is **rejected**: it would duplicate the projection across two
call sites, risk one path drifting, and split the task owner from the state owner.

## K. Shutdown controller recommended design

Wrap the bare sender in an app-internal controller carried by the handle (Route B/C hybrid):
```text
ClashShutdownHandle { shutdown_tx: Option<oneshot::Sender<()>>, runtime: <publisher> }
shutdown():
  → idempotent (take the Option)
  → set generation-local shutdown_requested marker
  → publish ShutdownRequested(1) via the watch sender (sync send_replace, no lock needed — single
    generation; if a mutex is later used keep send in-lock per the V2Ray R1 discipline)
  → send the oneshot OUTSIDE any lock
```
**Sender-drop must NOT be silently mapped to `CleanShutdown`.** Because Clash's graceful closure also
fires on sender-drop, a drop-without-`shutdown()` ends the serve `Ok(())` with the marker UNSET → the
monitor classifies `UnexpectedCompletion` (or `Unknown`), never `CleanShutdown`. The marker is the
sole signal that a deliberate shutdown was requested.

## L. Outer-monitor recommended design

**Route B — outer monitor + inner serve task** (mirrors V2Ray):
```text
spawn_prebound_clash_api_server:
  → pre-bind (existing, sync)
  → create watch::Sender<SidecarRuntimeSnapshot>, publish Running(1)
  → spawn outer monitor:
       inner = tokio::spawn(server.serve_with_listener_and_shutdown(listener, rx))  // returns ApiResult<()>
       outcome = inner.await                                                        // Result<ApiResult<()>, JoinError>
       exit = classify(outcome, shutdown_requested)
       publish Exited(1, exit)   // sole terminal writer + sole terminal logger
  → return handle { listen_addr, shutdown controller, runtime subscribe }
```
The inner task must **return** the `ApiResult` (stop swallowing it) so the monitor can distinguish
serve-error from clean/unexpected. The monitor's join handle is owned by the handle/controller and
awaited by `shutdown()` (replacing the current raw-serve-join await).

## M. Terminal mapping

`classify(outcome: Result<ApiResult<()>, JoinError>, shutdown_requested: bool)`:

| inner result | terminal |
| --- | --- |
| `Ok(Ok(()))`, shutdown requested | `CleanShutdown` |
| `Ok(Ok(()))`, not requested | `UnexpectedCompletion` |
| `Ok(Err(ApiError))` | `ServeError(e.to_string())` |
| `Err(join)` `is_panic()` | `Panicked(payload-or-fallback)` |
| `Err(join)` `is_cancelled()` | `Cancelled` |
| other `JoinError` | `Cancelled` (nearest defined) |

Identical shape to V2Ray's `classify_exit`; 01G-B may extract a shared helper or keep a Clash-local
copy (implementation detail).

## N. Panic / cancelled projection

1. **Serve future return type:** `ApiResult<()>` (= `Result<(), ApiError>`); clean graceful shutdown
   yields `Ok(())` (server.rs:257-274).
2. **Shutdown reliably produces normal completion:** yes — graceful closure fires on send *or* drop,
   `axum::serve(...).with_graceful_shutdown(...).await` returns `Ok(())`.
3. **Generation-local shutdown marker needed:** yes (an `Arc<AtomicBool>` set by the controller; read
   by the monitor) to separate `CleanShutdown` from `UnexpectedCompletion`/sender-drop.
4. **Panic payload conversion:** `JoinError::into_panic()` → `downcast_ref::<&str>()/<String>()` →
   stable fallback string (same as V2Ray).
5. **Stale terminal:** none — single generation, single monitor, single terminal; no cross-generation
   ratchet required.
6. **Monitor join handle final owner:** the handle's shutdown controller (awaited by `shutdown()`),
   not the raw inner serve join.

## O. App adapter reuse

1. Clash task owner can publish **app-level `SidecarRuntimeSnapshot` directly** (it is app code), so
   **no second mapping layer**.
2. Add `SidecarRuntimeSource::Clash(watch::Receiver<SidecarRuntimeSnapshot>)` to
   `app/src/sidecar_runtime.rs`.
3. Add constructor `SidecarRuntimeSubscription::from_clash(name, receiver)` (takes the receiver
   exposed by the handle/controller). (Unlike `from_v2ray_server`, the source is already an app
   snapshot, so the Clash arm of `snapshot_and_mark_seen()`/`changed()` is an identity
   `borrow_and_update().clone()`, not a map.)
4. `snapshot_and_mark_seen()` and `changed()` are reused — they already `match &mut self.source`; add
   the `Clash` arm.
5. **No second watch channel** beyond the one source the handle owns; the adapter holds that single
   receiver.

## P. bootstrap follow-up integration point

- `ServiceHandle` should carry a `SidecarRuntimeSubscription` (and the `ClashShutdownHandle`) instead
  of bare `shutdown`/`join`. Its `shutdown()` should drive the controller (publish ShutdownRequested →
  send) and await the **monitor** join (not the raw serve join).
- A later log-only observer can either live on `ServiceHandle` or be a small task owned by
  `runtime_shell`; the join outcome no longer needs separate retention (the monitor owns it).
- **No hard-fail / restart / degrade decided here.**

## Q. run-engine follow-up integration point

- `AdminServices` / the private `ClashApiHandle` should store the `SidecarRuntimeSubscription` +
  `ClashShutdownHandle`; `AdminServices::shutdown()` drives the controller and awaits the monitor.
- A future supervisor or log-only observer subscribes from `AdminServices`. **No policy decided here.**

## R. Five-route comparison

| Route | Verdict |
| --- | --- |
| 1. Keep log-only | Gap: serve error logged-and-swallowed; panic visible only at the shutdown join; no Running/ShutdownRequested/terminal projection; nothing to subscribe to. |
| 2. `JoinHandle::is_finished()` only | No active notification, no exit reason, no stable poll point; join outcome is `()` (no serve error). Insufficient. |
| 3. bootstrap & run-engine each wrap | Duplicates the projection across two sites that already share one helper → drift risk; splits task owner from state owner. Reject. |
| 4. `PreboundClashApiHandle` task-owner projection | **Recommended** — single watch source at the shared helper, unified shutdown controller, outer monitor; both paths inherit it; no sb-api change. |
| 5. Direct supervisor hard-fail | Reject — mixes mechanism with product policy. |

## S. Classification + recommended next card

**Classification: `B. HANDLE_RESHAPE_REQUIRED`.** The projection is fully app-local (no sb-api / no
cross-crate change — Route 4 / answer J), but it **requires reshaping** `PreboundClashApiHandle`
(add a runtime receiver + replace the bare sender with a shutdown controller) and its two wrappers
`ServiceHandle` / `ClashApiHandle` (carry subscription + controller; `shutdown()` publishes
ShutdownRequested and awaits the monitor). Shutdown *semantics* need a marker but not a redesign
(C not required); no cross-crate change (D not required); evidence is sufficient (E not required).

**Recommended next card: `APP-SIDECAR-LIVENESS-01G-B — implement Clash runtime completion
projection`** — app only; reshape `PreboundClashApiHandle` + wrappers; create the task-owner
`watch::Sender<SidecarRuntimeSnapshot>` publishing `Running(1)`; add a unified `ClashShutdownHandle`
that publishes `ShutdownRequested(1)` then sends; outer monitor as sole terminal writer capturing
panic/cancellation; add `SidecarRuntimeSource::Clash` + `from_clash`; **no consumer policy**.

## T. Checkpoint / push / final status

Checkpoint `checkpoint: audit clash runtime completion projection` (active_context.md + this file).
`git diff --check` / `verify-consistency.sh` / `check-boundaries.sh` run; only the two docs committed;
`a0_reality_spike/` left untracked; then pushed. Final `git status --short --branch` recorded in the
session report.

## State

`APP-SIDECAR-LIVENESS-01G-A` = `B. HANDLE_RESHAPE_REQUIRED`; next = `APP-SIDECAR-LIVENESS-01G-B`.
Defers unchanged: `SVC-V2RAY-API-01B` = DEFER/POLICY REVIEW; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray
breaking cleanup = DEFER/FUTURE MAJOR; `TIDY-RUSTDOC-LINKS` = DEFER/HISTORICAL BASELINE RED;
`TIDY-APP-BREAKER-FLAKE` = DEFER/NEEDS INDEPENDENT REPRODUCTION. Out-of-scope unchanged: H5/H6/H7.
