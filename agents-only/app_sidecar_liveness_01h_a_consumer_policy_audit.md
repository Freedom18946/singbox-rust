<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01H-A — sidecar runtime completion consumer policy audit

> Audit only. No Rust changed. Decides how app should consume the already-published sidecar runtime
> snapshots. Mechanism/policy stay separated; no hard-fail / restart / degrade / health probe.

## A. Accepted-commits push result

`git push origin main` → `d8845c96..cac2ccb9 main -> main` (01G-B code + checkpoint now on remote).
Post-push: `## main...origin/main` + untracked `agents-only/a0_reality_spike/`.

## B. Baseline git status

`## main...origin/main` + untracked `a0_reality_spike/`. Chain `cac2ccb9`/`bf7304fd`/`d8845c96`/
`84cea4dd` confirmed.

## C. Four-path consumer matrix

| Sidecar | start entry | snapshot source | who can subscribe today | earliest subscribe point | shutdown owner | sensible consumer owner |
| --- | --- | --- | --- | --- | --- | --- |
| bootstrap Clash | `bootstrap_runtime/api_services.rs::start_clash_api_server` → `spawn_prebound_clash_api_server` | app-local `watch::Sender<SidecarRuntimeSnapshot>` in `ClashRuntimePublisher` | `ClashShutdownHandle::subscribe_runtime_state()` (held inside `ServiceShutdown::Clash`) | at construction in `start_clash_api_server`, or via a `ServiceHandle` passthrough | bootstrap `ServiceHandle::shutdown()` (→ `ClashShutdownHandle::shutdown()`); handles in `runtime_shell` `Vec<ServiceHandle>` | **none** (source monitor already logs; bootstrap = visible-but-nonfatal) |
| bootstrap V2Ray | `api_services.rs::start_v2ray_api_server` | sb-core `watch::Sender<V2RayServerRuntimeSnapshot>` in `V2RayApiServer` | `V2RayServer::subscribe_runtime_state()` on the `Arc<V2RayApiServer>` | **before** the `Arc` is moved into the close-waiter `tokio::spawn` (api_services.rs:121-137) | bootstrap `ServiceHandle::shutdown()` (`Task` variant → close-waiter) | **none** (source monitor logs) |
| run-engine Clash | `admin_start.rs::start_clash_api_from_supervisor` → `spawn_prebound_clash_api_server` | app-local Clash `watch` | `ClashShutdownHandle::subscribe_runtime_state()` (held inside private `ClashApiHandle` in `AdminServices`) | at construction in `start_clash_api_from_supervisor` | `AdminServices::shutdown()` → `ClashApiHandle::shutdown()` | **run-engine** structured-event bridge (observer owned by run-engine) |
| run-engine V2Ray | sb-core `wire_experimental_sidecars` (inside supervisor) | sb-core V2Ray `watch` | `V2RayServer::subscribe_runtime_state()` via `supervisor.handle().state().await` → `state.context.v2ray_server` | any time after start, by reading supervisor `State.context` | sb-core `shutdown_context()` → `v2ray.close()` | **run-engine** structured-event bridge |

## D. bootstrap V2Ray receiver extraction point

In `start_v2ray_api_server`: the `Arc<V2RayApiServer>` is created, `start()`ed, then **moved** into the
close-waiter `tokio::spawn` (api_services.rs:121-137). A receiver must be extracted by calling
`server.subscribe_runtime_state()` **before** that move. It is reachable (the real impl returns
`Some`); it is **not** extracted today, so a future consumer card must add the pre-move extraction. No
capability is structurally lost — only un-wired.

## E. bootstrap Clash receiver extraction point

`spawn_prebound_clash_api_server` returns `PreboundClashApiHandle { shutdown: ClashShutdownHandle }`;
`ClashShutdownHandle::subscribe_runtime_state()` (added in 01G-B) yields the receiver. In bootstrap the
handle is wrapped into `ServiceShutdown::Clash` inside `ServiceHandle`, which does **not** currently
re-expose the receiver. Extraction options: (a) call `subscribe_runtime_state()` in
`start_clash_api_server` before wrapping, or (b) add a `ServiceHandle` passthrough. Capability present,
not lost.

## F. run-engine V2Ray receiver extraction point

`Arc<dyn V2RayServer>` lives in sb-core `Context.v2ray_server` (context.rs:91), wired by
`wire_experimental_sidecars`. The app reaches it via `supervisor.handle().state().await` → read guard
→ `state.context.v2ray_server.as_ref()?.subscribe_runtime_state()` (the same access pattern
`start_clash_api_from_supervisor` already uses for `state_guard.context.service_manager`). Subscribable
anytime, app-locally, with **no sb-core change** (reads existing `State.context`).

## G. run-engine Clash receiver extraction point

`ClashApiHandle { shutdown: ClashShutdownHandle }` is stored (private) in `AdminServices`.
`ClashShutdownHandle::subscribe_runtime_state()` yields the receiver; `start_admin_services` /
`AdminServices` can extract it at construction and spawn an observer it owns. Capability present.

**Capability-loss check (§6.5):** no — the 01G-B reshape *preserved* subscription via
`ClashShutdownHandle::subscribe_runtime_state()` and the V2Ray trait method; the only gap is that
bootstrap V2Ray must extract its receiver before the `Arc` move (D), which is wiring, not loss.

## H. Initial snapshot handling

An observer must call `snapshot_and_mark_seen()` first (a sidecar may already be terminal at subscribe
time; `watch` will not re-emit the seen version), then branch:

| Initial snapshot | observer action |
| --- | --- |
| `current = Running` | enter `changed()` wait |
| `current = ShutdownRequested` | enter wait for terminal; **no** alarm |
| `last_exit = CleanShutdown` (current None) | normal end → stop observer |
| `last_exit = UnexpectedCompletion` | record / project as abnormal |
| `last_exit = ServeError` | record / project as abnormal |
| `last_exit = Panicked` | record / project as abnormal |
| `last_exit = Cancelled` | record / project as abnormal |
| `Unknown` (phase or exit) | explicit degraded handling; never fabricate a normal state |

If `current` and `last_exit` co-exist: `current` = the live (newest) generation's state; `last_exit` =
the highest-generation terminal seen so far. A stale `last_exit` must **not** make a running newer
generation be reported dead — branch on `current` first, treat `last_exit` as history.

## I. `changed()` loop handling

`snapshot_and_mark_seen()` → branch initial → `loop { changed().await? → branch new snapshot → break on
terminal }` → observer exits after terminal. Per transition:

1. `Running → ShutdownRequested`: debug log or silent wait (expected, not abnormal).
2. `ShutdownRequested → CleanShutdown`: no error; normal end.
3. `Running → UnexpectedCompletion`: abnormal projection.
4. `Running → ServeError`: abnormal projection.
5. `Running → Panicked`: abnormal projection.
6. `Running → Cancelled`: abnormal projection.
7. `watch::RecvError`: treat as **projection channel closed**, NOT `CleanShutdown` (the source dropped
   its sender without a terminal having been observed by this receiver).
8. `RecvError` handling: a single `warn` (or a distinct `ProjectionClosed` consumer event) — not an
   `error`, and never synthesized into a terminal exit.

## J. `RecvError` semantics

`RecvError` ⇒ the source `watch::Sender` was dropped. It is **projection-closed**, decoupled from the
sidecar's actual terminal (which, if it happened, was already logged by the source monitor). The
consumer surfaces it as a separate `ProjectionClosed` event / `warn`, never as `CleanShutdown` or any
`SidecarExit`.

## K. source-logger vs consumer-logger division

Both source outer monitors already log the terminal once (V2Ray: sb-core monitor; Clash: app monitor).
**Recommended: Route A** — the source keeps the authoritative terminal log; the consumer does **not**
re-log the same terminal, only emits a structured `SidecarRuntimeEvent` (or records consumer-side
state). This avoids duplicate logs (Route C rejected) and avoids losing bootstrap visibility that
Route B (demote source to debug) would risk. Unique recommendation: **source-owned terminal log +
consumer structured event, no duplicate terminal log**.

## L. bootstrap three-route comparison

- **Route 1 (no new observer):** the source monitor already logs the terminal once; bootstrap policy is
  visible-but-nonfatal, which is satisfied by that log. `ServiceHandle` keeps owning shutdown. The
  subscription capability stays available for a future diagnostic card but no resident observer is
  added. **Recommended.**
- **Route 2 (resident log-only observer):** duplicates the source logger (Route A forbids re-logging),
  needs an observer-lifetime owner in `runtime_shell`, and adds a task with no consumer beyond a log
  bootstrap already has. Rejected — no real consumption value now.
- **Route 3 (observer → bootstrap state container):** bootstrap has no such container (`Runtime` /
  `runtime_shell` hold handles, not a completion store); building one exceeds this boundary. Rejected.

## M. bootstrap unique recommended policy

**Bootstrap Route 1**: no new observer. Rely on the source terminal logger (already present); keep the
`ServiceHandle`/`ClashShutdownHandle` subscription capability for a future diagnostic card. Bootstrap
product semantics (visible-but-nonfatal) are unchanged.

## N. run-engine supervisor existing structure

- App top loop `run_supervisor` (`supervisor.rs:209`) is a **signal-only** loop:
  `wait_for_signal()` → Reload / Terminate; then `runtime_lifecycle.shutdown()` +
  `supervisor.handle().shutdown_graceful()`. No `select!`, no app-level event bus, no `JoinSet`.
- `RuntimeLifecycle` (context.rs:145) holds `metrics_exporter` + `admin_services` + `watch_handle`;
  `shutdown(self)` tears them down. This is the natural owner for run-engine observer joins.
- sb-core `Supervisor` has an internal event loop, but it consumes **only** `ReloadMsg` (mpsc, size 32;
  `reload_sender()`); extending it to carry sidecar completion would modify sb-core — **out of scope**.
- `State` (supervisor.rs:58) is a **struct** (`current_ir`, `context`, `bridge`) — there is **no**
  `Degraded`/`Stopped`/`Fatal` lifecycle-status enum. So there is no existing place to record a
  degraded state; a policy card would have to introduce one (deferred).

Answers: (1) no unified app event loop — only a signal loop; (2) the only existing mpsc is sb-core's
reload channel (off-limits); no app `select!`/`JoinSet`/`watch` consumer exists; (3) admin services
lifecycle is owned by `RuntimeLifecycle`; (4) no degraded/stopped/fatal enum; (5) sidecar terminal
events should enter run-engine through a **new app-local** mpsc consumed within run-engine; (6) yes —
define `SidecarRuntimeEvent` first, let a later policy layer decide behavior; (7) yes — run-engine can
adopt **structured event + log-only handling** now, leaving product semantics unchanged.

## O. run-engine four-route comparison

- **Route 1 (don't consume):** supervisor stays blind to runtime death (only the source log exists).
  Misses the run-engine goal of structured observability.
- **Route 2 (observer task → app-level mpsc `SidecarRuntimeEvent` → run-engine consumer):** minimal,
  testable, app-only, extensible; the consumer is log-only now and a future policy card can swap in
  degrade/restart. **Recommended.**
- **Route 3 (supervisor directly polls multiple `watch` receivers in a `select!`):** would require
  rebuilding the signal-only top loop into a dynamic `select!` over a changing receiver set — more
  complex and churny than a small observer→mpsc indirection. Rejected for now.
- **Route 4 (terminal → immediate hard-fail):** rejected — policy not yet approved.

## P. `SidecarRuntimeEvent` minimal model

```rust
enum SidecarRuntimeEvent {
    Exited { name: String, exit: SidecarExitRecord },
    ProjectionClosed { name: String },
}
```

Decisions: (1) **no** `current` — only terminal/projection-closed cross to the consumer (Running /
ShutdownRequested stay in the snapshot). (2) **no** `observed_at` — the source carries no terminal
timestamp; an observed-at field, if ever needed, must be an explicitly-named consumer-layer stamp, not
faked as terminal time. (3) sidecar **kind** — fold into `name` (`"clash_api"` / `"v2ray_api"`); a
separate kind enum is optional and not required now. (4) **generation** — already inside
`SidecarExitRecord.generation`; no separate field. (5) error string — retained inside
`SidecarExit::{ServeError, Panicked}(String)`. (6) `ShutdownRequested` — **no** event (snapshot-only).
(7) `CleanShutdown` — still emit `Exited{CleanShutdown}` so the consumer can stop the observer/record
a clean stop, but the consumer must treat it as non-abnormal (no warn/error). (8) `Unknown` — carried
as `SidecarExit::Unknown` inside `Exited`, handled as explicit degraded, never normalized.

## Q. observer lifecycle owner

- **bootstrap:** no observer (Route 1) → no lifecycle concern.
- **run-engine:** **Route A-flavored, owned by `RuntimeLifecycle`** — the observer `JoinHandle`(s) (or
  a small `JoinSet`) live alongside `admin_services`; `RuntimeLifecycle::shutdown()` aborts/awaits them
  after `admin_services.shutdown()` has signalled the sidecars (so observers see the terminal and exit,
  or are aborted if they would otherwise block on a closed projection). Route B (sb-core supervisor
  `JoinSet`) is rejected (sb-core off-limits; bootstrap has no supervisor); Route C (detach) is rejected
  (leak / untestable).

## R. dead-code gate handling

After 01H-B wires run-engine observers: `from_v2ray_server`/`from_clash`/`snapshot_and_mark_seen`/
`changed`/`ClashShutdownHandle::subscribe_runtime_state` become used → the **module-level**
`#[allow(dead_code)]` on `sidecar_runtime` should be **removed**, and any genuinely still-unused
future-facing item (e.g. bootstrap-side subscription left un-wired under Route 1) should get a
**narrow** per-item `#[allow(dead_code)]` with a one-line reason, not a module-wide blanket. The broad
module allow must not persist as the default once a consumer exists.

## S. Five overall-route comparison

| Route | Verdict |
| --- | --- |
| 1. Source logger only, no active consumer | Mechanism exists but the supervisor never observes it. Insufficient for run-engine. |
| 2. bootstrap no observer; run-engine structured observer event | **Recommended** — minimal, keeps bootstrap's visible-but-nonfatal policy, avoids duplicate logs (Route A), app-only. |
| 3. observers on both bootstrap and run-engine | Adds a bootstrap observer with no consumer value + duplicate logging. Rejected. |
| 4. supervisor directly polls watch receivers | Dynamic `select!` over a changing set; rebuilds the signal-only loop. Rejected for now. |
| 5. terminal → hard-fail / restart | Policy not approved. Rejected. |

## T. Classification

**`A. RUN_ENGINE_EVENT_BRIDGE_READY`.** bootstrap needs **no** observer (the source terminal logger
already satisfies visible-but-nonfatal — M); run-engine can **locally** add a structured event bridge
(observer task → app-level `SidecarRuntimeEvent` mpsc → run-engine log-only consumer), with all four
receivers extractable app-locally (D–G) and the observer owned by `RuntimeLifecycle` (Q). No
both-sides observers (B not needed), no separate lifecycle-contract blocker (C — the owner is clear),
no supervisor redesign (D — the bridge is app-local, sb-core untouched), evidence sufficient (not E).

## U. Unique recommended next card

**`APP-SIDECAR-LIVENESS-01H-B — implement run-engine sidecar runtime event bridge`** — app only:
run-engine observer(s) subscribing run-engine Clash (`ClashShutdownHandle`) + run-engine V2Ray
(`supervisor State.context.v2ray_server`); define `SidecarRuntimeEvent { Exited, ProjectionClosed }`;
project terminal / projection-closed into an app-level mpsc consumed log-only within run-engine; the
source monitor stays the sole terminal logger; bootstrap keeps Route 1 (no observer); product policy
stays log-only (no hard-fail / restart / degrade / health probe); narrow the `sidecar_runtime`
module-level `#[allow(dead_code)]` to what remains unused.

## V. Checkpoint / push / final status

Checkpoint `checkpoint: audit sidecar runtime completion consumers` (active_context.md + this file);
`git diff --check` / `verify-consistency.sh` / `check-boundaries.sh` run; only the two docs committed;
`a0_reality_spike/` left untracked; then pushed. Final `git status --short --branch` recorded in the
session report.

## State

`APP-SIDECAR-LIVENESS-01H-A` = `A. RUN_ENGINE_EVENT_BRIDGE_READY`; next = `APP-SIDECAR-LIVENESS-01H-B`.
Defers unchanged: `SVC-V2RAY-API-01B` = DEFER/POLICY REVIEW; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray
breaking cleanup = DEFER/FUTURE MAJOR; `TIDY-RUSTDOC-LINKS` = DEFER/HISTORICAL BASELINE RED;
`TIDY-APP-BREAKER-FLAKE` = DEFER/NEEDS INDEPENDENT REPRODUCTION. Out-of-scope unchanged: H5/H6/H7.
