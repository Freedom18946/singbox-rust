<!-- tier: B -->
# APP-RELOAD-CONTEXT-CLEANUP-01A — pre-swap Context rollback cleanup & sidecar-leak audit

> Audit only. No Rust changed, no cleanup guard / `Drop` / test / reload-order change. Determines
> exactly what the new construction leaks when a run-engine reload fails **before** the state swap,
> and how a minimal rollback guard must distinguish **fresh** (must close) from **borrowed/inherited**
> (must NOT close) resources.
>
> Load-bearing claims independently re-derived by a 3-agent adversarial sweep (all CONFIRMED, high
> confidence). Line anchors are against HEAD `654341c0` (post-01C).

## A. Accepted-commit push result

`git push origin main` → `48c6ffce..654341c0  main -> main`. Then `## main...origin/main`
(in sync), `?? agents-only/a0_reality_spike/` (untouched). 01B/01C are now on origin.

## B. Baseline git status

`## main...origin/main`; HEAD `654341c0 checkpoint: record v2ray reload reuse handoff` →
`7dc853ef fix(sb-core): reuse v2ray server across equivalent reloads` → `48c6ffce` → `50e0e35d`.
Tracked tree clean; only `a0_reality_spike/` untracked.

## C. Router / no-router pre-swap-failure timeline

Both `handle_reload` (router, `supervisor.rs:563`) and `handle_reload_no_router` (`:718`) share the
shape (no-router has no `Engine::from_ir`):

```
step 0  request_shutdown OLD inbounds + 1200ms grace      (:572 / :727)   [old listeners begin closing]
        capture old_context + old_v2ray_cfg
        reusable_v2ray_server(...)  -> inherited_v2ray
Engine::from_ir(&new_ir)?           (router only)         [no new ctx yet → clean fail]
build_context_from_ir(&new_ir, inherited_v2ray)           (:615 / :766)   [NEW V2Ray STARTED here if fresh+bind-ok]
run_context_stage(Initialize)?                            (:619 / :770)   bare ?
build_bridge(...)  (infallible)                           (:611-625 / :762-776)
populate_bridge_managers(&new_context,&new_bridge).await? (:629 / :778)   bare ?
run_context_stage(Start)?                                 (:632 / :781)   bare ?  [services/endpoints START → bind]
spawn_blocking(ib.serve()) for NEW inbounds               (:647 / :787)            [new inbound listeners BIND]
run_context_stage(PostStart)?                             (:658 / :796)   bare ?
run_context_stage(Started)?                               (:659 / :797)   bare ?
preserve_v2ray = same_v2ray_server(old,new)               (:664 / :802)
== STATE SWAP == state_guard.context = new_context        (:688 / :815)
shutdown_replaced_context(&old_context, preserve_v2ray)   (:709 / :836)   [OLD teardown, post-swap only]
```

**Every fallible pre-swap call is a bare `?` with no `inspect_err`/cleanup.** The only
stop/teardown calls (`stop_endpoints`/`stop_services`/`shutdown_replaced_context`) target the
**OLD** context and run **after** a successful swap, so an early `?` never reaches them and they
never apply to the new construction.

## D. Pre-swap failure-point matrix (router; no-router identical minus Engine step)

| stage | line | new ctx exists | fresh V2Ray started | borrowed V2Ray injected | fails pre-swap | current cleanup | what leaks on failure |
| --- | --- | :---: | :---: | :---: | :---: | --- | --- |
| `Engine::from_ir?` | ~:611 | no | no | no | yes (`?`) | n/a | nothing (old kept) |
| `build_context_from_ir` | :615 | **yes** | **yes** (if fresh) | yes (if reuse) | no (infallible; bind err swallowed) | n/a | — (but new V2Ray now live) |
| `Initialize?` | :619 | yes | yes | yes | yes (`?`) | **none** | fresh V2Ray |
| `populate_bridge_managers?` | :629 | yes | yes | yes | yes (`?`) | **none** | fresh V2Ray (svcs/eps registered, not started) |
| `Start?` | :632 | yes | yes | yes | yes (`?`) | **none** | fresh V2Ray + started endpoints/services (bound sockets) |
| inbound `serve` spawn | :647 | yes | yes | yes | — | n/a | (new inbound listeners now bound) |
| `PostStart?` | :658 | yes | yes | yes | yes (`?`) | **none** | fresh V2Ray + endpoints + services + **new inbound listeners** |
| `Started?` | :659 | yes | yes | yes | yes (`?`) | **none** | same as PostStart |
| swap | :688 | — | — | — | N/A | (commit) | — |

**Reachability:** of the 8 managers `run_context_stage` drives, only `EndpointManager` propagates
errors (`endpoint/mod.rs` `run_stage` `?`); `ServiceManager` isolates per-service failures (does
not propagate). The concrete propagating PostStart failure is a **WireGuard endpoint**
(`wireguard.rs` `ensure_started(true)?` in `StartStage::PostStart`) or **Tailscale**; `Initialize`/
`populate`/`Start` can also fail for other reasons. So the PostStart/Started window (which leaks
all four categories) is gated on an endpoint failing post-start — real but not arbitrary.

## E. Context-owned resource matrix (build/start behavior; HEAD `654341c0`)

| resource | owner | started at build? | holds listener/socket | drop alone stops it? | explicit shutdown path | leaks on pre-swap fail |
| --- | --- | :---: | :---: | :---: | --- | :---: |
| **V2Ray API server (fresh)** | `Context.v2ray_server` | **YES** (`wire_experimental_sidecars`) | YES (TCP) | **NO** (monitor holds `lifecycle` Arc → `shutdown_tx` never fires) | `close()` only via `shutdown_context` | **YES** |
| V2Ray API server (inherited) | `Context.v2ray_server` (shared) | no (skipped) | shared w/ old | n/a | old context owns it | **NO** (must not close) |
| cache_file sidecar | `Context.cache_file` | YES (debouncer thread) | NO | **YES** (`FakeIpMetaDebouncer` `Drop` → `stop_and_join`) | — | **NO** (self-cleans) |
| new inbounds | `new_bridge.inbounds` | started at `serve` spawn (:647) | YES | **NO** (serve task holds Arc; only `request_shutdown` flag stops the accept loop) | `request_shutdown()` | **YES** (if PostStart/Started fail) |
| new endpoints | `new_bridge.endpoints` | started at `Start` (:632) | some YES (WireGuard UDP) | NO | `stop_endpoints` / `EndpointManager::shutdown` | **YES** |
| new services | `new_bridge.services` | started at `Start` (:632) | some YES (resolved UDP, DERP TCP+STUN, ssm-api TCP) | NO | `stop_services` (NOTE: `ServiceManager::close` is a **no-op**) | **YES** |
| all other Context fields | managers / markers / ZSTs | NO (passive until a Start stage) | NO | n/a | n/a | NO |

`Context` has **no `impl Drop`** and a derived (shallow) `Clone`; `network_monitor.start()` spawns a
netlink task but has **zero callers** (never run at build). So at `build_context_from_ir` time the
only build-started leaking resource is the fresh V2Ray; inbounds/endpoints/services are
bridge-owned and become leak-prone once `run_context_stage(Start)` / the `serve` spawn starts them.

## F. V2Ray fresh-listener reference chain (permanent leak)

1. `V2RayApiServer::start()` (`v2ray_api.rs:565+`): `pre_bind` binds the TCP listener; `shutdown_tx`
   stored in `lifecycle.current.shutdown_tx` (`Arc<Mutex<V2RayLifecycle>>`); a detached monitor task
   captures a **clone** of `lifecycle` (+ `runtime_tx`); the listener is moved into the inner serve
   task; the outer monitor `JoinHandle` is discarded.
2. When `new_context` drops pre-swap: only `Context.v2ray_server` held the `Arc<V2RayApiServer>`.
   Dropping it does **not** drop `lifecycle` (the monitor's clone keeps it), so `shutdown_tx` is
   neither sent nor dropped.
3. `shutdown_rx.await` never resolves; the incoming `futures::stream::unfold` returns `Some` even on
   `accept()` error → never ends; `serve_with_incoming_shutdown` runs forever; `inner.await` never
   returns; the monitor never reaches `commit_terminal`.
4. No `Drop` on `V2RayApiServer`/`V2RayLifecycle`/`RunningGeneration`; the outer monitor handle is
   discarded (Tokio does not abort on handle drop); no global task registry; the app layer only
   subscribes to the watch channel. **No timer/sender-drop/completion path ever recovers it.**

**Conclusion: permanent leak** (listener stays bound; `runtime snapshot` stays `Running`).
Confirmable cheaply (TCP connect to addr B still succeeds) via the same harness as 01C test K — not
done here (audit only).

## G. Does the new listener stay alive after the new context drops?

**Yes — permanently**, for both the fresh V2Ray listener (F) and the new inbound listeners (the
spawned `serve` task holds its own `Arc<dyn InboundService>`; the accept loop only exits when the
inbound's `shutdown` `AtomicBool` is set via `request_shutdown`, which the reload error path never
calls). Drop is insufficient — the startup path proves this by explicitly calling `request_shutdown`
on new inbounds during its own PostStart/Started rollback (`supervisor.rs:245-264`).

## H. Inherited-server rollback constraint

A reused (inherited) V2Ray is the **same `Arc`** the old context still owns. On pre-swap rollback it
must **NOT** be closed: closing it would kill the still-serving old listener (the very continuity
01C protects). The reuse path also binds **no** new listener, so there is nothing fresh to clean for
V2Ray in that case — the rollback simply drops the new context's borrowed `Arc` (refcount decrement)
and leaves the old owner intact. Discrimination is by pointer identity:
`Arc::ptr_eq(new.v2ray_server, old.v2ray_server)` — i.e. the existing `same_v2ray_server(&old,&new)`
helper. The old context is in scope for the whole `handle_reload`, so the predicate is reachable at
cleanup time; **no permanent ownership state and no lease token are needed** — a local
`fresh_v2ray = !same_v2ray_server(&old,&new)` flag suffices. (Inbounds/endpoints/services are always
freshly built per reload, never inherited, so they are always safe to stop on rollback.)

## I. fresh / inherited / disabled cleanup matrix

| new ctx V2Ray | source | close on pre-swap fail? | reason |
| --- | --- | :---: | --- |
| `None` | disabled / bind-skipped | no | no resource |
| fresh B | new + `start()` ok | **YES** | else permanent leak |
| inherited A | borrowed same `Arc` from old | **NO** | old context still the owner |
| fresh A (old exited) | reuse rejected → new + bind ok | **YES** | brand-new resource |
| projection-unavailable fallback | not a production path (only the real `V2RayApiServer` is built; a non-introspectable server fails eligibility → fresh build) | **YES** | treated as fresh |

## J. `shutdown_context_inner()` pre-swap safety — safe but **insufficient alone**

1. Calling it on a partially-initialized new context is **safe**: all manager `close()` are
   best-effort, idempotent, and do not assume a completed Start.
2. It closes: V2Ray (gated by `close_v2ray`) + `EndpointManager::close` (= `shutdown()`, which
   **does** iterate `ep.close()`) + outbound/inbound/platform/task_monitor/connections/network
   managers. It does **NOT** stop bridge-owned inbounds (not a Context field) and does **NOT** stop
   services — `ServiceManager::close()` is a **no-op** (`context.rs:70-73`).
3. Idempotent: yes. 4. Depends on completed Start: no. 5. Can it fail: each `close()` logs and
   returns `()`; nothing propagates.
6. Error policy: cleanup is best-effort `void` → it **cannot** override the original reload error;
   the original `Err` is returned unchanged (record cleanup errors as logs, preserve the reload
   error).
7. Contains `.await`: **no** — `shutdown_context_inner`, `stop_endpoints`, `stop_services`,
   `request_shutdown` are all synchronous.
8. Can run explicitly in the error path: yes (sync).
9. **A new helper is required** (not just reusing `shutdown_replaced_context`, which is the
   *post-swap old-context* path): the rollback must additionally `request_shutdown(new inbounds)` +
   `stop_services(new services)` (because `ServiceManager::close` is a no-op) + `stop_endpoints(new
   endpoints)` + `shutdown_context_inner(new, close_v2ray = fresh)`. This mirrors the startup
   rollback (`supervisor.rs:245-264`) but targets the NEW construction and gates V2Ray to fresh-only.
10. Router/no-router can share one helper (identical structure).

## K. Cleanup error handling

Cleanup is best-effort and returns `()` (the stop/close helpers log internally). Therefore the
original reload error is always preserved and returned to the caller; cleanup failures are logged,
never substituted. No new `Result` plumbing is required for the guard.

## L. Cleanup-guard form comparison (not implemented)

| option | form | verdict |
| --- | --- | --- |
| A | hand-written cleanup before each `?` | Rejected — high omission risk; every future pre-swap step must remember to clean. |
| **B ✅** | `let r = async { Init; populate; Start; spawn inbounds; PostStart; Started }.await; if let Err(e)=r { shutdown_failed_reload_context(&new_ctx,&new_bridge,fresh); return Err(e); }` | **Recommended** — one rollback branch covers all current + future pre-swap failure points uniformly; cleanup is sync so no await-in-Drop problem; preserves the original error. (Landing form of Route 4.) |
| C | RAII guard (`Drop`) | Rejected — async-free here, but a `Drop` guard cannot discriminate fresh vs inherited cleanly and spawning cleanup introduces uncontrolled background semantics. |
| D | build/activate split | Rejected as the minimal fix (larger boundary change; see R). |
| E | `Context` `Drop` | Rejected — would misclose the borrowed/inherited server and broaden global teardown semantics; cannot await. |

**Recommended form: B** — an async transaction block over the pre-swap stages + a single
`shutdown_failed_reload_context(new_context, new_bridge, fresh_v2ray)` rollback helper (shared by
router + no-router).

## M. Rollback-cleanup invariants (the 01B fix must satisfy)

```
pre-swap failure → no swap → old context keeps running → old listener A NOT closed
new ctx has fresh V2Ray B → rollback closes B → listener B released, task terminated
new ctx has inherited V2Ray A → rollback does NOT close A → only the new ctx's borrowed Arc drops; old keeps serving
new ctx has started inbounds/endpoints/services → rollback request_shutdown(inbounds)+stop_endpoints+stop_services → all released
cleanup failure → log cleanup error, preserve+return the original reload error
swap success → no rollback cleanup; continue to use 01C's shutdown_replaced_context (post-swap old teardown)
bind-failure visible-but-nonfatal unchanged → no fresh server bound → nothing to clean
```

## N. Defect scope

**Scope 2 — multiple Context/bridge-owned resource leaks.** The fresh V2Ray listener (F), the new
inbound listeners (G), and started socket-binding endpoints/services (resolved UDP, DERP TCP+STUN,
ssm-api TCP, WireGuard UDP) all leak on a pre-swap failure, because the reload path has **no**
rollback cleanup for the new construction (only `cache_file` self-cleans via `Drop`). It is **not**
Scope 1 (V2Ray-only). Plus an independent sub-defect: `ServiceManager::close()` is a no-op, so even
a `shutdown_context`-style teardown would not stop services — the guard must use `stop_services`.

## O. Six fix-route comparison

| route | summary | verdict |
| --- | --- | --- |
| 1 status quo | new listeners leak on failed reload | **Reject** |
| 2 `shutdown_context_inner(new, fresh-only)` only | closes V2Ray + endpoints, but **misses bridge inbounds and services** (ServiceManager.close no-op) | Insufficient alone |
| 3 V2Ray-only close | only fixes V2Ray; inbounds/endpoints/services still leak | Insufficient (Scope 2) |
| **4 transaction block + full rollback helper** | `request_shutdown(inbounds)+stop_endpoints+stop_services+shutdown_context_inner(fresh)` over all pre-swap steps | **RECOMMEND** (superset of 2/3; mirrors startup rollback) |
| 5 RAII / Context `Drop` | misclose borrowed server, can't await/discriminate | Reject |
| 6 build/activate split | cleaner long-term boundary, larger change | Escalate only if local rollback proves unsafe |

**Recommended: Route 4** (landed as form B).

## P. Test strategy for the implementation card (01B)

A fresh-V2Ray rollback → re-bind B succeeds. · B inherited-V2Ray rollback → old A still connectable;
A released only at old final shutdown. · C bind-failure no-op → old A not misclosed. · D cleanup
preserves the original reload error (cleanup is `void`; assert returned `Err` is the stage error). ·
E router/no-router parity (shared helper or structural coverage). · F repeated failed reloads → fresh
B released each time, no port accumulation. · **G new-inbound rollback** → after a failed reload the
new inbound port is re-bindable. · **H endpoint/service rollback** → a started DERP/resolved/ssm-api
socket is released on rollback. Use helper-level/mock coverage where a full supervisor reload e2e is
too heavy; never leave a permanently-bound listener in a test.

## Q. Router / no-router commonality

Identical structure (no-router lacks `Engine::from_ir`); both should route their pre-swap rollback
through the **same** `shutdown_failed_reload_context` helper so the guard cannot drift between paths.

## R. Activation-split needed?

**No** (not now). A local pre-swap rollback guard (Route 4) is safe and sufficient: all new resources
are reachable via `new_context` + `new_bridge`, cleanup is synchronous, and fresh/inherited
discrimination is a pointer compare. A build/activate split (`APP-RELOAD-TRANSACTION-02A`) is the
escalation only if a future finding shows local rollback cannot safely sequence teardown.

## S. Unique classification

**`B. GENERAL_CONTEXT_ROLLBACK_GUARD_REQUIRED`.** Multiple Context/bridge-owned resources
(fresh V2Ray, new inbounds, started endpoints/services) leak on a pre-swap failure and require a
single unified rollback guard; it is not V2Ray-only (not `A`), a local guard suffices so no
activation split is needed (not `C`), there is a real leak (not `D`), and the evidence is complete
and verified (not `E`).

## T. Unique recommended next card

**`APP-RELOAD-CONTEXT-CLEANUP-01B — implement pre-swap Context rollback guard`** (sb-core). Scope:
wrap the pre-swap stages of `handle_reload` + `handle_reload_no_router` in a transaction (form B);
add a shared `shutdown_failed_reload_context(new_context, new_bridge, fresh_v2ray)` that
`request_shutdown`s the new inbounds, `stop_endpoints`/`stop_services` the new endpoints/services,
and `shutdown_context_inner(new, close_v2ray = !same_v2ray_server(old,new))`; preserve the original
reload error. Sub-item to address in the same card or note: `ServiceManager::close()` is a no-op, so
the guard must use `stop_services` (do not rely on `shutdown_context` to stop services). Tests per P.

## U. Files modified

`agents-only/active_context.md` + `agents-only/archive/release-cleanup-2026-06/runtime-sidecar/app_reload_context_cleanup_01a_audit.md` only. No
Rust / Cargo / crate / fixture / `a0_reality_spike/` change.

## V. Checkpoint commit + push

`git diff --check` / `verify-consistency.sh` / `check-boundaries.sh` run before commit. Checkpoint
`checkpoint: audit pre-swap context rollback cleanup` (the two docs); `a0_reality_spike/` left
untracked; pushed to `origin main`.

## W. Final status

Recorded in the session report.

## Out-of-scope related observations (not part of this leak audit)

- **Old-inbound continuity on a failed reload:** step 0 `request_shutdown`s the OLD inbounds (+1200ms
  grace) *before* knowing the reload outcome; a pre-swap failure keeps `old_context` but its inbound
  listeners may already have closed during the grace — a continuity gap (the inbound analog of the
  V2Ray reload-continuity issue), **not** a leak. Candidate for a separate future card; not opened here.
- `ServiceManager::close()` no-op is logged above as an independent defect to fix within 01B's guard.

## State

`APP-RELOAD-CONTEXT-CLEANUP-01A` = **`B. GENERAL_CONTEXT_ROLLBACK_GUARD_REQUIRED`** (audit only).
Next = `APP-RELOAD-CONTEXT-CLEANUP-01B` (implement pre-swap Context rollback guard, sb-core).
`APP-RELOAD-SIDECAR-ORDER-01` CLOSED; `APP-SIDECAR-LIVENESS-01` CLOSED. Defers unchanged:
`APP-SIDECAR-POLICY-02A`, `SVC-V2RAY-API-01B` = DEFER; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray
breaking cleanup, `TIDY-RUSTDOC-LINKS`, `TIDY-APP-BREAKER-FLAKE` = DEFER. Out-of-scope unchanged:
H5, H7.
