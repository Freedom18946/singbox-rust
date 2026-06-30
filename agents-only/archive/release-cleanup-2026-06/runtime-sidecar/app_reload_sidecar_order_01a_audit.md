<!-- tier: B -->
# APP-RELOAD-SIDECAR-ORDER-01A — supervisor reload sidecar bind-order audit

> Reload-correctness audit only (H6). No Rust changed. Confirms whether run-engine reload has a
> context-owned-sidecar same-address start-before-close continuity defect, and names the minimal
> follow-up.

## A. Baseline git status

`## main...origin/main` + untracked `agents-only/a0_reality_spike/`. Chain `be630924`/`93059aff`/
`ce980d58`/`fffe916d` confirmed synced.

## B. Reload entry

App: `run_supervisor` (`app/src/run_engine_runtime/supervisor.rs`) signal loop → on `RunSignal::Reload`
→ `config_load::reload_with_state(...)` → `reload_with_supervisor` → sb-core
`Supervisor::reload(new_ir)` → enqueues `ReloadMsg` on the supervisor's internal mpsc → the supervisor
event loop calls `Self::handle_reload(state, new_ir)` (router path, `crates/sb-core/src/runtime/
supervisor.rs:563`). **The reload transaction (and the bug) live entirely in sb-core**, not app.

## C. Full reload timeline (router `handle_reload`, :563–693)

| step | code | operation | old context alive? | new V2Ray attempted bind? | error propagation |
| --- | --- | --- | ---: | ---: | --- |
| reload entry | sup.rs:563 | `handle_reload(state, new_ir)` | yes | no | — |
| step 0 | :573–583 | clone old endpoints/services/**context**; `request_shutdown()` on **bridge inbounds only** | yes (V2Ray NOT touched) | no | — |
| inbound grace | :586–592 | sleep `SB_INBOUND_RELOAD_GRACE_MS` (default 1200ms) for **inbound** ports | yes | no | — |
| new engine | :595 | `Engine::from_ir(&new_ir)?` | yes | no | `?` → early return, old kept |
| **new context build** | :599 | `build_context_from_ir(&new_ir)` → `wire_experimental_sidecars` → **new `V2RayApiServer::new` + `start()` → `pre_bind` same addr** | **yes (old V2Ray listener still bound)** | **YES — collides** | bind `Err` **swallowed** in wire (:1171 `warn`, server NOT attached) |
| init/start new mgrs | :603–643 | Initialize/Start/PostStart new context | yes | (already attempted) | `?` → early return on mgr failure |
| **state swap** | :646–679 | `state_guard.context = new_context` (has **no** V2Ray) | swap point | — | atomic write-lock |
| old shutdown | :687–689 | `stop_endpoints/services` + **`shutdown_context(&old_context)` → old V2Ray `close()`** | now closing | — | best-effort |
| return | :693 | `Ok(())` — **reload reports SUCCESS** | — | — | success despite dropped V2Ray |

## D. State swap vs old-context shutdown order

**New build/start (incl. new V2Ray `pre_bind`, :599) happens BEFORE old close (:689).** The state swap
(:668) also precedes the old `shutdown_context` (:689). So at the moment the new V2Ray tries to bind,
the **old V2Ray listener is still alive** (it is closed only after the swap). This is the
start-before-close ordering the audit set out to verify — **confirmed**.

## E. Sidecar ownership matrix

| Sidecar | ownership layer | rebuilt on reload? | listener re-bound? | same-address conflict risk |
| --- | --- | ---: | ---: | ---: |
| run-engine Clash API | app `AdminServices` (`start_admin_services` called **once**, sup.rs:290, outside the reload loop) | **no** | no | **none** (not in the sb-core reload transaction) |
| run-engine V2Ray API | sb-core `Context.v2ray_server` (rebuilt by `build_context_from_ir` every reload) | **yes** | **yes** (`pre_bind`, no `SO_REUSEADDR`) | **HIGH** — collides with the still-alive old listener |
| bootstrap Clash API | app bootstrap runtime (no reload path) | N/A | N/A | N/A |
| bootstrap V2Ray API | app bootstrap runtime (no reload path) | N/A | N/A | N/A |

## F. run-engine Clash affected?

**No.** `AdminServices` (which owns the Clash serve task via `spawn_prebound_clash_api_server`) is
started once at run-engine startup (`run_supervisor` → `start_admin_services`, sup.rs:290), **before**
the reload loop, and the reload loop never re-invokes it. The sb-core reload rebuilds only the sb-core
`Context` (inbounds/outbounds/router/V2Ray/cache), not the app `AdminServices`. So the Clash listener
is never re-bound on reload → no H6 conflict.

## G. run-engine V2Ray affected?

**Yes — this is the bug.** V2Ray lives in sb-core `Context.v2ray_server`, rebuilt on every reload via
`build_context_from_ir → wire_experimental_sidecars`, which calls `V2RayApiServer::start()` →
synchronous `pre_bind` on the (unchanged) listen address while the old V2Ray listener is still bound.
The bind fails `EADDRINUSE`; `wire_experimental_sidecars` swallows it (`warn` + does not attach the
server); the new context proceeds without V2Ray; the swap completes; the old V2Ray is then closed.

## H. bootstrap sidecars affected?

**No (N/A).** bootstrap is a separate runtime with no reload transaction; its sidecars are out of
H6's scope. Do not generalize H6 to bootstrap.

## I. V2Ray bind-conflict error propagation

`pre_bind` (`v2ray_api.rs`, plain `std::net::TcpListener::bind`, no `SO_REUSEADDR`) → `Err` →
`V2RayApiServer::start()` returns `Err` → `wire_experimental_sidecars` (:1171–1176) catches it,
emits `tracing::warn!("failed to start V2Ray API server")`, and **does not** `with_v2ray_server(...)`.
`build_context_from_ir` itself never fails on this path — it returns a context that simply lacks a
V2Ray server. The error therefore never reaches a `?` and never triggers reload rollback.

## J. Does reload still report success?

**Yes.** The swallowed bind failure leaves `handle_reload` to run to `Ok(())` (:693), and the app
reports `ReloadOutcome::Success`. The operator sees a successful reload while the V2Ray API listener
has silently vanished. This is the crucial distinction from startup: **startup visible-but-nonfatal**
(you never had it) vs **reload continuity silently lost** (a previously-working listener disappears on
a reload that reports success) — different product semantics.

## K. Config-variant matrix

| old → new | expected bind | current actual | continuity risk |
| --- | --- | --- | ---: |
| disabled → disabled | no listener | no listener | none |
| disabled → enabled(A) | bind A | A free (no old V2Ray) → **binds OK** | none |
| enabled(A) → disabled | close A | new has no V2Ray; old A closed | none |
| **enabled(A) → enabled(A)** | keep A continuously | **new `pre_bind` A while old A alive → EADDRINUSE → V2Ray dropped; reload "success"** | **HIGH (core scenario)** |
| enabled(A) → enabled(B) | bind B then close A | B free → **binds OK**; old A closed | none (address change paradoxically works) |
| enabled(A) → enabled(B occupied externally) | new bind fails | EADDRINUSE → dropped, reported success | medium (genuinely occupied, but silent) |
| enabled(A) → enabled(A) + **unrelated** config change | A must survive an unrelated reload | **A dropped anyway** (context fully rebuilt regardless) | **HIGH (worst: V2Ray dies on reloads that don't touch it)** |

Core finding: `enabled(A) → enabled(A)` (and any reload while V2Ray is enabled on a fixed address)
drops the V2Ray listener for that generation; a *subsequent* reload restores it (flip-flop), because
by then the old context — and its V2Ray — is gone, freeing A.

## L. Rollback semantics

1. New IR build failure (`Engine::from_ir` `?`, :595) → returns `Err` **before** swap → old context
   keeps running. ✔ rollback.
2. New context manager Initialize/Start failure (`?`, :603/616/642) → returns `Err` before/at swap →
   old context kept (but the already-`start()`ed new V2Ray, if it had bound, leaks until its Arc
   drops — a minor side issue, not H6).
3. Before swap the old context is retained (cloned at step 0); it is shut down only after the swap.
4. After swap, there is **no** rollback path — partial failures past the swap are not unwound.
5. Sidecar failure is nonfatal **by design** (mirrors startup) — but at reload it is absorbed rather
   than rolled back.
6. A naive "close old V2Ray first, then bind new" would risk: new build fails afterwards →
   reload failed **and** the old V2Ray already lost. So close-first is unsafe without a guarded
   sequence.
7. Reload is a **best-effort rebuild**, not a transactional swap, for the V2Ray sidecar specifically:
   its bind failure is silently absorbed and the swap proceeds.

## M. continuity / rollback / startup-honesty tension

- **continuity** wants same-address V2Ray to stay up across reloads — currently broken.
- **rollback** is preserved for IR/engine/manager build failures (old kept), so a naive close-old-first
  fix would weaken rollback (lose V2Ray if the new build then fails).
- **startup honesty** correctly treats bind failure as nonfatal, but reusing that exact swallow at
  reload silently discards a working listener.
  The minimal fix must preserve all three: keep V2Ray serving across an unchanged-address reload
  **without** closing it before the new build and **without** weakening rollback.

## N. Existing-test scan

`crates/sb-core/src/runtime/supervisor.rs`: no test exercises reload + V2Ray same-address continuity
(only `reload`/`handle_reload` impl + facade pin tests). `app/src/run_engine_runtime/`: reload tests
are fingerprint/wiring pins (`runtime_context_tracks_reload_fingerprint`,
`watch_runtime_carries_explicit_reload_wiring`), none cover V2Ray listener continuity. No targeted
test to run; none added (audit-only).

## O. External probe / control-flow evidence

No repo test modified. The defect is established by **deterministic control flow** (high confidence):
old V2Ray is guaranteed alive during the new build (it is closed only at :689, after the new
`pre_bind` at :599 and the swap at :668); `pre_bind` uses plain `bind` with no `SO_REUSEADDR` (per the
01D audit), so the same-address bind deterministically fails while the old listener is alive; the
failure is unconditionally swallowed at :1171. A `/tmp` probe design (not executed, not committed):
start a V2Ray listener on A; run a second `pre_bind(A)` while the first is alive → observe
`EADDRINUSE`; this matches `restart_after_failed_bind` / `bind_conflict_*` behavior already proven in
`v2ray_api.rs` tests. Runtime reproduction is unnecessary given the unambiguous control flow.

## P. Five fix-route comparison (compare only — not implemented)

- **Route 1 (status quo)**: confirmed continuity bug (new context lacks V2Ray after a same-address
  reload; reload reports success). **Reject.**
- **Route 2 (close old V2Ray before building new)**: lets the new bind A succeed, but breaks rollback
  (if the new build then fails, the old V2Ray is already lost) and introduces a visible V2Ray outage
  window. Not recommended without a guarded/transactional sequence.
- **Route 3 (reuse old V2Ray server when config unchanged)**: if `old.listen == new.listen` and the
  `v2ray_api` config is equivalent, carry the existing `Arc<dyn V2RayServer>` into the new context
  instead of rebuilding/rebinding. Preserves continuity and `StatsManager` identity, no rebind.
  **Key concern:** `shutdown_context(&old_context)` (:689) would `close()` a *shared* server — so the
  reused server must be transferred out of the old context (or excluded from the old close) before the
  old shutdown. Needs ownership-transfer handling. Smallest behavioral change; preferred candidate.
- **Route 4 (split context build/activate; swap then close-old then start-new)**: build the new context
  without starting the conflicting sidecar → swap → close old V2Ray → start new V2Ray. Cleaner ordering
  but requires splitting `Context` build vs activate (a larger lifecycle-boundary change) and defining
  failure reporting for the post-swap start.
- **Route 5 (listener/socket handoff to the new generation)**: transfer the old bound socket — most
  complex; only if server-reuse (Route 3) is infeasible.

## Q. Cross-sidecar generalization?

**No — the defect is V2Ray-specific.** Clash is app-owned (`AdminServices`, started once, not rebuilt
on reload) and bootstrap sidecars have no reload path. Only the context-owned V2Ray API is rebuilt and
rebound per reload. Do **not** widen H6 into a general context-sidecar reload refactor; cache_file (the
only other `wire_experimental_sidecars` sidecar) holds no listener and has no bind conflict.

## R. Classification

**`B. V2RAY_SAME_ADDRESS_RELOAD_CONTINUITY_BUG`.** Confirmed by control flow: only the context-owned
V2Ray API (rebuilt + rebound on every reload, same address, while the old listener is still alive, with
the bind failure swallowed and reload reporting success) loses continuity. Clash is not rebuilt (not A
"no gap", but the gap is narrow), no other context sidecar binds a port (not C general), and a fix does
not inherently require redesigning the whole reload transaction boundary (Route 3 server-reuse is local
to `wire_experimental_sidecars` / `build_context_from_ir` ownership handling) (not D), evidence is
sufficient (not E).

## S. Unique recommended next card

**`APP-RELOAD-SIDECAR-ORDER-01B — V2Ray reload continuity fix proposal`** (design only, no code).
Scope: design the minimal fix preserving continuity + rollback + startup honesty (M); evaluate Route 3
(reuse the unchanged `Arc<dyn V2RayServer>` with ownership transfer so `shutdown_context(old)` does not
close the reused server) as the primary candidate, Route 4 as the fallback; do not pick close-first
(Route 2). **Scope note:** unlike the app-only 01F/01G-B/01H-B liveness work, this fix lands in
**sb-core** (`crates/sb-core/src/runtime/supervisor.rs` + possibly `context.rs`), so 01B must call out
the crate-boundary change and respect `wire_experimental_sidecars` / `build_context_from_ir`
ownership.

## T. Files modified

`agents-only/active_context.md` + `agents-only/archive/release-cleanup-2026-06/runtime-sidecar/app_reload_sidecar_order_01a_audit.md` only. No Rust /
Cargo / crate / fixture change.

## U. Checkpoint commit + push

Checkpoint `checkpoint: audit reload sidecar bind ordering` (the two docs); `git diff --check` /
`verify-consistency.sh` / `check-boundaries.sh` run; `a0_reality_spike/` left untracked; then pushed.

## V. Final status

Recorded in the session report.

## State

`APP-RELOAD-SIDECAR-ORDER-01A` = `B. V2RAY_SAME_ADDRESS_RELOAD_CONTINUITY_BUG`; next =
`APP-RELOAD-SIDECAR-ORDER-01B` (design-only; fix lands in sb-core). H6 is now characterized, not yet
fixed. Defers unchanged: `APP-SIDECAR-LIVENESS-01` CLOSED; `APP-SIDECAR-POLICY-02A`, `SVC-V2RAY-API-01B`
= DEFER; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray breaking cleanup, `TIDY-RUSTDOC-LINKS`,
`TIDY-APP-BREAKER-FLAKE` = DEFER. Out-of-scope unchanged: H5, H7.
