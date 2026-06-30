<!-- tier: B -->
# APP-RELOAD-SIDECAR-ORDER-01C — V2Ray same-config reload reuse handoff

> sb-core-only correctness fix (implements 01B's `A/V2RAY_REUSE_HANDOFF_READY` design). On a
> run-engine hot reload with an unchanged, currently-Running V2Ray API config, the existing
> `Arc<dyn V2RayServer>` is carried into the new context instead of rebuilt+rebound — eliminating
> the same-address rebind that EADDRINUSE-collided with the still-alive old listener and made the
> reload silently drop a working V2Ray listener. Code commit `7dc853ef`. Does **not** fix the
> separate address-change pre-swap leak (registered `APP-RELOAD-CONTEXT-CLEANUP-01A`).

## A. Baseline git status

Before: `## main...origin/main`, HEAD `48c6ffce` (01B proposal), tracked tree clean, only
`agents-only/a0_reality_spike/` untracked. Code commit landed at `7dc853ef`.

## B. `V2RayApiIR` equivalence comparison

`V2RayApiIR` already `#[derive(PartialEq, Eq)]` (`crates/sb-config/src/ir/experimental.rs:59`), so
equivalence is a structural `old == new`, covering BOTH `listen` and `stats` (no derive widened).
A change in either field fails equality → no reuse.

## C. Reuse-eligibility helper

`reusable_v2ray_server(old_v2ray: Option<&V2RayApiIR>, new_v2ray: Option<&V2RayApiIR>,
old_server: Option<&Arc<dyn V2RayServer>>) -> Option<Arc<dyn V2RayServer>>`
(`supervisor.rs`, private). Returns `Some(Arc::clone(old))` iff: old enabled (`old_v2ray` Some) ∧
new enabled (`new_v2ray` Some) ∧ `old == new` ∧ old context holds a server ∧ that server is real
& introspectable (`subscribe_runtime_state()` is `Some`) ∧ its snapshot `current.phase ==
Running`. Otherwise `None` → existing rebuild path. Never infers from `last_exit`. Emits only
`debug` breadcrumbs (no warn/error on the normal rebuild fallback).

## D. `Running` determination

Via the trait snapshot: `server.subscribe_runtime_state()` → `watch::Receiver::borrow()` →
`current.as_ref().map(|g| &g.phase) == Some(Running)`. Synchronous (`borrow()`, no `.await`).
`ShutdownRequested`, exited (`current == None`), and non-introspectable (`subscribe` returns
`None`) are all rejected.

## E. `:0` handling

The eligibility gate compares the **config IR** (`old == new`), never the runtime bound port. For
`listen: ":0"`, `":0" == ":0"` → reuse → the reused server keeps its already-bound ephemeral
port (rebuilding `:0` would bind a different random port). No `SocketAddr` parsing /
normalization is introduced.

## F. Inherited-server parameter chain

Eligibility is computed in `handle_reload` (the only scope with old context + old IR + new IR),
then the eligible `Arc` is threaded:
`handle_reload` → `build_context_from_ir(ir, inherited_v2ray_server: Option<Arc<dyn V2RayServer>>)`
→ `wire_experimental_sidecars(ctx, ir, inherited_v2ray_server)`. Old IR is read from
`state_guard.current_ir.experimental?.v2ray_api` (captured in step 0).

## G. Wiring behavior when inherited is `Some`

`wire_experimental_sidecars`: when `exp.v2ray_api` is set AND `inherited_v2ray_server` is `Some`,
it installs the inherited server via `context.with_v2ray_server(inherited)` and **skips**
`V2RayApiServer::new()`, `start()`, and `pre_bind` entirely (no new listener). When `None`, the
prior behavior is unchanged (build + start + bind-failure-warn-and-skip).

## H. Non-reload construction call sites

Both startup paths — `start_with_registry` router (`supervisor.rs:173`) and no-router
(`:362`) — pass `inherited_v2ray_server = None`, so initial-start semantics are unchanged.

## I. Borrowed / commit / final three phases

- **A borrowed:** the new context holds a clone of the old `Arc` (same instance); old context
  stays close-owner. A pre-swap failure drops the new context (Arc decrement only — `Context` has
  no `Drop`), the old keeps serving, and `shutdown_replaced_context` is never reached. (Test J.)
- **B commit:** `preserve_v2ray = same_v2ray_server(&old, &new)` computed **before** the swap;
  after the swap the old teardown runs through `shutdown_replaced_context(&old, preserve_v2ray)`,
  skipping the shared server's `close()`. (Test F.)
- **C final:** the now-owning context's later teardown closes it normally via the unchanged
  `shutdown_context`. (Test H.) No `preserve` state is persisted into `Context` or the server.

## J. Reload-only teardown helper

`shutdown_replaced_context(old_context: &Context, preserve_v2ray: bool)` →
`shutdown_context_inner(old_context, !preserve_v2ray)`. `shutdown_context_inner(ctx, close_v2ray:
bool)` holds the former `shutdown_context` body, guarding only the V2Ray `close()` behind
`close_v2ray`; all manager closes are unchanged.

## K. `Arc::ptr_eq` usage

In `same_v2ray_server(a, b)`: `match (a.v2ray_server.as_ref(), b.v2ray_server.as_ref()) {
(Some(x), Some(y)) => Arc::ptr_eq(x, y), _ => false }`. Computed pre-swap in `handle_reload`
(both router + no-router) because the new context is moved into state at commit. `None`/`None`
yields `false` (no false-preserve).

## L. Generic `shutdown_context()` unchanged

`fn shutdown_context(ctx) { shutdown_context_inner(ctx, true) }` — signature and behavior
preserved; all 9 non-reload callers (startup rollback ×8, graceful shutdown ×1) are byte-for-byte
unchanged. No `preserve` parameter, no lease token, no `Context` mutation.

## M. `handle_reload()` modifications

Applied identically to **both** `handle_reload` (router) and `handle_reload_no_router`:
1. step-0 capture extended to also clone `old_v2ray_cfg = current_ir.experimental?.v2ray_api`;
2. compute `inherited_v2ray = reusable_v2ray_server(...)` before `build_context_from_ir(&new_ir,
   inherited_v2ray)`;
3. compute `preserve_v2ray = same_v2ray_server(&old, &new)` immediately before the state-swap
   block;
4. old teardown `shutdown_context(&old_context)` → `shutdown_replaced_context(&old_context,
   preserve_v2ray)`.

## N. Address-change pre-swap leak kept separate

Not touched. `APP-RELOAD-CONTEXT-CLEANUP-01A = OPEN / DEFERRED FOLLOW-UP` (a new V2Ray bound on a
free address that leaks if a later pre-swap stage `?`-fails). No `Context` `Drop`, cleanup guard,
build/activate split, pre-swap `shutdown_context(new)`, lease, or handoff was introduced. The
reuse path creates no new server in the same-config case, so it neither triggers nor depends on
that leak.

## O. Files modified

`crates/sb-core/src/runtime/supervisor.rs` only (impl + tests; `context.rs` not needed —
`with_v2ray_server` already existed). Checkpoint docs: `agents-only/active_context.md` +
`agents-only/archive/release-cleanup-2026-06/runtime-sidecar/app_reload_sidecar_order_01c_reuse_handoff.md`. No `app/`, `sb-api/`, Cargo, fixture,
or `a0_reality_spike/` change.

## P. Tests added (11, in `runtime::supervisor::tests::reuse_handoff`)

A reuse-running-equivalent · B no-reuse-on-config-change (listen + stats-only) · C
disabled-variants · D non-Running (ShutdownRequested / exited / no-snapshot / no-server) · E
`:0`-reuse · F teardown-skips-reused · G teardown-closes-distinct · H final-shutdown-closes ·
I None→None-safe · J pre-swap-borrowed-rollback-no-close · K (feature `service_v2ray_api`)
real-listener + StatsManager continuity. Uses a `MockV2Ray` (close counter + configurable
snapshot); K binds a real listener and closes it at the end (no leak).

## Q. Full reload e2e?

**No.** Coverage is composed: reuse helper + wiring skip-start (`build_context_from_ir`) +
pointer-equality teardown (`shutdown_replaced_context`) + final shutdown + (test K) a real bound
gRPC listener probed by TCP connect across the reuse. It does **not** drive the full
`Supervisor::handle_reload` mpsc/state-swap path e2e, which needs a complete multi-inbound config
and a running supervisor task — disproportionately heavy for this bounded fix, and the swap/teardown
edges are exercised directly via the helpers. Stated per Section 11.K.

## R. Config matrix recheck (matches targets)

disabled→disabled: no server ✓ · disabled→enabled(A): new bind ✓ · enabled(A) Running→disabled:
no reuse, old closed ✓ · **enabled(A) Running→enabled(A): reuse, zero rebind, old teardown skips
close** ✓ (tests A/F/K) · enabled(A) Running→enabled(B): no reuse, bind B, old closed ✓ (test B/G)
· enabled(A) Exited→enabled(A): no reuse, rebuild ✓ (test D) · enabled(A) ShutdownRequested→
enabled(A): no reuse, rebuild ✓ (test D) · enabled(`:0`) Running→enabled(`:0`): reuse, keeps real
port ✓ (test E). bind-failure visible-but-nonfatal behavior unchanged.

## S. Stats continuity proof

Test K asserts `Arc::ptr_eq(server1.stats().unwrap(), server2.stats().unwrap())` across the
reuse — the reused server keeps its single `StatsManager` instance (no new one created, counters
not reset). Pointer identity of the server Arc (`Arc::ptr_eq(&server1, &server2)`) is also
asserted.

## T. Targeted test results

`cargo test -p sb-core --all-features --lib reuse_handoff` → **11 passed, 0 failed** (incl. K).

## U. fmt / clippy / workspace / app regression

- `cargo fmt -p sb-core --check` → OK.
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings` → clean.
- `cargo test -p sb-core --all-features` → all pass (no failures; pre-existing flakes did not
  trigger).
- `cargo check --workspace --all-features` → PASS.
- `cargo test -p app --all-features` → 1 failure: `admin_debug::breaker::tests::
  default_metrics_owner_records_breaker_reopen_via_legacy_mark_failure` — the registered
  `TIDY-APP-BREAKER-FLAKE` (global-static pollution under parallelism). Isolated rerun (3/3) and
  full app lib SERIAL run (329 passed, 0 failed) both PASS → confirmed flaky, unrelated to this
  sb-core change. Not fixed (per discipline).

## V. Hygiene gates + baseline rustdoc

`git diff --check` clean · `verify-consistency.sh` PASS · `check-boundaries.sh` **0 violations
(exit 0, 537 assertions)** · `cargo doc -p sb-core --all-features --no-deps` → **14 warnings =
unchanged baseline (`TIDY-RUSTDOC-LINKS`), 0 new from 01C**.

## W. Code commit + checkpoint commit

- Code: `7dc853ef fix(sb-core): reuse v2ray server across equivalent reloads`.
- Checkpoint: `checkpoint: record v2ray reload reuse handoff` (this doc + active_context).
- **Not pushed** (upper layer decides, per card). `a0_reality_spike/` left untracked.

## X. Final status

Recorded in the session report.

## State

`APP-RELOAD-SIDECAR-ORDER-01C` = DONE (sb-core reuse handoff implemented + tested). Same-address
reload continuity fixed; StatsManager identity preserved. Follow-up `APP-RELOAD-CONTEXT-CLEANUP-01A`
= OPEN / DEFERRED (address-change pre-swap new-listener leak). Defers unchanged:
`APP-SIDECAR-LIVENESS-01` CLOSED; `APP-SIDECAR-POLICY-02A`, `SVC-V2RAY-API-01B` = DEFER;
`APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray breaking cleanup, `TIDY-RUSTDOC-LINKS`,
`TIDY-APP-BREAKER-FLAKE` = DEFER. Out-of-scope unchanged: H5, H7.
