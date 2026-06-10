<!-- tier: B -->
# APP-RELOAD-CONTEXT-CLEANUP-01B — pre-swap Context rollback guard (implemented)

> Implementation card. Lands the 01A audit's Route 4 (form B): a single pre-swap transaction
> block in both reload paths + one shared rollback helper. Code commit `47e15b0b`
> `fix(sb-core): clean up failed reload contexts before swap`. Only
> `crates/sb-core/src/runtime/supervisor.rs` changed.

## A. Baseline git status

`## main...origin/main` at `907f5944`; tracked tree clean; only `agents-only/a0_reality_spike/`
untracked (kept untracked, not staged, not committed).

## B. `build_context_from_ir()` construction-window recheck

**Stop condition NOT triggered.** `build_context_from_ir()` returns a bare `Context`
(infallible). After the fresh V2Ray `start()` inside `wire_experimental_sidecars`, the remaining
operations before return are `with_v2ray_server` (builder), tracing, `env::set_var`, and the ntp
marker wiring — none can `Err`, so the caller always receives the `Context` containing any
started fresh sidecar. The rollback helper can therefore always reach it. (Matches 01A audit D.)

## C. Shared rollback helper signature

```rust
fn shutdown_failed_reload_context(
    old_context: &Context,
    new_context: &Context,
    new_inbounds: &[Arc<dyn InboundService>],
    new_endpoints: &[Arc<dyn Endpoint>],
    new_services: &[Arc<dyn Service>],
)
```

Real existing types only; no wrapper struct, no lease token, no ownership field, no `Drop`.

## D. Helper cleanup order

1. `request_shutdown` each new inbound (the spawned serve task holds its own Arc; only the flag
   stops the accept loop / releases the listener);
2. `stop_endpoints(new_endpoints)`;
3. `stop_services(new_services)` — explicit because `ServiceManager::close()` is a no-op
   (independent defect logged in 01A; NOT generalized/fixed here);
4. `shutdown_context_inner(new_context, close_v2ray = !same_v2ray_server(old, new))`.

Order mirrors the existing startup-rollback (`supervisor.rs` PostStart/Started failure arms) and
graceful-shutdown sequence: inbounds → endpoints → services → context. No reordering needed.

## E. fresh / inherited V2Ray discrimination

Pointer identity via existing 01C `same_v2ray_server(old, new)` (`Arc::ptr_eq`):
same Arc → inherited → do NOT close; distinct Arcs → fresh → close; new `None`
(disabled or bind-skipped) → `close_v2ray=true` is a safe no-op (no resource). No config-string
or listen-address comparison anywhere in the guard.

## F. `shutdown_context_inner()` invocation

Only `shutdown_context_inner(new_context, fresh_only)` is called — never
`shutdown_context(new_context)` (which would unconditionally close an inherited server) and never
`shutdown_replaced_context` (post-swap old-context path, unchanged).

## G–I. Inbound / endpoint / service rollback

- G inbounds: `request_shutdown` per new inbound; real-socket test proves port release.
- H endpoints: `stop_endpoints` (per-endpoint `close()`, best-effort logged).
- I services: `stop_services` (per-service `close()`, best-effort logged). All three reuse the
  existing stop helpers verbatim; 01A audit J confirmed they are safe on
  partially-initialized objects (sync, idempotent, no completed-Start assumption).

## J. Cleanup error policy

All cleanup APIs return `()` (errors logged internally as warn); the helper returns `()`.
The transaction's `Err(error)` is returned unchanged after rollback — no `?` in cleanup, no new
`Result` plumbing. Report item D's "caller still receives X" is therefore structural; covered by
test `d_cleanup_error_does_not_disrupt_remaining_rollback` (a failing endpoint `close()` does not
disturb the remaining service/V2Ray cleanup).

## K/L. Transaction blocks (router / no-router)

Both `handle_reload` and `handle_reload_no_router` wrap Initialize → build_bridge → populate →
Start → (DNS/TLS global refresh, router only) → inbound serve wiring → PostStart → Started in
one `async { ... }.await` block returning `Result<Arc<Bridge>>`. The bridge is exported to the
rollback branch via a `new_bridge_slot: Option<Arc<Bridge>>` captured local, so a failure
*before* bridge construction rolls back with empty slices and a failure *after* it stops
bridge-owned resources. Both error branches call the SAME `shutdown_failed_reload_context` and
`return Err(error)` (original error preserved). Future pre-swap steps inserted inside the block
are covered automatically.

## M. Swap-success path

Unchanged: `preserve_v2ray = same_v2ray_server(...)` → state swap →
`stop_endpoints(old)` / `stop_services(old)` / `shutdown_replaced_context(old, preserve_v2ray)`.
No rollback cleanup runs after a successful swap (structural: the rollback branch returns early).

## N. Old-inbound continuity

NOT addressed (per card §12). `APP-RELOAD-INBOUND-CONTINUITY-01A = DEFER / FOLLOW-UP AUDIT`
remains registered: step 0 still `request_shutdown`s old inbounds before the reload outcome is
known; a pre-swap failure keeps the old context but its inbound listeners may already be closed.

## O. Files modified

- `crates/sb-core/src/runtime/supervisor.rs` (helper + 2 transaction blocks + tests; import of
  `InboundService` added). No app/, sb-api/, v2ray_api.rs, Cargo*, fixtures, Makefile, CI change.
- Checkpoint docs: `agents-only/active_context.md`, this file.

## P. New tests (`runtime::supervisor::tests::rollback_guard`)

| test | covers |
| --- | --- |
| `g_rollback_stops_inbounds_endpoints_and_services` | G + S (mock counters) |
| `f_rollback_releases_new_inbound_listener_port` | F (real TcpListener, re-bind) |
| `d_cleanup_error_does_not_disrupt_remaining_rollback` | D proxy (failing close) |
| `rollback_closes_fresh_v2ray_but_preserves_inherited` | fresh/inherited/none (mock) |
| `real_listener::a_rollback_closes_fresh_v2ray_and_releases_port` | A + Q (real gRPC bind) |
| `real_listener::b_rollback_preserves_inherited_v2ray_listener` | B + R |
| `real_listener::c_bind_failure_skip_rollback_is_noop_and_keeps_old` | C |
| `real_listener::e_repeated_failed_reloads_do_not_accumulate_leaks` | E + T |
| `real_listener::fresh_rollback_closes_exactly_once` | idempotent close sanity |

`real_listener` is `#[cfg(feature = "service_v2ray_api")]`; every bound listener is released
in-test. Port-release assertions retry (close() only signals; the serve task frees the listener
asynchronously).

## Q–T. Verification results

- **Q fresh port release**: PASS (a + fresh_rollback_closes_exactly_once).
- **R inherited keep-alive**: PASS (b: connect ok after rollback AND after dropping the new
  context; released only by old final `shutdown_context`).
- **S inbound/endpoint/service cleanup**: PASS (f real socket re-bind; g counters =1 each).
- **T repeated failure**: PASS (e: 3 rounds bind→fail→rollback→re-bind, no accumulation).

## U. Router / no-router parity

Both transaction-failure branches call the same `shutdown_failed_reload_context` (grep:
exactly 2 production call sites, one per path); helper body exists once. Structural parity —
no per-path cleanup copies. (No-router cfg branch compiles via default features: verified.)

## V. Gate results

fmt --check OK · `rollback` 10 PASS · `reload` 27 PASS · `v2ray` 26 PASS · full sb-core
**1109 PASS / 0 FAIL** · clippy all-features all-targets -D warnings clean · workspace
all-features check PASS · app `v2ray` 17 PASS · app full: 1st run 1 FAIL
(`default_metrics_owner_records_breaker_reopen_via_legacy_mark_failure` = registered
TIDY-APP-BREAKER-FLAKE; isolated rerun PASS; full-package rerun PASS — recorded, not fixed) ·
`git diff --check` clean · verify-consistency PASS · check-boundaries exit 0 (537 assertions) ·
rustdoc -D warnings: **14 errors = unchanged historical baseline**, none from supervisor.rs
(0 new).

## W. Commits

1. `47e15b0b` `fix(sb-core): clean up failed reload contexts before swap`
2. checkpoint: record pre-swap context rollback cleanup (this doc + active_context).
Not pushed (upstream acceptance decides).

## State

`APP-RELOAD-CONTEXT-CLEANUP-01B` = **DONE**. Defers unchanged:
`APP-RELOAD-INBOUND-CONTINUITY-01A` = DEFER / FOLLOW-UP AUDIT; `APP-SIDECAR-POLICY-02A`,
`SVC-V2RAY-API-01B`, `TIDY-RUSTDOC-LINKS`, `TIDY-APP-BREAKER-FLAKE` = DEFER.
