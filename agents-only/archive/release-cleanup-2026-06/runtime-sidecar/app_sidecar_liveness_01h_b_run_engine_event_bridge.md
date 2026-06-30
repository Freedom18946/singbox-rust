<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01H-B — run-engine sidecar runtime event bridge

> app-only consumer wiring. Builds a run-engine log-only event bridge over the existing sidecar
> runtime snapshots. Mechanism only — no product policy change. bootstrap untouched. Not pushed.

Code commit: `feat(app): bridge run-engine sidecar runtime events`.

## A. Baseline git status

`## main...origin/main` + untracked `a0_reality_spike/`. Chain `fffe916d`/`cac2ccb9`/`bf7304fd`/
`84cea4dd` confirmed.

## B. `RuntimeLifecycle` definition + existing shutdown order

`app/src/run_engine_runtime/context.rs:145` (router-gated module). Held `metrics_exporter`,
`admin_services`, `watch`. Original `shutdown(self)`: `watch.shutdown()` → `admin_services.shutdown()`
→ `metrics_exporter.shutdown()`.

## C. run-engine Clash subscription extraction

Added `AdminServices::clash_runtime_subscription(&self) -> Option<SidecarRuntimeSubscription>`
(admin_start.rs, gated `clash_api`): `self.clash_api.as_ref().map(|h|
SidecarRuntimeSubscription::from_clash("clash-api", h.shutdown.subscribe_runtime_state()))`. Removed
the `#[allow(dead_code)]` on `ClashShutdownHandle::subscribe_runtime_state` and
`ClashRuntimePublisher::subscribe` (now used).

## D. run-engine V2Ray subscription extraction

Added `v2ray_runtime_subscription(&Arc<Supervisor>)` (supervisor.rs, gated `v2ray_api`): reads
`supervisor.handle().state().await` → `guard.context.v2ray_server` →
`SidecarRuntimeSubscription::from_v2ray_server("v2ray-api", server.as_ref())`. Reads existing
`State.context` only — **no sb-core change**. The read guard is explicitly dropped before returning
the owned subscription (clippy `significant_drop_tightening`).

## E. `SidecarRuntimeEvent` model

`enum SidecarRuntimeEvent { Exited { name: String, exit: SidecarExitRecord }, ProjectionClosed {
name: String } }`. No timestamp / restart counter / health / snapshot / history / hard-fail / degrade.
Generation lives in `SidecarExitRecord`; error text in `SidecarExit`. `Running` / `ShutdownRequested`
stay in the snapshot and never cross the bridge.

## F. Terminal-determination rule

Pure `terminal_event_from_snapshot(name, &snapshot)`: `current.is_some()` → `None` (active generation
wins; a historical `last_exit` never reports the live sidecar dead); `current.is_none()` +
`last_exit = Some(exit)` → `Exited { name, exit.clone() }`; `current.is_none()` + `last_exit = None`
→ `None` (keep waiting). Test `active_generation_outranks_historical_exit` pins the
`Running(2)` + `CleanShutdown(1)` case → `None`.

## G. observer loop

`observe_sidecar_runtime(mut subscription, event_tx)`: `snapshot_and_mark_seen()` first (a sidecar may
already be terminal at subscribe time; `watch` won't re-emit the seen version) → if terminal, send &
return; else `loop { changed().await }` → terminal → send & return; `Err(RecvError)` → send
`ProjectionClosed` & return. At most one event; send failure is silent (no panic, no retry) and the
observer exits.

## H. unbounded mpsc rationale

`tokio::sync::mpsc::unbounded_channel`: at most run-engine Clash + V2Ray observers, each sending at
most one event → strictly bounded queue growth; `send()` is synchronous (no `.await`), so a stopped
consumer never blocks an observer and `RuntimeLifecycle::shutdown()` cannot deadlock on event
back-pressure. No bounded `send().await`, no broadcast, no second `watch`, no forwarding channel, no
reuse of the sb-core reload mpsc.

## I. consumer log-only behavior

`consume_sidecar_runtime_events` drains until the channel closes, calling
`handle_sidecar_runtime_event(&event) -> SidecarRuntimeAction` (always `Continue`). `Exited` → a
low-noise `debug` breadcrumb (NOT a re-log of the terminal; the source monitor already logged it);
`ProjectionClosed` → a `warn`. No engine exit / restart / degrade. The explicit `SidecarRuntimeAction`
return makes the (currently log-only) policy testable (`consumer_is_log_only`).

## J. bridge owner structure

`SidecarRuntimeEventBridge { observer_joins: Vec<JoinHandle<()>>, consumer_join: JoinHandle<()> }`.
`spawn(Vec<SidecarRuntimeSubscription>) -> Option<Self>`: empty → `None` (no empty consumer task);
non-empty → unbounded channel, one observer per subscription (each holds a sender clone), **drop the
root sender** (so the consumer ends once all observers finish), one consumer task.

## K. bridge shutdown order

`shutdown(self)`: abort all observers → await each observer join → (observer sender clones now dropped)
→ await the consumer's natural exit. Bounded — does **not** wait for the sidecar's own terminal (V2Ray
close happens later in outer context shutdown). Tests `bridge_shutdown_does_not_wait_for_terminal`
(source stays Running, shutdown completes within timeout) + `multiple_observers_then_shutdown`.

## L. `RuntimeLifecycle` wiring

Added `#[cfg(any(clash_api, v2ray_api))] sidecar_runtime_events: Option<SidecarRuntimeEventBridge>`
field + `attach_sidecar_runtime_events()`. `run_supervisor` builds the bridge via a new
`build_sidecar_runtime_bridge(&admin_services, &supervisor).await` **before** `admin_services` moves
into `RuntimeLifecycle::new`, then attaches it. `shutdown()` order is now `watch` →
**`admin_services` (signals Clash)** → **bridge** → `metrics_exporter`, so the Clash observer can
witness `ShutdownRequested → CleanShutdown` and any still-Running observer is aborted by the bridge.

## M. bootstrap unchanged

bootstrap stays source-logger-only: no receiver extracted from the bootstrap V2Ray `Arc`, no
subscription on the bootstrap `ServiceHandle`, no bootstrap observer. `app/src/bootstrap.rs` and
`app/src/bootstrap_runtime/` untouched.

## N. dead-code gate narrowing

Narrowed the module gate from `any(clash_api, v2ray_api)` to
`all(feature="router", any(feature="clash_api", feature="v2ray_api"))` (run-engine is the only
consumer, and run-engine is router-gated) and **removed the module-level `#[allow(dead_code)]`** — the
bridge now exercises every item. Removed the two per-item `#[allow(dead_code)]` on
`ClashShutdownHandle::subscribe_runtime_state` / `ClashRuntimePublisher::subscribe`. No blanket allow
remains.

## O. Files modified

`app/src/lib.rs` (module gate + drop allow), `app/src/sidecar_runtime.rs` (event/observer/consumer/
bridge + tests), `app/src/run_engine_runtime/admin_start.rs` (clash subscription, drop allows),
`app/src/run_engine_runtime/context.rs` (RuntimeLifecycle field/attach/shutdown order),
`app/src/run_engine_runtime/supervisor.rs` (v2ray subscription helper, build_sidecar_runtime_bridge,
wiring). No Cargo / sb-core / sb-api / bootstrap change.

## P. Tests added (`sidecar_runtime::tests::bridge`, gated clash_api)

`active_generation_outranks_historical_exit` (E), `consumer_is_log_only` (K),
`initial_terminal_is_reported` (A), `running_and_shutdown_requested_emit_no_event` (B/C),
`terminal_after_transitions_emits_once` (D), `projection_closed_is_reported` (F),
`dropped_receiver_does_not_block_observer` (G), `empty_subscriptions_yield_no_bridge` (H),
`bridge_shutdown_does_not_wait_for_terminal` (I), `multiple_observers_then_shutdown` (J). Bounded
`tokio::time::timeout`, no flaky sleeps. (L full-lifecycle: covered at helper level by I + the wiring;
a full `RuntimeLifecycle::shutdown` test needs a live supervisor — too heavy, deferred.)

## Q. Feature matrix

`cargo check -p app` PASS in all 5 modes (`--no-default-features`, default, `--features clash_api`,
`--features v2ray_api`, `--all-features`). no-default/default omit the bridge (no sidecar source);
clash_api / v2ray_api without router do not pull the run-engine bridge (router-gated); all-features
has both Clash + V2Ray sources.

## R. Targeted test results

`--lib sidecar_runtime`: **25 passed; 0 failed** (10 bridge + 10 V2Ray + 5 Clash).

## S. app full-suite + breaker flake

`cargo test -p app --all-features`: one run 328/1, immediate full-lib rerun 329/0; the lone failure is
the registered **TIDY-APP-BREAKER-FLAKE**
(`admin_debug::breaker::tests::default_metrics_owner_records_breaker_reopen_via_legacy_mark_failure`,
breaker.rs:1032) — passes in isolation (1/0), and `breaker.rs` has no reference to `sidecar_runtime`.
Intermittent parallel-global-state flake, unrelated; **01H-B adds 0 regressions**; breaker NOT
modified.

## T. fmt / clippy / workspace / sb-core regression

- `cargo fmt -p app --check`: PASS.
- `cargo clippy -p app --all-features --all-targets -- -D warnings`: PASS (0 warnings; fixed
  `redundant_pub_crate` → `pub`, `doc_markdown` `V2Ray`/`ShutdownRequested` backticks,
  `significant_drop_tightening` on the V2Ray state guard, and restored the stranded
  `#[allow(clippy::too_many_lines)]` onto `run_supervisor`).
- `cargo check --workspace --all-features`: PASS.
- `cargo test -p sb-core --all-features --lib v2ray_api`: 23 passed/0 (no regression).

## U. Hygiene gates

`git diff --check`: PASS. `verify-consistency.sh`: PASS. `check-boundaries.sh`: exit 0 (537
assertions, 0 violations). rustdoc untouched (app-only change; sb-core 14-error BASELINE RED unchanged
= `TIDY-RUSTDOC-LINKS`).

## V. Commits

- `feat(app): bridge run-engine sidecar runtime events`
- `checkpoint: record run-engine sidecar runtime event bridge`

## W. Final status / defers

`## main...origin/main [ahead N]` + untracked `a0_reality_spike/`. Not pushed (upper layer accepts).
Defers unchanged: `SVC-V2RAY-API-01B` = DEFER/POLICY REVIEW; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray
breaking cleanup = DEFER/FUTURE MAJOR; `TIDY-RUSTDOC-LINKS` = DEFER/HISTORICAL BASELINE RED;
`TIDY-APP-BREAKER-FLAKE` = DEFER/NEEDS INDEPENDENT REPRODUCTION. Out-of-scope unchanged: H5/H6/H7.

## State

`APP-SIDECAR-LIVENESS-01H-B` = DONE (run-engine log-only event bridge wired; mechanism complete). The
sidecar runtime liveness line now spans: sb-core source snapshots (01E/E-R1) → app adapter (01F) →
Clash task-owner projection (01G-B) → run-engine log-only consumer (01H-B). A future
consumer-**policy** card (hard-fail / restart / degrade / health probe) remains explicitly deferred;
bootstrap consumption also remains a future option (Route 1 today).
