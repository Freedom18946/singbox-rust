<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01G-B — implement Clash runtime completion projection

> app-only mechanism implementation. Builds an app-local runtime completion projection for the Clash
> API serve task shared by bootstrap and run-engine. Mechanism only — no consumer policy. Not pushed.

Code commit: `feat(app): expose clash runtime completion state`.

## A. Baseline git status

`## main...origin/main` + untracked `a0_reality_spike/`. Chain `d8845c96`/`84cea4dd`/`24323c02` confirmed.

## B. app feature matrix

- `clash_api = ["sb-api", "sb-api/clash-api", "sb-api/provider-reload"]` (does NOT pull sb-core).
- `v2ray_api = ["sb-core", "sb-core/service_v2ray_api", "sb-api", "sb-api/v2ray-api"]` (pulls sb-core).
- `router` pulls sb-core; the Clash projection plumbing lives under `all(feature="router",
  feature="clash_api")` (same gate as the pre-existing `spawn_prebound_clash_api_server`).
- `default = ["router"]` (clash_api/v2ray_api OFF by default → the adapter module is absent in default
  builds). `[dev-dependencies]` carries non-optional `sb-core` (with `router`), so test builds always
  have sb-core + router.

## C. `sidecar_runtime` gate adjustment

`lib.rs`: `#[cfg(feature = "v2ray_api")]` → `#[cfg(any(feature = "clash_api", feature = "v2ray_api"))]`
(still `#[allow(dead_code)]`, consumer deferred). Inside the module: the app-level snapshot types are
unconditional; sb-core imports + the `V2Ray` variant + `from_v2ray_server` + `map_v2ray_*` + V2Ray
tests are gated `v2ray_api`; the `Clash` variant + `from_clash` + Clash tests are gated `clash_api`;
each `match` arm in `snapshot_and_mark_seen`/`changed` is per-feature-gated.

## D. Clash-only / V2Ray-only compile isolation

`cargo check -p app` passes for: `--no-default-features`, default, `--features clash_api`,
`--features v2ray_api`, `--all-features`. Clash-only compiles without any sb-core reference (the
`Clash` arm uses only `watch` + app types); V2Ray-only keeps the V2Ray adapter and excludes the Clash
arm; all-features has both arms. No Cargo change.

## E. Publisher structure

`ClashRuntimePublisher { runtime_tx: watch::Sender<SidecarRuntimeSnapshot>, shutdown_requested:
Arc<AtomicBool> }` (`#[derive(Clone)]`), in `admin_start.rs` under `all(router, clash_api)`. Methods:
`new_running()` (watch initialized to `Running(1)`, `last_exit=None`), `subscribe()`,
`shutdown_requested()`, `mark_shutdown_requested()`, `commit_terminal(exit)`.

## F. Snapshot publication serialization

All mutations publish via `watch::Sender::send_if_modified(|snapshot| { mutate; returns changed })` —
mutation + publication happen atomically inside the watch's internal lock, with no `.await` held.
This structurally avoids the borrow-then-delayed-send backflow fixed for V2Ray in 01E-R1; no separate
mutex, no second channel.

## G. Generation model

Handle-local constant `generation = 1`. Each `PreboundClashApiHandle` is single-lifecycle; a new
handle creates a new independent watch source. No global counter, no cross-handle registry, no
draining `Vec`, no history queue.

## H. Shutdown controller

`ClashShutdownHandle { shutdown_tx: Option<oneshot::Sender<()>>, monitor_join:
Option<JoinHandle<()>>, runtime: ClashRuntimePublisher }`. `shutdown(&mut self)`:
`mark_shutdown_requested()` (marker=true + publish `ShutdownRequested(1)` in the watch lock) → take &
`send(())` the oneshot **outside** any lock → await the outer monitor. Idempotent: a repeated call is
a no-op (sender/join already taken). `subscribe_runtime_state()` exposes the receiver for a future
consumer (`#[allow(dead_code)]`, unused this card).

## I. Bare-drop semantics

No custom `Drop`. If the controller is dropped without `shutdown()`, the `oneshot::Sender` drops →
sb-api's graceful-shutdown future (`let _ = shutdown.await`) completes → the serve future returns
`Ok(())` with the marker still `false` → the monitor classifies `UnexpectedCompletion`. A bare drop is
**never** disguised as `CleanShutdown`.

## J. `PreboundClashApiHandle` reshape

`{ listen_addr, shutdown: oneshot::Sender<()>, join: JoinHandle<()> }` →
`{ listen_addr, shutdown: ClashShutdownHandle }`. The bare sender + join are no longer exposed to the
two consuming paths, so `ShutdownRequested` is always published before signalling and the outer
monitor is the sole terminal committer.

## K. Outer monitor structure

In `spawn_prebound_clash_api_server`: pre-bind → read `actual_addr` (fallible, before publish) →
`ClashRuntimePublisher::new_running()` (publishes `Running(1)`) → `tokio::spawn` outer monitor → return
handle. The outer monitor `tokio::spawn`s the inner serve task (returns `ApiResult<()>`), awaits its
`JoinHandle`, classifies, logs once, and `commit_terminal`s. Between the `Running` publish and the
monitor spawn there is no fallible op / early return (§10 satisfied).

## L. Terminal mapping (`classify_clash_exit<E: Display>`)

`Ok(Ok(()))`+marker → `CleanShutdown`; `Ok(Ok(()))`+!marker → `UnexpectedCompletion`; `Ok(Err(e))` →
`ServeError(e.to_string())`; `Err(join)` panic → `Panicked(payload-or-fallback)`; cancelled →
`Cancelled`; other → `Cancelled` (nearest defined). Panic payload via `into_panic()` +
`downcast_ref::<&str>()/<String>()` + stable fallback. No `catch_unwind`, no new deps.

## M. Log owner before/after

Before: the inner serve task logged `"Clash API server error"` and swallowed the `ApiResult`. After:
the inner task **returns** the `ApiResult` and the **outer monitor** is the single terminal logger
(clean / unexpected / serve-error / panic / cancelled), once per handle. No double logging.

## N. bootstrap `ServiceHandle` reshape

`ServiceHandle.shutdown` is now a private `ServiceShutdown` enum: `Task { shutdown, join }` (the
bootstrap V2Ray path, unchanged behavior) | `Clash(ClashShutdownHandle)` (gated `all(router,
clash_api)`). `ServiceHandle::from_task(...)` constructor added for cross-module construction
(`runtime_shell` test). `ServiceHandle::shutdown()` matches the enum; the Clash arm delegates to
`ClashShutdownHandle::shutdown()`. The bootstrap Clash producer builds the `Clash` variant; the
bootstrap V2Ray producer builds `Task`.

## O. run-engine `ClashApiHandle` reshape

`{ listen_addr, shutdown: oneshot::Sender, join: JoinHandle }` →
`{ listen_addr, shutdown: ClashShutdownHandle }`; `ClashApiHandle::shutdown(self)` delegates to the
controller. `AdminServices::shutdown()` (unchanged) calls it. `listen_addr` retained for the
admin-listen conflict check.

## P. adapter `Clash` source

`SidecarRuntimeSource::Clash(watch::Receiver<SidecarRuntimeSnapshot>)` +
`SidecarRuntimeSubscription::from_clash(name, receiver)` (infallible — Clash always has a source). The
Clash arms of `snapshot_and_mark_seen()`/`changed()` are identity reads (`borrow_and_update().clone()`,
no second mapping). The Clash task owner publishes the app-level snapshot directly.

## Q. forwarding task / second channel

**None.** One source `watch` channel per handle (owned by the publisher); the controller/adapter hold
receivers. No forwarding task, no app-side mirror channel, no fabricated timestamp.

## R. Tests added

- `sidecar_runtime` (clash mod, gated clash_api): `clash_source_is_identity` (I),
  `clash_late_subscriber_reads_terminal` (L), `clash_changed_does_not_reconsume_seen_version` (J),
  `clash_changed_returns_new_version` (K), `clash_source_closed_propagates_recv_error`. Existing V2Ray
  tests moved under a `v2ray` mod (gated v2ray_api), unchanged.
- `admin_start` (clash_runtime mod, gated all(router,clash_api)): `publisher_starts_running` (A),
  `mark_shutdown_requested_publishes_shutdown_requested` (B), `terminal_is_monotonic` (C),
  `classify_ok_without_request_is_unexpected` (D), `classify_ok_with_request_is_clean` (E),
  `classify_serve_error` (F), `classify_panic` (G), `classify_cancelled` (H), `bind_conflict_returns_
  error` (N), `immediate_shutdown_yields_clean_terminal` (M, real pre-bound server). Existing bootstrap
  Clash/V2Ray shutdown regressions retained (O), updated to the new handle shapes.

## S. Feature-matrix check results

`cargo check -p app` PASS in all 5 modes (`--no-default-features`, default, `--features clash_api`,
`--features v2ray_api`, `--all-features`). Gate isolation confirmed: Clash-only has no sb-core ref;
V2Ray-only excludes the Clash arm; all-features has both.

## T. Targeted test results

`--lib sidecar_runtime`: 15 passed/0 (10 V2Ray + 5 Clash). `--lib clash_runtime`: 10 passed/0.
`--all-features clash` filter: 23 passed/0.

## U. fmt / clippy / workspace / sb-core regression

- `cargo fmt -p app --check`: PASS.
- `cargo clippy -p app --all-features --all-targets -- -D warnings`: PASS (0 warnings; fixed 1
  `missing_const_for_fn`-era carryover + 3 `doc_markdown` `V2Ray` backticks + module-doc `V2Ray`
  backticks on the new code).
- `cargo check --workspace --all-features`: PASS.
- `cargo test -p sb-core --all-features --lib v2ray_api`: 23 passed/0 (no regression).

## V. Hygiene gates

- `cargo test -p app --all-features`: intermittent — one full-suite run 318/1, immediate re-run
  319/0. The lone failure is the **pre-existing parallel-global-state breaker flake**
  (`admin_debug::breaker::tests::default_metrics_owner_records_breaker_reopen_via_legacy_mark_failure`;
  flakes even within a `breaker`-filtered run, 20/1). Unrelated to 01G-B (no file touched by this card
  references `breaker`). Registered: **TIDY-APP-BREAKER-FLAKE** (DEFER / NEEDS INDEPENDENT
  REPRODUCTION). 01G-B adds 0 regressions; breaker was NOT modified.
- `git diff --check`: PASS. `verify-consistency.sh`: PASS. `check-boundaries.sh`: exit 0 (537
  assertions, 0 violations).
- rustdoc not re-run (out of scope); 01G-B touches only `app`, introduces 0 new sb-core rustdoc
  failures; the historical sb-core 14-error BASELINE RED is `TIDY-RUSTDOC-LINKS`.

## W. Commits / final status / defers

- `feat(app): expose clash runtime completion state`
- `checkpoint: record clash runtime completion projection`

`## main...origin/main [ahead N]` + untracked `a0_reality_spike/`. Not pushed (upper layer accepts).
Defers unchanged: `SVC-V2RAY-API-01B` = DEFER/POLICY REVIEW; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray
breaking cleanup = DEFER/FUTURE MAJOR; `TIDY-RUSTDOC-LINKS` = DEFER/HISTORICAL BASELINE RED;
`TIDY-APP-BREAKER-FLAKE` = DEFER/NEEDS INDEPENDENT REPRODUCTION. Out-of-scope unchanged: H5/H6/H7.

## State

`APP-SIDECAR-LIVENESS-01G-B` = DONE (Clash runtime completion projection built; unconsumed by design).
Both V2Ray (01E/F) and Clash (01G-B) sidecars now expose an app-level `SidecarRuntimeSnapshot`
subscription. Next candidate = the consumer wiring (bootstrap observer / run-engine supervisor /
log-only observer) and the consumer-policy review — all deferred to later cards.
