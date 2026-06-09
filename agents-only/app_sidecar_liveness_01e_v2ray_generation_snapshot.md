<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01E — implement V2Ray generation-aware runtime snapshot

> Phase 0 implementation (sb-core only). Establishes a generation-aware runtime snapshot for the
> repeatedly-startable `V2RayApiServer` and exposes a cloneable `watch::Receiver` through the public
> `V2RayServer` trait. No app consumer wired (deferred to 01F).

Code commit: `feat(sb-core): expose generation-aware v2ray runtime snapshot`.

## A. Baseline git status

`## main...origin/main` + untracked `agents-only/a0_reality_spike/` (left untracked).
Synced chain confirmed: `877aefff` / `6746a5d5` / `90562381`.

## B. pre-bind sync/async

`V2RayApiServer::pre_bind` is **synchronous** (`std::net::TcpListener::bind` → `set_nonblocking` →
`tokio::net::TcpListener::from_std`; no `.await`). Therefore admission + bind + generation
allocation + sender install all run inside one short lifecycle-mutex critical section.

## C. close-during-start race handling

Closed by the single critical section. `start()` holds the lifecycle mutex across the synchronous
`pre_bind`, allocates the generation, installs the shutdown sender, and **publishes `Running`
inside the lock** before releasing it; the serve task is spawned only after the lock drops.
`close()` takes the same mutex, so it can never observe `current == None` between a start's
admission and its `Running` publish — there is no "service starts after close returned" window. No
`start_in_progress` reservation was needed (B). Test `start_publishes_running_synchronously` pins
this (Running observable immediately, no await).

## D. old AtomicBool / blind guard handling

`started: Arc<AtomicBool>` and `ResetStartedOnDrop` (the generation-blind `store(false)` guard) are
**removed**. Liveness is now `current.is_some()`; terminal reset is the monitor's
generation-checked `commit_terminal`, which only clears `current` if it still owns the terminating
generation. The duplicate-start single-slot guarantee is now the mutex + `current.phase == Running`
check.

## E. New public snapshot types (`crates/sb-core/src/context.rs`)

`V2RayServerRuntimeSnapshot { current: Option<V2RayServerActiveGeneration>, last_exit:
Option<V2RayServerExitRecord> }` (derives `Default`); `V2RayServerActiveGeneration { generation: u64,
phase: V2RayServerActivePhase }`; `#[non_exhaustive] enum V2RayServerActivePhase { Running,
ShutdownRequested }`; `V2RayServerExitRecord { generation: u64, exit: V2RayServerExit }`;
`#[non_exhaustive] enum V2RayServerExit { CleanShutdown, UnexpectedCompletion, ServeError(String),
Panicked(String), Cancelled }`. No sidecar name / timestamp / restart counter / stats / probe /
history Vec / `ShutdownSignalDropped` (per §4 constraints).

## F. trait method + object safety

Added additive default to `V2RayServer`:
`fn subscribe_runtime_state(&self) -> Option<tokio::sync::watch::Receiver<V2RayServerRuntimeSnapshot>> { None }`.
Object-safe (no generics, no `async`, owned `Option<Receiver>` return); held as `Arc<dyn
V2RayServer>` at `context.rs:91` still compiles. External/mock implementors inherit `None`
(test `trait_default_subscribe_returns_none`). `V2RayApiServer` overrides to
`Some(self.runtime_tx.subscribe())`. Types live in `context.rs` next to the trait; consumed by
`v2ray_api.rs` via `use crate::context::{...}`. No crate-root re-export needed — `V2RayServer`
itself is exposed via `sb_core::context::`, matching existing style; **lib.rs unchanged.**

## G. Lifecycle mutex fields

`struct V2RayLifecycle { next_generation: u64, current: Option<RunningGeneration>, last_exit:
Option<V2RayServerExitRecord> }` behind `Arc<parking_lot::Mutex<…>>` on the server. `struct
RunningGeneration { generation: u64, phase: V2RayServerActivePhase, shutdown_requested:
Arc<AtomicBool>, shutdown_tx: Option<oneshot::Sender<()>> }`. The `watch::Sender` publishes; the
mutex arbitrates. No `.await` is ever held across the mutex.

## H. Startup reservation

**Not needed.** Synchronous `pre_bind` fits inside the critical section (B/C), so no
`start_in_progress` flag. Bind failure / overflow early-return inside the locked block, releasing
the listener and consuming no generation.

## I. Generation allocation + overflow

`allocate_generation(&mut V2RayLifecycle)` hands out `next_generation` and advances via
`checked_add(1)`; on `None` it returns `Err` **without** advancing (no wrap). First successful
start = generation 1. Bind failure / duplicate-running start / transient `EADDRINUSE` rollback
consume no generation. Test `generation_overflow_does_not_wrap` (next=`u64::MAX` → Err, counter
unchanged).

## J. start() timing

`listen_addr` resolve → lock → if `current.phase == Running` return Ok (duplicate no-op) → `pre_bind?`
→ `allocate_generation` (drop listener + Err on overflow) → install `RunningGeneration` (Running) →
`send_replace(snapshot)` → unlock → spawn counter-init → spawn outer monitor (which spawns the inner
tonic serve task) → Ok. Running is published before the lock releases (C).

## K. close() timing

Sync/idempotent/non-blocking: lock → `current` None ⇒ Ok; `ShutdownRequested` ⇒ Ok (no resend);
`Running` ⇒ set `ShutdownRequested`, set `shutdown_requested` marker, take `shutdown_tx`, build
snapshot → unlock → `send_replace` → send shutdown signal outside the lock → Ok. Never waits,
commits a terminal, fabricates CleanShutdown, clears current, or overwrites last_exit.
(Stub build, no feature: close commits CleanShutdown inline since there is no monitor.)

## L. generation-local shutdown marker

`RunningGeneration.shutdown_requested: Arc<AtomicBool>`. `close()` sets it for the target
generation; the monitor reads its own generation's marker to choose `CleanShutdown` (true) vs
`UnexpectedCompletion` (false) — never consulting the (possibly-newer) live snapshot.

## M. outer monitor structure

Per successful generation: `tokio::spawn` an outer monitor that `tokio::spawn`s the inner tonic
serve task, awaits its `JoinHandle`, classifies the outcome, logs the terminal once, and calls
`commit_terminal(generation, exit)`. Sole terminal writer for its generation.

## N. terminal mapping (`classify_exit<E: Display>`)

`Ok(Ok(()))`+marker → `CleanShutdown`; `Ok(Ok(()))`+!marker → `UnexpectedCompletion`; `Ok(Err(e))` →
`ServeError(e.to_string())`; `Err(join)` panic → `Panicked(payload-string-or-fallback)`; `Err(join)`
cancelled → `Cancelled`; other `JoinError` → `Cancelled` (nearest defined, unreachable today). Panic
payload extracted via `downcast_ref::<&str>`/`<String>`, else a stable string. No `catch_unwind`, no
new deps. Generic so tests synthesize outcomes (`classify_exit_maps_{completion_and_error,panic,
cancelled}`).

## O. stale terminal commit rule (`commit_terminal`)

Under the mutex: clear `current` iff `current.generation == g`; set `last_exit` iff `last_exit` is
`None` or `g > last_exit.generation`; never regress. Tolerates arbitrary stale order (terminal(2)
then terminal(1) with current=Running(3) keeps current=3, last_exit=2). Stale terminals not entering
the snapshot are still logged once by their monitor. Tests G/H/I:
`stale_terminal_does_not_clear_newer_current`, `last_exit_only_advances_by_generation`,
`arbitrary_stale_monitor_order_preserves_state`.

## P. watch sender + late subscriber

`runtime_tx: watch::Sender<…>` lives on the server (`watch::channel(default)` in `new()`), outliving
every serve task; `send_replace` publishes the full snapshot inside the lock. `subscribe()` gives
late subscribers the latest value. Tests `late_subscriber_reads_terminal`,
`successful_bind_publishes_running` (late subscriber sees Running).

## Q. log owner before/after

Before: the inner serve task logged "Received shutdown signal" / "V2Ray API server error" /
"…stopped". After: the **outer monitor** is the single terminal logger per generation
(clean/unexpected/serve-error/panic/cancel, tagged with `generation`), even for a stale terminal not
entering the snapshot. The inner task still logs the informational "Received shutdown signal" (not a
terminal). No double terminal logging; `close()` logs no fake terminal.

## R. Files modified

- `crates/sb-core/src/context.rs` — snapshot types + trait method.
- `crates/sb-core/src/services/v2ray_api.rs` — lifecycle, helpers, start/close rewrite, monitor,
  test rewrite.
- (lib.rs unchanged; no Cargo changes.)

## S. New / rewritten tests (`v2ray_api.rs`)

Both-build (non-gated): `initial_snapshot_is_empty` (A), `trait_default_subscribe_returns_none` (N),
`generation_overflow_does_not_wrap` (O), `stale_terminal_does_not_clear_newer_current` (G),
`last_exit_only_advances_by_generation` (H), `arbitrary_stale_monitor_order_preserves_state` (I),
`late_subscriber_reads_terminal` (M), `classify_exit_maps_completion_and_error` (J),
`classify_exit_maps_panic` (K), `classify_exit_maps_cancelled` (L).
Feature-gated (real listener): `bind_conflict_returns_error_and_no_phantom_generation` (D),
`successful_bind_publishes_running` (B+M), `restart_after_failed_bind`,
`duplicate_start_keeps_same_generation` (C), `normal_close_publishes_shutdown_then_clean_exit` (E),
`bounded_retry_restart_reaches_generation_two` (F), `task_exit_without_close_is_unexpected_completion`,
`start_publishes_running_synchronously` (P). Removed `reset_started_guard_drop_resets_state` (guard
deleted); retained stats/creation tests.

## T. Targeted test results

`cargo test -p sb-core --all-features --lib v2ray_api` → **21 passed; 0 failed**. Full
`cargo test -p sb-core --all-features` → all 40 binaries 0 failed.

## U. fmt / clippy / workspace / rustdoc / hygiene gates

- `cargo fmt -p sb-core --check`: **PASS**.
- `cargo clippy -p sb-core --all-features --all-targets -- -D warnings`: **PASS** (fixed one
  `question_mark` lint by using `?` for `pre_bind`).
- `cargo check --workspace --all-features`: **PASS** (app + workspace compile against the new public
  API; `cargo test -p app --all-features v2ray` exit 0).
- `RUSTDOCFLAGS="-D warnings" cargo doc -p sb-core --all-features --no-deps`: **pre-existing FAIL**
  (14 broken intra-doc links in unrelated modules — `error.rs`, inbound/router/dns; identical 14
  errors on clean HEAD via `git stash`). **01E introduces zero new doc errors** (verified: no doc
  error cites context.rs / v2ray / snapshot / V2RayServer). Not caused by this card; fixing those
  links is out of scope.
- `git diff --check`: **PASS**. `verify-consistency.sh`: PASS. `check-boundaries.sh`: **exit 0**
  (537 assertions, 0 violations).

## V. Code commit

`feat(sb-core): expose generation-aware v2ray runtime snapshot` (sb-core context.rs + v2ray_api.rs).

## W. Checkpoint commit / final status

Checkpoint `checkpoint: record generation-aware v2ray runtime snapshot` (active_context.md + this
file). Not pushed — left to the upper layer. `SVC-V2RAY-API-01B` remains `DEFER / POLICY REVIEW`.
`agents-only/a0_reality_spike/` left untracked.

## State

`APP-SIDECAR-LIVENESS-01E` = DONE (sb-core source snapshot live). Next candidate = 01F (app adapter
mapping the source snapshot into app sidecar completion). H5 (instance-scoped stats), H6 (supervisor
reload start-before-close), H7 (stats not a liveness probe) remain out of scope.
