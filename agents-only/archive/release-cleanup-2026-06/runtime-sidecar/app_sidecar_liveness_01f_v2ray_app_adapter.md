<!-- tier: B -->
# APP-SIDECAR-LIVENESS-01F — app-level V2Ray runtime snapshot adapter

> Phase 1 (app only). A thin, read-only adapter mapping sb-core's
> `V2RayServerRuntimeSnapshot` into an app-internal `SidecarRuntimeSnapshot`. No consumer wired
> (deferred); no bootstrap/run-engine/Clash/ServiceHandle changes; not pushed.

Code commit: `feat(app): add v2ray sidecar runtime snapshot adapter`.

## A. Accepted-commits push result

`git push origin main` → `877aefff..ae5898d9 main -> main`. Post-push `## main...origin/main` +
untracked `agents-only/a0_reality_spike/`.

## B. Baseline git status

`## main...origin/main` + untracked `a0_reality_spike/`. Chain `ae5898d9`/`3f09a338`/`9fc7b2bd`/
`140d2d25` confirmed.

## C. app shared-module location

`app/src/lib.rs` is the module entry. Added `#[cfg(feature = "v2ray_api")] #[allow(dead_code)]
pub(crate) mod sidecar_runtime;` next to `run_engine_runtime`. Both bootstrap_runtime and
run_engine_runtime can reach it via `crate::sidecar_runtime`. New file
`app/src/sidecar_runtime.rs`.

## D. Cargo unchanged?

Yes. `sb-core` is already an app dependency; the V2Ray types are reachable under the existing app
feature `v2ray_api = ["sb-core","sb-core/service_v2ray_api","sb-api","sb-api/v2ray-api"]` (same gate
api_services.rs already uses). `tokio::sync::watch` is available via the workspace tokio (app already
uses oneshot/mpsc/broadcast). **No Cargo.toml / Cargo.lock changes.**

## E. New app-level snapshot types

`SidecarRuntimeSnapshot { current: Option<SidecarActiveGeneration>, last_exit:
Option<SidecarExitRecord> }` (derives `Default`); `SidecarActiveGeneration { generation: u64, phase:
SidecarActivePhase }`; `enum SidecarActivePhase { Running, ShutdownRequested, Unknown }`;
`SidecarExitRecord { generation: u64, exit: SidecarExit }`; `enum SidecarExit { CleanShutdown,
UnexpectedCompletion, ServeError(String), Panicked(String), Cancelled, Unknown }`. App-internal
semantics only — no stats, health, restart policy, or full-history Vec; not pushed into sb-core. (Item
visibility is `pub` inside the `pub(crate)` module per repo convention — `clippy::redundant_pub_crate`
in the enabled nursery group forbids redundant `pub(crate)`; effective visibility stays crate-capped.)

## F. `Unknown` degrade semantics

sb-core's `V2RayServerActivePhase` and `V2RayServerExit` are `#[non_exhaustive]`. Both mapping
functions keep a wildcard arm: an unrecognized future source variant maps to `SidecarActivePhase::
Unknown` / `SidecarExit::Unknown` — never `panic!`/`unreachable!()`, never a silent collapse to
`CleanShutdown` or a real phase. The wildcard is also required for the crate-external match to compile.

## G. Subscription adapter structure

```rust
pub struct SidecarRuntimeSubscription { name: String, source: SidecarRuntimeSource }
enum SidecarRuntimeSource { V2Ray(watch::Receiver<V2RayServerRuntimeSnapshot>) }
```
Holds the single source `watch::Receiver` directly — **no forwarding task, no second watch channel**.
`from_v2ray_server(name, &dyn V2RayServer) -> Option<Self>`, `name() -> &str`,
`snapshot_and_mark_seen() -> SidecarRuntimeSnapshot`, `async changed() -> Result<…,
watch::error::RecvError>`.

## H. `snapshot_and_mark_seen()` semantics

Uses `rx.borrow_and_update()` (not `borrow()`): a startup observer reads the current snapshot and
marks that version seen, so a subsequent `changed()` only resolves on a genuinely newer version (no
immediate re-consumption of the same version). Returns the mapped app snapshot.

## I. `changed()` semantics

`rx.changed().await?` → `map(rx.borrow_and_update())`. No task spawn, no new channel. A closed source
channel surfaces as `watch::error::RecvError` (propagated, **not** disguised as `CleanShutdown` or any
exit) — channel-closure policy is left to a later consumer layer.

## J. Trait receiver extraction

`from_v2ray_server` calls `server.subscribe_runtime_state()`: `Some(rx)` → adapter; **`None` → `None`**
(capability absent, e.g. an external implementor using the trait default). `None` is never treated as
"exited" and never panics — it lets callers distinguish "no runtime projection yet" from "terminated".

## K. Forwarding task / second channel?

**None.** Exactly one source `watch::Receiver` is held and mapped on demand. No spawned task, no
app-side `watch` channel, no state mirror.

## L. Files modified

- `app/src/sidecar_runtime.rs` (new) — types, mapping, subscription adapter, 10 unit tests.
- `app/src/lib.rs` — gated `pub(crate) mod sidecar_runtime;` declaration.
- (No Cargo / sb-core / sb-api changes.)

## M. Tests added

`maps_empty_snapshot` (A), `maps_running_generation` (B), `maps_shutdown_requested_generation` (C),
`maps_each_exit_variant` (D, all 5 exits with generation + error strings), `late_subscriber_reads_
terminal` (E), `changed_does_not_reconsume_seen_version` (F, bounded `tokio::time::timeout`, no sleep),
`changed_maps_new_version` (G), `source_closed_propagates_recv_error` (H), `capability_absent_yields_
none` (I, trait-default mock), `real_v2ray_server_yields_some` (J, real `V2RayApiServer`, no bind).

## N. Targeted test results

`cargo test -p app --all-features --lib sidecar_runtime` → **10 passed; 0 failed**.

## O. fmt / clippy / workspace / sb-core regression

- `cargo fmt -p app --check`: PASS.
- `cargo clippy -p app --all-features --all-targets -- -D warnings`: PASS (exit 0). Fixed 10 lints on
  the new code first: 6× `redundant_pub_crate` (→ `pub` items in the `pub(crate)` module), 3×
  `doc_markdown` (backticked `V2Ray`), 1× `missing_const_for_fn` (`map_v2ray_phase` → `const fn`).
- `cargo check --workspace --all-features`: PASS.
- `cargo test -p sb-core --all-features --lib v2ray_api`: **23 passed; 0 failed** (no regression).

## P. Hygiene gates

- `cargo test -p app --all-features`: PASS on retry (304/0). One **pre-existing parallel-global-state
  flake** — `admin_debug::breaker::tests::default_metrics_owner_records_breaker_reopen_via_legacy_
  mark_failure` — failed once then passed in isolation and on a full re-run. Unrelated to 01F:
  breaker.rs does not reference `sidecar_runtime`; the new module is isolated. **01F adds 0
  regressions.**
- `git diff --check`: PASS. `verify-consistency.sh`: PASS. `check-boundaries.sh`: exit 0 (537
  assertions, 0 violations).
- rustdoc not re-cleaned (out of scope). `RUSTDOCFLAGS="-D warnings" cargo doc -p sb-core
  --all-features --no-deps` remains the same 14-error BASELINE RED; **01F introduced 0 new rustdoc
  failures** (01F touches only `app`, not sb-core docs).

## Q. Commits

- `feat(app): add v2ray sidecar runtime snapshot adapter`
- `checkpoint: record app v2ray runtime snapshot adapter`

## R. Final status / defers

`## main...origin/main [ahead N]` + untracked `a0_reality_spike/`. Not pushed. Defers unchanged:
`SVC-V2RAY-API-01B` = DEFER/POLICY REVIEW; `APP-V2RAY-SURFACE-02D` = CLOSED; V2Ray breaking cleanup =
DEFER/FUTURE MAJOR; `TIDY-RUSTDOC-LINKS` = DEFER/HISTORICAL BASELINE RED. Out-of-scope unchanged:
H5 (instance-scoped stats), H6 (reload start-before-close), H7 (stats ≠ liveness probe).

## State

`APP-SIDECAR-LIVENESS-01F` = DONE (app adapter built, unconsumed by design). Next candidate = the
consumer wiring (bootstrap observer / run-engine) and/or 01G Clash projection — both deferred to
later cards.
