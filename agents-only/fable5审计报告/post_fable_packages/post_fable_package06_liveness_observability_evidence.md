<!-- tier: B -->
# post_fable_package06_liveness_observability_evidence

## Scope

Package06 closes liveness observability without changing fatal/restart policy.
Inbound serve exits are now monitored and classified; Clash API startup failure is
visible through the sidecar runtime bridge; DNS resolver build failure warns
instead of disappearing; V2Ray rapid same-port re-enable has a bounded bind retry.

## Code Evidence

- `crates/sb-core/src/runtime/supervisor.rs`
  - `State` owns `InboundRuntimeMonitor` handles.
  - `start_inbounds_until_ready` starts from `Bridge` metadata, waits for readiness
    where supported, and returns monitors only after activation.
  - reload rollback drains only failed new monitors; commit swaps monitors with
    bridge/context and drains old monitors after commit.
  - final shutdown marks committed monitors as deliberate before bounded drain.
- `app/src/sidecar_runtime.rs`
  - `SidecarExit::StartFailed(String)` models terminal startup failure.
  - event breadcrumbs include `component`, `sidecar`, `status`, `exit_kind`,
    `listen`, and `error`.
- `app/src/run_engine_runtime/admin_start.rs`
  - Clash API bind/create failure keeps a runtime publisher and exposes terminal
    `StartFailed`; clean shutdown stays low-noise.
- `crates/sb-core/src/services/v2ray_api.rs`
  - same-port `AddrInUse` bind retry is bounded to 1s and happens before
    generation allocation / `Running` publication.

## CAL Status

| Finding | Status | Evidence |
|---|---|---|
| CAL-06 inbound liveness | DONE | monitor classification tests; fake inbound drain tests; failed reload keeps old monitor |
| CAL-13 Clash API down signal | DONE | `StartFailed` publisher and sidecar event bridge tests |
| CAL-15 V2Ray rapid re-enable | DONE | `bounded_same_port_release_retry_reaches_generation_two` |
| CAL-16 DNS resolver visibility | DONE | `dns_resolver_build_failure_is_nonfatal_but_observable` |
| CAL-12 residual | PARTIAL/NO-REGRESSION | failed reload continuity extended; no restart/drain redesign |

## Verification

Passed locally on 2026-06-13:

- `cargo test -p sb-core --lib supervisor`
- `cargo test -p sb-core --lib --features service_v2ray_api rollback`
- `cargo test -p sb-core --lib --features service_v2ray_api v2ray`
- `cargo test -p app --lib --features adapters,clash_api,v2ray_api`
- `cargo test -p app --features adapters,clash_api,v2ray_api run_engine_runtime`
- `cargo test -p sb-adapters --lib`
- `cargo build -p app --bin app --features adapters,clash_api,v2ray_api`
- `cargo check -p app --features parity`
- `cargo check --workspace --all-features`
- `git diff --check`
- `WORK=/tmp/pf07-after-package06 bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh`
  - `CONTRACT-EQUIVALENCE PROBE: PASS` (`PASS=14 FAIL=0`)

Notes:

- `cargo test -p sb-adapters --lib` still reports pre-existing unused-import
  warnings in `crates/sb-adapters/src/register.rs`; tests pass.

## 06b Acceptance Fix

On 2026-06-13, package06b fixed an app lib test/API exposure gap: `ClashShutdownHandle`
again exposes a crate-internal `subscribe_runtime_state()` method backed by its
own `ClashRuntimePublisher`, preserving the `immediate_shutdown_yields_clean_terminal`
test contract without changing sidecar policy.

Passed locally for 06b:

- `cargo test -p app --lib --features adapters,clash_api,v2ray_api`
- `cargo test -p app --features adapters,clash_api,v2ray_api run_engine_runtime`
- `cargo test -p sb-core --lib supervisor`
- `git diff --check`
