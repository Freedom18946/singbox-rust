<!-- tier: B -->
# APP-SIDECAR-BIND-01 - Clash API app-sidecar bind honesty

Status: DONE. Code commit: `e1f0be43`; checkpoint commit pending in this document.

## Scope

Fix only the app-layer Clash API sidecar startup honesty issue found by
APP-SIDECAR-AUDIT-01. Do not change SimpleV2RayApiServer, sb-core V2Ray gRPC sidecar,
ServiceManager projection, Cargo dependencies, fixtures, CI, REALITY, or parity ledgers.

## Entry Chains

- Bootstrap path: `app/src/bootstrap.rs::start_from_config` reads
  `experimental.clash_api.external_controller`, then calls
  `bootstrap_runtime::api_services::start_clash_api_server`, which now delegates to the
  shared pre-bound helper before returning a `ServiceHandle`.
- Run-engine path: `run_engine_runtime::admin_start::start_admin_services` calls
  `start_clash_api_from_supervisor`, which builds the `ClashApiServer` from supervisor state
  and then calls the same shared pre-bound helper before returning a `ClashApiHandle`.

Both entries now share the common startup root:

- `app/src/run_engine_runtime/admin_start.rs::spawn_prebound_clash_api_server`

## Old Failure Shape

Before this card, both app entries spawned a task that called
`ClashApiServer::start_with_shutdown`. The actual bind happened inside the spawned task in
`crates/sb-api/src/clash/server.rs::start_with_shutdown`, after the caller had already received
a shutdown/join handle. On bind conflict:

- bootstrap returned `Some(ServiceHandle)` and stored it in the runtime service handle list;
- run_engine returned `Some(ClashApiHandle)` and logged `started clash api server from
  run_engine`;
- the only bind failure visibility was an asynchronous task error log.

That was a class-C `SPAWN_THEN_LIVE_HANDLE_BUG`.

## Fix

The shared helper now pre-binds before spawning:

1. `std::net::TcpListener::bind(listen_addr)`;
2. `set_nonblocking(true)`;
3. `tokio::net::TcpListener::from_std(...)`;
4. read the actual listener address;
5. spawn `ClashApiServer::serve_with_listener_and_shutdown(listener, shutdown_rx)`;
6. return a handle only after the listener exists.

This uses the existing sb-api pre-bound listener API and adds no dependency. The std-listener
pre-bind path was chosen because the bootstrap helper is still synchronous and the card allowed
only minimal app callsite changes; widening `app/src/bootstrap.rs` to await this helper is not
needed for startup honesty.

## Caller Policy

The product policy is unchanged: visible but non-fatal log-and-continue.

- Bootstrap Clash API: bind/start failure logs a warning and returns `None`; no live-looking
  `ServiceHandle` is returned.
- Run-engine Clash API: bind/start failure logs an error and returns `None`; the started log is
  emitted only after the helper returns `Ok`.

No hard-fail behavior was introduced.

## ServiceHandle Liveness Boundary

Startup honesty is fixed. Runtime liveness projection remains absent.

The app handles contain shutdown and join ability only:

- bootstrap `ServiceHandle`: `oneshot::Sender<()>` plus `JoinHandle<()>`;
- run_engine `ClashApiHandle`: `oneshot::Sender<()>` plus `JoinHandle<()>`.

They do not expose a watch state, readiness state, or task-completion projection for callers to
poll. If the Clash task exits after successful startup, the task logs the error path, but callers
do not get a health/liveness model. That should be a separate lifecycle card if product behavior
needs it.

## Tests

Added/strengthened under app lib tests:

- `clash_bind_conflict_returns_error_before_handle`: occupies a local ephemeral port, calls the
  shared helper, asserts `Err` with bind/address-in-use semantics and therefore no handle.
- `clash_successful_bind_returns_handle`: starts a real local server on an available port,
  verifies TCP connectivity, shuts it down, and verifies the port is released with bounded retry.
- `clash_restart_after_failed_bind`: fails on an occupied port, releases it, then verifies a
  retry starts successfully.
- `bootstrap_clash_callsite_does_not_return_handle_on_bind_error`: covers the bootstrap helper
  return path and ensures no live-looking `ServiceHandle` is returned.
- `run_engine_clash_callsite_does_not_report_started_on_bind_error`: static control-flow check
  that run_engine uses the shared helper, no longer calls `start_with_shutdown` from the task
  path, returns `None` on helper error, and logs `started` only after that branch.

The logging assertions are intentionally control-flow/static rather than subscriber-capture based
to keep tests stable and dependency-free.

## Modified Files

- `app/src/run_engine_runtime/admin_start.rs`
- `app/src/bootstrap_runtime/api_services.rs`

## Explicit Non-Changes

- `app/src/bootstrap_runtime/api_services.rs::start_v2ray_api_server` and
  `SimpleV2RayApiServer` are untouched.
- sb-core V2Ray gRPC sidecar is untouched.
- ServiceManager and `/services/health` are untouched.
- No Cargo.toml or Cargo.lock changes.
- `agents-only/a0_reality_spike/` remains untouched untracked.

## Deferred Items

- `APP-V2RAY-SIMPLE-01 = POLICY REVIEW`: decide whether the app bootstrap V2Ray simple helper
  should be removed, routed to the sb-core V2Ray gRPC sidecar, or replaced with a real listener.
- `APP-SIDECAR-BIND-01A.1 = OPTIONAL LIFECYCLE REVIEW`: decide whether app sidecar handles need
  runtime liveness projection after successful startup.
- `SVC-V2RAY-API-01B = DEFER / POLICY REVIEW`: unchanged from audit checkpoint.

## Validation Snapshot

- `cargo test -p app --all-features clash`: PASS; 8 app lib tests matched, including all new
  Clash startup-honesty tests.
- `cargo clippy -p app --all-features --all-targets -- -D warnings`: PASS, 0 warning.
- `cargo check --workspace --all-features`: PASS.
- `bash agents-only/06-scripts/verify-consistency.sh`: PASS.
- `bash agents-only/06-scripts/check-boundaries.sh`: PASS.
- `git diff --check`: PASS.
- `cargo fmt --check`: FAIL only on pre-existing trojan formatting drift in
  `crates/sb-adapters/src/outbound/trojan.rs` and
  `crates/sb-adapters/tests/trojan_integration.rs`; APP-SIDECAR-BIND-01 did not touch those
  files.
