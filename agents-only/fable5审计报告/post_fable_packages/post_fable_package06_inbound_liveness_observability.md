<!-- tier: B -->
# post_fable_package06_inbound_liveness_observability

## Status

DONE for package06 scope (`bbc00416`). CAL-12 remains a documented residual
outside this observability package.

## Source Findings

- CAL-06: inbound serve tasks have no liveness monitor, watchdog, or restart signal.
- CAL-13: Clash API down has no machine-readable GUI signal.
- CAL-15: rapid V2Ray disable/enable can silently lose the API server.
- CAL-16: DNS resolver construction failures are silently ignored.

## Objective

Make primary dataplane and auxiliary-service failures visible enough that GUI and
operators can distinguish "running" from "degraded".

## Implementation Contract

- Keep or wrap inbound serve handles so unexpected return or panic is logged and
  classified.
- Reuse sidecar terminal-state classification patterns where they fit, but keep
  inbound semantics separate from auxiliary sidecar policy.
- Add visible warnings or status for DNS resolver build failures instead of silent
  fallback.
- Add a machine-readable or structured status breadcrumb for Clash API unavailable,
  within the accepted log-only sidecar policy.
- For V2Ray rapid re-enable, either add a release/ready barrier or document the
  remaining race with a focused regression/probe.

## Out Of Scope

- Reload atomicity and bind readiness for swap; package 05 owns that.
- Changing sidecar policy from auxiliary/log-only to fatal.
- Full metrics surface redesign.

## Acceptance Criteria

- Inbound accept-loop panic or unexpected exit produces an error-level signal.
- DNS resolver-from-IR failure is visible.
- Clash API bind failure or crash has a machine-readable or clearly structured status
  path documented for GUI use.
- V2Ray rapid same-port disable/enable behavior is either fixed or captured by a
  reliable probe with explicit follow-up.

## Tests / Verification

- Add a test or failpoint for inbound serve abnormal termination if practical.
- Add DNS resolver failure log/status test.
- Add sidecar API-down classification/status test.
- Run relevant app and `sb-core` tests.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.

## Docs To Update

- `agents-only/active_context.md` on completion.
- Observability evidence note under `agents-only/`.
- This package file, under Completion Notes.

## Dependencies

- Coordinate with package 05 if readiness channels or supervisor task ownership are
  changed.

## Completion Notes

- CAL-06 DONE: supervisor now owns `InboundRuntimeMonitor` handles in committed
  `State`; startup, reload rollback, old-runtime teardown, and final shutdown
  use bounded monitor drain. Abnormal exits classify as `unexpected_completion`,
  `serve_error`, `panicked`, or `join_cancelled` and log stable inbound fields
  (`component`, `tag`, `kind`, `phase`, `exit_kind`, `error`). Deliberate
  `request_shutdown()` exits are clean and low-noise. No automatic restart was
  added.
- CAL-13 DONE: Clash API stays auxiliary/log-only, but a configured bind/create
  failure now publishes a terminal `StartFailed` sidecar snapshot. The run-engine
  sidecar event bridge emits structured breadcrumbs with `component="sidecar"`,
  `sidecar="clash-api"`, `status`, `exit_kind`, `listen`, and `error`.
- CAL-15 DONE: `V2RayApiServer::start()` retries same-port `AddrInUse` release
  for up to 1s before consuming a generation or publishing `Running`; exhausted
  retry still returns the existing start error and remains log-only to callers.
- CAL-16 DONE: DNS resolver setup flows through `apply_dns_resolver_from_ir`;
  resolver build failure remains non-fatal but logs `component="dns"`, `phase`,
  and `error` in startup and reload paths.
- CAL-12 residual PARTIAL/NO-REGRESSION: package05 atomic reload behavior is
  preserved and failed reload keeps the old listener plus old inbound monitor.
  This package does not add automatic inbound restart or redesign global graceful
  drain semantics.

Evidence: `post_fable_package06_liveness_observability_evidence.md`.
