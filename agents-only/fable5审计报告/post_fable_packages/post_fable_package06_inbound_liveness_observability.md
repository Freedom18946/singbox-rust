<!-- tier: B -->
# post_fable_package06_inbound_liveness_observability

## Status

PLANNED.

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

Not started.
