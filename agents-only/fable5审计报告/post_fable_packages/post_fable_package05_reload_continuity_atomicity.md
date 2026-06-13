<!-- tier: B -->
# post_fable_package05_reload_continuity_atomicity

## Status

DONE (`a9236205`).

## Source Findings

- CAL-04: failed reload shuts down old inbounds before new activation succeeds.
- CAL-05: inbound bind/serve failure is not part of startup or reload success.
- CAL-07: runtime registry installs before swap and is not restored on rollback.
- CAL-12: graceful shutdown drain can abort active connections through nested runtime drop.
- CAL-14: same-port reload relies on fixed grace sleep without a release barrier.

## Objective

Make reload atomic from the user's perspective: failed reload must preserve the old
serving inbounds, bind failure must fail the reload, and committed runtime registry
state must match the active bridge.

## Implementation Contract

- First run the package 07 probes for GUI reload behavior and Go reload semantics, or
  explicitly record why implementation proceeds without them.
- Reorder reload so fallible new-context work happens before old inbounds are torn
  down wherever possible.
- Connect inbound bind readiness into reload success/failure. A new inbound that fails
  to bind must prevent swap and report reload failed.
- Move runtime inbound/outbound registry installation to the committed swap point, or
  restore the old registry during rollback.
- Keep router and no-router reload paths behaviorally synchronized.
- Leave diff-based incremental reload as a later enhancement unless required to
  preserve same-port handoff.

## Out Of Scope

- Broad inbound liveness monitoring beyond readiness; package 06 owns ongoing
  monitoring.
- TUN dataplane implementation.
- V2Ray reuse redesign; preserve the already closed 01C behavior.

## Acceptance Criteria

- A validation-passing but activation-failing reload leaves old listeners accepting.
- A new inbound bind failure reports reload failed and does not swap to a dead
  listener.
- After rollback, detour lookups use the old active bridge registry.
- Existing rollback guard tests continue passing.
- Same-port reload behavior is no longer only a fixed-sleep best effort, or the exact
  remaining limitation is documented with a test.

## Tests / Verification

- Add real-listener tests for failed-reload continuity.
- Add a bind-failure test for startup and reload paths as applicable.
- Add a registry rollback test covering detour/runtime outbound lookup.
- Run `cargo test -p sb-core --lib --features service_v2ray_api rollback`.
- Run relevant supervisor tests for router and no-router feature combinations.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.

## Docs To Update

- `agents-only/active_context.md` on completion.
- A focused reload-continuity evidence note under `agents-only/`.
- This package file, under Completion Notes.

## Dependencies

- Should consume package 07 H-2 and H-9 probes before implementation.
- Package 06 may share readiness/monitoring infrastructure; coordinate if both are
  active.

## Completion Notes

Closed 2026-06-13 by `a9236205` as a conservative reliability fix.

- `Supervisor::reload` and `SupervisorHandle::reload` now wait for the event-loop
  activation result via `ReloadMsg::Apply { result }`; `/reload`, SIGHUP/watch
  reload, and direct callers receive activation failures instead of optimistic
  success.
- Reload order is now build/activate/readiness/commit first, then old-resource
  teardown. Old inbounds are no longer pre-shutdown before activation.
- HTTP, SOCKS, and MIXED expose bind readiness and report occupied-port failures
  through the ready channel. Other inbound types remain best-effort and are logged
  as the readiness coverage boundary.
- Runtime inbound/outbound registries are published only after startup success or
  reload commit. `build_bridge` uses local handles and no longer installs global
  runtime handles during speculative construction.
- Same-port in-process reload is intentionally rejected before touching old
  listeners. The error names the overlapping endpoint and says in-process
  same-port handoff is unsupported; GUI process restart remains supported.
- CAL status: CAL-04 CLOSED, CAL-05 CLOSED for supported ready inbounds, CAL-07
  CLOSED, CAL-12 not expanded beyond preserving existing shutdown behavior, CAL-14
  CLOSED as safe rejection rather than fd handoff.

Evidence: `post_fable_package05_reload_continuity_evidence.md`.
