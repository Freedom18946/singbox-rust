<!-- tier: B -->
# post_fable_package05_reload_continuity_atomicity

## Status

PLANNED.

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

Not started.
