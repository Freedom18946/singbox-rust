<!-- tier: B -->
# post_fable_package03_tun_dataplane

## Status

PLANNED.

## Source Findings

- CAL-10: TUN defaults to skeleton/no-op behavior and GUI stack names are not usable.
- H-5: smoltcp/Enhanced TUN quality is not proven with real traffic.

## Objective

Turn GUI TUN mode from config-accepted into a real, validated dataplane path or make
remaining platform/runtime limits explicit and test-backed.

## Implementation Contract

- Decide and implement how GUI stack values `system`, `gvisor`, and `mixed` map to
  Rust TUN backends.
- Prefer a real backend for GUI defaults; if a value cannot be supported, fail loudly
  with a clear compatibility note rather than silently no-op.
- Validate Enhanced/smoltcp behavior with real traffic on the available platform.
- Preserve existing accepted limitations for redirect/tproxy/tun2socks unless this
  package explicitly changes them.

## Out Of Scope

- Schema acceptance for TUN fields; package 02 owns that.
- GUI launch contract; package 01 owns that.
- Full cross-platform TUN certification beyond the available local platform.

## Acceptance Criteria

- GUI TUN stack values no longer hit the current `InvalidInput` or Manual no-op path
  silently.
- A macOS local TUN smoke test is documented: start, route a simple request, verify
  traffic uses the configured outbound or record a precise platform blocker.
- Unsupported stacks or platforms emit explicit errors or warnings that are visible
  to the operator.

## Tests / Verification

- Add unit tests for stack-name parsing/mapping.
- Add or document a live TUN smoke script under `agents-only` or test fixtures.
- Run TUN-related Rust tests.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.

## Docs To Update

- TUN dataplane evidence note under `agents-only/`.
- `agents-only/active_context.md` on completion or de-scope.
- This package file, under Completion Notes.

## Dependencies

- Depends on package 02.
- Benefits from package 07 once GUI launch is available.

## Completion Notes

Not started.
