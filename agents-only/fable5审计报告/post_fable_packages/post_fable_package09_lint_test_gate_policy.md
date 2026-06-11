<!-- tier: B -->
# post_fable_package09_lint_test_gate_policy

## Status

PLANNED.

## Source Findings

- CAL-08: workspace deny lint policy applies to only a small part of the workspace.
- CAL-19: selector/proxy-pool tests are ignored after API drift.
- CAL-27: specific feature `cargo test` builds produce warnings.
- CAL-29: known flakes have environment, timing, or filesystem roots.

## Objective

Make local quality gates honest and intentional without triggering a noisy, all-at-once
lint migration.

## Implementation Contract

- Produce a per-crate lint impact inventory before enabling additional
  `lints.workspace = true`.
- Do not enable deny lints across all crates in one step unless the inventory shows
  it is tractable and the user approves the policy.
- Fix or explicitly de-scope stale selector/proxy-pool tests.
- Remove the known feature-specific warnings.
- Harden flakes where low-risk, or document exact isolation commands where hardening
  is not worth the blast radius.

## Out Of Scope

- Re-enabling GitHub Actions.
- Rewriting broad protocol tests unrelated to the identified stale or flaky areas.
- Large-scale unwrap/expect refactors without a policy decision.

## Acceptance Criteria

- Lint policy decision is recorded with per-crate counts.
- Selector/proxy-pool ignored tests are either active again or explicitly de-scoped.
- The feature-specific warning pair is gone or documented as intentionally accepted.
- Flake handling is clearer than the current tribal-memory state.

## Tests / Verification

- Run lint inventory commands and store summarized output under `agents-only/`.
- Run affected selector/proxy-pool tests.
- Run `cargo test -p sb-core --lib` for the warning check.
- Run targeted flake tests in isolation.
- Run `cargo clippy --workspace --all-features --all-targets`.
- Run `git diff --check`.

## Docs To Update

- Lint/test gate decision note under `agents-only/`.
- `agents-only/active_context.md` on completion if gates change.
- This package file, under Completion Notes.

## Dependencies

- User policy approval is required before broad lint enforcement.

## Completion Notes

Not started.
