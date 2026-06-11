<!-- tier: B -->
# post_fable_package01_gui_contract

## Status

PLANNED.

## Source Findings

- CAL-02: Rust does not emit the GUI-required `sing-box started` startup string.
- CAL-17: reported kernel version `0.1.0` may trigger GUI version gates.
- H-3: GUI version comparison behavior is still unknown.

## Objective

Make the Rust kernel recognizable as a successfully started sing-box process for
GUI.for SingBox, without claiming stronger readiness than the runtime can prove.

## Implementation Contract

- Add a Go-compatible startup signal containing `sing-box started` at the current
  supervisor-started output point.
- Probe GUI version parsing before changing version reporting semantics.
- If version policy is changed, document whether the Rust binary reports an
  implementation version, a compatibility version, or both.
- Do not change reload behavior in this package.
- Do not claim bind-confirmed readiness unless package 05 has already connected
  inbound bind readiness into startup success.

## Out Of Scope

- TUN schema or data-plane fixes.
- Reload continuity or bind readiness implementation.
- Full GUI E2E validation beyond the minimal launch-signal probe.

## Acceptance Criteria

- `app run` output includes `sing-box started` in the mode used by GUI launch.
- A focused test asserts the startup output contract.
- GUI version parsing has a recorded decision: keep `0.1.0`, report a compatibility
  version, or expose both with clear precedence.
- Documentation states the exact readiness semantics of the startup line.

## Tests / Verification

- Add or adapt an output-level test for the startup line.
- Run the package-specific test.
- Run `cargo check --workspace --all-features`.
- Run `git diff --check`.
- If package 07 harness exists, run the GUI launch probe and record the result.

## Docs To Update

- `agents-only/active_context.md` if the package is completed.
- This package file, under Completion Notes.
- Any GUI contract note created by package 07.

## Dependencies

- None for the startup string.
- Version policy should consume package 07 H-3 findings if available.

## Completion Notes

Not started.
