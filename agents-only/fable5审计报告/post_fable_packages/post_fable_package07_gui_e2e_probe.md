<!-- tier: B -->
# post_fable_package07_gui_e2e_probe

## Status

PLANNED.

## Source Findings

- H-1: the Rust kernel likely has not been launched by the real GUI.
- H-2: GUI config switching may be reload or process restart.
- H-3: GUI version-gating behavior for `0.1.0` is unknown.
- H-9: Go reload semantics need a precise design reference.

## Objective

Create a verification package that grounds the next architecture decisions in real
GUI and Go behavior before high-risk runtime work proceeds.

## Implementation Contract

- Build or document a reproducible local harness for GUI.for SingBox launching the
  Rust binary.
- Record GUI startup recognition, version parsing, stop semantics, node selection,
  and system-proxy or non-TUN traffic path.
- Trace whether GUI config changes call reload APIs or restart the kernel process.
- Read and summarize Go sing-box reload behavior relevant to build-before-teardown,
  same-port handoff, and diff granularity.
- This package is validation/probe work; do not fix product code while running it.

## Out Of Scope

- Implementing GUI contract fixes; package 01 owns them.
- Implementing reload fixes; package 05 owns them.
- TUN dataplane fixes; package 03 owns them.

## Acceptance Criteria

- A step-by-step GUI E2E note exists under `agents-only/` with pass/fail/blocked
  status for startup, version, stop, node selection, and one non-TUN traffic path.
- GUI reload versus restart behavior is documented with source or runtime evidence.
- Go reload behavior is summarized with source references and implications for
  package 05.
- Any newly discovered GUI contract break is registered as a new post_fable follow-up
  or added to the relevant existing package.

## Tests / Verification

- Run the local GUI harness or equivalent script after packages 01 and 02.
- Capture command output/log excerpts sufficient to prove each step.
- Run `git diff --check` for generated notes.

## Docs To Update

- New GUI E2E/probe note under `agents-only/`.
- This package file, under Completion Notes.
- `agents-only/active_context.md` if probes change priority or next-step ordering.

## Dependencies

- Depends on packages 01 and 02 for the most useful first GUI run.
- Feeds packages 03, 05, and 01 version policy.

## Completion Notes

Not started.
