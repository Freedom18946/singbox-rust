<!-- tier: B -->
# post_fable_package01_gui_contract

## Status

DONE (2026-06-11, code commit `0a4cae74`). GUI launch-recognition contract advanced;
this is NOT a GUI-ready claim (TUN schema = package02, bind readiness = package05,
GUI E2E = package07).

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

Completed 2026-06-11, code commit `0a4cae74` (`fix(app): emit sing-box startup signal`).

### Startup output changes (`app/src/run_engine_runtime/output.rs`)

- Added `STARTUP_KEYWORD = "sing-box started"` plus pure helpers `startup_log_line()` /
  `startup_text_line()` (testable; no runtime-architecture change).
- `LogOnly` (the GUI path: `run --disable-color -c … -D …` → `cli/run.rs`
  `print_startup: true`): now logs `sing-box started; press Ctrl+C to quit` (tracing INFO).
- `TextStdout` (`bin/run.rs --format text`): now prints
  `sing-box started pid=<pid> fingerprint=<ver>` (old fields kept, keyword prefix added;
  no in-repo consumer of the old `started pid=` prefix).
- `JsonStdout`: untouched — stdout stays pure JSON, no text mixed in.
- Readiness semantics: the startup line means supervisor start complete (admin services
  started; emit point `run_engine_runtime/supervisor.rs`). It is NOT inbound
  bind-confirmed readiness — bind-ready belongs to package05.

### Version probe conclusion (CAL-17 / H-3)

- GUI has NO kernel-version feature gating. `useCoreBranch.ts:147-160` parses
  `/version (\S+)/` from `Exec(CoreFilePath, ['version'])`; the parsed value feeds only
  the update hint (`localVersion !== remoteVersion`, :64-66) and UI display.
  `1.10/1.11/1.12` literals in the GUI frontend occur only in SVG path data (Icon
  components) — no version-branch logic exists.
- Rust `version` subcommand already prints `sing-box version 0.1.0 (<git_sha>)`
  (`app/src/cli/version.rs:40-48`) — regex-parseable.
- Decision: keep `0.1.0`, version output unchanged. `0.1.0` does not block the package01
  objective; no follow-up version package needed. H-3's gating question is closed at the
  source-evidence level; runtime E2E confirmation belongs to package07.

### Probe evidence useful for package07

- GUI captures stdout+stderr merged: `bridge/exec.go:80` (`cmd.Stderr = cmd.Stdout`),
  line-scanned with `strings.Contains` — the tracing-to-stderr startup line is captured.
- GUI launch args `run --disable-color -c … -D …` (`constant/kernel.ts:296-308`) are
  already accepted by `app/src/cli/mod.rs:139,142` (GlobalArgs `-D/--directory`,
  `--disable-color`).
- GUI re-attach after restart requires the kernel process name to start with `sing-box`
  (`stores/kernelApi.ts:235` + pid.txt) — binary naming matters for package07 E2E.

### Tests / verification run

- `git diff --check` → clean.
- `cargo test -p app --lib output` → 7 passed, 0 failed (new:
  `startup_lines_contain_gui_launch_keyword`,
  `emit_startup_output_logonly_uses_keyword_line`; existing `wp30ao_pin_…` kept).
- `cargo check --workspace --all-features` → PASS.
- Live smoke: `./target/debug/app run --disable-color -c examples/quick-start/01-minimal.json`
  emitted `INFO …: sing-box started; press Ctrl+C to quit` within 3s (grep captured).
- package07 GUI launch-probe harness does not exist yet → not run (per Tests section,
  conditional).
