<!-- tier: B -->
# post_fable_package14_gui_runtime_build_profile

## Status

DONE (2026-06-14). package07/F-2 is closed by the explicit `app` feature
profile `gui_runtime`. package07 remains PARTIAL because the interactive Wails
desktop-window E2E is still not agent-drivable.

## Source Findings

- F-2: the default `cargo build -p app` binary is intentionally minimal and did
  not include runtime adapters or the Clash API required by the GUI
  process-contract harness.
- Prior package07 notes used scattered `--features adapters,clash_api` build
  guidance, which made the GUI drop-in runtime contract easy to miss.

## Objective

Define and test one stable GUI runtime/drop-in build contract without widening
the default app feature set.

## Implementation Contract

- Keep `default = ["router"]` as the quiet/minimal app build.
- Add `gui_runtime = ["router", "adapters", "clash_api"]`.
- Keep `v2ray_api` opt-in. The package07 harness and GUI process-contract path
  require Clash API telemetry, not V2Ray API; configs that need V2Ray API build
  with `--features gui_runtime,v2ray_api`.
- Update package07 harness/docs to use `--features gui_runtime`.
- Add a build-profile guard test so future manifest edits cannot silently
  remove the GUI runtime requirements or expand the default build into a
  misleading drop-in profile.

## Out Of Scope

- Turning package07 into DONE; interactive Wails E2E remains blocked.
- Changing product runtime behavior.
- Changing all app default features or broad parity feature composition.
- Adding workflow automation or CI.

## Acceptance Criteria

- `cargo build -p app --bin app --features gui_runtime` produces a runnable
  binary.
- The package07 process-contract harness passes with the `gui_runtime` binary.
- The default app feature set remains router-only and is documented as not a GUI
  drop-in proxy runtime.
- Profile guard tests pass with and without `--features gui_runtime`.
- Required app/adapters/workspace gates pass.

## Tests / Verification

See `post_fable_package14_gui_runtime_build_profile_evidence.md`.

## Completion Notes

Completed 2026-06-14 by adding `gui_runtime`, profile guard tests, package07
harness guidance, and package docs/evidence. No package07 interactive GUI claim
is made; only F-2 is closed.
