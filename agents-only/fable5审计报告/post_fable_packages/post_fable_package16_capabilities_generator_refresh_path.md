<!-- tier: B -->
# post_fable_package16_capabilities_generator_refresh_path

## Status

DONE.

## Objective

Restore the tracked refresh path for the docs-only capability snapshot by
repairing the generator evidence map and making stale evidence anchors fail
before output is written.

This package closes the package11 doc-tool residual. It does not change runtime
behavior, does not assert new capability readiness, and does not mark package03
or package07 DONE.

## Implementation Summary

- `scripts/capabilities/generate.py` now validates generated evidence anchors:
  missing evidence paths and missing needles are hard errors instead of falling
  back to line 1.
- Static evidence anchors were moved to current semantic locations:
  `tls.ech.quic` points to `crates/sb-config/src/validator/v2/outbound.rs`,
  `tls.ech.tcp` provider evidence points to
  `app/src/run_engine_runtime/supervisor.rs`, and acceptance closure evidence
  uses current docs/report anchors.
- `scripts/capabilities/test_generate.py` runs the generator, parses the output,
  rejects the known stale validator anchor, and verifies every evidence path/line
  exists.
- `reports/capabilities.json` and `docs/capabilities.md` are refreshed as
  docs-only snapshots with package16 staleness metadata pointing live status to
  `agents-only/active_context.md`.

## Out Of Scope

- Runtime capability changes.
- GUI readiness, drop-in readiness, or behavior parity claims.
- package03 privileged TUN proof and package07 real Wails desktop-window E2E.
- `.github/workflows/*`, `agents-only/a0_reality_spike/`, and the original fable5
  audit body.

## Verification

See `post_fable_package16_capabilities_generator_refresh_path_evidence.md`.

## Completion Notes

Package16 is complete once the generator validation, refreshed tracked snapshot,
package docs, and verification evidence are committed. Remaining post-FABLE
acceptance work is still external/manual: package03 root TUN dataplane proof and
package07 interactive Wails E2E.
