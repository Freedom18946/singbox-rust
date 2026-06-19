<!-- tier: B -->
# P1313-01 Config Schema And GUI Fixtures

Priority: P0

Primary evidence:

- `agents-only/reference/GO_PARITY_MATRIX.md` PX-002
- `go_fork_source/sing-box-1.13.13/option/options.go`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/utils/generator.ts`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/frontend/src/constant/profile.ts`
- `GUI_fork_source/GUI.for.SingBox-1.25.1/UPGRADE_1.19.0_TO_1.25.1.md`

## Goal

Create a current, reproducible schema/config fixture baseline for Go 1.13.13 and GUI 1.25.1
so future packages work against the same config truth.

## Current Gap

PX-002 still records root config divergence around `$schema` / `schema_version`, tag/name
strategy, and strict unknown-field behavior. GUI 1.25.1 changed generated config shape:
`icon`/`hidden` on selector/urltest entries, suppressed `cache_file.store_rdrc`, fixed
default outbound ids, and option-object generation controls.

## Task Split

1. Inventory root schema fields.
   - Compare Go `Options` root fields: `$schema`, `log`, `dns`, `ntp`, `certificate`,
     `endpoints`, `inbounds`, `outbounds`, `route`, `services`, `experimental`.
   - Compare Rust root config and raw/IR layers.
   - Decide whether `$schema` only configs must pass without Rust `schema_version`.

2. Lock duplicate tag semantics.
   - Reconfirm inbound duplicate tag behavior.
   - Reconfirm outbound+endpoint shared namespace duplicate behavior.
   - Add fixtures for explicit tag, missing tag with index fallback, and duplicate collision.

3. Build GUI 1.25.1 generated config fixtures.
   - Default mixed-in profile.
   - Default TUN-disabled profile.
   - TUN-enabled profile with `system`, `gvisor`, and `mixed` stack values.
   - HTTP-only, SOCKS-only, and mixed system-proxy profiles with users/auth.
   - Selector/urltest/default outbounds with `icon` and `hidden` ignored or accepted.
   - Experimental cache_file with GUI-suppressed `store_rdrc`.
   - Default DNS local/remote/fakeip resolver shape.

4. Add strict validation tests.
   - Fixture must parse through the same production check path used by the app.
   - Unknown fields should fail where Go fails and be explicitly accepted where the project
     chooses compatibility.
   - Add negative fixtures for stale GUI 1.19 shapes only if they still appear in user data.

5. Update docs.
   - Record the final schema posture in this package evidence.
   - Point to `active_context.md` for volatile gate state; do not duplicate global counts.

## Acceptance

- `cargo test -p sb-config --test compatibility_matrix`
- New fixture tests under `crates/sb-config/tests/` or an existing GUI fixture suite.
- `cargo check -p app --features gui_runtime`
- `./agents-only/06-scripts/verify-consistency.sh`

## Non-Goals

- No GUI desktop automation.
- No Wails build.
- No runtime dataplane proof.
- No broad schema rewrite beyond fixtures and parser decisions.
