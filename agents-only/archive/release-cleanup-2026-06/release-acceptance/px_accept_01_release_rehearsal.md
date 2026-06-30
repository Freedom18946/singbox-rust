# PX-ACCEPT-01 Local Drop-in Release Rehearsal

Date: 2026-06-29
HEAD at rehearsal: `39d1c4a0c4104d2f0c2b8a264e8b8aeda94f4fbb`
Branch: `main`
Profile: `gui_runtime`
Binary: `target/debug/app`
Source fixture: `crates/sb-config/tests/golden/gui1251/composite_route_dns_profile.json`
Probe script: `agents-only/archive/release-cleanup-2026-06/release-acceptance/px_accept_01_release_rehearsal_probe.sh`
Probe workdir: `/tmp/px_accept_01_release_rehearsal`
Probe summary: `/tmp/px_accept_01_release_rehearsal/summary.json`

## Result

PX-ACCEPT-01 is **PASS-LOCAL / release rehearsal pass** for the local drop-in path.

The probe summary is:

- `profile`: `gui_runtime`
- `kernel`: `/Users/bob/Desktop/Projects/ING/sing/singbox-rust/target/debug/app`
- `pass`: 31
- `fail`: 0
- `warn`: 1
- `ok`: true

The single warning is non-blocking: `/connections` returned a valid snapshot shape, but the
best-effort slow local request was not observed as active in that snapshot.

Conclusion: **未发现阻止下一步打包/人工 GUI 验收的本地 blocker**.

## Probe Coverage

The rehearsal used the real `target/debug/app` binary built with `--features gui_runtime`.
The script rendered the GUI 1.25.1 composite fixture into `/tmp`, changing only runtime-local
fields: random loopback ports, Clash external controller/secret, core admin token, CacheFile path,
local DNS hosts, local origin URL, and non-public rule-set content.

Covered local chain:

- Startup and `sing-box started` log.
- Mixed inbound, Clash API, and core admin listen checks.
- Clash API auth: missing Bearer on `/configs` returns `401`; Bearer access returns GUI-readable fields.
- HTTP/mixed proxy with fixture proxy user reaches a local origin with `200`.
- DNS CLI query and `--explain` resolve `px-accept.local` through local predefined DNS.
- Clash `/dns/query?name=localhost&type=A` returns a valid endpoint response.
- Selector/cache: `/proxies` exposes `GLOBAL`/`Select`/`Direct`; selector PUT persists across restart.
- Clash mode cache: GUI/strict contract `PATCH /configs {"mode":"direct"}` persists across restart.
- Core admin reload switches mixed port, closes old mixed port, opens the new one, and proxying still works.
- Reload state: Clash `/configs` reflects the reloaded mixed port; core admin `/explain` reflects the reloaded route; `/connections` returns a valid snapshot.

Note: `PUT /configs` remains the existing Go-compatible no-op path. Mode switching uses `PATCH /configs`,
matching the P1313/GUI contract and the dual-kernel golden spec.

## Focused Revalidation

These P1313 strict-revalidation subset commands passed on the final code:

```bash
cargo test -p sb-config --test gui1251_config gui1251_fixtures_pass_production_load_path_without_schema_version
cargo test -p sb-config --test gui1251_config gui1251_composite_route_dns_profile_covers_low_priority_shape
cargo test -p app --test gui_runtime_profile --features gui_runtime
cargo test -p sb-api --test clash_http_e2e test_get_configs_gui_1251_shape_from_config_ir
cargo test -p sb-api --test clash_http_e2e test_clash_get_configs_reads_cache_file_mode
cargo test -p sb-api --test clash_http_e2e test_select_proxy
cargo test -p sb-api --test clash_http_e2e test_get_connections
cargo test -p sb-api --test clash_websocket_e2e test_connections_ws_single_client_snapshot
cargo test -p sb-api --test connections_snapshot_test
cargo test -p sb-api --test clash_http_e2e test_patch_configs_flushes_cache_file_mode
cargo build -p app --bin app --features gui_runtime
WORK=/tmp/px_accept_01_release_rehearsal bash agents-only/archive/release-cleanup-2026-06/release-acceptance/px_accept_01_release_rehearsal_probe.sh
```

## Local Fixes Made During Rehearsal

The first rehearsal attempt exposed local blockers, which are fixed in this line:

- DNS CLI no longer starts a nested Tokio runtime from the async app main; `dns query` now reuses the current runtime.
- Clash `/configs` now reads live supervisor state when available, so reload-updated ports are visible without restarting the Clash API sidecar.
- `PATCH /configs` mode persistence now flushes CacheFile writes, making rapid restart rehearsal deterministic.
- The probe avoids false negatives by using the existing `PATCH /configs` mode-switch contract and ordering the reload block rule before action-only DNS/sniff rules.

## PX Accounting

The following PX items can be treated as **release rehearsal pass, not new parity movement**:

- PX-001
- PX-002
- PX-003
- PX-004
- PX-005
- PX-006
- PX-007 / PX-008 / PX-009
- PX-010
- PX-013

This does not change dual-kernel BHV counts or parity denominator state.

## Non-claims

This rehearsal does **not** claim:

- Wails desktop packaging or click automation.
- Root/privileged TUN dataplane proof.
- Linux `systemd-resolved` runtime proof.
- REALITY official FoxIO JA4, extension-order distribution, `HelloChrome_Auto` drift, or tier-2 camouflage closure.
- Any dual-kernel BHV number movement.
- Any public-network fresh-cohort gate.

