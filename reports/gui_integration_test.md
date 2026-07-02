# GUI Integration Test Report

> Historical GUI smoke snapshot. The paths and GUI version below describe the
> original run context, not the current GUI reference or a current rerun recipe.

- Scope: L17.3.1 GUI.for SingBox smoke validation
- Date: 2026-02-14 (historical GUI smoke snapshot)
- Result: `SKIP` (aligned with current capstone status model; historical run reason unchanged)
- Reason: `gui_smoke_manual_step` (this round did not enable GUI auto smoke)
- Related status: `reports/stability/l17_capstone_status.json`

## Environment

- GUI path: `$GUI_ROOT` (historical run used GUI.for SingBox 1.19.0)
- Rust kernel binary: `$REPO/target/release/run`
- Config path: `$REPO/configs/example.json`
- API URL: `http://127.0.0.1:19090`

## Evidence

- Capstone status: latest `PASS_STRICT` (2026-02-24 fast run), historical `PASS_ENV_LIMITED` (2026-02-14)
- Gate snapshot: latest `gui_smoke=SKIP`, `docker=SKIP`, `canary=SKIP`; historical `gui_smoke/docker/canary=ENV_LIMITED`

## Re-run Commands

```bash
# Optional: include GUI smoke in capstone run
L17_GUI_SMOKE_AUTO=1 scripts/l17_capstone.sh --profile fast --api-url http://127.0.0.1:19090
```

```bash
# Direct GUI smoke script
scripts/gui_smoke_test.sh \
  --gui-root "${GUI_ROOT}" \
  --kernel-bin "${REPO:-$PWD}/target/release/run" \
  --config "${REPO:-$PWD}/configs/example.json" \
  --api-url http://127.0.0.1:19090 \
  --report "${REPO:-$PWD}/reports/gui_integration_test.md" \
  --artifacts-dir "${REPO:-$PWD}/reports/gui-smoke-artifacts"
```
