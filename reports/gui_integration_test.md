# GUI Integration Test Report

- Scope: L17.3.1 GUI.for SingBox smoke validation
- Date: 2026-02-14
- Result: `ENV_LIMITED`
- Reason: `gui_smoke_manual_step` (this round did not enable GUI auto smoke)
- Related status: `reports/stability/l17_capstone_status.json`

## Environment

- GUI path: `/Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0`
- Rust kernel binary: `/Users/bob/Desktop/Projects/ING/sing/singbox-rust/target/release/run`
- Config path: `/Users/bob/Desktop/Projects/ING/sing/singbox-rust/configs/example.json`
- API URL: `http://127.0.0.1:19090`

## Evidence

- Capstone status: `PASS_ENV_LIMITED`
- Gate snapshot: `gui_smoke=ENV_LIMITED`, `docker=ENV_LIMITED`, `canary=ENV_LIMITED`

## Re-run Commands

```bash
# Optional: include GUI smoke in capstone run
L17_GUI_SMOKE_AUTO=1 scripts/l17_capstone.sh --profile fast --api-url http://127.0.0.1:19090
```

```bash
# Direct GUI smoke script
scripts/gui_smoke_test.sh \
  --gui-root /Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0 \
  --kernel-bin /Users/bob/Desktop/Projects/ING/sing/singbox-rust/target/release/run \
  --config /Users/bob/Desktop/Projects/ING/sing/singbox-rust/configs/example.json \
  --api-url http://127.0.0.1:19090 \
  --report /Users/bob/Desktop/Projects/ING/sing/singbox-rust/reports/gui_integration_test.md \
  --artifacts-dir /Users/bob/Desktop/Projects/ING/sing/singbox-rust/reports/gui-smoke-artifacts
```
