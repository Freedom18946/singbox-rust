# GUI Integration Test Report (Template)

- Scope: L17.3.1 GUI.for SingBox smoke validation
- Baseline: Go+GUI+TUN remains primary network baseline; Rust kernel runs in parallel mode
- Date: _TBD_
- Tester: _TBD_

## Environment

- GUI path: `/Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0`
- Rust kernel binary: _TBD_
- Config path: _TBD_
- API URL: _TBD_

## Acceptance Checklist

- [ ] GUI startup succeeds without crash
- [ ] Configuration loads successfully
- [ ] Proxy switch updates GUI state and backend selection
- [ ] Subscription import succeeds and nodes refresh
- [ ] Connections panel shows active connections
- [ ] Logs panel streams entries continuously

## Automated Probe Evidence

- Probe artifact: `reports/gui-smoke-artifacts/http_probes.json`
- Kernel log: `reports/gui-smoke-artifacts/kernel.stdout.log`
- Manual notes: `reports/gui-smoke-artifacts/manual_notes.md`

## Run Command

```bash
scripts/gui_smoke_test.sh \
  --gui-root /Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0 \
  --kernel-bin /Users/bob/Desktop/Projects/ING/sing/singbox-rust/target/release/run \
  --config /Users/bob/Desktop/Projects/ING/sing/singbox-rust/configs/example.json \
  --api-url http://127.0.0.1:19090 \
  --report /Users/bob/Desktop/Projects/ING/sing/singbox-rust/reports/gui_integration_test.md \
  --artifacts-dir /Users/bob/Desktop/Projects/ING/sing/singbox-rust/reports/gui-smoke-artifacts
```

## Findings

- _TBD_
