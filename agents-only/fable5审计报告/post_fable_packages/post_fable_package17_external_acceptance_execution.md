<!-- tier: B -->
# post_fable_package17_external_acceptance_execution

## Status

DONE as an external acceptance execution/record package (2026-06-16).

This package does not close package03 or package07. It records real attempts at
the two remaining external gates and preserves their PARTIAL/BLOCKED status
because the required PASS evidence was not obtained.

## Objective

Execute the remaining post-FABLE external acceptance gates:

- package03 privileged TUN dataplane proof;
- package07 real Wails desktop-window interactive E2E.

Only real evidence may change package03/package07 status. Rust-only tests,
process-contract harnesses, Wails build success, or a visible window alone are
not sufficient.

## Execution Summary

Artifact root: `/tmp/pf17_external_acceptance/`.

| Gate | Result | Status impact |
|---|---|---|
| GUI runtime build | PASS | supporting evidence only |
| package07 process-contract harness | PASS, 14/14 | package07 still PARTIAL |
| package03 normal-user TUN proof | PASS loud failure before `sing-box started` | supporting evidence only |
| package03 privileged TUN proof | BLOCKED, exit 3: UID 501/no noninteractive sudo | package03 remains PARTIAL |
| Wails doctor/build | doctor PASS; fresh build PASS via `GOPROXY=https://goproxy.cn,direct` | supporting evidence only |
| Real Wails desktop-window attempt | BLOCKED: window/profile visible, Start attempted, no core/API/traffic proof | package07 remains PARTIAL |

## Status Decisions

- package03 remains PARTIAL. The 03b privileged harness did not run as root/admin
  and did not produce `configured_outbound_hit=true`, curl HTTP 200, or
  `sing-box started`.
- package07 remains PARTIAL. The real Wails app built and exposed a desktop
  window, but the GUI-driven Start -> core -> Clash API -> local traffic -> Stop
  sequence was not completed.
- package17 is DONE because it executed and recorded the external gates without
  manufacturing closure.

## Manual Rerun Commands

Build the GUI runtime kernel:

```bash
cargo build -p app --bin app --features gui_runtime
./target/debug/app version
```

Rerun the package07 process-contract baseline:

```bash
WORK=/tmp/pf17_gui_contract bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh
```

Rerun package03 normal-user proof:

```bash
PF03B_SKIP_BUILD=1 WORK=/tmp/pf17_tun_normal PF03B_MODE=normal \
  bash agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh
```

Rerun package03 privileged proof:

```bash
sudo -E PF03B_SKIP_BUILD=1 WORK=/tmp/pf17_tun_privileged PF03B_MODE=privileged \
  bash agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh
```

Manual Wails acceptance checklist:

- Build/copy the Rust `gui_runtime` binary into the GUI kernel path.
- Launch GUI.for SingBox 1.25.1 as a desktop app.
- Select/start a controlled profile through the GUI UI.
- Confirm the GUI-started Rust core writes pid/config artifacts and prints
  `sing-box started`.
- Confirm Clash API telemetry/proxy data loads.
- Confirm local loopback traffic succeeds through the GUI-started proxy.
- Stop through the GUI UI and confirm pid/ports are cleaned up.
- If TUN is enabled, run with required OS entitlement/root and capture dataplane
  proof separately.

## Completion Notes

Evidence: `post_fable_package17_external_acceptance_execution_evidence.md`.

No product code changed. No workflow files, `agents-only/a0_reality_spike/`, or
original fable5 audit body files were touched.
