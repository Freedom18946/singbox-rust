<!-- tier: B -->
# post_fable_package15_acceptance_closeout_manual_gates

## Status

DONE as a closeout/runbook package. This package does not mark package03 or
package07 DONE. It records that the automatic post-FABLE path is boxed and that
the remaining acceptance evidence requires external conditions: root/admin TUN
dataplane proof and a real interactive Wails desktop-window run.

## Objective

Provide one reproducible index for the remaining manual gates so future runs do
not confuse "blocked by environment" with product readiness or silently drop the
last acceptance steps.

## Current Post-FABLE State

| State | Packages | Notes |
|---|---|---|
| DONE | 01, 02, 04, 05, 06, 08, 09, 10, 11, 12, 13, 14 | Automatic/code-doc packages closed. |
| PARTIAL boxed | 03 | Normal-user TUN failure is deterministic and pre-start; privileged dataplane proof needs root/admin. |
| PARTIAL blocked | 07 | Process-contract harness passes; real Wails desktop-window interaction is not agent-drivable. |

## Closeout Script

Run:

```bash
WORK=/tmp/pf15_acceptance_closeout \
  bash agents-only/fable5审计报告/post_fable_packages/post_fable_package15_acceptance_closeout_manual_gates.sh
```

The script writes `result.json`, `summary.txt`, command logs, and copied 03b
`result.json` files under `WORK`. It builds the `gui_runtime` binary, runs the
package07 process-contract harness, runs package03b normal-user proof when
non-root, and runs package03b privileged proof. A non-root privileged run is
recorded as `BLOCKED_PRIVILEGE`/exit 3 and does not become a fake PASS.

## Manual Acceptance Commands

GUI runtime/process-contract:

```bash
cargo build -p app --bin app --features gui_runtime
./target/debug/app version
WORK=/tmp/pf15_gui_runtime bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh
```

TUN normal-user boxed proof:

```bash
PF03B_SKIP_BUILD=1 WORK=/tmp/pf15_tun_normal PF03B_MODE=normal \
  bash agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh
```

TUN privileged proof:

```bash
sudo -E PF03B_SKIP_BUILD=1 WORK=/tmp/pf15_tun_privileged PF03B_MODE=privileged \
  bash agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh
```

Real Wails GUI checklist:

- Build/copy Rust `gui_runtime` binary into GUI's expected kernel path.
- Launch GUI.for SingBox 1.25.1 desktop window.
- Start core and confirm GUI reaches running state after `sing-box started`.
- Confirm Clash API telemetry/proxy list loads and node selection is usable.
- Confirm system proxy/non-TUN traffic works through a local or controlled target.
- Toggle stop/start and profile/config restart; verify clean stop and rebind.
- If testing TUN, run with proper OS entitlement/root and capture traffic proof.

## Completion Notes

Package15 is complete when its closeout script, docs, evidence, and package map
updates are committed. It intentionally leaves package03 and package07 PARTIAL
until the required external evidence exists.
