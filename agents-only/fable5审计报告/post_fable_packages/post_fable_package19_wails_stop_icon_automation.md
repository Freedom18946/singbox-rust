<!-- tier: B -->
# post_fable_package19_wails_stop_icon_automation

## Status

DONE as a script/docs/evidence package (2026-06-17).

Latest run status: `BLOCKED_ACCESSIBILITY`. package19 added source-informed
Stop icon automation, but the current desktop session could not expose the
Wails window to AX/Computer Use far enough to prove the seeded profile and
Start control. Swift/CGWindow did confirm the real Wails window geometry, so
the blocker is narrower than a missing app launch. package07 remains PARTIAL.

Evidence: `post_fable_package19_wails_stop_icon_automation_evidence.md`.

## Objective

Close or sharply narrow the package07 residual blocker after package18:
package18 proved the real Wails Start -> GUI-owned Rust core -> Clash API ->
loopback traffic chain, but did not verify GUI Stop. package19 owns the
running-view Stop icon path and may only create package07 DONE evidence if a
real GUI click stops the GUI-owned core before cleanup.

This package is script/docs/evidence-only. It does not change Rust product code,
GUI product code, workflow automation, or original fable5 audit body files.

## Implementation

Script:

```bash
agents-only/fable5审计报告/post_fable_packages/post_fable_package19_wails_stop_icon_automation.sh
```

Default work directory:

```bash
/tmp/pf19_wails_stop_icon_automation
```

Controlled seed:

- profile `PF19 Local Direct`;
- secret `pf19probe`;
- mixed inbound `127.0.0.1:20122`;
- Clash API `127.0.0.1:20123`;
- local origin `127.0.0.1:18080`;
- TUN disabled and `autoSetSystemProxy: false`.

The script preserves package18's build, App Support backup/restore, Wails
launch, Start/core/API/traffic checks, and exact app bundle target:

```bash
GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app
```

## Stop Automation

package19 adds a Stop-specific automation layer informed by:

- `frontend/src/views/HomeView/components/OverView.vue`: the running-view
  toolbar order is `log`, `restart`, `stop`, with Stop declared as
  `icon="stop"` and `@click="handleStopKernel"`;
- `frontend/src/stores/kernelApi.ts`: `stopCore()` calls
  `KillProcess(corePid)` and waits for core-stop state.

The script writes:

- `window_bounds.json`;
- `stop_toolbar_candidates.json`;
- `stop_coordinates.json`;
- full screenshots plus Stop toolbar crops when the Stop phase is reached;
- backend logs for AXPress, Computer Use assist, Swift/CGEvent, optional
  `cliclick`, and System Events.

Native geometry uses AX first, then a `/tmp` Swift helper with
`CGWindowListCopyWindowInfo`. The Swift fallback chooses the largest visible
layer-0 window for the target PID to avoid Wails same-process auxiliary windows.
If AX toolbar candidates are unavailable, coordinates fall back to the
source-informed right-side toolbar position.

## Status Semantics

`PASS` requires all of:

- a Stop click event sent to the real Wails window;
- GUI-owned Rust core pid exits before cleanup;
- ports `20122` and `20123` are released before cleanup;
- `cleanup_killed_core=false`;
- `package07_closure_eligible=true`.

Cleanup can restore App Support and kill leftovers, but cleanup can never turn
Stop into PASS.

Latest run did not reach Stop because AX/Computer Use could not expose the
seeded profile/start controls. The script therefore recorded
`BLOCKED_ACCESSIBILITY`, `stop_event_sent=false`, and
`package07_closure_eligible=false`.

## Manual Rerun

```bash
cargo build -p app --bin app --features gui_runtime
GOPROXY=https://goproxy.cn,direct ~/go/bin/wails build -clean
WORK=/tmp/pf19_wails_stop_icon_automation \
  bash agents-only/fable5审计报告/post_fable_packages/post_fable_package19_wails_stop_icon_automation.sh
```

Baseline regressions:

```bash
WORK=/tmp/pf19_process_contract bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh
WORK=/tmp/pf19_closeout bash agents-only/fable5审计报告/post_fable_packages/post_fable_package15_acceptance_closeout_manual_gates.sh
cargo test -p app --test gui_runtime_profile --features gui_runtime
cargo test -p app --test inbound_http --features gui_runtime
cargo check --workspace --all-features
cargo clippy --workspace --all-features --all-targets
git diff --check
```

## Package07 Impact

package07 remains PARTIAL. package18 still carries the real Wails
Start/core/API/traffic proof. package19 added the stronger Stop automation
stack, but the latest package19 run is blocked before Stop by current-machine
desktop accessibility/window exposure: CGWindow can see the Wails window, while
AX and Computer Use cannot expose the window contents.

The remaining blocker is `BLOCKED_ACCESSIBILITY`, not a product-code Stop PASS
or a cleanup-assisted stop.
