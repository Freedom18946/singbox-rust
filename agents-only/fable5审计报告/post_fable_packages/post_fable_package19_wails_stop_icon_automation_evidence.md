<!-- tier: B -->
# post_fable_package19_wails_stop_icon_automation_evidence

Date: 2026-06-17.

Artifact root:

```bash
/tmp/pf19_wails_stop_icon_automation
```

## Latest Result

`/tmp/pf19_wails_stop_icon_automation/result.json`:

```json
{
  "status": "BLOCKED_ACCESSIBILITY",
  "message": "Wails window bounds exist, but AX tree/Computer Use could not expose the seeded profile or Start control",
  "drive_method": "native",
  "gui_pid": "80435",
  "core_pid": null,
  "stop_event_sent": false,
  "stop_backend": null,
  "stop_core_exited_pre_cleanup": false,
  "stop_ports_released_pre_cleanup": false,
  "cleanup_killed_core": false,
  "cleanup_killed_gui": true,
  "package07_closure_eligible": false
}
```

Important nuance: `cleanup_killed_core=false` is not a Stop success. No core was
started in this package19 run because the script could not prove the seeded
profile/start controls were visible or accessible. package07 therefore remains
PARTIAL.

## Stage Summary

Observed `result.json.stages` highlights:

| Stage | Result |
|---|---|
| AX precheck | `pass` |
| Preexisting GUI process check | `none` |
| cargo build | `pass` |
| Wails build | `pass` |
| App Support backup | `pass` |
| Controlled seed | `pass` |
| Local loopback origin | `pass` |
| Wails launch | `open_invoked` |
| Desktop window | `swift_bounds_confirmed` |
| Profile/start visible | `blocked_accessibility_after_window_geometry` |
| Cleanup restore | App Support restored |
| Ports after cleanup | `20122`/`20123` closed |

## Window Geometry Evidence

`window_bounds.json`:

```json
{
  "height": 706,
  "pid": 80435,
  "source": "cgwindow",
  "width": 980,
  "x": 230,
  "y": 75
}
```

`launch_window_geometry.log`:

```text
1170 163 window_relative_source_informed_fallback
```

This proves the package19 Swift helper could find the real Wails process window
through CoreGraphics. The helper chooses the largest visible layer-0 window for
the target PID, avoiding the 500x500 auxiliary same-process Wails window seen
during development.

## Accessibility Blocker

System Events AX tree extraction failed even though the global precheck returned
true:

```text
System Events got an error: Can't get window 1 of process 1 whose unix id = 80435. Invalid index. (-1719)
```

The final run wrote `assist_profile_needed.txt` requesting Computer Use
confirmation for `PF19 Local Direct` and `Click to Start`. During the same run,
the assistant attempted Computer Use against the exact app bundle path and the
tool returned `cgWindowNotFound`. No external visibility sentinel was written.

Because the script could not prove the seeded profile/start controls, it did not
attempt Start or Stop and did not claim package07 closure eligibility.

## Key Evidence Files

- `result.json` - final machine-readable status.
- `seed_user.yaml`, `seed_profiles.yaml` - controlled GUI data seed.
- `cargo_build_gui_runtime.log`, `wails_build_goproxy_cn.log` - build evidence.
- `window_bounds.json` - Wails PID window bounds from Swift/CGWindow.
- `stop_coordinates.json` - source-informed fallback coordinate metadata.
- `ui_tree_launch.txt.err`, `ui_tree_before_start_click.txt.err` - AX failures.
- `screenshot_launch.png`, `screenshot_launch_analysis.json` - screenshot
  artifacts from the run.
- `assist_profile_needed.txt` - external/Computer Use checkpoint request.

## Verification

| Command | Result |
|---|---|
| `cargo build -p app --bin app --features gui_runtime` | PASS |
| `GOPROXY=https://goproxy.cn,direct ~/go/bin/wails build -clean` | PASS |
| `WORK=/tmp/pf19_wails_stop_icon_automation bash ...package19...sh` | `BLOCKED_ACCESSIBILITY` |
| `WORK=/tmp/pf19_process_contract bash ...package07_probe_harness.sh` | PASS, 14/14 |
| `WORK=/tmp/pf19_closeout bash ...package15_acceptance_closeout_manual_gates.sh` | `PASS_WITH_MANUAL_BLOCKERS` |
| `cargo test -p app --test gui_runtime_profile --features gui_runtime` | PASS, 3/3 |
| `cargo test -p app --test inbound_http --features gui_runtime` | PASS, 6/6 |
| `cargo check --workspace --all-features` | PASS |
| `cargo clippy --workspace --all-features --all-targets` | PASS |
| `git diff --check` | PASS |

## Status Decision

package19 is DONE as a reproducible script/docs/evidence package because it adds
the stronger Stop automation stack and preserves a narrow machine-readable
blocker.

package07 remains PARTIAL. The combined package18/package19 evidence does not
yet contain a full real Wails GUI Stop PASS: package18 reached Start/core/API/
traffic and then `BLOCKED_STOP`; package19 added Stop targeting but the latest
run is blocked before Start by current-machine desktop accessibility/window
exposure.
