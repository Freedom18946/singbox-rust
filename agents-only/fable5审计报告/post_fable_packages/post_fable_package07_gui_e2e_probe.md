<!-- tier: B -->
# post_fable_package07_gui_e2e_probe

## Status

PARTIAL, PAUSED_INDEFINITE (2026-06-19). Process-contract equivalence probe PASS (14/14).
package18 built/launched the real Wails app and reached GUI-owned Rust
core/API/loopback-traffic proof with `start_click=native_sent`, but ended
`BLOCKED_STOP`. package19 added stronger Stop-icon automation and narrowed the
latest blocker to `BLOCKED_ACCESSIBILITY`: CGWindow sees the Wails window, while
AX/Computer Use cannot expose the seeded profile/start controls on this machine.
Follow-ups F-1/F-2/F-3 are closed by packages 12/14/13; package07 remains
PARTIAL until a real GUI Stop click stops the GUI-owned core and releases ports
before cleanup. Full evidence:
`post_fable_package07_gui_e2e_probe_note.md` + harness
`post_fable_package07_probe_harness.sh` (same directory).

Strategic pause: as of 2026-06-19, real Wails/GUI joint testing and package20
style automation follow-ups are paused indefinitely. The current priority is to
preserve the user's installed GUI.for.SingBox app state: do not seed App
Support, do not launch the repository-built Wails app, and do not install the
Rust `target/debug/app` as the user's GUI kernel unless the user explicitly
resumes this line. Cleanup/details: `post_fable_gui_joint_test_pause.md`.

## Source Findings

- H-1: the Rust kernel likely has not been launched by the real GUI.
- H-2: GUI config switching may be reload or process restart.
- H-3: GUI version-gating behavior for `0.1.0` is unknown.
- H-9: Go reload semantics need a precise design reference.

## Objective

Create a verification package that grounds the next architecture decisions in real
GUI and Go behavior before high-risk runtime work proceeds.

## Implementation Contract

- Build or document a reproducible local harness for GUI.for SingBox launching the
  Rust binary.
- Record GUI startup recognition, version parsing, stop semantics, node selection,
  and system-proxy or non-TUN traffic path.
- Trace whether GUI config changes call reload APIs or restart the kernel process.
- Read and summarize Go sing-box reload behavior relevant to build-before-teardown,
  same-port handoff, and diff granularity.
- This package is validation/probe work; do not fix product code while running it.

## Out Of Scope

- Implementing GUI contract fixes; package 01 owns them.
- Implementing reload fixes; package 05 owns them.
- TUN dataplane fixes; package 03 owns them.

## Acceptance Criteria

- A step-by-step GUI E2E note exists under `agents-only/` with pass/fail/blocked
  status for startup, version, stop, node selection, and one non-TUN traffic path.
- GUI reload versus restart behavior is documented with source or runtime evidence.
- Go reload behavior is summarized with source references and implications for
  package 05.
- Any newly discovered GUI contract break is registered as a new post_fable follow-up
  or added to the relevant existing package.

## Tests / Verification

- Run the local GUI harness or equivalent script after packages 01 and 02.
- Capture command output/log excerpts sufficient to prove each step.
- Run `git diff --check` for generated notes.

## Docs To Update

- New GUI E2E/probe note under `agents-only/`.
- This package file, under Completion Notes.
- `agents-only/active_context.md` if probes change priority or next-step ordering.

## Dependencies

- Depends on packages 01 and 02 for the most useful first GUI run.
- Feeds packages 03, 05, and 01 version policy.

## Completion Notes

Completed 2026-06-13 (probe/docs-only; no product code touched). Detail + raw evidence:
`post_fable_package07_gui_e2e_probe_note.md`; reproducible harness
`post_fable_package07_probe_harness.sh`.

### Method (why PARTIAL)

An automated agent cannot click a Wails desktop window (Start/Stop/toggle), and `pnpm dev`
alone lacks the Wails-injected bridge — so interactive GUI E2E is BLOCKED (not
agent-drivable). The GUI **build env is ready** (`wails doctor` SUCCESS). Substituted a
**process-contract equivalence probe**: the Rust kernel placed/launched exactly as the GUI
does (`run --disable-color -c <abs>/config.json -D <abs>`, kernel at
`data/sing-box/sing-box`), exercising every kernel-facing contract. Harness: 14/14 PASS.

### Answers (runtime evidence unless marked static)

- **Startup recognition**: PASS — kernel prints `sing-box started`; GUI resolves its start
  promise (`kernelApi.ts:257`). Emitted after inbound bind (strong readiness, matches Go).
- **Version/gating**: `sing-box version 0.1.0 (<sha>)`, regex-parseable; no GUI version
  gating (static, CAL-17/H-3 closed). `0.1.0` does not block.
- **Stop**: PASS — SIGINT (GUI KillProcess Unix path) → graceful exit ~0.27s, drained,
  `shutdown ok:true`, port released; well under Go's 10s FatalStopTimeout.
- **Config switch = restart, not reload**: static (GUI `restartCore` = stop→start; only
  `mode` is a Clash-API hot switch; no SIGHUP/reload) + runtime (restart cycle: port
  released then same-port rebind, no EADDRINUSE, pid changed).
- **Non-TUN traffic**: PASS over SOCKS5 (200), HTTP CONNECT (200), and package13
  plain-HTTP forward GET (200). Local origin used (sandbox egress); full
  inbound→route→direct path exercised. F-3 is closed by package13; interactive
  Wails E2E remains blocked.
- **Clash API (node selection/telemetry)**: PASS — `/configs` + `/proxies` return real
  json with Bearer; 401 without token. (feature-gated; not required for startup.)
- **TUN toggle**: not run (needs OS TUN + root; package03 dataplane scope).
- **Go reload/start reference**: documented for package05 — `started`=strong-readiness
  barrier; all Go reload = full Close→New→Start instance replacement (no in-process/
  same-port handoff); GUI uses process restart so package05 is NOT a GUI prerequisite.

### New follow-ups raised

- **F-1 (P0)**: CLOSED by package12. GUI default DNS config (type-based servers with
  `domain_resolver`/`server_port`/`path`/`interface`) now passes the strict production
  load path; this corrected the prior "run is lenient" assumption.
- **F-2 (build profile)**: CLOSED by package14. Default `cargo build -p app` remains a
  router-only/minimal build and is not a GUI drop-in proxy runtime; GUI process-contract
  harnesses build with `--features gui_runtime`.
- **F-3 (parity gap)**: CLOSED by package13. HTTP inbound now supports
  absolute-form plain HTTP GET forwarding while preserving CONNECT. This does
  not change package07's interactive Wails E2E BLOCKED status.

### Verification

`git diff --check` clean; `cargo build -p app --bin app --features gui_runtime` OK;
`./target/debug/app version` OK; harness 14/14 PASS (`WORK=/tmp/pf07run bash <harness>`).

Package15 closeout: `post_fable_package15_acceptance_closeout_manual_gates.sh`
indexes this process-contract harness and records the remaining real Wails
desktop-window E2E as a manual gate. package07 remains PARTIAL until that
interactive run is actually performed and documented.

Package17 external acceptance execution:

- `WORK=/tmp/pf17_gui_contract bash post_fable_package07_probe_harness.sh`
  reran the process-contract baseline and passed 14/14.
- `wails doctor` PASS; a fresh Wails build succeeded with
  `GOPROXY=https://goproxy.cn,direct` after the default Go proxy timed out.
- The built app was launched with controlled App Support data, the real Wails
  desktop process was visible to System Events, and the seeded `PF17 Local
  Direct` profile plus `Click to Start` text were present in the AX UI tree.
- Agent UI automation attempted Start, but no GUI-started Rust core, pid file,
  generated config, Clash API, local proxy traffic, or GUI-driven Stop proof was
  obtained.
- package07 remains PARTIAL/BLOCKED; package17 is an execution record, not a
  successful interactive GUI E2E closure.

Package18 Wails desktop click automation:

- Added `post_fable_package18_wails_desktop_click_automation.sh` plus docs and
  evidence.
- Latest artifact root: `/tmp/pf18_wails_click_automation/`.
- The real Wails app launched from the built app bundle with controlled App
  Support data and a seeded `PF18 Local Direct` profile.
- The run produced GUI-owned Rust `pid.txt`, `config.json`, a GUI app-bundle
  `core_command.txt`, successful Bearer `pf18probe` `/configs` and `/proxies`,
  and loopback HTTP `200` through the mixed proxy.
- Status remains PARTIAL because result was `BLOCKED_STOP`: Stop did not
  complete through GUI automation.

Package19 Wails Stop icon automation:

- Added `post_fable_package19_wails_stop_icon_automation.sh` plus docs and
  evidence.
- Latest artifact root: `/tmp/pf19_wails_stop_icon_automation/`.
- The script preserves package18's Start/core/API/traffic gates and adds
  source-informed Stop targeting from the running-view toolbar order
  `log`, `restart`, `stop`.
- Latest result is `BLOCKED_ACCESSIBILITY`: Swift/CGWindow confirmed the real
  Wails window bounds, but AX and Computer Use could not expose the seeded
  profile/start controls; the script did not reach Start or Stop.
- package07 remains PARTIAL. No cleanup kill, SIGINT harness path, direct
  `KillProcess` call, or human/manual click is counted as GUI Stop PASS.
