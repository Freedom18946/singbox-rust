<!-- tier: B -->
# post_fable_package07_gui_e2e_probe

## Status

PARTIAL (2026-06-13). Process-contract equivalence probe PASS (14/14); interactive Wails
desktop-window E2E = BLOCKED (not agent-drivable). Headline blocker F-1 found. Full
evidence: `post_fable_package07_gui_e2e_probe_note.md` + harness
`post_fable_package07_probe_harness.sh` (same directory).

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
- **Non-TUN traffic**: PASS over SOCKS5 (200) + HTTP CONNECT (200); plain-HTTP forward GET
  → 405 (F-3, CONNECT-only). Local origin used (sandbox egress); full inbound→route→direct
  path exercised.
- **Clash API (node selection/telemetry)**: PASS — `/configs` + `/proxies` return real
  json with Bearer; 401 without token. (feature-gated; not required for startup.)
- **TUN toggle**: not run (needs OS TUN + root; package03 dataplane scope).
- **Go reload/start reference**: documented for package05 — `started`=strong-readiness
  barrier; all Go reload = full Close→New→Start instance replacement (no in-process/
  same-port handoff); GUI uses process restart so package05 is NOT a GUI prerequisite.

### New follow-ups raised

- **F-1 (P0, NEW BLOCKER)**: GUI default DNS config (type-based servers with
  `domain_resolver`/`server_port`/`path`/`interface`) rejected by Rust strict validator on
  the production load path (`run` and `--check`) → kernel exits → GUI never starts. Isolated
  to DNS server fields (rest of full GUI-shape config passes). DNS sibling of package02;
  needs a dedicated schema-parity package. Corrects the prior "run is lenient" assumption.
- **F-2 (build profile)**: default `cargo build -p app` has no runtime adapters and cannot
  run a proxy; GUI drop-in requires `--features adapters` (or `parity`). For package11 doc.
- **F-3 (parity gap)**: HTTP inbound is CONNECT-only (`http.rs:448` → 405 for non-CONNECT);
  Go supports plain-HTTP forward. Lower priority.

### Verification

`git diff --check` clean; `cargo build -p app --bin app --features adapters,clash_api` OK;
`./target/debug/app version` OK; harness 14/14 PASS (`WORK=/tmp/pf07run bash <harness>`).
