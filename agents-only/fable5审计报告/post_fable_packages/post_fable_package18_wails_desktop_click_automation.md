<!-- tier: B -->
# post_fable_package18_wails_desktop_click_automation

## Status

DONE as a script/docs/evidence package (2026-06-17).

Latest run status: `BLOCKED_STOP`. The real Wails app was built/launched with a
controlled profile, the GUI-owned Rust core produced pid/config artifacts, Clash
API responded, and loopback proxy traffic passed. The full package07 gate is
still not DONE because the GUI Stop control was not successfully clicked by
script/MCP before cleanup.

Evidence: `post_fable_package18_wails_desktop_click_automation_evidence.md`.

## Objective

Build a reproducible Wails desktop-click automation package that operates the
real GUI.for SingBox 1.19.0 app instead of substituting a process-contract
harness.

The package is evidence-first and docs/script-only. It does not change Rust
product code, GUI product code, workflow automation, or original fable5 audit
body files.

## Implementation

Script:

```bash
agents-only/fable5审计报告/post_fable_packages/post_fable_package18_wails_desktop_click_automation.sh
```

Default work directory:

```bash
/tmp/pf18_wails_click_automation
```

The script phases are:

- preflight and AX permission check;
- `cargo build -p app --bin app --features gui_runtime`;
- `GOPROXY=https://goproxy.cn,direct ~/go/bin/wails build -clean`;
- backup/restore of `~/Library/Application Support/GUI.for.SingBox`;
- controlled App Support seed with one `PF18 Local Direct` profile;
- real Wails app launch from
  `GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app`;
- desktop driving through native AX/coordinate attempts, with real-desktop
  `computer-use`/external assist checkpoints;
- pid/config/API/proxy-traffic verification;
- GUI Stop attempt and cleanup/restore trap.

The controlled profile keeps TUN and system proxy mutation disabled:

- `autoSetSystemProxy: false`;
- `autoStartKernel: false`;
- mixed inbound `127.0.0.1:20122`;
- Clash API `127.0.0.1:20123`, secret `pf18probe`;
- local origin `127.0.0.1:18080`;
- direct/select/block outbounds with non-conflicting generated tags.

## Status Semantics

`PASS` is reserved for the complete real desktop flow:

GUI Start -> GUI-owned Rust core -> `sing-box started`/pid/config proof ->
Clash API -> loopback proxy traffic -> GUI Stop -> pid/ports cleaned.

Non-PASS statuses are intentionally not hidden. The latest status is
`BLOCKED_STOP`, with Start/core/API/traffic evidence present but Stop not
completed through a verified GUI click.

## Package07 Impact

package07 remains PARTIAL. package18 materially improves package07 evidence by
proving a real Wails-launched Rust `gui_runtime` core can generate config, serve
Clash API, and proxy loopback traffic, but it does not satisfy the full
interactive closure rule because:

- the Stop control was not successfully clicked by native automation or
  `computer-use` before cleanup.

## Manual Rerun

```bash
cargo build -p app --bin app --features gui_runtime
GOPROXY=https://goproxy.cn,direct ~/go/bin/wails build -clean
WORK=/tmp/pf18_wails_click_automation \
  bash agents-only/fable5审计报告/post_fable_packages/post_fable_package18_wails_desktop_click_automation.sh
```

Baseline regressions remain:

```bash
WORK=/tmp/pf18_process_contract bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh
WORK=/tmp/pf18_closeout bash agents-only/fable5审计报告/post_fable_packages/post_fable_package15_acceptance_closeout_manual_gates.sh
cargo test -p app --test gui_runtime_profile --features gui_runtime
cargo test -p app --test inbound_http --features gui_runtime
cargo check --workspace --all-features
cargo clippy --workspace --all-features --all-targets
git diff --check
```

## Completion Notes

No product-code changes were made. The remaining real desktop blocker is
automating the running-view Stop icon reliably enough that the script can observe
pid exit and port release without cleanup doing the stopping.
