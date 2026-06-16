<!-- tier: B -->
# post_fable_package17_external_acceptance_execution_evidence

Date: 2026-06-16.

Package17 is an execution/record package. It attempted the remaining external
gates and records why package03/package07 must remain PARTIAL on this machine.

## Environment

Artifact root: `/tmp/pf17_external_acceptance/`.

Observed facts:

- Platform: macOS arm64.
- User: UID 501 (`bob`).
- `sudo -n true`: failed with `sudo: a password is required`.
- Wails tooling: `~/go/bin/wails doctor` PASS, Wails v2.11.0.

## Command Results

| Command | Result |
|---|---|
| `cargo build -p app --bin app --features gui_runtime` | PASS |
| `./target/debug/app version` | PASS: `sing-box version 0.1.0 (0d1cbe7b1426)` observed |
| `WORK=/tmp/pf17_gui_contract bash .../post_fable_package07_probe_harness.sh` | PASS: 14/14 |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf17_tun_normal PF03B_MODE=normal bash .../post_fable_package03b_tun_smoke_harness.sh` | PASS |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf17_tun_privileged PF03B_MODE=privileged bash .../post_fable_package03b_tun_smoke_harness.sh` | BLOCKED, exit 3 |
| `~/go/bin/wails doctor` | PASS |
| `~/go/bin/wails build -clean` | FAILED/BLOCKED by `proxy.golang.org` TLS handshake timeout |
| `GOPROXY=https://goproxy.cn,direct ~/go/bin/wails build -clean` | PASS, fresh app produced |

## Package03 TUN Gate

Normal-user proof remained deterministic:

```json
{
  "status": "PASS",
  "message": "normal-user TUN startup failed before 'sing-box started' with a loud permission/backend error",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "permission_failed_before_started",
    "sing_box_started_seen": false,
    "cleanup": "complete",
    "configured_outbound_hit": false,
    "curl_success": false
  },
  "uid": 501
}
```

Privileged proof did not execute as root/admin:

```json
{
  "status": "BLOCKED",
  "exit_code": 3,
  "message": "privileged mode requires root/admin privileges; rerun with sudo -E after building the kernel",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "not_run_missing_privilege",
    "sing_box_started_seen": false,
    "cleanup": "complete",
    "configured_outbound_hit": false,
    "curl_success": false
  },
  "uid": 501
}
```

Decision: package03 remains PARTIAL. Required closure evidence is still a
root/admin 03b harness PASS with `configured_outbound_hit=true`, curl HTTP 200,
`sing-box started`, and cleanup complete.

## Package07 Wails Gate

Process-contract baseline:

- `post_fable_package07_probe_harness.sh` PASS, 14/14.
- The baseline covered startup keyword, SOCKS5, HTTP CONNECT, package13 plain
  HTTP forward GET, Clash API auth/telemetry, SIGINT stop, and same-port rebind.
- This remains supporting evidence only; it is not a real Wails desktop-window
  interactive proof.

Wails build and launch:

- `wails doctor` PASS.
- Default `wails build -clean` was blocked by a Go proxy TLS handshake timeout.
- `GOPROXY=https://goproxy.cn,direct wails build -clean` PASS and produced a
  fresh app bundle.
- The attempt backed up and restored
  `~/Library/Application Support/GUI.for.SingBox`.
- Controlled App Support data seeded one profile named `PF17 Local Direct`,
  mixed inbound `127.0.0.1:20122`, Clash API `127.0.0.1:20123` with secret
  `pf17probe`, local DNS, direct/select/block outbounds, and TUN disabled.

Latest desktop attempt excerpt:

```json
{
  "status": "BLOCKED",
  "message": "Wails desktop attempt did not satisfy full interactive PASS criteria",
  "stages": {
    "fresh_wails_build": "pass_fresh_goproxy_cn",
    "app_support_backup": "pass",
    "seed_test_data": "pass",
    "desktop_launch": "open_invoked",
    "desktop_window": "process_visible_to_system_events",
    "start_click": "attempted",
    "core_started": "not_run",
    "clash_api": "not_run_core_not_run",
    "loopback_proxy_traffic": "not_run_core_not_run",
    "stop_click": "pass_ports_released",
    "cleanup_restore": "restored_app_support"
  }
}
```

The AX UI tree contained the seeded `PF17 Local Direct` profile and
`Click to Start` text, proving the real window/profile was visible to desktop
automation. Start did not produce a GUI-started core pid, generated config,
Clash API response, or local traffic artifact.

Decision: package07 remains PARTIAL/BLOCKED. Required closure evidence is still a
complete GUI-driven Start -> Rust `gui_runtime` core -> Clash API -> local
traffic -> GUI Stop flow.

## Artifacts

Key files:

- `/tmp/pf17_external_acceptance/env_check.txt`
- `/tmp/pf17_external_acceptance/cargo_build_gui_runtime.log`
- `/tmp/pf17_external_acceptance/app_version.log`
- `/tmp/pf17_external_acceptance/package07_process_contract.log`
- `/tmp/pf17_tun_normal/result.json`
- `/tmp/pf17_tun_privileged/result.json`
- `/tmp/pf17_external_acceptance/wails_doctor.log`
- `/tmp/pf17_external_acceptance/wails_build.log`
- `/tmp/pf17_external_acceptance/wails_build_goproxy_cn.log`
- `/tmp/pf17_external_acceptance/wails_open_click3/result.json`
- `/tmp/pf17_external_acceptance/wails_open_click3/ui_tree_before_start_click.txt`
- `/tmp/pf17_external_acceptance/wails_open_click3/start_click.log`

## Residual Gates

- package03: rerun the 03b privileged harness under root/admin entitlement.
- package07: rerun real Wails desktop-window acceptance with human interaction or
  stronger desktop automation that can activate Start and capture core/API/traffic
  proof.

No product code changed in package17.
