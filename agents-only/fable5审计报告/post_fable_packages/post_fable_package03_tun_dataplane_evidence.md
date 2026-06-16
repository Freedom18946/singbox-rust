<!-- tier: B -->
# post_fable_package03 TUN dataplane evidence

Date: 2026-06-13
Code commit: `edf42095` (`fix(sb-adapters): wire GUI TUN stack to runtime backend`)
Status: PARTIAL

## Conclusion

Package03 fixed the runtime wiring and startup honesty gap for GUI TUN configs:
GUI-default-ish `stack: "mixed"` now resolves to the Enhanced/smoltcp backend,
TUN runtime preparation happens before the supervisor can report started, and
TUN open/configure failure blocks startup instead of being hidden behind
`sing-box started`.

Local dataplane traffic is not proven on this macOS normal-user environment.
The live smoke reached the real TUN runtime attempt and failed before startup
with `Operation not permitted (os error 1)`, which is an acceptable platform
permission blocker for this package but keeps the package short of DONE.

## Stack policy

| GUI/runtime stack | Runtime policy | Operator signal |
|---|---|---|
| missing / empty / `default` | Enhanced/smoltcp | normal runtime |
| `mixed` | Enhanced/smoltcp | normal runtime; GUI default path |
| `smoltcp` | Enhanced/smoltcp | normal runtime |
| `gvisor` | Enhanced/smoltcp compat path | loud warning: no gVisor netstack is wired |
| `system` | Unsupported | loud error: no real system-stack backend is wired |
| `manual` + `dry_run: true` | diagnostic no-op | loud warning: no dataplane |
| `manual` without explicit dry run | Unsupported | loud error |
| unknown | InvalidInput | loud error listing supported values and restrictions |

## Runtime field mapping

| GUI / Go field | Runtime target | Notes |
|---|---|---|
| `address` | Enhanced TUN IPv4/IPv6 device addresses | split by IP family; each entry may include CIDR; host IP is used for current platform config |
| `inet4_address` / `inet6_address` | fallback device addresses | used only when `address` lacks that IP family |
| `route_address` | effective include routes | takes precedence over legacy `include_routes` |
| `route_exclude_address` | effective exclude routes | takes precedence over legacy `exclude_routes` |
| `auto_route` | platform hook route config | hook configure failure is fatal during TUN startup preparation |
| `auto_redirect` | platform hook redirect config | fatal if requested but unsupported |
| `strict_route` | platform hook strict-route config | fatal if requested but unsupported |
| `dry_run` | diagnostic gate | default is now `false`; only explicit `true` permits manual/no-op |

## Startup honesty

- `TunInbound::try_new` prepares the selected backend at build time.
- Enhanced/smoltcp calls platform device creation plus route/redirect hooks before
  the supervisor can publish runtime readiness.
- `Bridge.startup_errors` records fatal TUN build failures.
- `Supervisor::start_with_registry` rejects non-empty startup errors before
  `sing-box started`.
- Reload paths also call the same bridge startup check, but package03 does not
  claim package05 reload continuity or bind readiness closure.

## Live smoke

Command:

```bash
./target/debug/app run --disable-color -c /tmp/pf03-tun-smoke-utun9/config.json -D /tmp/pf03-tun-smoke-utun9
```

Config shape:

- inbound `type: "tun"`, `stack: "mixed"`, `interface_name: "utun9"`
- `address`: `172.19.0.1/30`, `fdfe:dcba:9876::1/126`
- `auto_route: true`, `strict_route: true`
- `route_address: ["10.0.0.0/8"]`
- `route_exclude_address: ["192.168.0.0/16"]`
- outbound `direct`, route final `direct`

Observed result:

```text
status=exited:1
started_seen=0
ERROR sb_adapters::register: failed to prepare TUN runtime backend inbound=tun-in error=Operation not permitted (os error 1)
Error: Supervisor::start_with_registry failed

Caused by:
    runtime startup blocked by adapter errors: tun inbound 'tun-in' failed to prepare runtime backend
```

Interpretation: the GUI default `mixed` value entered the real Enhanced/smoltcp
startup path. macOS denied the TUN open/configure operation for this normal-user
run. The process exited before `sing-box started`, so the GUI cannot mistake this
for a ready dataplane.

## Verification snapshot

| Command | Result |
|---|---|
| `cargo test -p sb-adapters --lib tun --features "adapter-tun tun router"` | PASS: 71 passed, 1 ignored |
| `cargo test -p sb-adapters --lib enhanced --features "adapter-tun tun router"` | PASS: 30 passed |
| `cargo test -p sb-config --lib pf02` | PASS: 8 passed |
| `cargo build -p app --bin app --features adapters,clash_api` | PASS |
| `cargo check --workspace --all-features` | PASS |
| `git diff --check` | PASS |
| `WORK=/tmp/pf07-after-tun bash agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh` | PASS: 14 pass, 0 fail |

## Remaining limits

- DONE requires a privileged/local-platform smoke that proves real TUN traffic,
  not only a real TUN startup attempt plus loud permission failure.
- `system` remains intentionally unsupported until a true system-stack backend is
  implemented.
- `gvisor` is compatibility-mapped to Enhanced/smoltcp; no gVisor netstack exists
  in this repository.
- package03 does not close WireGuard dataplane, reload continuity, generic bind
  readiness, or F-3 HTTP plain forwarding.

---

## 03b privileged dataplane acceptance harness

Date: 2026-06-14
Status: STILL PARTIAL, but boxed behind a reproducible privileged harness.

### Environment

- Platform: Darwin arm64 (`Darwin 25.5.0`, local user `bob`, UID 501).
- HEAD at start: `83387086`.
- `sudo -n true`: failed with `sudo: a password is required`.
- Local route state note: this machine already had `198.18.0.0/15` routed via
  `utun4` before the normal-user run. The harness captures before/after route
  and interface state so a privileged run can distinguish pre-existing network
  state from routes it adds.

### Harness

Path:

```bash
agents-only/fable5审计报告/post_fable_packages/post_fable_package03b_tun_smoke_harness.sh
```

Modes:

- `PF03B_MODE=normal`: validates config and expects a loud TUN permission/backend
  failure before `sing-box started`.
- `PF03B_MODE=privileged`: requires root/admin privileges and proves real traffic
  by curling a routed target without proxy flags.
- `PF03B_MODE=auto`: chooses normal for non-root, privileged for root.

The harness writes `result.json`, `config.json`, app/check/proxy logs, curl
artifacts, and before/after route/interface snapshots under `WORK`.

### Config

The generated config keeps the GUI-default-ish TUN shape:

- inbound `type: "tun"`, `tag: "pf03b-tun-in"`, `stack: "mixed"`,
  `interface_name: "utun9"`;
- `address: ["172.19.0.1/30"]`;
- `route_address: ["198.18.0.0/16"]`;
- `route_exclude_address: ["127.0.0.0/8", "::1/128"]`;
- `auto_route: true`, `strict_route: true`;
- route rule `ip_cidr: "198.18.0.0/16" -> pf03b-http-out`;
- `final: "block"` so success cannot come from the fallback outbound;
- outbound `pf03b-http-out` is an HTTP CONNECT proxy pointing to a local Python
  proof stub on `127.0.0.1:<dynamic-port>`.

Privileged success requires plain:

```bash
curl --noproxy '*' http://198.18.0.2:18080/pf03b
```

to return HTTP 200 and the local stub to log
`CONNECT 198.18.0.2:18080`.

### Commands and results

| Command | Result |
|---|---|
| `cargo test -p sb-adapters --lib tun --features "adapter-tun tun router"` | PASS: 71 passed, 1 ignored |
| `cargo test -p sb-adapters --lib enhanced --features "adapter-tun tun router"` | PASS: 30 passed |
| `cargo test -p sb-config --lib pf02` | PASS: 8 passed |
| `cargo build -p app --bin app --features adapters,clash_api` | PASS |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf03b-tun-smoke-normal PF03B_MODE=normal bash .../post_fable_package03b_tun_smoke_harness.sh` | PASS |
| `PF03B_SKIP_BUILD=1 WORK=/tmp/pf03b-tun-smoke-privileged PF03B_MODE=privileged bash .../post_fable_package03b_tun_smoke_harness.sh` | BLOCKED, exit 3: root/admin privileges required |
| `cargo check --workspace --all-features` | PASS |
| `cargo clippy --workspace --all-features --all-targets` | PASS |

Normal-user `result.json` summary:

```json
{
  "status": "PASS",
  "message": "normal-user TUN startup failed before 'sing-box started' with a loud permission/backend error",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "permission_failed_before_started",
    "sing_box_started_seen": false,
    "cleanup": "complete"
  }
}
```

Privileged `result.json` summary:

```json
{
  "status": "BLOCKED",
  "exit_code": 3,
  "message": "privileged mode requires root/admin privileges; rerun with sudo -E after building the kernel",
  "stages": {
    "config_validation": "pass",
    "tun_startup": "not_run_missing_privilege",
    "configured_outbound_hit": false,
    "cleanup": "complete"
  }
}
```

### Log excerpts

Normal-user app log:

```text
ERROR sb_adapters::register: failed to prepare TUN runtime backend inbound=pf03b-tun-in error=Operation not permitted (os error 1)
runtime startup blocked by adapter errors: tun inbound 'pf03b-tun-in' failed to prepare runtime backend
```

Config validation log:

```text
Config validation passed
```

### Conclusion

03b does not close package03 as DONE on this machine because the privileged
dataplane proof did not run. The closure state is now better boxed:

- normal-user GUI-style TUN startup behavior is deterministic and loud;
- privileged real-traffic proof has a one-command harness and exact acceptance
  criteria;
- the local blocker is specific: no root/admin privilege is available through
  noninteractive sudo in this agent session.

---

## package15 closeout pointer

Package15 adds
`post_fable_package15_acceptance_closeout_manual_gates.sh` as the post-FABLE
manual-gate index. It reruns/captures the 03b normal-user and privileged gates
under a shared `WORK` directory, preserving package03 as PARTIAL unless the
privileged dataplane proof actually passes.
