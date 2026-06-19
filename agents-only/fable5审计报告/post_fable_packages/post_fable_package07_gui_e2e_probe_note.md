<!-- tier: B -->
# post_fable_package07 — GUI E2E Probe (note)

## Status

**PARTIAL.**
- **Process-contract equivalence probe: PASS** (14/14, reproducible) — the Rust kernel
  satisfies every process-level contract GUI.for SingBox 1.19.0 imposes on the kernel,
  exercised with GUI's exact launch arg vector + config layout.
- **Interactive Wails desktop-window E2E: PARTIAL/BLOCKED.** package17 could only
  observe the real Wails window/profile. package18 improved this with desktop
  automation plus external assist and reached GUI-owned core/API/loopback-traffic
  proof with `start_click=native_sent`, but the run ended `BLOCKED_STOP`.
  `pnpm dev` alone still lacks the Wails-injected bridge.
- The probe originally found follow-ups F-1/F-2/F-3; they are now closed by
  packages 12/14/13. package07 remains PARTIAL only because the real interactive
  Wails desktop-window Start/Stop flow is not fully proven.

This is probe/docs-only — no product code, no GUI source changed.

## Environment

- macOS 26.5.1 (darwin/arm64, Apple M1), 2026-06-13, repo at commit `1a110996`.
- Rust kernel built `cargo build -p app --bin app --features gui_runtime`.
- Toolchain: wails v2.11.0 (`~/go/bin/wails`, not on PATH), go 1.26.4, node v26.3.0,
  pnpm 10.30.2. `wails doctor` → SUCCESS (Xcode CLT / Node / npm Installed).
- Harness: `post_fable_package07_probe_harness.sh` (same directory). Reproduce:
  `cargo build -p app --bin app --features gui_runtime && \
   WORK=/tmp/pf07run bash <harness>`.

## GUI Launch Harness

Static contract (from GUI source):
- `constant/kernel.ts:296-308` `DefaultCoreConfig` args:
  `run --disable-color -c $APP_BASE_PATH/$CORE_BASE_PATH/config.json -D $APP_BASE_PATH/$CORE_BASE_PATH`.
- Kernel path `data/sing-box/sing-box`; BasePath = `dir(os.Executable())`
  (`bridge/bridge.go:44-51`); macOS `data` is a symlink to
  `~/Library/Application Support/<AppName>/` (`bridge/bridge.go:134-140`).
- `bridge/exec.go:80` merges stderr into stdout; scans lines for the keyword.

Runtime harness reproduces this: lays out `<work>/data/sing-box/sing-box` (symlink to the
built kernel) + `config.json`, launches with the **exact** arg vector above.

## Startup Recognition

- Static: `stores/kernelApi.ts:257` resolves the start promise only when an output line
  contains `sing-box started` (`constant/kernel.ts:17` `CoreStopOutputKeyword`); no timeout.
- **Runtime: PASS.** Kernel stdout line `sing-box started; press Ctrl+C to quit` observed
  (from package01). GUI would resolve `runCoreProcess` and enter running state. The full
  bind log precedes it (`Mixed (HTTP+SOCKS5) inbound bound addr=127.0.0.1:20122`), so the
  Rust `started` line — like Go's — is emitted after inbound bind (strong readiness).

## Version Probe

- `./target/debug/app version` → `sing-box version 0.1.0 (63f8c22241bb)`.
- GUI parses `/version (\S+)/` (`hooks/useCoreBranch.ts:147-160`) → captures `0.1.0`.
  Used only for the update hint + display; **no version gating** anywhere in the GUI
  frontend (confirmed package01, CAL-17/H-3 closed). `0.1.0` does not block.

## Stop Semantics

- Static: GUI `KillProcess` sends **SIGINT** on Unix (`bridge/exec_others.go:16-18`),
  waits up to 10s, then SIGKILL (`bridge/exec.go:187-215`). pid.txt written/removed by GUI.
- **Runtime: PASS.** `kill -INT <pid>` → graceful shutdown in **~0.27s**
  (log: `Received SIGINT` → `beginning graceful shutdown deadline_ms=9999` →
  `all inbound connections drained` → `shutdown summary {"ok":true}`), well under the 10s
  FatalStopTimeout. Listen port released immediately after exit.

## Config Switch / Restart Semantics

- Static: **every** GUI config change = rewrite config.json + full process restart
  (`restartCore` = stop → cleanup → start, `kernelApi.ts:350-360`); triggered by port
  change, allow-lan, TUN toggle, tun-stack/device, profile switch. **Only exception: mode
  switch** goes through Clash API PATCH `/configs` (no restart). **No sing-box reload /
  SIGHUP anywhere.** system-proxy toggle does not restart the kernel.
- **Runtime: PASS** (restart cycle). stop (SIGINT) released the port; immediate relaunch
  rebound the same port with **no EADDRINUSE**; pid changed (`12343 → 12372`), confirming
  restart = a new process, matching GUI semantics. So Rust survives GUI's stop→start churn
  without a TIME_WAIT bind failure.

## Non-TUN Traffic Probe

Local origin (`python3 -m http.server`) used as target — the sandbox may block external
egress, but a local target still exercises inbound → route → direct outbound → origin.

| path | result | note |
|---|---|---|
| direct (no proxy) baseline | 200 | origin healthy |
| **SOCKS5** via mixed | **200** | full data path works |
| **SOCKS5h** (remote-resolve) via mixed | **200** | works |
| **HTTP CONNECT tunnel** via mixed | **200** | `http: CONNECT route host=127.0.0.1 port=18080` |
| plain-HTTP forward GET via mixed | **200** | F-3 closed by package13; absolute-form GET reaches local origin |

Non-TUN proxying **works** over the two methods browsers / system-proxy actually use
(SOCKS5 for all; HTTP CONNECT for HTTPS), and package13 adds the basic Go-parity
plain-HTTP forward path for `http://` requests.

## Clash API Telemetry (GUI reads these after start)

Built with `--features gui_runtime` (which includes `clash_api`); config carries
`experimental.clash_api` (`127.0.0.1:20123`, secret). **Runtime: PASS.**
- `GET /configs` (Bearer) → real json (`"mixed-port":20122,"mode":"rule",...`).
- `GET /proxies` (Bearer) → real proxy set (`DIRECT/GLOBAL/select/direct/block`, node selection).
- `GET /configs` **without** token → **401** (auth enforced).
GUI's traffic/proxy panels and node selection would function against the Rust kernel.
(Clash API is feature-gated and **not** required for GUI to detect startup — startup
depends solely on the `sing-box started` keyword.)

## TUN Toggle Observation

Not exercised at runtime (would need a real OS TUN device + root, and is package03's
dataplane scope). Static: GUI TUN toggle = `updateConfig('tun')` → restartCore (full
restart). package02 made the GUI flat TUN config pass schema/IR; turning TUN into a real
validated dataplane remains **package03** (CAL-10: `mixed/gvisor` stack → real backend).
No fix attempted here.

## Go 1.13.13 Reload / Start Reference → package05 implications

Start phase order (`box.go`, `adapter/lifecycle.go:12-17`):
```
1 logger.start
2 internalServices.Initialize (cache-file, clash-api, v2ray-api)
3 Initialize: network,dnsTransport,dnsRouter,connection,router,outbound,inbound,endpoint,service
4 Start: outbound,dnsTransport,dnsRouter,network,connection,router        (no inbound) -> "pre-started"
5 internalServices.Start
6 Start: inbound,endpoint,service        <-- listener bind happens HERE (box.go:470)
7 PostStart: outbound,...,inbound,endpoint,service
8 internalServices.PostStart
9 Started: ...all...
10 internalServices.Started               -> "sing-box started" (box.go:434)
```
- **`sing-box started` = strong readiness**: bind (step 6) precedes it; any bind failure
  aborts Start and triggers Close rollback — Go never prints `started` half-bound. Rust's
  observed order (bind log before `started`) matches. package05 should keep this barrier:
  emit ready only after all inbounds bind; bind failure must fail+rollback, not partial-ready.
- **All reload paths are full instance replacement, not in-place.** CLI SIGHUP
  (`cmd_run.go:169-202`) = `Close()` old box → `box.New()` → `Start()`; it pre-checks the
  new config (`check()`), keeping the old instance if invalid. libbox `ServiceReload` =
  GUI platform builds a new `BoxService` and swaps it. Clash API `PUT /configs` is a no-op
  stub (`configs.go:69-71`); `PATCH` only switches `mode`. **There is no same-port handoff
  in Go** — Close fully releases ports before the new instance rebinds (Go does not set
  SO_REUSEADDR; `listener_tcp.go:37-39`), so a release→reoccupy window exists.
- **Close order** (`box.go:500-502`): service → endpoint → inbound → outbound → router →
  connection → dnsRouter → dnsTransport → network (stop accepting before tearing down deps).
- Timeouts: StartTimeout 10s / StopTimeout 5s / FatalStopTimeout 10s (`constant/timeout.go`).
- **For package05**: GUI itself only ever does stop→start (process restart), so GUI
  workflows do **not** require an in-process atomic reload. package05's reload-continuity
  work is for the kernel's own SIGHUP/API reload, not a GUI prerequisite. If Rust ever
  wants seamless same-port reload (beyond Go), it needs SO_REUSEPORT/fd-handoff — Go's
  architecture does not provide it. Pre-check-before-teardown (Go's `check()`) is the
  cheap correctness win to mirror.

## New Follow-Ups

- **F-1 (P0) — CLOSED by package12.** GUI 1.19.0's default DNS uses Go 1.12
  type-based servers with `domain_resolver` / `server_port` / `path` /
  `interface`; Rust strict validator originally rejected that shape on the
  production load path. package12 accepts and lowers the focused GUI DNS fields
  while preserving strict unknown-field rejection. The earlier "run is lenient,
  doesn't call validate_v2" assumption remains corrected: the production load
  path is strict.
- **F-2 (build-profile) — CLOSED by package14.** `cargo build -p app` remains a
  default `["router"]` minimal binary, not a GUI drop-in proxy runtime. The
  official process-contract build is now `--features gui_runtime`, which pins
  `router`, `adapters`, and `clash_api`. Configs that need the V2Ray API should
  build with `--features gui_runtime,v2ray_api`.
- **F-3 (parity gap) — CLOSED by package13.** HTTP inbound now supports
  absolute-form plain HTTP GET forwarding through the same router/outbound
  registry path as CONNECT, with proxy-only headers stripped before origin.
  HTTPS remains CONNECT-only; interactive Wails E2E is still blocked.
- **(info) selector/urltest** outbounds are handled via the bridge/registry, not the
  switchboard direct-register path (a benign `Using 501 degraded mode` WARN at register;
  `/proxies` still reports the selector correctly). No action.

## Final Recommendation

Next priority has moved past F-1, F-2, and F-3: DNS schema parity is closed by
package12, the GUI runtime build profile is closed by package14, and plain HTTP
proxy parity is closed by package13. package03 remains PARTIAL for privileged
TUN dataplane proof, while package07 itself remains PARTIAL until an interactive
Wails desktop-window E2E can be driven.

Package15 adds the closeout/manual-gate index
`post_fable_package15_acceptance_closeout_manual_gates.sh`. Package17 then ran a
real Wails desktop attempt: the app built and the seeded profile was visible, but
Start did not yield core/API/traffic evidence. package07 therefore remains
PARTIAL/BLOCKED until a human operator or stronger desktop automation completes
the interactive desktop-window flow.

## package17 External Wails Attempt

Date: 2026-06-16.

Artifact root: `/tmp/pf17_external_acceptance/`.

Supporting baseline:

- `cargo build -p app --bin app --features gui_runtime` PASS.
- `./target/debug/app version` PASS; observed
  `sing-box version 0.1.0 (0d1cbe7b1426)`.
- `WORK=/tmp/pf17_gui_contract bash post_fable_package07_probe_harness.sh`
  PASS: 14/14 process-contract checks, including SOCKS5, HTTP CONNECT,
  package13 plain HTTP forward GET, Clash API auth, SIGINT stop, and same-port
  rebind.

Wails environment:

- `~/go/bin/wails doctor` PASS: Wails v2.11.0, Go 1.26.1, Node 26.3.0, Xcode
  CLT present.
- `~/go/bin/wails build -clean` with the default Go proxy failed on a
  `proxy.golang.org` TLS handshake timeout.
- `GOPROXY=https://goproxy.cn,direct ~/go/bin/wails build -clean` PASS and
  produced a fresh
  `GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app`.

Desktop-window attempt:

- The attempt backed up `~/Library/Application Support/GUI.for.SingBox`, seeded
  controlled test data only under that directory, copied `target/debug/app` to
  the GUI kernel path, and restored the original App Support directory during
  cleanup.
- Seeded profile: `PF17 Local Direct`, mixed inbound `127.0.0.1:20122`, Clash API
  `127.0.0.1:20123` with secret `pf17probe`, local DNS, direct/select/block
  outbounds, TUN disabled.
- The first direct Mach-O launch exited early without exposing a desktop window.
- Launching the app bundle with `open -n` exposed a real `GUI.for.SingBox`
  desktop process to System Events. The AX UI tree contained the seeded
  `PF17 Local Direct` profile and `Click to Start` text.
- Start was attempted through AppleScript/System Events plus a coordinate
  fallback, but no core pid, generated config, Clash API response, or local
  proxy traffic artifact was produced.
- Cleanup restored App Support and left ports `20122`/`20123` closed.

Latest attempt result excerpt:

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

Status decision:

This is a real Wails desktop-window attempt, but it is not a package07 DONE
signal. The required GUI-driven Start -> Rust `gui_runtime` core -> Clash API ->
local traffic -> Stop sequence was not proven. package07 remains PARTIAL/BLOCKED
until a human operator or stronger desktop automation can activate Start and
capture the complete flow.

## package18 Wails Desktop Click Automation

Date: 2026-06-17.

Artifact root: `/tmp/pf18_wails_click_automation/`.

New package18 artifacts:

- `post_fable_package18_wails_desktop_click_automation.sh`
- `post_fable_package18_wails_desktop_click_automation.md`
- `post_fable_package18_wails_desktop_click_automation_evidence.md`

Latest result:

```json
{
  "status": "BLOCKED_STOP",
  "drive_method": "computer_use_mcp",
  "stages": {
    "desktop_window": "external_confirmed",
    "profile_visible": "external_confirmed",
    "core_started": "pid_config_ports_present",
    "clash_api": "pass",
    "loopback_proxy_traffic": "pass",
    "stop_click": "native_attempted_waiting_external",
    "stop_cleanup": "failed"
  }
}
```

Evidence gained:

- The real Wails app launched from
  `GUI_fork_source/GUI.for.SingBox-1.19.0/build/bin/GUI.for.SingBox.app`.
- The seeded `PF18 Local Direct` profile was visible in the real Wails window.
- The GUI-generated `data/sing-box/config.json` existed and used mixed inbound
  `127.0.0.1:20122`, Clash API `127.0.0.1:20123`, and secret `pf18probe`.
- The GUI-owned core command pointed to the app bundle's `Contents/MacOS/data`
  symlink path.
- `/configs` and `/proxies` passed with Bearer `pf18probe`.
- Loopback HTTP through the GUI-started mixed proxy returned `200` and body
  `pf18 origin ok`.

Why package07 is still PARTIAL:

- The latest full package18 run reached Start as `native_sent`, not as a
  manually clicked Start.
- The Stop icon in the running Wails view was not successfully clicked by native
  automation or `computer-use`; cleanup released ports afterward, so Stop was
  not GUI-proven.
