<!-- tier: B -->
# post_fable package map

> Source: `../06_全局汇报_A-K.md` (REPO-GLOBAL-CALIBRATION-01A, 2026-06-10).
> Purpose: turn fable5 findings into executable work packages for Codex/fable
> collaboration. This directory is planning-only; package implementation happens in
> later tasks.

## Highest Goal

Deliver a Rust binary that can replace Go sing-box 1.13.13 for GUI.for SingBox
1.25.1 users: GUI can launch it, generated configs validate, mainstream proxy
traffic works, TUN/system-proxy flows are usable, node selection persists, and
reload/config switching does not silently break service.

## Operating Rules

- `agents-only/active_context.md` remains the single source of truth for volatile
  phase, gate, and current status.
- This package map records fable5 follow-up work only; do not rewrite the original
  audit report files while executing a package.
- Do not touch `agents-only/a0_reality_spike/`.
- Each package must close as: implement, add or adapt tests, verify locally, review,
  update relevant `agents-only` docs, then commit and push.
- GitHub Actions stay disabled; validation is local.
- Do not claim GUI readiness from MT-GUI-04, 209/209, or REALITY parity alone.

## Strategic Pause

As of 2026-06-19, real Wails/GUI joint testing is paused indefinitely. Do not
open package20 or continue desktop automation until the user explicitly resumes
that line. The local hygiene action is recorded in
`post_fable_gui_joint_test_pause.md`: repository Wails build artifacts were
removed, while the user's App Support state was left on the observed Go
kernel/current profile because no PF18/PF19 seed markers or Rust kernel install
were present.

## Package Status

| Package | Title | Priority | Covers | Status |
|---|---|---:|---|---|
| post_fable_package01 | GUI contract | P0 | CAL-02, CAL-17 | DONE (`0a4cae74`) |
| post_fable_package02 | Schema parity, TUN first | P0 | CAL-01, H-4 | DONE (`e3defcdf`) |
| post_fable_package12 | DNS schema parity, GUI default | P0 | F-1 | DONE (`349eecf3`) |
| post_fable_package03 | TUN dataplane | P1 | CAL-10, H-5 | DONE (`edf42095` runtime wiring; post003 extension 2026-06-20: UDP NAT + IPv6 datapath, fixed connected-UDP send + TUN egress through proxy outbounds; live root proof PASS for TCP IPv4+IPv6 through HTTP outbound) |
| post_fable_package04 | WireGuard dataplane | P0/P1 | CAL-03, CAL-09 | DONE (`f70bf5ef`; endpoint route target + legacy feature wiring) |
| post_fable_package05 | Reload continuity and atomicity | P1 | CAL-04, CAL-05, CAL-07, CAL-12, CAL-14 | DONE (`a9236205`; atomic reload + safe same-port rejection) |
| post_fable_package06 | Inbound liveness and observability | P1/P2 | CAL-06, CAL-13, CAL-15, CAL-16 | DONE (`bbc00416`; inbound/sidecar/DNS/V2Ray visibility) |
| post_fable_package07 | GUI E2E probe | Probe | H-1, H-2, H-3, H-9 | PARTIAL, PAUSED_INDEFINITE (probe PASS; package18 proved real Wails Start/core/API/traffic; package19 latest blocker is `BLOCKED_ACCESSIBILITY`; no package20 until resumed) |
| post_fable_package08 | Long-tail protocols and subscription | P2 | CAL-18, CAL-28, H-10 | DONE (loud unsupported tor/tailscale/ssr; dns confirmed real; trojan tests enabled → 0 ignored; subscription fixtures) |
| post_fable_package09 | Lint, test, and gate policy | P1/P2/P3 | CAL-08, CAL-19, CAL-27, CAL-29 | DONE (selector tests rewritten + 2 stubs removed; trojan feature/DialOpts follow-ups closed; lint inventory closed, enforcement deferred; clippy gate → 0; 09b hardened DNS resolver-hijack flakes) |
| post_fable_package10 | Runtime and config hygiene | P2/P3 | CAL-11, CAL-20, CAL-21, CAL-22, CAL-23, CAL-24, CAL-25 | DONE (stderr tracing cleanup; FakeIP/experimental validation hardened; explicit unsupported system_proxy; HTTP heartbeat lifecycle guard; runtime entrypoint ownership pinned) |
| post_fable_package11 | Documentation calibration | P3 | CAL-26 | DONE (external docs marked as current-state unsafe snapshots; generator residual closed by package16) |
| post_fable_package13 | HTTP inbound plain forward parity | P2 | F-3 | DONE (absolute-form GET forwards through router/outbound; CONNECT preserved) |
| post_fable_package14 | GUI runtime build profile | P2 | F-2 | DONE (`gui_runtime` pins router+adapters+clash_api; default build remains non-drop-in) |
| post_fable_package15 | Acceptance closeout/manual gates | P2 | package03/package07 manual gates | DONE (automatic path indexed; root TUN + interactive Wails remain manual evidence) |
| post_fable_package16 | Capabilities generator refresh path | P3 | package11 residual | DONE (validated generator anchors; tracked capabilities docs/report refreshed as docs-only) |
| post_fable_package17 | External acceptance execution | P1 | package03/package07 external gates | DONE (real external gates attempted; package03/package07 remain PARTIAL without required PASS evidence) |
| post_fable_package18 | Wails desktop click automation | P1 | package07 external gate | DONE (script/docs/evidence package; latest real Wails run reached GUI-owned core/API/traffic, then `BLOCKED_STOP`; package07 remains PARTIAL) |
| post_fable_package19 | Wails Stop icon automation | P1 | package07 Stop residual | DONE (script/docs/evidence package; Stop targeting added; latest run `BLOCKED_ACCESSIBILITY` before Start/Stop, so package07 remains PARTIAL) |

## Recommended Execution Order

1. `post_fable_package01_gui_contract.md` and
   `post_fable_package02_schema_parity_tun_first.md` in parallel. These unlock the
   first real GUI launch attempt.
2. `post_fable_package07_gui_e2e_probe.md` immediately after packages 01 and 02.
   Use it to decide how exposed reload continuity is in actual GUI workflows.
3. `post_fable_package12_dns_schema_parity_gui_default.md` closes package07 F-1
   before package03, so the GUI default DNS config can pass the strict production
   load path.
4. `post_fable_package04_wireguard_dataplane.md` is DONE for endpoint/outbound
   wiring; public peer interoperability remains outside package04 scope.
5. `post_fable_package05_reload_continuity_atomicity.md` after GUI reload and Go
   reload probes are documented. It is the highest-risk core-path package.
6. `post_fable_package06_inbound_liveness_observability.md` after or together with
   package 05 if the ready/monitor channel is shared.
7. `post_fable_package03_tun_dataplane.md` after package 02 and package12, because
   the GUI TUN config and GUI default DNS config must first parse. Package03 is
   now PARTIAL: runtime wiring/loud failure are fixed, but privileged dataplane
   traffic proof remains open.
8. Package13 closes package07 F-3 HTTP plain-forward parity, and package14 closes
   F-2 with an explicit GUI runtime build profile. Packages 08-11 are lower-risk
   support work and can be scheduled around the P0/P1 path.
9. Package15 is the closeout index: automatic post-FABLE packages are closed,
   while package03 root TUN proof and package07 real Wails E2E remain manual gates.
10. Package16 closes the package11 doc-tool residual by restoring a validated
    `reports/capabilities.json` / `docs/capabilities.md` refresh path.
11. Package17 executes the external acceptance gates. The current machine still
    lacks noninteractive root for TUN, and the Wails desktop window did not reach
    GUI-driven Start/core/API/traffic proof, so package03/package07 stay PARTIAL.
12. Package18 adds a reproducible Wails desktop-click automation/evidence package.
    Latest run reached real GUI-owned Rust core/API/traffic proof, but Stop did
    not complete through GUI automation; package07 remains PARTIAL.
13. Package19 adds source-informed Stop-icon automation. Latest run confirmed
    Wails CGWindow geometry but blocked on AX/Computer Use window-content
    exposure before Start/Stop, so package07 remains PARTIAL.
14. GUI joint testing is now paused indefinitely. Do not continue package20 or
    desktop automation work until the user explicitly resumes the line.

## CAL Coverage Matrix

| Finding | Package | Note |
|---|---|---|
| CAL-01 | post_fable_package02 | TUN schema rejects GUI-generated Go 1.12 fields. |
| CAL-02 | post_fable_package01 | Missing `sing-box started` launch signal. |
| CAL-03 | post_fable_package04 | WireGuard endpoint is not in outbound namespace. |
| CAL-04 | post_fable_package05 | Failed reload kills old inbounds and does not recover. |
| CAL-05 | post_fable_package05 | Inbound bind/serve failures are not success criteria. |
| CAL-06 | post_fable_package06 | Inbound serve tasks have no liveness monitor. |
| CAL-07 | post_fable_package05 | Runtime outbound/inbound registry installs before swap and is not restored on rollback. |
| CAL-08 | post_fable_package09 | Workspace panic/unwrap lint policy is mostly inactive. |
| CAL-09 | post_fable_package04 | Legacy WireGuard outbound feature is not wired into app builds. |
| CAL-10 | post_fable_package03 | TUN data path and GUI stack names are not usable. |
| CAL-11 | post_fable_package10 | Production `eprintln!` pollution. |
| CAL-12 | post_fable_package05 | Graceful shutdown drain can be defeated by nested runtime drop. |
| CAL-13 | post_fable_package06 | Clash API down has no machine-readable GUI signal. |
| CAL-14 | post_fable_package05 | Same-port reload relies on fixed grace sleep and no `SO_REUSEADDR`/handoff. |
| CAL-15 | post_fable_package06 | Rapid V2Ray disable/enable can silently lose the API server. |
| CAL-16 | post_fable_package06 | Bad DNS resolver from IR is silently skipped. |
| CAL-17 | post_fable_package01 | Kernel version `0.1.0` may trigger GUI feature gating. |
| CAL-18 | post_fable_package08 | Long-tail outbound types remain stubs in parity builds. |
| CAL-19 | post_fable_package09 | Selector/proxy-pool tests have been ignored since API drift. |
| CAL-20 | post_fable_package10 | `ServiceManager::close` is a structural footgun, despite current compensation. |
| CAL-21 | post_fable_package10 | FakeIP invalid masks are silently discarded. |
| CAL-22 | post_fable_package10 | `experimental` parse failure is silently discarded. |
| CAL-23 | post_fable_package10 | `system_proxy` unsupported-platform behavior reports success. |
| CAL-24 | post_fable_package10 | `serve_http` heartbeat task leaks on the shared-runtime legacy path. |
| CAL-25 | post_fable_package10 | Three runtime entrypoints remain, including dead/legacy paths. |
| CAL-26 | post_fable_package11 | External docs and capability ledgers are stale. |
| CAL-27 | post_fable_package09 | Specific feature test builds still produce warnings. |
| CAL-28 | post_fable_package08 | Deep trojan handshake tests remain ignored. |
| CAL-29 | post_fable_package09 | Flake group root causes need hardening or clearer isolation. |
| F-1 | post_fable_package12 | GUI default DNS type-based server fields were rejected by strict schema. |
| F-2 | post_fable_package14 | GUI runtime/drop-in build profile was ambiguous; default build has no adapters. |
| F-3 | post_fable_package13 | HTTP inbound plain-forward GET parity gap from package07. |

## Unknowns Coverage

| Unknown | Package | Probe outcome should decide |
|---|---|---|
| H-1 GUI has likely never launched Rust kernel | post_fable_package07 | Whether more GUI contract breaks exist. |
| H-2 GUI reload versus process restart | post_fable_package07 | Exposure and priority of package 05. |
| H-3 GUI behavior for kernel version `0.1.0` | post_fable_package07 and 01 | Version string/reporting policy. |
| H-4 Other Go 1.12 fields rejected by strict schema | post_fable_package02 | Whether package 02 expands beyond TUN. |
| H-5 TUN smoltcp quality | post_fable_package03 | Whether TUN data path can be closed or must be de-scoped. |
| F-1 GUI default DNS schema blocker | post_fable_package12 | CLOSED: default DNS shape passes strict production load path. |
| F-2 GUI runtime build profile | post_fable_package14 | CLOSED: build with app feature `gui_runtime`; default build is not proxy runtime. |
| Manual acceptance closeout | post_fable_package15 | DONE: root TUN and interactive Wails gates are indexed without marking package03/package07 DONE. |
| Capabilities generator stale anchors | post_fable_package16 | CLOSED: static evidence anchors are validated and tracked docs/report refresh is restored. |
| External acceptance execution | post_fable_package17 | DONE as an execution record: root TUN is BLOCKED by no noninteractive sudo; Wails window reached a visible profile but no GUI-driven core/traffic proof. |
| Wails desktop click automation | post_fable_package18 | DONE as a script/docs/evidence package: real Wails core/API/traffic proof reached; latest run `BLOCKED_STOP`, package07 remains PARTIAL. |
| Wails Stop icon automation | post_fable_package19 | DONE as a script/docs/evidence package: Stop targeting added; latest run `BLOCKED_ACCESSIBILITY`, package07 remains PARTIAL; follow-up automation paused. |
| GUI joint test pause | post_fable_gui_joint_test_pause | Current strategic decision: real Wails/GUI automation is paused indefinitely; local generated Wails artifacts removed; user manual app test pending. |
| H-7 Go BoltDB cache versus Rust sled cache | Future package if needed | Migration or compatibility posture. |
| H-9 Go reload semantic details | post_fable_package07 and 05 | Exact reload design target. |
| H-10 Subscription format coverage | post_fable_package08 | Additional fixture set and parser backlog. |
| F-3 HTTP inbound plain-forward parity gap | post_fable_package13 | CLOSED: absolute-form GET forwards through existing router/outbound path. |

## File Index

- `post_fable_package01_gui_contract.md`
- `post_fable_package02_schema_parity_tun_first.md`
- `post_fable_package03_tun_dataplane.md`
- `post_fable_package04_wireguard_dataplane.md`
- `post_fable_package05_reload_continuity_atomicity.md`
- `post_fable_package06_inbound_liveness_observability.md`
- `post_fable_package06_liveness_observability_evidence.md`
- `post_fable_package07_gui_e2e_probe.md`
- `post_fable_package08_longtail_protocols_subscription.md`
- `post_fable_package09_lint_test_gate_policy.md`
- `post_fable_package10_runtime_config_hygiene.md`
- `post_fable_package11_doc_calibration.md`
- `post_fable_package11_doc_calibration_evidence.md`
- `post_fable_package12_dns_schema_parity_gui_default.md`
- `post_fable_package13_http_inbound_plain_forward_parity.md`
- `post_fable_package13_http_inbound_plain_forward_parity_evidence.md`
- `post_fable_package14_gui_runtime_build_profile.md`
- `post_fable_package14_gui_runtime_build_profile_evidence.md`
- `post_fable_package15_acceptance_closeout_manual_gates.md`
- `post_fable_package15_acceptance_closeout_manual_gates_evidence.md`
- `post_fable_package15_acceptance_closeout_manual_gates.sh`
- `post_fable_package16_capabilities_generator_refresh_path.md`
- `post_fable_package16_capabilities_generator_refresh_path_evidence.md`
- `post_fable_package17_external_acceptance_execution.md`
- `post_fable_package17_external_acceptance_execution_evidence.md`
- `post_fable_package18_wails_desktop_click_automation.md`
- `post_fable_package18_wails_desktop_click_automation_evidence.md`
- `post_fable_package18_wails_desktop_click_automation.sh`
- `post_fable_package19_wails_stop_icon_automation.md`
- `post_fable_package19_wails_stop_icon_automation_evidence.md`
- `post_fable_package19_wails_stop_icon_automation.sh`
- `post_fable_gui_joint_test_pause.md`
