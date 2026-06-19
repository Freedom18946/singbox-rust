<!-- tier: B -->
# post1313 Diff Analysis

Date: 2026-06-19

Scope: planning against refreshed references only. No Rust implementation happened in this
round.

## Current Reference Baseline

- Go reference: `go_fork_source/sing-box-1.13.13`
- GUI reference: `GUI_fork_source/GUI.for.SingBox-1.25.1`
- Live context confirms the refresh in `agents-only/active_context.md`.
- Current post-FABLE status lowers GUI joint testing priority: package07 is
  `PAUSED_INDEFINITE`, and packages15-19 are done as evidence/automation records.

## Important Calibration

`GO_PARITY_MATRIX.md` contains two different concepts:

- Acceptance closure: historical `209/209 closed`, including accepted limitations,
  won't-fix, de-scoped, and Rust-only items.
- Behavior/API diff evidence: PX rows still mark multiple Go 1.13.13 surfaces as
  `MAJOR_DIFF`, `FAIL`, or `PARTIAL`.

The post1313 packages use the PX rows as work discovery, not the acceptance closure number
as proof of drop-in equivalence.

## Diff Domains From The PX Ledger

| Domain | PX source | Current evidence summary | Planning impact |
|---|---|---|---|
| Root config and schema posture | PX-002 | `$schema` / `schema_version`, tag/name mapping, strict unknown fields, duplicate tags | P1313-01 |
| Route/rule schema | PX-003 | Rule actions, logical rules, DNS rule schema, route options, rule_set defaults | P1313-03, P1313-04 |
| DNS core | PX-004 | No full Go-style `DNSRouter` / `TransportManager` / action/cache flow; EDNS0, TTL rewrite, RDRC, reverse mapping gaps | P1313-02, P1313-03 |
| Route dataplane | PX-005 | UDP NAT still stubbed; route connection/packet behavior partial | P1313-04, P1313-09 |
| Lifecycle managers | PX-006 | Rust managers remain more registry-like; Go has staged lifecycle and dependency order | P1313-05 |
| Adapter interfaces | PX-007, PX-008, PX-009 | Missing Go-like handler/upstream/router/ruleset/DNS/FakeIP/time/cert/cache/clash/v2ray surfaces | P1313-06 |
| Clash API | PX-010 | Mostly stubbed/wiring gaps against router/dns/cache/history/mode list | P1313-08 |
| SSMAPI | PX-011 | Functionality largely implemented; needs stronger E2E SS client revalidation under new reference | P1313-11 |
| V2Ray API | PX-012 | gRPC exists; router-wide tracker and endpoint policy still need settlement | P1313-10 |
| CacheFile | PX-013 | Rust JSON/sled posture diverges from Go cachefile buckets/cache_id/FakeIP/RDRC/selector storage | P1313-07 |
| DERP / resolved | PX-014, PX-015 | Mostly aligned/accepted limitation; specific strategy/platform tails remain | P1313-11 |

## GUI 1.25.1 Diff Risks

The GUI 1.25.1 upgrade report shows a large GUI source delta:

- Wails bridge now supports `ExecBackground` `LogFile`; kernel startup sends logs through
  `CoreLogFilePath`.
- Clash API clients now resolve explicit host/port and bracketed IPv6, not just a forced
  `127.0.0.1` port.
- `getProxyDelay(proxy, url, timeout)` includes a caller-controlled timeout.
- WebSocket channels are lazy and independent for `/logs`, `/memory`, `/traffic`, and
  `/connections`.
- `getProxyEndpoint()` now includes schema, host, port, username, password, and proxy type.
- Generator output changed: selector/urltest/default outbounds carry `icon`/`hidden`;
  `cache_file.store_rdrc` is suppressed; DNS rule strategy emission is currently disabled;
  default outbound id typo was fixed.

Planning impact: GUI work should focus on golden config/API shape fixtures and local
contract probes. Do not resume desktop automation until the user explicitly asks.

## Priority Logic

P0 is assigned where a gap can invalidate most later work or block generated configs:

- config/schema fixture baseline
- DNS transport + DNS rule/cache semantics
- lifecycle/start order
- cachefile persistence
- Clash API control-plane contract

P1 is assigned where the work is important but should follow P0 surfaces:

- route/rule engine execution details
- adapter surface contracts
- UDP NAT dataplane
- V2Ray router-wide tracking
- service regression closeout

P2 is assigned to GUI 1.25.1 desktop-adjacent work because GUI joint testing is currently
paused, but fixture/API shape is still worth keeping fresh.

## Explicit Non-Goals

- No `.github/workflows/*`.
- No public-network live cohort work.
- No REALITY T3 reopening.
- No official FoxIO JA4 closure claim.
- No libbox/mobile/release packaging work from Go `clients/`, `include/`, or `release`.
- No claim that GUI is fully ready from MT-GUI-04, `209/209`, or REALITY closure alone.
