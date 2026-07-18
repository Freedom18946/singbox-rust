<!-- tier: A -->
# Go-Rust Parity Matrix - Current PX Calibration

> Current calibration: 2026-06-29.
> Baseline: current Rust `main`, Go reference `go_fork_source/sing-box-1.13.13`,
> GUI.for SingBox reference `GUI_fork_source/GUI.for.SingBox-1.25.1`, post-FABLE
> packages 01-19, and post1313 packages P1313-01..12.
>
> This document is the Go/Rust implementation and API calibration ledger. It is
> not the dual-kernel behavior parity ledger, not a GUI desktop readiness
> certificate, and not a public-network acceptance record.

## Current Calibration

The January/February closure ledger is now historical. The active reading path is:

1. `agents-only/active_context.md` for volatile phase, gate, and next-step state.
2. `agents-only/post1313/` for the current Go 1.13.13 / GUI 1.25.1 package evidence.
3. `agents-only/fable5审计报告/post_fable_packages/README.md` for post-FABLE package state.
4. `labs/interop-lab/docs/dual_kernel_golden_spec.md` for behavior parity accounting.
5. This file for the current PX implementation/API calibration plus historical closure appendix.

The post1313 package set is locally closed through P1313-01..12. The strict revalidation
record on 2026-06-28 re-ran the focused package commands, forced selected stale ignored
tests, repaired the admin `/explain` and Clash `/connections` WebSocket regressions, and
left no new dual-kernel parity movement claim.

## Status Legend

| Status | Meaning |
|---|---|
| `PASS-LOCAL` | Implemented or calibrated in the local Rust mainline with package-level tests/evidence. It does not by itself move BHV or prove GUI desktop readiness. |
| `PARTIAL-ACCEPTED` | A known limitation or Rust/Go policy divergence remains, but it is explicit and not a current blocker for this ledger. |
| `RUST-EXTENSION` | Rust exposes additional behavior that is outside the Go reference surface. |
| `EXTERNAL/PAUSED` | Evidence depends on an external host, privilege, GUI desktop automation, or public-network condition that is intentionally outside this matrix. |
| `HISTORICAL` | Retained for provenance only; use current rows above it for present status. |

## Current PX Ledger

| PX | Domain | Current Status | Evidence | Current Meaning / Remaining Non-Claims |
|---|---|---|---|---|
| PX-001 | CLI and command surface | `PARTIAL-ACCEPTED` | `app/tests/reload_sighup_restart.rs`, `app/tests/config_merge_order.rs`, `app/tests/check_json.rs`, `app/tests/cli.rs` | Core run/check/reload/config merge behavior is aligned enough for current package work. Rust-only import/watch/YAML and extra flags remain extensions; keep CLI snapshots current. |
| PX-002 | Root config schema and GUI fixtures | `PASS-LOCAL` | P1313-01; `crates/sb-config/tests/golden/gui1251/`; `cargo test -p sb-config gui1251`; compatibility and schema-version tests | GUI 1.25.1 generated shapes, `$schema` posture, tag fallback, strict validation, `icon`/`hidden`, and cache_file defaults are pinned by fixtures. No GUI desktop automation is claimed. |
| PX-003 | Route/DNS rule schema and actions | `PASS-LOCAL` | P1313-03, P1313-04; DNS rule parity, route options parity, router decision tests | Route and DNS rule fields/actions are calibrated against Go 1.13.13 at parser and local decision layers. Platform-only metadata remains context-driven. |
| PX-004 | DNS client, router, and transport manager | `PASS-LOCAL` | P1313-02, P1313-03; `cargo test -p sb-config dns`; `cargo test -p sb-core dns`; all-feature DNS check set from strict revalidation | Typed DNS servers, legacy upgrade, manager construction, dependency ordering, rule actions, cache knobs, RDRC, reverse mapping, predefined responses, and ECS behavior are locally covered. No public DNS network probing is required. |
| PX-005 | Route dataplane and UDP NAT | `PASS-LOCAL` | P1313-04, P1313-09; `cargo test -p sb-core udp --features router`; `cargo test -p sb-adapters udp --features socks,e2e`; Rust interop UDP cases | Route strategy and UDP packet relay/NAT are closed locally for the app/adapter bridge path. Root TUN privileged dataplane proof remains outside this matrix. |
| PX-006 | Lifecycle managers and start order | `PASS-LOCAL` | P1313-05; lifecycle, reload atomicity, rollback, supervisor, DNS, and app reload tests | Startup/reload activation now has deterministic stage ordering, DNS activation, registry publication after commit, and rollback-preserving behavior. Same-port in-process reload remains intentionally rejected. |
| PX-007 | Adapter handler/upstream/router/ruleset surface | `PASS-LOCAL` | P1313-06; `sb-types` port contracts; `adapter_surface_contract` test | Object-safe adapter-facing contracts now exist for handler/upstream/router/ruleset and related services. This is a Rust contract layer, not a byte-for-byte Go architecture clone. |
| PX-008 | Adapter DNS/FakeIP/RDRC/cache hooks | `PASS-LOCAL` | P1313-03, P1313-06, P1313-07; cache_file and adapter surface tests | DNS/FakeIP query options, persistence hooks, RDRC behavior, reverse mapping, and cache service integration are available through adapter-facing ports. |
| PX-009 | Adapter service surfaces: time/cert/cache/clash/v2ray | `PASS-LOCAL` | P1313-06, P1313-07, P1313-08, P1313-10 | Time, certificate, CacheFile, Clash, V2Ray, URLTest history, and service bundles are exposed for runtime integration. Rust-only helper endpoints remain explicitly outside the Go parity path. |
| PX-010 | Clash API and GUI channel contract | `PASS-LOCAL` | P1313-08; strict revalidation; `p0_clash_api_contract_strict` Rust run; Clash HTTP/WS tests | `/configs`, `/proxies`, delay, WebSocket channels, connection tracking, auth, and GUI 1.25.1 API shape are locally covered. Dual-kernel oracle ignores `DIV-M-006` through `DIV-M-009` remain authoritative in the golden spec. |
| PX-011 | SSMAPI service | `PASS-LOCAL` | P1313-11; app-level SSMAPI regression; sb-core/sb-adapters SSMAPI and Shadowsocks tests | SSMAPI endpoint binding, runtime user updates, TCP/UDP client paths, counters, and cache persistence have app-level regression coverage. No new BHV movement is claimed. |
| PX-012 | V2Ray StatsService and router tracker | `PASS-LOCAL` | P1313-10; sb-core V2Ray tests; sb-api V2Ray helper tests | Go-shaped gRPC stats names, query/reset behavior, configured filters, and router-wide tracker hooks are closed locally. HTTP JSON helpers are Rust-only compatibility/testing surfaces. |
| PX-013 | CacheFile persistence | `PASS-LOCAL / FORMAT-DIVERGENCE ACCEPTED` | P1313-07; cache_file, DNS, router ruleset fallback, Clash, supervisor reload state tests | Rust keeps sled and implements Go-compatible behavior at the service/adapter layer. It does not read or write Go bbolt `cache.db` files; regular-file cache paths fail loudly. |
| PX-014 | DERP / Tailscale service tails | `PARTIAL-ACCEPTED` | P1313-11; DERP tests with injected DNS resolver behavior | Key DERP config and runtime semantics are locally covered. `domain_resolver` strategy depth and h2c/HTTP2 DERP tails are optional future work, not current blockers. Full Tailscale endpoint parity remains de-scoped. |
| PX-015 | resolved / systemd-resolved integration | `PARTIAL-ACCEPTED` | P1313-11; resolved adapter tests; historical `reports/PX015_LINUX_VALIDATION_2026-02-10.md` | Rust has local service/stub coverage and strict replacement semantics. Linux systemd runtime proof still requires a Linux host and remains an accepted limitation, not a blocker for this matrix. |

## Current Domain Snapshot

| Domain | Current Calibration |
|---|---|
| Config and GUI generated shape | Locally calibrated through P1313-01 and P1313-12 fixtures/probes. |
| DNS and DNS rules | Locally calibrated through P1313-02 and P1313-03. |
| Route rules and UDP dataplane | Locally calibrated through P1313-04 and P1313-09. |
| Lifecycle, reload, and liveness-adjacent startup order | Locally calibrated through post-FABLE package05/package06 and P1313-05. |
| Adapter/API service surfaces | Locally calibrated through P1313-06, P1313-08, P1313-10, and P1313-11. |
| Cache persistence | Locally calibrated through P1313-07 with an accepted storage-format divergence. |
| GUI desktop automation | `EXTERNAL/PAUSED`; package07 remains partial/paused and package20 must not be resumed without explicit user direction. |
| REALITY ClientHello / JA4 tails | Governed by `active_context.md` and MT-REAL-02 evidence, not this matrix. |

## Known Non-Claims

- This matrix does not claim GUI desktop readiness or a finished drop-in release.
- This matrix does not update dual-kernel BHV counts. Use
  `labs/interop-lab/docs/dual_kernel_golden_spec.md` for that ledger.
- This matrix does not resume Wails click automation, package20, or GUI joint testing.
- This matrix does not claim root TUN privileged dataplane proof.
- This matrix does not close real-network or tier-2 REALITY camouflage; those
  remain governed by `active_context.md` and the REALITY acceptance model.
- This matrix does not restore or add `.github/workflows/*`.
- This matrix does not make public-network live cohort health a merge gate.

## Verification Records To Reuse

- `agents-only/post1313/p1313_strict_revalidation_2026_06_28.md`
- `agents-only/post1313/p1313_01_config_schema_and_gui_fixtures.md`
- `agents-only/post1313/p1313_02_dns_transport_manager.md`
- `agents-only/post1313/p1313_03_dns_rule_actions_and_cache_semantics.md`
- `agents-only/post1313/p1313_04_route_rule_engine_and_network_strategy.md`
- `agents-only/post1313/p1313_05_lifecycle_managers_and_start_order.md`
- `agents-only/post1313/p1313_06_adapter_surface_contracts.md`
- `agents-only/post1313/p1313_07_cachefile_persistence.md`
- `agents-only/post1313/p1313_08_clash_api_and_gui_channel_contract.md`
- `agents-only/post1313/p1313_09_udp_nat_and_packet_dataplane.md`
- `agents-only/post1313/p1313_10_v2ray_stats_and_router_tracker.md`
- `agents-only/post1313/p1313_11_service_regression_closeout.md`
- `agents-only/post1313/p1313_12_gui1251_low_priority_contract.md`
- `agents-only/fable5审计报告/post_fable_packages/README.md`

## Historical Appendix

The old closure ledger remains useful provenance, but it is no longer the active
summary at the top of this file.

| Historical Item | Meaning Now |
|---|---|
| `209/209 closed` | Historical acceptance closure accounting. It included accepted limitations, de-scoped items, Rust-only items, and won't-fix decisions. It never meant every item had full behavior-level parity proof. |
| `183/209 aligned` baseline | Historical January calibration that explained why later closure and behavior parity needed separate ledgers. |
| Accepted TLS/REALITY limitations | Superseded for live status by MT-REAL-02 and `active_context.md`; local REALITY profile parity and FoxIO JA4 cross-check are boxed, while real-network camouflage remains open. |
| PX rows from 2025-12/2026-01 | Replaced by the Current PX Ledger above. Their value is provenance for post-FABLE and P1313 work discovery. |
| Old `validator/v2.rs` anchors | The validator was split into `validator/v2/` modules. Use current source search, package records, and tests rather than stale line anchors. |

When quoting this file, use the Current PX Ledger for implementation/API status and
the Historical Appendix only for closure provenance.
