<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 300 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-07-11) - MIG-03 WP08 router stack merge DONE

- **WP08 accepted:** `router/` is sole implementation home. `routing/` is a 25-line WP14
  compatibility facade; ConfigIR engine/explain/trace moved under router, duplicate toy matcher,
  IR, and reload router were deleted. Router-domain `pub struct Engine` count is one.
- ConfigIR and rule-set paths share label-aware suffix matching; DNS continues through canonical
  `RuleMatcher` with no local domain matcher. Explain JSON has an exact field-order/value lock;
  rule-hot-reload now atomically replaces canonical `Arc<RouterIndex>` built through config pipeline.
- Acceptance: workspace all-feature check/clippy, fmt, boundaries, diff-check, sb-core/app full and
  focused router/DNS/hot-reload tests, and 232 Python tool tests pass. Five route/DNS dual-kernel
  cases have `gate_score=0` and zero mismatches; no new S4 divergence.
- **Authorized transition:** WP11 is unblocked on serialized WP06 → WP08 → WP11 lane. Next step:
  inventory all sb-core `SB_*` reads, inject explicit runtime option structs from app composition root.
- **Scope note:** structural ownership/dedup plus acceptance-drift repairs only. No parity/BHV,
  packaging, or REALITY denominator movement is claimed.

## Resume (2026-07-11) - MIG-03 WP07 QUIC family relocation DONE

- **WP07 accepted:** Hysteria v1/v2 inbound/outbound, Naive H2, and shared QUIC protocol code now
  live in sb-adapters. sb-core has no hysteria*/quic/naive_h2 outbound module or protocol reference;
  Hysteria2 IR construction moved from switchboard into adapter registration.
- Hysteria2 canonical outbound retains TCP plus relocated UDP PacketConn behavior and full transport
  fields (Brutal, CA path/PEM, ALPN/SNI, 0-RTT, obfs/salamander). Opt-in app UDP loopback passes with
  a real authenticated QUIC association; Hysteria v1 E2E, integration tests, and Criterion bench pass.
- Acceptance: core+adapters tests, workspace all-feature check, strict workspace clippy, fmt,
  boundaries, diff-check, and focused feature-isolation checks pass. sb-core source drops 4,708 Rust
  lines. Remaining quinn/hyper users are DNS/DERP/dev or compatibility-feature paths assigned to
  WP09/WP13, not WP07 protocol ownership.
- **Authorized transition:** WP08 is next on the serialized WP06 → WP08 → WP11 lane; WP13 remains
  responsible for legacy feature/dependency edge retirement after its prerequisites.
- **Scope note:** structural ownership relocation plus preservation/verification of existing
  protocol behavior only. No parity/BHV, packaging, or REALITY denominator movement is claimed.

## Resume (2026-07-11) - MIG-03 WP06 scaffold retirement DONE

- **WP06 accepted:** bridge/runtime/switchboard now consume only canonical sb-adapters registry
  connectors. Registry rejection is a fatal startup error with tag/kind context; no scaffold,
  degraded, core direct/block, or implicit-direct protocol fallback remains.
- Scaffold feature/Cargo references and 16 core legacy files are gone. `OutboundImpl` has one
  Connector variant; inbound TCP helper ownership moved to adapters with DNS/keepalive/telemetry
  semantics preserved. Net diff is -5818 lines; final gui_runtime binary is 241,952 bytes smaller
  than the recorded pre-WP06 build.
- Acceptance: three-crate tests, registry fatal/no-READY test, workspace all-target/all-feature
  check, strict clippy, fmt, boundaries, diff-check, SS/Trojan net-e2e, release GUI mixed→direct
  traffic smoke all pass. Final strict interop is 87/95; every WP06-affected case is clean and
  remaining failures are pre-existing harness/config/S4 baselines documented in WP06.
- **Authorized transition:** WP07 is unblocked. Next step: relocate the full
  hysteria/hysteria2/naive/quic family from sb-core to sb-adapters, then run its protocol/bench/
  global acceptance set.
- **Scope note:** structural ownership/fallback retirement only. No parity/BHV, packaging, or
  REALITY denominator movement is claimed.

## Resume (2026-07-11) - MIG-03 WP05 adapter gap closure DONE

- **WP05 accepted:** `de25101d` moves active SOCKS UDP map/session/transport ownership into
  sb-adapters, closes product feature reachability, and preserves D14 env/default/wire-size
  behavior. SOCKS/mixed now share the legacy per-IP limiter; SOCKS reports active TCP and
  compatible UDP associate/packet/active metrics.
- WP04 matrix GAP count is now zero. Core SOCKS UDP scaffold tests moved to active adapter/product
  tests; exact adapter references to the four core UDP scaffold symbols are zero. Selector/urltest
  and generic balancer/group ownership remain WP12.
- Acceptance: adapter default/all-feature and core regression suites, three app product profiles,
  feature isolation, Python tool suites, global five gates, and SOCKS TCP/UDP + mixed dual-kernel
  runs all pass. No D18 item or behavior-expansion decision appeared.
- **Authorized transition:** WP06 is unblocked. Next step: remove bridge fallback/orphan scaffold
  implementations and stale `ADAPTER_FORCE` surface exactly per WP04 §11/WP06.
- **Scope note:** WP05 structural/compatibility closure only. No parity/BHV denominator,
  packaging, REALITY, WP06 deletion, or WP12 ownership movement is claimed.

## Resume (2026-07-11) - MIG-03 WP04 semantic audit DONE

- **WP04 accepted:** `mig03/mig03_wp04_coverage_matrix.md` corrects stale scaffold
  assumptions, inventories all live construction paths, and records per-protocol eight-dimension
  coverage, D9/D10/D14 decisions, cross-dependencies, test disposition, and parity handoffs.
- Two WP05 GAP groups remain: SOCKS inbound Rust-only limiter/active-TCP/compatible metrics plus
  core UDP dependencies; SOCKS outbound product-profile UDP reachability plus core UDP helper
  migration. HTTP/mixed/direct/TUN/redirect/tproxy/block and registry-only protocols require no
  WP05 scaffold-semantic fill. Selector/urltest implementation ownership remains WP12.
- No D18 item remains. Next dependency step: execute WP05 exactly from matrix §11; WP06 stays
  blocked until WP05 acceptance.
- **Scope note:** documentation audit only. No production code, feature, test, packaging,
  parity/BHV, or REALITY denominator movement is claimed.

## Resume (2026-07-10) - MIG-03 WP01 + combined WP02/WP03 DONE

- **WP01-03 accepted:** census/ADR red-team omissions corrected; one canonical
  `sb-types` outbound/inbound/packet contract now owns adapter and core holders.
  Legacy connector/UDP traits, compatibility aliases, `connect_io`, and
  `sb-proto` are removed.
- Registration wrappers are 0; `register.rs` is a 7-line façade. Packet paths
  snapshot finalized route controls, enforce idle/explicit deadlines, report
  effective timeout duration, and reject I/O after close. Named stream routing
  always uses canonical boxed dialing.
- Validation: global five gates, crate/focused tests, scaffold smoke, feature
  isolation, and dual-kernel SOCKS TCP/UDP replay+diff pass clean. No parity/BHV,
  packaging, or REALITY denominator movement claimed.
- **Authorized transition:** `adapter/inbound_transition.rs` and scaffold-era
  core direct ownership remain scheduled for WP06; selector family dedup remains
  WP12. Next MIG-03 dependency step: WP04 semantic audit, then WP05.

## Resume (2026-07-07) - agents-only doc compression + maintenance automation

- **agents-only top level compressed**: boxed MT-REAL-02 docs (baseline long report, 3 fresh
  intakes, a41/a42 spikes, mt_mixed_fresh_evidence) moved via `git mv` into
  `archive/mt_real_02/`; workflow notes moved to `memory/workflow_notes.md`. All repo references updated
  (incl. `trojan.rs` comment, golden spec, AGENTS.md). Nothing deleted.
- **NOT moved (hard constraints)**: `mt_real_01_evidence/` + `mt_real_02_evidence/` (paths
  hard-coded in `scripts/tools/*.py` regression tests); `fable5审计报告/` (2026-06-29 disposition:
  stays put, anchored by root README / docs / capabilities generator); `mig03/`, `post1313/` (active).
- **Maintenance automation upgraded**: `06-scripts/verify-consistency.sh` now enforces S-tier
  line caps (active_context ≤300, workpackage ≤120) and a top-level file whitelist as hard
  failures, plus stale-Resume / oversized-log advisories. `log.md` pre-2026-06 bulk rolled into
  `archive/logs/`.
- **Scope note**: documentation/process hygiene only. No code, parity/BHV, gate, or packaging
  movement is claimed.

## Resume (2026-07-06) - MIG-03 architecture de-dup migration PLANNED

- **MIG-03 planning complete, no code changed**: `agents-only/mig03/` now holds the full
  planning set (README index + overview + WP01-WP14; this initial snapshot predated WP01
  execution) for the in-repo
  strangler-fig migration: trait unification, scaffold retirement, router-stack merge,
  control-plane/env convergence, feature slimming. User rejected the new-repo rewrite path.
- Baseline metrics snapshot lives in `mig03/mig03_00_overview.md` §1/§6 (sb-core 108k LOC /
  103 features / 161 SB_* env vars; register.rs 4,264 lines; ≥6 OutboundConnector defs).
- All optional technical choices pre-decided by user delegation (2026-07-06): see
  `mig03/mig03_01_decisions.md` D1-D18; user gates removed from packages (only D18 escalation
  remains). This planning snapshot initially exposed WP01 + WP04; live WP status is in each
  package header and the current update above; lane rules are in the README.
- **Scope note**: planning artifacts only. No behavior, parity/BHV, gate, or packaging
  movement is claimed.

## Resume (2026-07-03) - app helper-CLI audit cleanup batch (15 rounds, all DONE locally)

- **One batch, one pattern**: 15 consecutive audit-cleanup rounds hardened the `app` helper
  CLIs — every round replaced panic paths (`unwrap`/`expect`/nested `block_on`) or silent
  failure paths with structured errors, tightened the input/output contract, added focused
  unit + real-binary integration tests, and passed the same verification set (app fmt, focused
  tests, all-target/all-feature check, strict clippy, CLI smoke, `git diff --check`).
- **Covered surfaces**: `metrics-serve` (bind-before-READY), `merge` (inline-resource read
  errors, abort-before-write), `sb-bench` (invalid env targets; `SB_BENCH_PAR=0` fallback; CSV
  write errors), `bench io` (zero requests/concurrency; HTTP method validation), `coverage-http`
  (invalid `SB_COV_ADDR` non-zero exit), `prom` (async handlers off nested runtime; `--filter`
  regex validation), `tools synctime` (pre-UNIX clock), `sb-handshake slice` (fallible JSONL
  writes, `skipped_bad_lines`), metadata bins `version`/`sb-version`/`sb-rule-coverage` (JSON
  `Result` paths), `sb-explaind` (invalid `SB_DEBUG_ADDR`, port-query 400), `generate
  tls-keypair` (`--days` honored, `--days 0` rejected), `preflight` (missing/invalid config
  fails), `subs` (structured read/parse/write errors), `prefetch` (byte/duration totals; SOCKS
  UDP helper lint unblock in sb-adapters).
- **Scope note**: app helper-CLI hygiene only. No REALITY closure, dual-kernel BHV/parity
  movement, release packaging completion, or workflow automation is claimed. Full per-round
  details: git history 2026-07-03 (`029e48d8`, `71bb2026`, `5a97b46d`, …) + `log.md`.

## Strategic State

Phase: MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local profile parity CLOSED, official-JA4 + camouflage OPEN.

## Current Build And Gate

- 2026-07-11 WP07 final: workspace all-feature check, strict workspace clippy, fmt, boundaries,
  diff-check, core+adapters tests, Hysteria v1 E2E, Hysteria2 integration/UDP E2E, and benchmark
  execution **PASS**. Exact evidence and dependency handoffs: WP07 package.

## T3 ClientHello Fingerprint Parity — T3-0…T3-2 DONE (2026-06-08)

- CLOSED (local): functional dataplane, normalized-profile parity, required field-set parity,
  coordinated GREASE structure, and local from-spec JA4 Go==Rust diagnostic.
- OPEN: official FoxIO-tool JA4 crosscheck, extension-order statistical parity,
  `HelloChrome_Auto` drift, tier-2 camouflage. NON-GOAL: L4 byte identity.
- A2.3 runtime status-JSON rehearsal DEFERRED. Detail: t32 governance; T3-1B `052d4392`.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — `make verify-reality-local` (A1/A2 committed; A2.3 deferred).
2. External healthy-cohort observation — pre-release, NON-gating (tri-state; no single node
   is a closure identity; outage ≠ regression).
3. ClientHello fingerprint parity — tier-3: local profile parity CLOSED (see T3 section);
   official-JA4 + ext-order distribution + camouflage OPEN.

## Closed Tracks (compressed; detail in archive)

- **A4 projection** CLOSED through A4.4 (`a5b7a41f`+`b042a683`, 2026-06-06): route C canonical
  STRICT, projection TERMINAL; 34/34 projected, 0 promotable; deferred G1/G2/G3.
- **A2 REALITY-gate wiring** DONE (`71e51669`+`e44c67d3`, 2026-06-06): L18 REALITY_LOCAL gate
  after ORACLE; A2.3 runtime status-JSON DEFERRED.
- **MT-REAL-02 stage-2** closed (R45-R60): per-outbound rollup + planner --latest-* filters.
  History (fresh13 per-rep R73/R90/R91; fresh09 broken R85/R88):
  `archive/mt_real_02/mt_real_02_baseline.md`.

## Still-Valid Constraints

- Do not return to a static ClientHello template; do not hard-code precedence or
  position-to-mode behavior. (R12 seed-modes = stable sampler; R13 position coupling falsified.)
- Real node usability is not guaranteed; node outage is not sampler regression.
- The user pursues the highest goal, not maintenance-only posture; stage closure ≠ project closure.
- Any fresh-cohort live run must pass R81 subset-schema dry-run gate.
- closure scope is per-outbound + per-class; never extend A.1 to cohort-B group closure
  without the required same-class chain.
- A broken closure chain cannot be patched; restart needs a fresh consecutive sequence.
  A single-node recheck of a broken rep only opens a new chain at round 1.
- Rotated-replacement per-rep closure is not original-cohort closure.
- Public-node (cohort C / fresh09) closure = external-healthy-cohort observation, not a merge
  gate; no single node mandatory; merge-precheck = local gate only.
- Retired non-goal: original cohort-C closure (was bound to fresh09).

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY: `archive/mt_real_02/mt_real_02_baseline.md`;
  L01-L25: `archive/l01_l25_summary.md`; closed MT-* tracks: `archive/mt_summary.md`;
  REALITY archive: `archive/reality_summary.md`; golden spec:
  `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
