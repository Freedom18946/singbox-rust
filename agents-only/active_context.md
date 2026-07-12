<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 300 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-07-12) - tier-1 REALITY gate RED→GREEN: VLESS nil-uuid Go-alignment

- **Surfaced while building JA4 bins**: `make verify-reality-local` was FAILING at HEAD `ec97f112`
  (`negative_all_pass:false`) — the `bad_uuid` negative control. Positive 20/20 always passed.
- **Root cause = real Rust/Go divergence** (not a fixture flaw): the fixture's `bad_uuid` is the
  nil/all-zeros UUID; Rust VLESS rejected nil at config/dial (`vless UUID must not be nil` /
  `VLESS UUID cannot be nil`), but Go `vless.NewClient` accepts any well-formed UUID incl.
  `uuid.Nil` and lets the server authenticate at the data stage. Rust fail-fast diverged from Go.
- **Fix = align Rust to Go**: removed both nil-uuid guards in `crates/sb-adapters/src/outbound/vless.rs`
  (`start`/`dial`), added Go-equivalence comments; inverted `test_vless_connector_start_with_nil_uuid`.
  Now nil uuid dials, reaches the VLESS data stage, and the server rejects it (early eof).
- **Verified**: tier-1 gate `local_deterministic_gate: PASS` (positive 20/20, `negative_all_pass:true`,
  bad_uuid now `vless_dial ok / vless_probe_io fail`); `vless_integration` 17-pass. **Parallel note**:
  VMess has the same nil-uuid guard (`vmess.rs:446`) — not exercised by this gate, left for a
  separate Go-checked decision.

## Resume (2026-07-12) - REALITY official-JA4 FoxIO cross-check CLOSED (algorithm level)

- **official-JA4 tail closed at the algorithm level.** The harness from-spec JA4 algorithm
  (`parse_clienthello`) now reproduces FoxIO's OWN published reference values — canonical
  worked example `t13d1516h2_8daaf6152771_e5627efa2ab1` + the full ALPN-segment table —
  vendored under BSD-3 `LICENSE-JA4` at `reality_clienthello_parity/fixtures/foxio_reference_vectors/`
  (FoxIO-LLC/ja4@`0e54bc83`), enforced by offline blocking test `tests/test_foxio_reference_vectors.py`.
- Fixed a real from-spec bug the cross-check exposed: ALPN `a`-segment now implements FoxIO's
  non-alphanumeric→hex rule (`parse_clienthello:_ja4_alpn_segment`); also empty-sigalg / empty-ext
  `c`-segment edge cases. Mainstream `h2` path unchanged → reality golden `…_d8a2da3f94cd` unmoved.
- Status token flipped `DIAGNOSTIC_PENDING_FOXIO_REFERENCE` → `FOXIO_REFERENCE_VERIFIED`; `run_check.py`
  summary `foxio_reference_crosscheck` now carries the live verifier result (was a hard-coded DEFERRED
  string). golden_spec `DEV-REALITY-01` + three-tier model updated.
- **Scope caveat**: algorithm/vector conformance (our JA4 == FoxIO's published JA4), NOT a
  second-tool (tshark) fingerprint of live captures, NOT byte identity. Still OPEN: ext-order
  distribution, `HelloChrome_Auto` drift, tier-2 camouflage. No `52/56` BHV movement (REALITY
  has no S3 BHV-ID). Evidence: `labs/interop-lab/reality_clienthello_parity/fixtures/foxio_reference_vectors/PROVENANCE.md`.

## Resume (2026-07-12) - MT-INTEROP-03 dual-kernel baseline cleanup DONE

- **MT-INTEROP-03 accepted:** final 103-case run is 101 `PASS`, 1 `DIV-COVERED`,
  1 `ENV-LIMITED`, 0 `FAIL`. This replaces WP14's historical 87/103 noisy baseline.
- Four former `INTEROP_*` cases are self-managed. DNS TTL reference direction and cache bounds,
  WS memory warm-up, shutdown drain ordering, reload readiness debounce, Go group-delay route,
  FakeIP fixture/oracle, WireGuard compatibility fields, and isolated Rust/Go bootstrap are closed.
- VLESS local dual-kernel dataplane is strict PASS after fixing request version/address order.
  VMess remains explicit `ENV-LIMITED`: local Rust upstream uses a non-canonical test dialect;
  only two declared assertion stages are accepted, while launch or any extra failure remains FAIL.
- FakeIP cursor behavior is locked as S4 `DIV-M-012`; static S4 labels never suppress failures.
  Evidence: `archive/mt_interop_03/acceptance.md`.
- **Recommended next:** REALITY external research tail (official FoxIO JA4, extension-order
  distribution, HelloChrome_Auto drift), then tier-2 camouflage. GUI desktop remains paused until
  explicitly reopened.

## Resume (2026-07-12) - MIG-03 WP14 final acceptance DONE

- **MIG-03 accepted and archived:** WP01-WP14 closed. Final D17 metrics meet every target;
  canonical contracts, adapter protocol ownership, single router stack, externalized Web/DERP
  services, frozen runtime options, duplicate cleanup, and feature slimming are closed.
- WP14 removed final `routing/` compatibility facade and locked non-return in boundary V8. Stable
  architecture docs, navigation, experience memory, phase map, and archived acceptance evidence
  now match source facts.
- Workspace all-feature fmt/check/clippy/test, five app profiles, Python tool suites, Trojan
  integration, strict boundaries, consistency, and diff-check pass. Interop full run: 87/103;
  all 16 failures classified as external-env, dual/Go oracle, non-promotable Rust diagnostic,
  harness assertion, or historical S4 baseline; no new unclassified difference. Exact evidence:
  `archive/mig03/mig03_wp14_final_acceptance_and_archive.md`.
- **Scope note:** architecture migration closure only. No parity/BHV/REALITY movement claimed.

## Resume (2026-07-11) - MIG-03 WP09/WP10/WP12 red-team acceptance DONE

- **WP09 accepted:** DERP moved to `sb-service-derp`; SSM/V2Ray API moved to `sb-api`;
  app owns concrete service registration. sb-core service tree has no axum/tonic and retains
  only non-Web kernel services.
- **WP10 accepted:** `sb_api::debug` is sole HTTP/auth/middleware owner. app keeps endpoint state
  plus route extension; all endpoints retained. Real HTTP tests lock 200/401/429, request-id,
  envelope, audit, and extension behavior.
- **WP12 accepted:** core selector/p3/udp-balancer and transport/tls/subscribe/config/socks5
  shadows retired or relocated per D15. WireGuard/Tailscale layer split is explicit; no D18 item.
- Red-team fixes closed default-profile metrics linkage, relocated test dependencies/feature gates,
  DERP header panic paths, and stale boundary assertions. Workspace all-features, focused crate/app
  tests, three app profiles, clippy, fmt, 427 boundaries, and diff-check pass.
- **Transition closed:** WP13 accepted; WP14 is next MIG-03 frontier.

## Resume (2026-07-11) - MIG-03 WP11 env/config convergence DONE

- 141 个 core-owned `SB_*` 全部由 app 组合根一次解析，注入 `CoreRuntimeOptions` 六域；
  core `SB_*` 字面量/直接读取/白名单均为 0，构造后冻结。
- DNS/router/net/service/debug/admin 消费链与测试已迁移；变量无废弃。登记权威：
  `agents-only/archive/mig03/mig03_wp11_env_registry.md`。
- 验收：workspace all-features check、clippy、sb-core/app full test、fmt、boundaries 429、
  diff-check 全绿。
- **Authorized transition:** WP14 已解锁；按 `workpackage_latest.md` 继续下一项 MIG-03 frontier。

## Resume (2026-07-11) - MIG-03 WP08 router stack merge DONE

- **WP08 accepted:** `router/` is sole implementation home. Its former 25-line `routing/`
  compatibility facade was removed by WP14; ConfigIR engine/explain/trace moved under router, duplicate toy matcher,
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

- **WP04 accepted:** `archive/mig03/mig03_wp04_coverage_matrix.md` corrects stale scaffold
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
  stays put, anchored by root README / docs / capabilities generator); `post1313/` remains active.
- **Maintenance automation upgraded**: `06-scripts/verify-consistency.sh` now enforces S-tier
  line caps (active_context ≤300, workpackage ≤120) and a top-level file whitelist as hard
  failures, plus stale-Resume / oversized-log advisories. `log.md` pre-2026-06 bulk rolled into
  `archive/logs/`.
- **Scope note**: documentation/process hygiene only. No code, parity/BHV, gate, or packaging
  movement is claimed.

## Resume (2026-07-06) - MIG-03 architecture de-dup migration PLANNED

- **MIG-03 planning snapshot (later executed and archived)**: `agents-only/archive/mig03/` holds the full
  planning set (README index + overview + WP01-WP14; this initial snapshot predated WP01
  execution) for the in-repo
  strangler-fig migration: trait unification, scaffold retirement, router-stack merge,
  control-plane/env convergence, feature slimming. User rejected the new-repo rewrite path.
- Baseline metrics snapshot lives in `archive/mig03/mig03_00_overview.md` §1/§6 (sb-core 108k LOC /
  103 features / 161 SB_* env vars; register.rs 4,264 lines; ≥6 OutboundConnector defs).
- All optional technical choices pre-decided by user delegation (2026-07-06): see
  `archive/mig03/mig03_01_decisions.md` D1-D18; user gates removed from packages (only D18 escalation
  remains). This planning snapshot initially exposed WP01 + WP04; live WP status is in each
  package header and the current update above; lane rules are in the README.
- **Scope note**: planning artifacts only. No behavior, parity/BHV, gate, or packaging
  movement is claimed.

## Strategic State

Phase: MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local profile parity CLOSED; official-JA4
algorithm cross-check CLOSED (vendored FoxIO BSD-3 vectors, 2026-07-12); ext-order distribution
+ `HelloChrome_Auto` drift + camouflage OPEN.

## Current Build And Gate

- 2026-07-11 WP07 final: workspace all-feature check, strict workspace clippy, fmt, boundaries,
  diff-check, core+adapters tests, Hysteria v1 E2E, Hysteria2 integration/UDP E2E, and benchmark
  execution **PASS**. Exact evidence and dependency handoffs: WP07 package.

## T3 ClientHello Fingerprint Parity — T3-0…T3-2 DONE (2026-06-08)

- CLOSED (local): functional dataplane, normalized-profile parity, required field-set parity,
  coordinated GREASE structure, and from-spec JA4 Go==Rust; **official FoxIO JA4 algorithm
  cross-check CLOSED (2026-07-12)** via vendored FoxIO BSD-3 reference vectors.
- OPEN: extension-order statistical parity, `HelloChrome_Auto` drift, tier-2 camouflage.
  NON-GOAL: L4 byte identity; second-tool fingerprint of live captures.
- A2.3 runtime status-JSON rehearsal DEFERRED. Detail: t32 governance; T3-1B `052d4392`.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — `make verify-reality-local` (A1/A2 committed; A2.3 deferred).
2. External healthy-cohort observation — pre-release, NON-gating (tri-state; no single node
   is a closure identity; outage ≠ regression).
3. ClientHello fingerprint parity — tier-3: local profile parity CLOSED (see T3 section);
   official-JA4 algorithm cross-check CLOSED (FoxIO vectors); ext-order distribution +
   `HelloChrome_Auto` drift + camouflage OPEN.

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
