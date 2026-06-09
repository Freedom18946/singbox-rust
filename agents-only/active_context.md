<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-09)
T3-2 + DRIFT-01 + SVC-DNS-01 + SVC-LISTENER-AUDIT-01 + **SVC-V2RAY-API-01A** +
**APP-SIDECAR-BIND-01 DONE**; REALITY remains boxed.
- **SVC-V2RAY-API-01A** (`4141724b`; detail:
  `svc_v2ray_api_01a_bind_failure_propagation.md`): V2Ray gRPC sidecar now pre-binds the
  TCP listener before `start()` returns `Ok`; `started` claim uses `compare_exchange` with
  rollback on bind/register failure; task-scoped RAII cleanup resets `started` on task exit
  (normal shutdown, serve failure, cancellation/drop).
- Supervisor policy unchanged: visible-but-nonfatal log-and-continue; no false "wired" on start
  `Err`; ServiceManager registration / hard-fail policy deferred to **SVC-V2RAY-API-01B**.
- **APP-SIDECAR-AUDIT-01 DONE** (`484d12f1`; `app_sidecar_bind_audit.md`): two app Clash API
  entries class C; bootstrap SimpleV2Ray class E. **APP-SIDECAR-BIND-01 DONE** (`e1f0be43`;
  detail: `app_sidecar_bind_01_clash_api_honesty.md`): bootstrap + run-engine Clash API share
  `spawn_prebound_clash_api_server`; listener binds before handle return; bind failure returns no
  live-looking handle and no false `started`; caller policy remains visible-but-nonfatal; runtime
  `ServiceHandle` liveness projection remains absent by design boundary.
- **APP-V2RAY-SIMPLE-01 AUDIT PROPOSED** (`app_v2ray_simple_01_policy_audit.md`): classify
  **B/MISSING_REAL_LISTENER_BUG**; next 01A real-listener wiring; SimpleV2Ray untouched; SVC-01B defer.
- Recent validation: `cargo fmt -p app --check`, `cargo test -p app --all-features clash` (8/8),
  app clippy `-D warnings`, workspace check, consistency, boundaries, `git diff --check` all PASS.
- sb-core full-suite **pre-existing** flakes (NOT SVC-DNS-01/01A; fail on clean HEAD too):
  `cache_file::test_fakeip_persistence_sled`, `dns_steady::{udp_pool_timeout_is_handled, bad_domain_returns_err}`.

## Strategic State

Phase: MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, is not in
the S1/S6 denominator; no increment unless an S3 case is promoted (T3 added none).
DEV-REALITY-01 = ARCH-LIMIT (residual): local profile parity CLOSED, official-JA4 + camouflage OPEN.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **all PASS, 0 clippy warn**
  (lint relaxed 2026-06-03: warnings/dead_code deny→warn, safety kept deny).
- cargo check --workspace --all-features: **PASS**. strict check-boundaries.sh: **exit 0**.
- python3 unittest (reality_probe_tools / clienthello_family /
  dual_kernel_verification): **PASS**. trojan_integration: **17 PASS, 2 ign**.

## T3 ClientHello Fingerprint Parity — T3-0…T3-2 DONE (2026-06-08)

- CLOSED (local): functional dataplane (token-match + 4 phases + L18 REALITY_LOCAL gate);
  normalized-profile parity (committed harness `labs/interop-lab/reality_clienthello_parity/`,
  digest `bc002612a968fae0`); required field-set parity; coordinated GREASE structure
  (`6f8ae63a`, independent OsRng per ClientHello, FIXED→RANDOMIZED, 230,242/262,144 unique — sampled).
- LOCAL-DIAGNOSTIC: from-spec JA4 `t13d1516h2_…` Go==Rust observed locally.
- OPEN: official FoxIO-tool JA4 crosscheck **PENDING**; extension-order statistical parity;
  `HelloChrome_Auto` drift; tier-2 real-network camouflage. NON-GOAL: L4 byte identity.
- A2.3 full capstone runtime status-JSON rehearsal **DEFERRED**. No uTLS-equivalent port.
- Detail: t32_reality_tier3_governance_update.md; harness commit T3-1B `052d4392`.
- agents-only/a0_reality_spike/ stays pre-existing untracked (do not commit/delete).

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
  History (fresh13 per-rep R73/R90/R91; fresh09 broken R85/R88): mt_real_02_baseline.md.

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

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`; L01-L25:
  `archive/L*/`; closed MT-* tracks: `archive/MT-*/`; golden spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
