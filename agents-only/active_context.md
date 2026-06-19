<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-14) - POST-FABLE wave

- **package10 DONE**: CAL-11/20-25 closed via tracing cleanup, config validation,
  explicit unsupported system_proxy, HTTP heartbeat guard, and entrypoint pins.
- **package09 DONE** (`f2dcc34b` + 09b): selector/proxy-pool tests restored; DNS
  resolver-hijack flakes hardened; CAL-08 inventory closed/deferred; clippy gate → 0.
- **package08 DONE** (`c31e9d1d`): long-tail stubs loud; dns real in parity; deepest trojan
  tests enabled; sb-subscribe fixtures pin unknown-type baselines.
- **package06 (Inbound liveness/observability) DONE** (`bbc00416`): inbound monitors
  classify exits; Clash `StartFailed` sidecar snapshots; DNS warning helper; V2Ray same-port retry.
- **package05 DONE** (`a9236205`): reload waits for activation/readiness before commit;
  failed reload keeps old listeners/registries; same-port in-process reload is rejected.
- **package04 DONE** (`f70bf5ef`): endpoint tags enter outbound namespace; app
  `adapters`/`parity` wire legacy `wireguard`; public WG peer proof remains out of scope.
- **package03 PARTIAL** (`edf42095`, 03b boxed + package17 rerun): GUI TUN is loud;
  normal-user proof PASS; privileged dataplane remains blocked by UID 501/no sudo.
- **package12 DONE** (`349eecf3`): F-1 CLOSED; GUI default DNS shape passes strict load path.
- **post_fable packages15-19 DONE; GUI joint testing PAUSED_INDEFINITE**:
  package07 stays PARTIAL; Wails build artifacts removed and user App Support left on Go kernel/config.
- **package01/package02 DONE**: startup keyword (`0a4cae74`); GUI flat TUN parses/lowers (`e3defcdf`).

## Resume (2026-06-10) — closed (detail in baseline/archive)
T3-2 + SVC-* + APP-SIDECAR-* + APP-V2RAY-* + APP-RELOAD-* CLOSED; REALITY boxed.

## Strategic State

Phase: MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local profile parity CLOSED, official-JA4 + camouflage OPEN.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **all PASS, 0 clippy warn**
  (lint relaxed 2026-06-03: warnings/dead_code deny→warn, safety kept deny).
- cargo check --workspace --all-features: **PASS**. strict check-boundaries.sh: **exit 0**.
- python3 unittest (reality_probe_tools / clienthello_family /
  dual_kernel_verification): **PASS**. trojan_integration: **20 PASS, 0 ignored**.

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

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`; L01-L25: `archive/L*/`; closed MT-* tracks: `archive/MT-*/`; golden spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
