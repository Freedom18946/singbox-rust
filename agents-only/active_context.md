<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-06)

REALITY local deterministic gate committed (A1/A2): fixture +
`make verify-reality-local` (opt-in merge-precheck). Public fresh-cohort
is now the external healthy-cohort observation tier (pre-release,
non-gating; golden_spec S4 3-tier model). Build PASS; boundary exit 1.

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); public fresh-cohort rounds
are now pre-release observation (non-gating). Parity 52/56 BHV (92.9%)
unchanged. DEV-REALITY-01 = ARCH-LIMIT (residual): local client parity
validated, ClientHello fingerprint parity open (golden_spec S4).

## MT-REAL-02 Stage-2 Closure Summary

Five latest non-all_ok candidates falsified as noise. Full record in
`archive/mt_real_02/round_45_60_evidence_framework.md`; closure +
stage-3 paths in `archive/mt_real_02/closure_report.md`.

## Evidence Framework Capability

Per outbound: latest_health, latest_run_health_counts,
latest_divergence_phase_counts, latest_divergence_phase_dominance,
latest_divergence_run_ratio, is_bi_modal, dominant_phase_history,
is_phase_shifting. Top level adds latest_*_outbounds (phase_dominant,
phase_no_dominance, bi_modal, phase_shifting). Planner filters:
--latest-health, --latest-run-health, --only-latest-run-health,
--latest-phase-dominance, --latest-bi-modal, --latest-phase-shifting.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **all PASS, 0 clippy
  warn** (lint relaxed 2026-06-03: warnings/dead_code deny→warn, safety
  lints kept deny, sb-tls test mods allow expect_used; 28 warns cleared).
- python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification:
  **PASS** (R91 committed-evidence contract included).
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md after R91: **33 rounds, 264 runs, 117 all_ok**.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — opt-in merge-precheck
   `make verify-reality-local` (A1/A2 committed).
2. External healthy-cohort observation — pre-release, NON-gating:
   MT-REAL-02 fresh-cohort; PASS/DEGRADED/INCONCLUSIVE; health-gate +
   R81 dry-run + intake_counts; dead nodes replaced+recorded; no single
   node (incl. dead fresh09) is a closure identity; outage ≠ regression.
3. ClientHello byte-level fingerprint parity — residual OPEN.

Retired non-goal: original cohort-C closure (was bound to fresh09).
History (mt_real_02_baseline.md): fresh13 per-rep closure R73+R90+R91;
fresh09 steady-state broken R85/R88.

## Still-Valid Constraints

- Do not return to a static ClientHello template.
- Do not hard-code precedence or position-to-mode behavior.
- Round 12 seed-selected signature modes are the stable sampler.
- Round 13 position hard coupling is falsified.
- Real node usability is not guaranteed; node outage is not sampler
  regression.
- The user pursues the highest goal, not maintenance-only posture.
- MT-REAL-02 stage closure is not project closure.
- Any fresh-cohort live run must pass R81 subset-schema dry-run gate.
- closure scope is per-outbound + per-class; never extend A.1 to
  cohort-B group closure without the required same-class chain.
- A broken closure chain cannot be patched; restart needs a fresh
  consecutive sequence.
- Rotated-replacement per-rep closure is not original-cohort closure.
- Public-node (cohort C / fresh09) closure is external-healthy-cohort
  observation, not a merge gate; no single public node is mandatory and
  original cohort-C closure is a retired non-goal. Merge-precheck
  (opt-in, not yet auto-enforced) = local gate `make verify-reality-local`
  (golden_spec S4 3-tier model).
- A single-node recheck of a broken rep is not a closure attempt;
  even a hypothetical clean recheck only opens a new chain at round 1.

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`.
  L01-L25: `archive/L*/`. Closed MT-* tracks: `archive/MT-*/`.
  Golden spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
