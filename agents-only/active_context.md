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
non-gating; golden_spec S4 3-tier model). A4.1 mapping spike + A4.2A read-only
projection prototype landed (see A4 track).

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); public fresh-cohort rounds
are now pre-release observation (non-gating). Parity 52/56 BHV (92.9%)
unchanged. DEV-REALITY-01 = ARCH-LIMIT (residual): local client parity
validated, ClientHello fingerprint parity open (golden_spec S4).

## MT-REAL-02 Stage-2 Closure Summary

Five latest non-all_ok candidates falsified as noise; full record + stage-3 paths
in archive/mt_real_02/ (round_45_60_evidence_framework.md, closure_report.md).

## Evidence Framework Capability

Per-outbound rollup capability fields + planner --latest-* filters; full list in
live_rollup.json + mt_real_02_baseline.md.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **all PASS, 0 clippy warn**
  (lint relaxed 2026-06-03: warnings/dead_code deny→warn, safety kept deny).
- python3 unittest (reality_probe_tools / clienthello_family /
  dual_kernel_verification): **PASS**. trojan_integration: **17 PASS, 2 ign**.
- live_rollup after R91: **33 rounds, 264 runs, 117 all_ok**.

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

## A4 External-Observation Track (2026-06-06)

- HEAD includes the committed A4 formal external healthy-cohort schema + stdlib
  validator + fixtures (labs/interop-lab/reality_external_observation/).
- A4.1 historical mapping spike DONE (a41_historical_mapping_spike.md);
  A4.2A historical projection prototype DONE (a42_historical_projection_spike/).
- canonical live schema v1 stays STRICT; historical records live permanently at
  the projection layer and do NOT auto-promote to canonical observations.
- Do NOT coerce unknown/mixed historical evidence into canonical phase booleans.
- Do NOT invent matrix exit codes. pre-R44 records are outside promotable scope.
- Real epochs R44/R77/R82/R85; DIRECT phase-probe in R80/R82/R83/R84.
- R82 and R91 projections are both PARTIAL, canonical_candidate=null.
- Next card: A4.3 projection-layer disposition (no public network).
- agents-only/a0_reality_spike/ stays pre-existing untracked; do not commit/delete.

## Still-Valid Constraints

- Do not return to a static ClientHello template.
- Do not hard-code precedence or position-to-mode behavior.
- Round 12 seed-selected modes = stable sampler; Round 13 position coupling falsified.
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
- Public-node (cohort C / fresh09) closure = external-healthy-cohort observation,
  not a merge gate; no single node mandatory; merge-precheck = local gate only.
- A single-node recheck of a broken rep is not a closure attempt;
  even a hypothetical clean recheck only opens a new chain at round 1.

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`.
  L01-L25: `archive/L*/`. Closed MT-* tracks: `archive/MT-*/`.
  Golden spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
