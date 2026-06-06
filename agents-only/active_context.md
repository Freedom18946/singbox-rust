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

REALITY local deterministic gate committed (A1/A2; `make verify-reality-local`,
opt-in merge-precheck). Public fresh-cohort = external healthy-cohort observation
(pre-release, non-gating). A4 projection track CLOSED through A4.4 (see below).

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); public fresh-cohort rounds
are now pre-release observation (non-gating). Parity 52/56 BHV (92.9%)
unchanged. DEV-REALITY-01 = ARCH-LIMIT (residual): local client parity
validated, ClientHello fingerprint parity open (golden_spec S4).

## MT-REAL-02 Stage-2 + Evidence Framework

Stage-2 closed (5 non-all_ok candidates falsified as noise); per-outbound rollup
capability + planner --latest-* filters. Detail: archive/mt_real_02/,
live_rollup.json, mt_real_02_baseline.md.

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

## A4 Projection Track — CLOSED through A4.4 (2026-06-06)

- A4.1 mapping + A4.2A prototype + A4.3 disposition (route C, `a5b7a41f`) + A4.4
  contract (`b042a683`, reference/reality_historical_projection_contract.md) all DONE.
- Inventory (a43 + a42/outputs/batch_inventory.json): 34/34 projected; 0 promotable;
  31 PARTIAL; 3 UNSUPPORTED; canonical_candidate null; adversarially verified (0 refuted).
- Route C: canonical schema stays STRICT; historical projection TERMINAL (universal-four
  floor + R80/82/83/84 ⊥ R85-91 ceiling); prototype stays agents-only. Deferred G1/G2/G3.

## A2 REALITY-Gate Wiring (2026-06-06)

- A2.1 DONE (a21_reality_local_gate_wiring_evaluation.md). Route B adopted for
  implementation = an L18 local capstone gate, NOT server-side merge enforcement
  (GitHub Actions permanently disabled; no required-check layer).
- A2.2 next: wire `make verify-reality-local` into scripts/l18/l18_capstone.sh after
  ORACLE. Fixed-port single-instance preflight REQUIRED (18443/18444/18445/11180/11181
  free before fixture); NO exit-77 skip by default (missing dep → reviewer-readable FAIL).
- tier-2 (public fresh-cohort) remains pre-release only; tier-3 ClientHello remains OPEN.
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
