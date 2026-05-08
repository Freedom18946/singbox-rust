<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.

---

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); stage-3 path A active on
demand, gated by fresh sample intake. Parity 52/56 BHV (92.9%);
ARCH-LIMIT-REALITY label.

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

- cargo check --workspace: PASS
- python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification:
  **201 tests PASS** (R84 added 4 committed-evidence contract).
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md after R84: **26 rounds, 229 runs, 93 all_ok**.

## Next Steps

- MT-REAL-02 R84 fresh04 cohort-A-style re-evaluation DONE
  (2026-05-08). Authorized fresh04 only ×5. Pre-gate passed.
  Live: 5/5 same_failure (uniform timeout).
  **A.same_failure_only**. R83 app_minimal_diverged did NOT
  reproduce in 5 runs; cohort-A-style stable phase divergence
  carrier hypothesis FALSIFIED. closure_status.evaluated=
  **false** (R84 not a closure attempt; broken chain at R83
  NOT patched). Future fresh04 closure attempt = R84 as round
  1 + two more authorized rounds. latest_health:
  latest_divergence -> latest_same_failure. class_history=
  [other, timeout, null, timeout, null, timeout]. Rollup:
  latest_divergence_outbounds []; latest_same_failure 6->7.
  BHV 52/56 unchanged.
- MT-REAL-02 R83 fresh04 cohort-B closure attempt DONE
  (2026-05-08). Mixed (1 div + 2 same-failure); closure NOT
  achieved; chain broken.
- MT-REAL-02 R82 fresh04 same-failure live recheck DONE
  (2026-05-08). 3/3 same_failure(timeout); A.1; was timeout-
  class round 2 of 3.
- MT-REAL-02 R81 subset-schema pre-gate hardening DONE
  (2026-05-08). No-live tooling; closes R80 gap.
- MT-REAL-02 R80 fresh04 recheck DONE; matrix_error.
- MT-REAL-02 R79 fresh05 divergence-carrier recheck DONE.
- MT-REAL-02 R74/R75 evidence accounting DONE (tests +11).
- MT-REAL-02 R73 fresh REALITY/VLESS bounded live DONE.

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

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY:
  agents-only/mt_real_02_baseline.md
- L01-L25: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
