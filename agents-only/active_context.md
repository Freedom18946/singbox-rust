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
  **193 tests PASS** (R82 added 3 committed-evidence contract).
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md after R82: **24 rounds, 221 runs, 93 all_ok**.

## Next Steps

- MT-REAL-02 R82 fresh04 same-failure live recheck DONE
  (2026-05-08). Authorized fresh04 only ×3 = 3 runs. Pre-gate
  passed (intake `covered_existing=1`; dry-run `selected_count=1
  planned_total_runs=3`; **subset_schema_gate_passed=true,
  violations=[]**). Live: 3/3 status=completed,
  run_same_failure=3, labels probe_io_all_timeout +
  reality_all_timeout (uniform). class_counts={timeout:27}.
  Phase probe 3/3 timeout (consistent with matrix). Classification
  **A.1** — same-failure timeout-class round 2 of 3 for fresh04.
  Closure counting: R78 timeout-class round 1, R80 excluded
  (matrix_error), R82 timeout-class round 2; cohort-B single-
  outbound closure for fresh04 still requires one more round
  (proposed R83). class_history=[other, timeout, null, timeout].
  fresh04 latest_health: latest_unknown -> latest_same_failure.
  BHV 52/56 unchanged. Not parity completion. Not cohort-B closure.
- MT-REAL-02 R81 subset-schema pre-gate hardening DONE
  (2026-05-08). No live; closes R80 pre-gate gap.
- MT-REAL-02 R80 fresh04 same-failure recheck DONE (2026-05-08).
  3/3 matrix_error; closed by R81; superseded by R82.
- MT-REAL-02 R79 fresh05 divergence-carrier recheck DONE.
- MT-REAL-02 R74/R75 evidence accounting DONE (tests +11).
- MT-REAL-02 R73 fresh REALITY/VLESS bounded live DONE.
- MT-MIXED-FRESH-01 mixed fresh config intake DONE.
- MT-TROJAN-FRESH-15 line CLOSED.

## Still-Valid Constraints

- Do not return to a static ClientHello template.
- Do not hard-code precedence.
- Do not hard-code position-to-mode behavior.
- Round 12 seed-selected signature modes remain the stable sampler.
- Round 13 position hard coupling is falsified.
- Real node usability is not guaranteed; node outage is not sampler
  regression.
- The user pursues the highest goal, not a maintenance-only posture.
- MT-REAL-02 stage closure is not project closure.
- Any fresh-cohort live run must pass the R81 subset-schema dry-run
  gate before live authorization.
- Do not write A.1/A.2/A.3 outcomes as cohort-B single-outbound
  closure completion; closure requires a separate longer-repeat
  round.

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY:
  agents-only/mt_real_02_baseline.md
- L01-L25: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
