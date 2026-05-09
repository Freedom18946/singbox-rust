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
  **PASS** (R88 added 4 committed-evidence contract tests).
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md after R88: **30 rounds, 255 runs, 111 all_ok**.

## Next Steps

- MT-REAL-02 R88 fresh09 recheck DONE (2026-05-09).
  Authorized fresh09 ×5. Pre-gate passed (selected_count=1,
  planned_total_runs=5, target=example.com:80,
  subset_schema_gate_passed=true).
  Live: 5/5 same_failure(timeout), matrix_status=0, no phase labels.
  **A.fresh09_timeout_steady_state**: R85 timeout reproduced as
  steady-state (5/5 timeout); fresh09 recovery_consecutive_rounds=0;
  R88 NOT a closure attempt by design (chain reset at R85).
  **fresh09 NOT recovered**; **per-rep closure NOT achieved**;
  **original cohort C closure NOT claimed**. BHV 52/56 unchanged.
- MT-REAL-02 R87 fresh10 round-3 closure DONE.
  3/3 all_ok; **A.per_rep_recovery_closure**: fresh10 chain
  R73+R86+R87; rotated active set all per-rep closed.
- MT-REAL-02 R86 rotation-bank DONE; **A.rotation_bank_clean**:
  fresh01/fresh15 consecutive=3 closure; fresh10 round 2 banked.
- MT-REAL-02 R85 recovery-watch round 2 DONE; **B.partial_per_rep**:
  fresh01/fresh15 consecutive=2; fresh09 timeout reset=0.
- MT-REAL-02 R84 fresh04 5/5 same_failure(timeout) DONE.
- MT-REAL-02 R83/R82/R81/R80/R79/R74/R75/R73 DONE.

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
  Original cohort C identity (fresh01+fresh09+fresh15) requires
  fresh09 itself to clear, not a replacement rep.
- A single-node recheck of a broken rep is not a closure attempt;
  even a hypothetical clean recheck only opens a new chain at round 1.

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY:
  agents-only/mt_real_02_baseline.md
- L01-L25: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
