<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-06-03)

MT-REAL-02 **dormant since R91 (2026-05-09)**, ~3.5 weeks no new rounds;
paused awaiting an authorized fresh-sample intake (any live run must
clear the R81 subset-schema dry-run gate). Continue: read this +
`mt_real_02_baseline.md`. Build PASS; boundary exit 1 (known drift).

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

- check/build/clippy (all-features,all-targets): **all PASS, 0 clippy
  warn** (lint relaxed 2026-06-03: warnings/dead_code deny→warn, safety
  lints kept deny, sb-tls test mods allow expect_used; 28 warns cleared).
- python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification:
  **PASS** (R91 committed-evidence contract included).
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md after R91: **33 rounds, 264 runs, 117 all_ok**.

## Next Steps

- MT-REAL-02 R91 fresh13 round-3 closure attempt DONE (2026-05-09).
  Authorized fresh13 ×3 only. Pre-gate passed (selected_count=1,
  planned_total_runs=3, target=example.com:80,
  subset_schema_gate_passed=true, violations=[]). Live: 3/3
  run_all_ok, matrix_status=0, no phase labels.
  **A.fresh13_per_rep_recovery_closure**; fresh13
  recovery_consecutive_rounds=3 (R73+R90+R91); **fresh13 per-rep
  recovery closure achieved**. **original cohort C closure NOT claimed**;
  BHV 52/56 unchanged.
- R90 fresh13 round2 banked (3/3 run_all_ok, recovery=2; closure NOT
  declared). R89 fresh12 D.matrix_error_inconclusive (NOT banked). R88
  fresh09 recheck: R85 timeout 5/5, recovery=0, fresh09 NOT recovered.
- R87 fresh10 round-3 closure DONE; R86 rotation-bank DONE; R85
  recovery-watch round 2 DONE; R84-R73 prior fresh rounds DONE.
  Rotated active set fresh01/fresh15/fresh10 is per-rep closed, but
  this never substitutes for fresh09's original-cohort identity.

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

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`.
  L01-L25: `archive/L*/`. Closed MT-* tracks: `archive/MT-*/`.
  Golden spec: `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
