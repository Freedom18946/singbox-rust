<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.

---

## Strategic State

Phase: MT-REAL-02 stage-2 closed (R45-R60); stage-3 path A active
on demand. Parity 52/56 BHV (92.9%); ARCH-LIMIT-REALITY label.

## MT-REAL-02 Stage-2 Closure Summary

Five latest non-all_ok candidates were falsified as noise. Full record
in `agents-only/archive/mt_real_02/round_45_60_evidence_framework.md`;
closure rationale + stage-3 paths in `archive/mt_real_02/closure_report.md`.

## Evidence Framework Capability

Per outbound: latest_health, latest_run_health_counts,
latest_divergence_phase_counts, latest_divergence_phase_dominance,
latest_divergence_run_ratio, is_bi_modal, dominant_phase_history,
is_phase_shifting.

Top level: latest_*_outbounds plus latest_phase_dominant_outbounds,
latest_phase_no_dominance_outbounds, latest_bi_modal_outbounds,
latest_phase_shifting_outbounds.

Planner filters: --latest-health, --latest-run-health,
--only-latest-run-health, --latest-phase-dominance, --latest-bi-modal,
--latest-phase-shifting.

## Current Build And Gate

- cargo build -p app --features acceptance,clash_api,service_ssmapi:
  PASS
- python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification:
  68 tests PASS.
- live_rollup.json/md: 18 rounds, 113 runs, 24 all_ok (R70 added
  R63 HK final confirmation #3).

## Next Steps

- R70 HK final confirmation + current-sample-face closure DONE
  (2026-05-04). Classification: **A — Current sample face
  formally closed / no new signal**. (1) HK-A-BGP-2.0
  longer-repeat #3 (4 runs) → 4/4 uniform
  `probe_io_all_connection_reset` + `reality_all_connection_reset`,
  zero divergence, probe_io class == reality class.
  R61+R62+R63 = **3/3 longer-repeat rounds satisfied**;
  closure_report rule "is_phase_shifting=false stably across 3+
  longer-repeat rounds" is met. HK-A-BGP-2.0 formally
  reclassified off analyst-layer bi-modal/phase-shifting
  suspect list. (2) Default planner: 0 uncovered;
  `--include-covered --limit 5` only returns 5 latest_all_ok
  recovery-watch nodes — sample face saturated. (3) Evidence
  `round63_stage3_hk_final_confirmation_summary.json` added;
  rollup 17→18 rounds, 109→113 runs, all_ok 24→24. Latest
  divergence/bi_modal/phase_shifting all `[]`;
  latest_stable_same_failure still the 6-node set. HK by_outbound:
  latest_round=63, is_bi_modal=false, is_phase_shifting=false,
  divergence_run_ratio=0.0. No sampler/dataplane patch. BHV
  52/56 unchanged. go_fork_source / .github/workflows untouched.
  Fresh-signal gate: next round needs user-supplied fresh
  REALITY/VLESS nodes or new config.
- R69 HK #2 (R62) classification A; R68 rollup ordering audit
  (c8f58140); R67 R61 recon (ba7aa8d7) classification A;
  v2 validator inbound field-lowering sweep B-tier deferred.

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

## Historical Detail

- R33-R60 full record + early ClientHello/Vision/REALITY history:
  agents-only/mt_real_02_baseline.md
- L01-L25 project history: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
