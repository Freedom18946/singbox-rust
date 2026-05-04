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

- cargo check --workspace: PASS
- python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification:
  68 tests PASS.
- live_rollup.json/md: 17 rounds, 109 runs, 24 all_ok (R69 added
  R62 HK-confirmation #2).

## Next Steps

- R69 stage-3 current-sample closure + fresh-signal gate COMPLETED
  (2026-05-04). Classification: **A — Current sample closed / no
  new signal**. (1) HK-A-BGP-2.0 longer-repeat #2 (4 runs) → 4/4
  uniform `probe_io_all_connection_reset` + `reality_all_connection_reset`,
  zero divergence. probe_io class == reality class. R61 + R62 are
  now 2/3 longer-repeat rounds satisfying closure_report's
  reclassification rule; **one more longer-repeat round still
  needed** before HK formally moves off bi-modal/phase-shifting.
  (2) Default planner from current `phase3_ip_direct.json` selected
  0 uncovered candidates; `--include-covered --limit 5` only surfaced
  5 latest_all_ok recovery-watch nodes — committed sample face is
  saturated. (3) Evidence file `round62_stage3_hk_confirmation_summary.json`
  added; rollup totals 16→17 rounds, 105→109 runs, all_ok 24→24.
  Latest lists unchanged from R68 baseline (latest_divergence still
  empty; latest_stable_same_failure still the 6-node set). No
  sampler/dataplane patch. BHV unchanged (52/56). go_fork_source
  untouched. Fresh-signal gate verdict: **next signal-hunting round
  requires user-supplied fresh REALITY/VLESS nodes or a new config**;
  old samples cannot manufacture new structural signal.
- R68 rollup round-ordering audit (c8f58140): fixed `round_sort_key`
  + argv-independent input ordering; 68 Python tests pass.
- R67 stage-3 path A R61 recon (ba7aa8d7) classification A still
  holds under repaired rollup.
- R66 BHV-SV-005/006/007 (DIV-H-005, b15e814c) Class C; R65
  BHV-LC-003 (DIV-H-006, 833753dc) Class C.
- v2 validator inbound field-lowering sweep B-tier deferred.

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
