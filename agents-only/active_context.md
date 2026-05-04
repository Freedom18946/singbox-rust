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
  **75 tests PASS** (R71 +7 intake tests).
- live_rollup.json/md unchanged: 18 rounds, 113 runs, 24 all_ok.

## Next Steps

- R71 fresh sample intake gate DONE (2026-05-04). Classification:
  **A — intake gate ready, waiting for fresh config**. New tool
  `scripts/tools/reality_vless_sample_intake.py` validates a
  candidate REALITY/VLESS config against the committed baseline +
  rollup and emits redacted (SHA-256/12) classifications:
  `fresh_ready` / `duplicate` / `not_ready` / `covered_existing`.
  Tag-collision and fingerprint-collision paths both detected;
  raw UUID / public_key / short_id / server never written. Operator
  guide at `agents-only/mt_real_02_fresh_sample_intake.md` (A-tier).
  No fresh config supplied this round → 0 fresh_ready candidates;
  R72 cannot start until operator drops a candidate config per
  intake doc step 1. No live probe. No sampler/dataplane patch.
  No edits to baseline `phase3_ip_direct.json`, `go_fork_source/*`,
  or `.github/workflows/*`. BHV 52/56 unchanged.
- R70 HK final confirmation + current-sample-face closure DONE
  (ac57c2fe). Classification A. R61+R62+R63 = 3/3 longer-repeat
  rounds; HK-A-BGP-2.0 formally reclassified off
  bi-modal/phase-shifting suspect list. closure_report addendum
  written. Fresh-signal gate verdict carried forward into R71.
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
