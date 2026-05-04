<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 100 lines.

---

## Strategic State

Current phase: MT-REAL-02 stage-2 evidence-driven loop is closed
through R45-R60.

Parity: 52/56 BHV (92.9%); ARCH-LIMIT-REALITY remains the accounting
label.

Current focus: stage-3 path selection. R62 framework abstraction is
closed; next is the R63 dual-kernel gap. Stage-3 Path A (expand sample
face) is on demand only.

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
  68 tests PASS (R68 added 6 ordering tests).
- live_rollup.json/md: 16 rounds, 105 runs, 24 all_ok (R68 rebuilt
  with deterministic round ordering).

## Next Steps

- R68 rollup round-ordering audit COMPLETED (2026-05-04). Root cause:
  `round_sort_key` returned `(0, int)` for pure-int rounds and
  `(1, str)` for suffixed ones, so `"59-B"` sorted AFTER `"61"` and
  pinned `HK-A-BGP-2.0.latest_round` to `59-B`. Fix: parse leading
  int + suffix → `(major, suffix)`, giving `58 < 59 < 59-B < 60 < 61`;
  also canonicalize `--evidence` input order by `(round_sort_key,
  path basename)` so latest-state is argv-independent. After rebuild:
  HK-A-BGP-2.0 → `latest_round=61`, `latest_health=latest_same_failure`,
  no longer in `latest_divergence_outbounds` (now empty); joins
  `latest_stable_same_failure_outbounds` (count 5→6). No sampler/
  dataplane patch. BHV unchanged (52/56).
- R67 stage-3 path A R61 recon (commit ba7aa8d7) classification A
  (no new signal) still holds under repaired rollup; only the latest_*
  attribution moved from divergence to same-failure for HK-A-BGP-2.0.
- R66 BHV-SV-005/006/007 (DIV-H-005, commit b15e814c): Class C —
  Rust honest provider routes; Go fork has hard-coded stubs.
- R65 BHV-LC-003 (DIV-H-006, commit 833753dc): Class C — Rust honest
  broken-service fixture + live `/services/health`; Go fork has no
  route, no `ServiceStatus`, fail-fast `Manager.Start`.
- v2 validator inbound field-lowering sweep B-tier deferred.
- resolved-error-propagation still on case_backlog.md as B-tier.

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
