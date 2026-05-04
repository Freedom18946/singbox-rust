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
  62 tests PASS (R67 2026-05-04)
- live_rollup.json/md reflects 16 rounds, 105 executed runs, 24
  all_ok runs (R67 2026-05-04 added 3 R61 stage-3 batches).

## Next Steps

- R67 MT-REAL-02 Stage-3 Path A Round 61 sample-face recon COMPLETED
  (2026-05-04). Classification: **A — No new signal**. Three bounded
  live batches (15 runs, 3 all_ok): (1) stable same-failure × 4
  outbounds × 2 runs → JP-A-BGP-1.0 recovered, other 3 still in
  same node-level dead bucket; (2) phase-shifting × HK-A-BGP-2.0 ×
  4 runs → uniform probe_io+reality connection_reset, single round
  does not falsify prior bi-modal per closure_report's 3+-round rule;
  (3) sanity × 3 all_ok × 1 run → HK-A-BGP-0.3 healthy, HK-A-BGP-1.0
  & 2.5 decayed to uniform connection_reset. probe_io class == reality
  class on every failing run → no transport-vs-app signal. Three
  evidence files in mt_real_02_evidence/round61_stage3_*; rollup
  rebuilt (16 rounds, 105 runs, 24 all_ok; recovered 2→3; latest
  stable same-failure 4→5; phase-shifting now empty in latest 3-round
  window). No sampler/dataplane patch. BHV unchanged (52/56).
- R66 BHV-SV-005/006/007 (DIV-H-005, commit b15e814c, 2026-05-04):
  Class C — Rust honest provider routes (3/3 e2e PASS); Go fork has
  hard-coded stubs, tunnel lookups commented out, method divergence
  on healthcheck.
- R65 BHV-LC-003 (DIV-H-006, commit 833753dc, 2026-05-04):
  Class C — Rust honest broken-service fixture + live
  `/services/health`; Go fork has no route, no `ServiceStatus`,
  fail-fast `Manager.Start`.
- v2 validator inbound field-lowering sweep
  (vmess/vless/trojan/anytls/shadowtls/naive) remains B-tier deferred.
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

- R33-R60 full record: agents-only/mt_real_02_baseline.md
- Early ClientHello, Vision, and REALITY history:
  agents-only/mt_real_02_baseline.md
- L01-L25 project history: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
