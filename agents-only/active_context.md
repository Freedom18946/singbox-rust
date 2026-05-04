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

Five latest non-all_ok candidates were falsified as noise by tooling
and live evidence. Latest all_ok baseline: 16 outbounds. Full evidence
evolution and falsified hypotheses live in
`agents-only/archive/mt_real_02/round_45_60_evidence_framework.md`.
Stage-2 closure rationale and stage-3 options:
`agents-only/archive/mt_real_02/closure_report.md`.

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
- python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py: 47 tests PASS
- live_rollup.json/md reflects 13 rounds, 90 executed runs, 21 all_ok
  runs.

## Next Steps

- WP LC-003-D-epsilon-retry CLOSED (fcdb9c65): Sub-WP D 6 files plus
  a kernel lifecycle scope expansion. Audit caught a dual-path race:
  populate_bridge_managers ran AFTER run_context_stage(Start) so
  ServiceManager.start_stage(Start) saw an empty registry, while a
  parallel start_services helper drove svc.start(stage) without
  writing ServiceManager.statuses, hiding bind failures from
  /services/health. Fix reorders populate before Start in all 4
  init/reload paths, drops the redundant helper drivers, and adds a
  service.rs regression test pinning the late-registration contract.
  LC-003 7/7 assertions PASS; ζ trace cleanup landed in the same
  series.
- BHV-LC-003 / DIV-H-006 in mt_gui_04_capability_inventory.md still
  flagged NOT-FEASIBLE; with LC-003 now verifiable, an audit WP can
  re-classify (out of this WP's scope).
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
