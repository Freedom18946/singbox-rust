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
  **142 tests PASS**.
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md after R73: 19 rounds, 188 runs, 70 all_ok
  (was 18 / 113 / 24).

## Next Steps

- MT-REAL-02 R75 fresh divergence attribution + run_health
  materialization DONE (2026-05-08). No-live; no-node-contact. Per-run
  `run_health` now materialized into round73 `runs[]` via the new
  `scripts/tools/round_summary_run_health.py::materialize_run_health`
  helper; round73 summary + by_outbound recomputed from per-run facts
  (75 / 46 / 2 / 27 / 5 / 4). fresh02 (app_pre_post + app_minimal) and
  fresh06 (app_minimal + bridge_io + minimal_transport) phase labels
  attribute under golden_spec S4 `DEV-REALITY-01` (ARCH-LIMIT) — no
  new S4 entry needed. live_rollup deterministically regenerates
  identically to R74. Tests +7 (`RoundSummaryRunHealthMaterialization
  Tests`). BHV 52/56 unchanged.
- MT-REAL-02 R74 R73 evidence accounting audit DONE (2026-05-08).
  Pure ledger correction: split divergence_run_count from
  divergence_phase_label_count. R73 corrected facts unchanged.
  Tests +4 (`RunDivergenceAccountingTests`).
- MT-REAL-02 R73 fresh REALITY/VLESS bounded live DONE (2026-05-08).
  15×5=75 executed; rollup +1 round, +75 executed_runs, +46 run_all_ok,
  +15 outbound keys (neutral fresh01..fresh15). Hys2/WS/plain-VLESS
  live: 0. Classification A — actionable; no new structural divergence.
- MT-MIXED-FRESH-01 mixed fresh config intake DONE (2026-05-07). A —
  no-live; redacted intake only. WS audit: max_early_data +
  early_data_header_name silently dropped (5/5 = 2048 → 0; header
  default match). Hys2 readiness 12/12, no live tool.
- MT-TROJAN-FRESH-15 success-evidence cosmetic + line closure DONE
  (2026-05-07). MT-TROJAN-FRESH line CLOSED.
- R71 fresh sample intake DONE (2026-05-04) A.

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

- R33-R60 + early ClientHello/Vision/REALITY:
  agents-only/mt_real_02_baseline.md
- L01-L25: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
