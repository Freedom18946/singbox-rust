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
  **190 tests PASS** (R81 added 14: 11 immediate + 3 committed-
  evidence contract).
- cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration: **17 PASS, 2 ignored**.
- live_rollup.json/md after R80: 23 rounds, 218 runs, 93 all_ok
  (R81 is no-live; rollup unchanged).

## Next Steps

- MT-REAL-02 R81 subset-schema pre-gate hardening DONE
  (2026-05-08). No live, no node contact, no sampler/dataplane.
  Closes R80 pre-gate gap: new module
  `reality_vless_subset_schema_gate.py` (prefix branch + reality/
  vless allow-list branch + recursive nested-prefix rule), wired
  into `reality_vless_probe_batch.py` dry-run path only. Dry-run
  gate failure: plan/summary/stdout carry
  `subset_schema_gate_passed=false`, exit 2. Live shape
  unchanged. Compat audit clean (cohort/plan/evidence consumers
  use dict.get). Violations carry only path/field/reason, no raw
  values. Classification A. BHV 52/56 unchanged; not parity
  completion. fresh04 retest still pending → recommended R82
  (cleansed subset, requires explicit re-authorization).
- MT-REAL-02 R80 fresh04 same-failure recheck DONE (2026-05-08).
  3/3 matrix_error due to `__id_in_gui` schema mismatch (closed
  by R81). Phase probe 3/3 timeout — supporting evidence
  consistent with R78 same-failure(timeout). Classification C.
  fresh04 latest_health: latest_same_failure → latest_unknown.
- MT-REAL-02 R79 fresh05 divergence-carrier recheck DONE
  (2026-05-08). 5/5 run_all_ok; R78 app_pre_post_diverged did not
  repeat; fresh05 latest_all_ok / recovered. BHV 52/56 unchanged.
- MT-REAL-02 R74/R75 evidence accounting + run_health
  materialization DONE (2026-05-08). Pure ledger work; tests +11.
- MT-REAL-02 R73 fresh REALITY/VLESS bounded live DONE (2026-05-08).
  15×5=75 executed. A — actionable; no new structural divergence.
- MT-MIXED-FRESH-01 mixed fresh config intake DONE (2026-05-07).
- MT-TROJAN-FRESH-15 line CLOSED (2026-05-07).

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

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY:
  agents-only/mt_real_02_baseline.md
- L01-L25: agents-only/archive/L*/
- Dual-kernel golden spec:
  labs/interop-lab/docs/dual_kernel_golden_spec.md
