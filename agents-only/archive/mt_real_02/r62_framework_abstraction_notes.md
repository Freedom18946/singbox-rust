<!-- tier: B -->
# R62 Framework Abstraction Notes
> Date: 2026-04-30
> Scope: R62-A pure refactor only

## Goal

R62-A starts Stage-3 Path B by extracting the reusable evidence
classification primitives from the REALITY rollup script. Behavior
must remain unchanged.

## Design choices

- Use a Python package, not a Rust crate.
  - The current evidence loop is Python-based.
  - Keeping it in scripts/tools avoids cargo workspace churn.
- Keep functions stateless and function-based.
  - No classes were introduced.
  - R62-B can compose them for a fake protocol smoke test.
- Keep protocol-specific divergence phase labels in the caller.
  - REALITY still owns its 4 divergence phase labels in
    reality_vless_evidence_rollup.py.
  - The generic package receives the label set as a parameter.
- Keep thresholds as default function parameters.
  - dominant_threshold=0.75
  - no_dominance_threshold=0.50
  - bi-modal ratio window=(0.25, 0.75)
  - bi-modal min_runs=6
  - phase-shifting window=3
  - No CLI flags were added in R62-A.
- Keep I/O and schema orchestration in the REALITY wrapper.
  - Evidence loading, rollup aggregation, JSON/MD output, and field
    ordering remain in reality_vless_evidence_rollup.py.

## Extracted API

- classify_run_health
- classify_outbound_latest_health
- compute_phase_counts
- compute_phase_dominance
- compute_bi_modal
- compute_phase_shifting

## Verification

- Existing Python tests remain at 47 tests.
- Regenerated live_rollup.json is byte-identical to the pre-refactor
  backup.
- R62-B should extract planner filter predicates and add a non-REALITY
  smoke test to prove the package is genuinely reusable.
