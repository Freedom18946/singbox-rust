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

## Generic evidence schema (R62-B closure)

R62-B closes the framework abstraction by extracting planner filter
predicates from the protocol wrapper. A protocol-specific caller still
owns evidence loading and plan rendering, but the filter semantics are
now reusable.

Per-outbound rollup entries consumed by the generic filters:

- latest_label_counts
- latest_run_health_counts (planner-facing latest run label counts)
- latest_round_run_count
- latest_divergence_run_count
- latest_divergence_phase_counts
- latest_divergence_phase_dominance
- is_phase_shifting
- dominant_phase_history

Protocol-specific caller inputs:

- divergence_phase_labels: frozenset[str]
- outbound names, config shape, and evidence file layout
- any protocol-specific phase label vocabulary

Default thresholds, all overrideable at function call sites:

- dominant_threshold=0.75
- no_dominance_threshold=0.50
- bi_modal ratio window=(0.25, 0.75)
- bi_modal min_runs=6
- phase_shifting window=3

Planner filter primitives:

- passes_latest_health
- passes_latest_run_health
- passes_only_latest_run_health
- passes_latest_phase_dominance
- passes_bi_modal
- passes_phase_shifting

The fake-protocol smoke tests use phase_alpha, phase_beta,
phase_gamma, and phase_delta labels to verify that the health,
phase-metric, and planner-filter layers have no dependency on the
REALITY phase vocabulary.
