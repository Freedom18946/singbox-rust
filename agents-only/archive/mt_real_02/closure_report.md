<!-- tier: B -->
# MT-REAL-02 Stage-2 Closure Report

> Date: 2026-04-30
> Closes: evidence-driven loop R45-R60
> Does NOT close: MT-REAL-02 as a project. Stage-3 paths are below.

## What stage-2 was

A 16-round evidence-tooling loop driven by the rule:
"classify first, only touch sampler/dataplane on stable structural
signal."

The loop built an evidence framework that mechanically classifies every
outbound's behavior across rounds. Future "this looks weird" reactions
can now be checked against committed rollup fields instead of manual
log reading.

## What stage-2 proved

Two propositions now have mechanical evidence.

1. No outbound in the current sample set carries a sampler or dataplane
   signal. Every latest non-all_ok node has been reduced to either a
   node-level dead bucket or cross-round mixed noise. See
   round_45_60_evidence_framework.md for per-node classification.

2. The classification is machine-readable. Rollup exposes
   latest_health, latest_run_health_counts,
   latest_divergence_phase_counts,
   latest_divergence_phase_dominance,
   latest_divergence_run_ratio, is_bi_modal,
   dominant_phase_history, is_phase_shifting, and matching top-level
   outbound lists. Planner can filter on all of them.

No future MT-REAL-02 round needs to re-derive these categories by hand.

## Why this matters for the highest goal

The user's highest goal is a Rust binary that can drop-in replace Go
sing-box. Stage-2 closure does not mean MT-REAL-02 is done. It means
the current evidence regime has saturated.

To make further sampler/dataplane judgments, one of the stage-3 paths
below must expand or reuse the regime.

## Stage-3 paths

Path A: expand sample face.

Add new configs, nodes, network conditions, and time windows. Tooling
is ready. The constraint is real-node availability and operator time.
This path may yield zero new signal per round.

Path B: abstract evidence framework.

Lift latest_health, phase_dominance, bi_modal, and phase_shifting from
REALITY-specific rollup into a generic dual-kernel verification harness
that other protocols can reuse. This is medium engineering work and
multiplies tool ROI.

Path C: pivot to next dual-kernel gap.

Use labs/interop-lab/docs/dual_kernel_golden_spec.md S5 to pick the
next high-priority BHV gap and start a fresh stage on another protocol.
This leaves MT-REAL-02 in maintenance.

User-elected order recorded on 2026-04-30:

1. R61 closure and active_context trim.
2. R62 path B framework abstraction.
3. R63 path C next dual-kernel gap.

Path A is on demand only.

## What not to do post-closure

- Do not run a fresh MT-REAL-02 sampler/dataplane patch round unless a
  new evidence regime first surfaces a stable signal.
- Do not retry hypotheses listed under "Falsified hypotheses" in
  round_45_60_evidence_framework.md.
- Do not reclassify HK-A-BGP-2.0 as a sampler signal from any single
  future run. Only is_phase_shifting=false stably across 3 or more
  longer-repeat rounds would change that.

## Addendum: HK-A-BGP-2.0 post-closure reclassification (2026-05-04)

The 3-round longer-repeat rule above is now satisfied:

- R61 (2026-05-04, 4 runs): 4/4 uniform
  `probe_io_all_connection_reset` + `reality_all_connection_reset`,
  zero divergence.
- R62 (2026-05-04, 4 runs): 4/4 same uniform same-failure shape,
  zero divergence.
- R63 (2026-05-04, 4 runs): 4/4 same uniform same-failure shape,
  zero divergence; probe_io class == reality class on every run.

In the rebuilt rollup HK-A-BGP-2.0 now reports `latest_round=63`,
`is_bi_modal=false`, `is_phase_shifting=false`,
`latest_divergence_run_ratio=0.0`. HK-A-BGP-2.0 is therefore formally
removed from the analyst-layer bi-modal / phase-shifting suspect
list under the rule defined above. It remains in the
`latest_stable_same_failure` bucket with the other five committed
node-level dead nodes; that does not constitute a sampler or
dataplane signal.

This reclassification did not patch sampler or dataplane, did not
modify `go_fork_source/*` or `.github/workflows/*`, and did not
change the BHV ledger (52/56). Stage-3 path A on the committed
`phase3_ip_direct.json` sample face is now exhausted — fresh signal
hunting requires user-supplied fresh REALITY/VLESS nodes or a new
config.
