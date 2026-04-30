<!-- tier: C -->
# MT-REAL-02 R45-R60 Evidence Framework Evolution

> Archive of evidence-tooling progression from rollup origin (R45)
> through bi-modal/phase-shifting metrics (R60). For full-detail
> reasoning per round, grep agents-only/mt_real_02_baseline.md.

## Tool capability timeline

| Round | Date | Tool delta | Key insight |
| --- | --- | --- | --- |
| R45 | 2026-04-26 | rollup origin | aggregate dashboard built |
| R46 | 2026-04-26 | coverage planner | uncovered/prior_non_all_ok/covered_all_ok buckets |
| R47-R52 | 2026-04-26 | live coverage runs + planner sentinel exclusion | full ready-node coverage of phase3 config |
| R53 | 2026-04-26 | latest-aware rollup/planner | one-shot historical failures stop dominating recheck queue |
| R54 | 2026-04-26 | latest non-all-ok repeat | 6 nodes confirmed as stable failure buckets |
| R55 | 2026-04-26 | plan-json batch + latest_health | reproducible planner -> batch pipeline |
| R56 | 2026-04-29 | health-aware planner + batch hard timeout | recovered set first identified (US-0.8) |
| R57 | 2026-04-29 | per-run health rollup | HK-A-BGP-2.0 isolated as mixed run-health |
| R58 | 2026-04-30 | --only-latest-run-health | 4 stable same-failure separated from HK mixed |
| R59-A | 2026-04-30 | divergence_phase_counts | per-phase composition visible |
| R59-B | 2026-04-30 | phase_dominance metric + HK 12-run | HK 50/50 bi-modal exposed |
| R60 | 2026-04-30 | bi_modal + phase_shifting + 4-node 4-run | all candidates classified, no sampler signal |

## Conclusive classifications at R60 close

- Node-level dead buckets:
  - JP-A-BGP-0.3: reality_dial_eof
  - JP-A-BGP-1.0: timeout
  - UK-A-BGP-0.5: connection_reset
  - US-A-BGP-0.5: connection_reset
- Bi-modal + phase-shifting noise bucket:
  - HK-A-BGP-2.0: R59-B 12 runs had 6 divergence-bearing samples
    and 6 uniform timeout samples; dominant phase oscillates between
    app_pre_post_diverged and app_minimal_diverged across rounds.
- Recovered nodes:
  - TW-A-BGP-1.0: R47 one-shot divergence, R48 3/3 all_ok.
  - US-A-BGP-0.8: R49-R50 probe IO matched failure, R56 2/2 all_ok.
- Latest all_ok baseline:
  - 16 outbounds.

## Falsified hypotheses

- "HK is sampler signal" was falsified by R57 mixed phase evidence
  plus R59-B cross-round dominant phase shift.
- "Stable same-failure 4 nodes are sampler signal" was falsified by
  R60 4-run repeat staying 100 percent same-class with no divergence.
- "Single-round phase dominance ratio determines bucket type" was
  falsified by HK keeping ratio 0.6667 while dominant phase changed
  from app_minimal_diverged in R57 to app_pre_post_diverged in R59-B.
  Real signal requires cross-round comparison via is_phase_shifting.

## Evidence file index

- live_rollup.json / live_rollup.md: regenerated through R60.
- round41, round42, round44, round47, round48, round50, round52,
  round54, round56, round57, and round58 evidence summaries.
- round59b_hk_longer_repeat_summary.json.
- round60_stable_same_failure_longer_repeat_summary.json.
