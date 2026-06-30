<!-- tier: C -->
# Legacy Research And Logs Summary

Purpose: replace old `analysis/`, `dump/`, `workflows/`, `layer12-review-2026-03/`, `logs/`, and `TBD.md` raw archive material.

## Analysis

- L1/L2/L4 acceptance-gap analyses are closed history.
- Clash API audit tracked and fixed multiple P0/P1/P2 shape and behavior gaps; remaining cosmetic/extra fields were accepted where documented.
- Dependency, crate, feature, and violation inventories are old baselines. Re-run current tooling before making any present-tense claim.
- L2.7 URLTest was implemented; L2.8/L2.9/L2.10 docs were planning/prework, not live queues.

## Dump

- Old dumps contained Go-spec intake and prework for CacheFile and ConnMetadata.
- Durable result: those lines fed L03 service completion; raw notes are no longer needed for navigation.

## Workflows

- Early workflow/blocker/refactor/test maps belonged to L1-era planning.
- GitHub Actions/workflow automation remains permanently disabled by current project rules. Old workflow docs do not override that.

## Layer 1/2 Review

- Layer 1/2 reviews found global state, panic-surface, `super::`, public re-export, and boundary issues.
- Many were remediated during maintenance and audit lines.
- Treat remaining categories as structural-quality guidance only; verify current code before opening work.

## Logs

- Old logs and historic `workpackage_latest` snapshots were compressed. They are not startup reading.
- Use current `active_context.md` and `workpackage_latest.md`; use `log.md` only for targeted archaeology.

## TBD

- Old TBD material had no current authority after L/MT closeout. Current next steps live in `active_context.md`.
