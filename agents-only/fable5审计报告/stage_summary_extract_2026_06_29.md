<!-- tier: B -->
# fable5 Stage Summary Extract - 2026-06-29

> Source: the 8 top-level fable5 reports in this directory, generated 2026-06-10
> at HEAD `02d8d16e`.
> Purpose: preserve the conclusions that are useful for a stage summary, without
> re-promoting obsolete audit findings into current truth.

## Disposition

- Keep the 8 raw reports in `agents-only/fable5审计报告/` and commit them.
- Do not move this directory to `agents-only/archive/` in this cleanup round: the
  tracked `post_fable_packages/` map, `docs/STATUS.md`, and capability snapshots
  still point here as a live historical anchor.
- Treat the raw reports as B-tier historical calibration. They are evidence for how
  the post-FABLE work was discovered, not the live blocker list.
- For current status, read `agents-only/active_context.md`,
  `agents-only/fable5审计报告/post_fable_packages/README.md`, and
  `agents-only/post1313/`.

## Stage-Summary Conclusions

1. fable5 was the pre-closeout calibration snapshot that explained why prior
   "closed" ledgers did not equal GUI drop-in readiness. It identified gaps that
   sat outside the earlier acceptance axes: GUI launch contract, strict GUI config
   schema, WireGuard endpoint/outbound wiring, TUN usability, reload continuity,
   inbound readiness/liveness, and documentation/test drift.

2. The audit also established positive ground truth. Clash API, selector
   persistence, mainstream outbound assembly, socks/http/mixed inbound paths, DNS
   and SRS parsing, rollback cleanup, V2Ray reuse, bad-config rejection, and
   protocol parse panic safety already had meaningful evidence at the time.

3. The strongest technical seed was the reload/liveness cluster: old inbounds were
   stopped before new activation, inbound bind failures were not part of startup or
   reload success criteria, runtime registries could be installed before swap, and
   inbound serve tasks lacked monitor/ready semantics. This became the source
   material for post-FABLE reload and liveness packages.

4. The strongest product seed was the GUI-entry cluster: `sing-box started`, GUI TUN
   schema, GUI/default DNS schema, runtime build profile, and real Wails automation
   all needed explicit evidence. Later post-FABLE and P1313 work absorbed this line;
   raw fable5 P0s should not be restated as current blockers without rechecking the
   package map.

5. Documentation and gate drift were real but bounded. The useful lesson is not a
   fresh defect count; it is the rule that external-facing docs and capability
   snapshots must point to current authority instead of copying volatile numbers.

## Current-State Translation

- `post_fable_packages/README.md` maps fable5 CAL findings to packages 01-19. Most
  automatic packages are marked DONE there; package07/Wails GUI joint testing
  remains partial/paused by strategy.
- `agents-only/post1313/` records the later Go 1.13.13 / GUI 1.25.1 refresh. P1313-12
  and the 2026-06-28 strict revalidation are the newer contract references.
- `agents-only/active_context.md` remains the only place to quote volatile phase,
  gate, parity, and current-next-step facts.

## Recommended Wording For A Phase Summary

Use this wording, or something close:

> fable5 was retained as the June 10 historical calibration that generated the
> post-FABLE package map. Its raw P0/P1 findings are not current status by
> themselves; they explain the origin of the GUI-contract, schema, WireGuard, TUN,
> reload, liveness, lint/test, and documentation closeout lines. Current truth is
> tracked by `active_context.md`, the post-FABLE package map, and post1313 records.
