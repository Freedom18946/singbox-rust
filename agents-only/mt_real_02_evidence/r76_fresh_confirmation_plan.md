# R76 — Fresh REALITY/VLESS confirmation plan (no-live)

Authorization: NOT YET AUTHORIZED. This is a planning artifact only. Live execution requires a separate explicit user authorization that names the cohort(s) to run. Default recommendation: authorize cohort A only (10 runs) first; B and C wait on the A outcome.

Source round: R73 — `agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.json`. Cohort grouping is derived from the materialized `by_outbound[*].run_health_counts` field added in R75 (see `scripts/tools/round_summary_run_health.py`). The cohort classifier itself lives at `scripts/tools/reality_vless_confirmation_cohorts.py`.

## Cohort summary

| Cohort | Outbounds | runs/outbound | planned_total_runs | Default authorization order |
| --- | --- | ---: | ---: | --- |
| A — divergence carrier | fresh02, fresh06 | 5 | 10 | first (recommended) |
| B — same failure | fresh03, fresh04, fresh05, fresh07 | 3 | 12 | second; defer until A landed |
| C — recovery watch | fresh01, fresh09, fresh15 | 3 | 9 | third; defer until A and B landed |

Combined planned ceiling across all three cohorts: 31 live runs.
Recommended first authorization: cohort A only, 10 runs.

## Cohort A — divergence carrier

- outbounds: fresh02, fresh06
- selected_count: 2
- runs_per_outbound: 5
- planned_total_runs: 10
- objective: Confirm whether the 2 R73 divergence-carriers reproduce phase divergence and whether all repeat samples stay inside the four MT-REAL-02 phase labels (app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged). 5 runs each is enough to land at least one second-round confirmation sample if R73 phase-mix repeats; if phase mix shifts, the round-level run_divergence count and phase-label breakdown will diverge from R73 (fresh02 had 1 run_divergence carrying 2 phase labels; fresh06 had 1 run_divergence carrying 3 phase labels).
- entry_gate: Pre-gate: re-run reality_vless_sample_intake.py on the cohort-only neutral subset; confirm fresh_ready=2, covered_existing=2 (both already in rollup post-R73), duplicate=0; require explicit user authorization listing this cohort by name; require BHV 52/56 unchanged at gate time.
- stop_condition: Stop after 5 runs/outbound = 10 runs total. Do not auto-extend. Do not promote phase labels to S4 entries. If a NEW phase label appears (something outside the four enumerated in reality_vless_evidence_rollup.DIVERGENCE_PHASE_LABEL_ORDER), stop the round mid-flight and report; this would indicate a structural taxonomy change requiring its own audit.
- notes: fresh02 R73 facts: 1 run_divergence (app_pre_post + app_minimal) + 4 run_same_failure (timeout). fresh06 R73 facts: 1 run_divergence (app_minimal + bridge_io + minimal_transport) + 3 run_same_failure (other) + 1 run_all_ok.

Expected classifications:

- **A**: Repeated divergence stays inside the existing four phase labels; no new phase label appears; phase-label totals may shift in count but not in kind. Most likely outcome.
- **B**: fresh02 keeps timing out (4/5 timeouts in R73 already) and we get fewer than 1 divergence sample due to node-health; classification stays node-health-limited, not sampler.
- **C**: A tooling or dataplane regression surfaces (e.g. config normalization fails, validator rejects); abort the round before any retry and treat as tooling/dataplane blocker.
- **D**: Pre-gate identity fails (fresh_ready != 2, BHV != 52/56, or no explicit authorization). Live MUST NOT start.

## Cohort B — same failure

- outbounds: fresh03, fresh04, fresh05, fresh07
- selected_count: 4
- runs_per_outbound: 3
- planned_total_runs: 12
- objective: Confirm same-failure stability across a second round. Per the closure_report rule a same-failure outbound only formally closes after 3+ longer-repeat rounds; this round is round 2. fresh07 carries the same uniform connection_reset symptom as HK-A-BGP-2.0 in R61-R63 and must be tagged so for telemetry. 3 runs/outbound matches the minimum longer-repeat depth in prior rounds (R59-B/R60/R61/R62/R63 family).
- entry_gate: Pre-gate: same intake re-run as cohort A but expect covered_existing=4. Authorization must explicitly list this cohort. BHV 52/56 unchanged.
- stop_condition: Stop after 3 runs/outbound = 12 runs total. If any same-failure outbound flips to run_divergence in this round, do NOT extend cohort B; instead, surface that outbound separately for the next round's cohort A re-evaluation.
- notes: fresh03/04/05 R73 facts: 5/5 run_same_failure (probe_io_all_other + reality_all_other). fresh07 R73 facts: 5/5 run_same_failure (probe_io_all_connection_reset + reality_all_connection_reset) — same-symptom signal as HK-A-BGP-2.0 R61-R63.

Expected classifications:

- **A**: All 4 outbounds remain 3/3 same-failure with the R73 failure label distribution unchanged (fresh03/04/05 stay probe_io_all_other + reality_all_other; fresh07 stays connection_reset). After this round 2, one more round 3 would satisfy the "3+ longer-repeat rounds" closure rule.
- **B**: Mixed fates within a node — partial timeouts replace the previously uniform other/connection_reset. Still node-health limited; downgrade depth in next round, do not promote.
- **C**: Tooling/dataplane blocker; abort.
- **D**: Pre-gate identity fails; live MUST NOT start.

## Cohort C — recovery watch

- outbounds: fresh01, fresh09, fresh15
- selected_count: 3
- runs_per_outbound: 3
- planned_total_runs: 9
- objective: Begin building round-2 evidence for recovery confirmation. closure_report rule: recovery classification requires THREE rounds of consistent run_all_ok. R73 was round 1. We sample 3 representative outbounds out of 9 (R73 5/5 set: fresh01, fresh08-fresh15) at depth 3, not all 9 at depth 2: 3 runs/node satisfies the longer-repeat shape used in R59-B/R60/R61/R62/R63, while 2 runs would be too shallow to count as a longer-repeat round. Selecting 3 reps (not 5) follows minimum-authorization. The remaining 6 (fresh08, fresh10, fresh11, fresh12, fresh13, fresh14) are NOT closed; they sit at round-1-only and become eligible for a future R77/R78 cohort C extension.
- entry_gate: Pre-gate: same intake re-run on the 3-rep neutral subset. Authorization must list these 3 outbounds explicitly. BHV 52/56 unchanged. Reps were chosen by ordinal spread (fresh01 lower, fresh09 middle, fresh15 upper) to avoid clustering on one geographic region; ordinal spread is the only signal available without re-leaking original tags.
- stop_condition: Stop after 3 runs/outbound = 9 runs total. Do not promote any outbound to "recovered" classification on this round's evidence alone — that requires a third (R77-style) round per closure_report.
- notes: Representatives: ['fresh01', 'fresh09', 'fresh15']. The 6 not selected (fresh08, fresh10, fresh11, fresh12, fresh13, fresh14) remain at R73 round-1-only and stay eligible for future rounds.

Expected classifications:

- **A**: 3/3 run_all_ok per representative — round 2 of recovery confirmation banked; remaining 6 stay at round-1-only.
- **B**: One representative produces same-failure or partial all_ok (node-health drift since R73). Do not promote any rep; in next round rotate the failing rep out and pull a different one from the 6 unselected.
- **C**: Tooling/dataplane blocker; abort.
- **D**: Pre-gate identity fails; live MUST NOT start.

## Recovery-watch outbounds NOT selected this round

- fresh08, fresh10, fresh11, fresh12, fresh13, fresh14

These remain at R73 round-1-only. They are eligible for a future R77/R78-style cohort C extension but are explicitly NOT promoted to round-2 evidence under this plan.

## Dry-run command suggestions (do NOT run live until authorized)

- **pre-gate intake** — Re-derives fresh_ready / covered_existing on the cohort subset only. Run before any live authorization to confirm the cohort still maps cleanly onto the rollup.
  ```
  python3 scripts/tools/reality_vless_sample_intake.py --candidate-config /tmp/<cohort>_subset.json --rollup-json agents-only/mt_real_02_evidence/live_rollup.json --output-json /tmp/<cohort>_intake.json
  ```

- **pre-gate plan dry-run** — Confirms target/timeout/runs/selected_count without opening a socket. Mirrors what R73 ran for its identity gate.
  ```
  python3 scripts/tools/reality_vless_probe_batch.py --config /tmp/<cohort>_subset_clean.json --plan-json /tmp/<cohort>_plan.json --runs <N> --target example.com:80 --timeout 10 --phase-timeout-ms 10000 --probe-io-timeout-ms 10000 --output-dir /tmp/<cohort>-dryrun --dry-run
  ```

- **live invocation TEMPLATE (DO NOT RUN until authorized)** — Same shape as R73 minus --dry-run. Expect to be preceded by an explicit user authorization message naming this cohort.
  ```
  python3 scripts/tools/reality_vless_probe_batch.py --config /tmp/<cohort>_subset_clean.json --plan-json /tmp/<cohort>_plan.json --runs <N> --target example.com:80 --timeout 10 --phase-timeout-ms 10000 --probe-io-timeout-ms 10000 --output-dir /tmp/<cohort>-live
  ```

## Authorization scope constraints

- No Hysteria2 live (consistent with all prior MT-REAL-02 rounds).
- No WS / plain-VLESS live (consistent with R73 cohort scope).
- No sampler/dataplane modification.
- No go_fork_source/* modification.
- No .github/workflows/* modification.
- BHV 52/56 must remain unchanged through any live execution; this is a Rust-only quality / supporting-evidence line, not a dual-kernel parity event.

## Redaction

- All outbound names in this plan are neutral keys (fresh01..fresh15) introduced in R73 pre-gate. No raw tag, server, uuid, public_key, short_id, server_name, path, header, or password is referenced.
- Cohort C representatives (fresh01, fresh09, fresh15) are chosen by ordinal spread; the original geographic regions of these neutral keys are not exposed here.

## Status flags

- live_executed: False
- node_contact_executed: False
- sampler_dataplane_modified: False
- go_fork_source_modified: False
- github_workflows_modified: False
- bhv_52_56_unchanged_at_plan_time: True
