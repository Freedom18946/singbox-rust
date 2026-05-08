# R78 - Cohort B same-failure bounded live confirmation (redacted)

Authorization: explicit user authorization for cohort B only. Outbounds: fresh03, fresh04, fresh05, fresh07. REALITY/VLESS only. No cohort A/C, no Hysteria2, no WS/plain-VLESS, no auto-extension beyond 12 runs.

## Pre-gate

- HEAD at gate: 65cabe41; main synced with origin/main: true
- intake counts: covered_existing=4, fresh_ready=0, duplicate=0, not_ready=0
- dry-run: selected_count=4, runs_per_outbound=3, planned_total_runs=12, target=example.com:80
- BHV: 52/56 unchanged

## Live scope

- executed_runs: 12 / 12
- outbounds: fresh03, fresh04, fresh05, fresh07
- runs_per_outbound: 3
- target: example.com:80
- cohort A/C executed: no
- Hysteria2 / WS / plain-VLESS live: no / no / no
- sampler/dataplane, go_fork_source/*, .github/workflows/*: untouched

## Run-health accounting

- run_all_ok: 8
- run_divergence: 1
- run_same_failure: 3
- run_unknown: 0
- divergence_phase_label_count: 1
- distinct_divergence_phase_label_count: 1
- divergence_phase_label_breakdown: {"app_pre_post_diverged": 1}

## Per-outbound comparison

| outbound | R73 run_health | R73 failure class | R78 run_health | R78 labels | assessment |
| --- | --- | --- | --- | --- | --- |
| fresh03 | ok=0, div=0, same_failure=5 | other | ok=3, div=0, same_failure=0 | all_ok=3 | resolved_to_all_ok |
| fresh04 | ok=0, div=0, same_failure=5 | other | ok=0, div=0, same_failure=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure_persists |
| fresh05 | ok=0, div=0, same_failure=5 | other | ok=2, div=1, same_failure=0 | all_ok=2, app_pre_post_diverged=1 | flipped_to_known_taxonomy_divergence; surface separately for cohort A-style re-evaluation |
| fresh07 | ok=0, div=0, same_failure=5 | connection_reset | ok=3, div=0, same_failure=0 | all_ok=3 | resolved_to_all_ok |

## fresh07 HK-symptom check

- R73: connection_reset same-failure, same symptom family as HK-A-BGP-2.0 R61-R63.
- R78: 3/3 all_ok; connection_reset same-type did not persist.

## Per-run facts

### fresh03

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_all_ok | all_ok |
| 2 | run_all_ok | all_ok |
| 3 | run_all_ok | all_ok |

### fresh04

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_same_failure | probe_io_all_timeout, reality_all_timeout |
| 2 | run_same_failure | probe_io_all_timeout, reality_all_timeout |
| 3 | run_same_failure | probe_io_all_timeout, reality_all_timeout |

### fresh05

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_divergence | app_pre_post_diverged |
| 2 | run_all_ok | all_ok |
| 3 | run_all_ok | all_ok |

### fresh07

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_all_ok | all_ok |
| 2 | run_all_ok | all_ok |
| 3 | run_all_ok | all_ok |

## Classification

- Final: A - actionable; no new structural divergence; mixed cohort B outcome.
- New structural divergence: false
- Unexpected phase labels: none
- fresh05 flipped to one known-taxonomy `app_pre_post_diverged` run; do not extend cohort B, surface fresh05 separately for cohort A-style re-evaluation.
- fresh04 remains node/env-health-limited same-failure, now timeout rather than R73 other.
- This is Rust/live supporting evidence only; it is not dual-kernel parity completion. BHV remains 52/56.

## Redaction

- Only neutral keys fresh03/fresh04/fresh05/fresh07 are committed.
- Raw tag/server/uuid/public_key/short_id/path/header/server_name/password material remains only in local /tmp inputs and is not committed.
