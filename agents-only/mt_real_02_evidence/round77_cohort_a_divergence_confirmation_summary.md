# R77 - Cohort A divergence-carrier bounded live confirmation (redacted)

Authorization: explicit user authorization for cohort A only. Outbounds: fresh02, fresh06. REALITY/VLESS only. No cohort B/C, no Hysteria2, no WS/plain-VLESS, no auto-extension beyond 10 runs.

## Pre-gate

- HEAD at gate: 214eb67a; main synced with origin/main: true
- intake counts: covered_existing=2, fresh_ready=0, duplicate=0, not_ready=0
- dry-run: selected_count=2, runs_per_outbound=5, planned_total_runs=10, target=example.com:80
- BHV: 52/56 unchanged

## Live scope

- executed_runs: 10 / 10
- outbounds: fresh02, fresh06
- runs_per_outbound: 5
- target: example.com:80
- cohort B/C executed: no
- Hysteria2 / WS / plain-VLESS live: no / no / no
- sampler/dataplane, go_fork_source/*, .github/workflows/*: untouched

## Run-health accounting

- run_all_ok: 10
- run_divergence: 0
- run_same_failure: 0
- run_unknown: 0
- divergence_phase_label_count: 0
- distinct_divergence_phase_label_count: 0
- divergence_phase_label_breakdown: {}

## Per-outbound comparison

| outbound | R73 run_health | R73 phase labels | R77 run_health | R77 phase labels | assessment |
| --- | --- | --- | --- | --- | --- |
| fresh02 | ok=0, div=1, same_failure=4 | app_minimal_diverged=1, app_pre_post_diverged=1 | ok=5, div=0, same_failure=0 | - | R73 divergence resolved to 5/5 all_ok in R77 |
| fresh06 | ok=1, div=1, same_failure=3 | app_minimal_diverged=1, bridge_io_diverged=1, minimal_transport_diverged=1 | ok=5, div=0, same_failure=0 | - | R73 divergence resolved to 5/5 all_ok in R77 |

## Per-run facts

### fresh02

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_all_ok | all_ok |
| 2 | run_all_ok | all_ok |
| 3 | run_all_ok | all_ok |
| 4 | run_all_ok | all_ok |
| 5 | run_all_ok | all_ok |

### fresh06

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_all_ok | all_ok |
| 2 | run_all_ok | all_ok |
| 3 | run_all_ok | all_ok |
| 4 | run_all_ok | all_ok |
| 5 | run_all_ok | all_ok |

## Classification

- Final: A - actionable; no new structural divergence; R73 phase divergence resolved inside existing taxonomy.
- New structural divergence: false
- Unexpected phase labels: none
- This is Rust/live supporting evidence only; it is not dual-kernel parity completion. BHV remains 52/56.

## Redaction

- Only neutral keys fresh02/fresh06 are committed.
- Raw tag/server/uuid/public_key/short_id/path/header/server_name/password material remains only in local /tmp inputs and is not committed.
