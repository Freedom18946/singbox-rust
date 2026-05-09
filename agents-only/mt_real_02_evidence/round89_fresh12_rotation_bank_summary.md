# R89 - fresh12 isolated rotation-bank round

Authorization: REALITY/VLESS live only, outbound fresh12, 3 planned runs, target example.com:80. No auto-extension, no retry repair, no in-round rotation.

## Outcome

- Classification: **D.matrix_error_inconclusive**.
- fresh12: 2/3 `matrix_timeout`; 1/3 completed `run_same_failure` with connection_reset labels.
- `run_health_counts={run_all_ok: 0, run_divergence: 0, run_same_failure: 1, run_unknown: 2}`.
- `matrix_status_counts={0: 1, 124: 2}`.
- R89 is **not counted as recovery success**.
- fresh12 recovery_consecutive_rounds remains **1** from the prior all_ok round.
- fresh12 round 2 banked: **false**.
- fresh12 closure declared: **false**.
- original cohort C closure declared: **false**.
- BHV 52/56 unchanged; not dual-kernel parity completion.
- No observed phase labels; no NEW phase label; no NEW structural divergence.

## Pre-gate

- HEAD at gate: `a1d92ffc8d088f5d15a952d20fa1d3ecdf605618`
- origin/main at gate: `a1d92ffc8d088f5d15a952d20fa1d3ecdf605618`
- main synced with origin/main: true
- intake_counts: `covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0`
- dry-run: `selected_count=1, runs_per_outbound=3, planned_total_runs=3, target=example.com:80`
- `subset_schema_gate_passed=true`, `subset_schema_gate.violations=[]`

## Live Scope

- executed_runs: 3 / 3
- outbounds: fresh12
- runs_per_outbound: 3
- target: example.com:80
- excluded outbounds executed: no
- excluded protocols executed: no
- sampler/dataplane, source fork, workflow automation, and golden spec: untouched

## Per-run Facts

| outbound | run | status | matrix_status | labels | run_health |
| --- | ---: | --- | ---: | --- | --- |
| fresh12 | 1 | matrix_timeout | 124 | - | run_unknown |
| fresh12 | 2 | matrix_timeout | 124 | - | run_unknown |
| fresh12 | 3 | completed | 0 | probe_io_all_connection_reset, reality_all_connection_reset | run_same_failure |

## fresh12 Bank Status

| field | value |
| --- | --- |
| scope | isolated rotation bank round |
| prior state | R73 round-1-only all_ok |
| R89 state | matrix_error_inconclusive |
| completed run state | same_failure (connection_reset) |
| round_counted_for_recovery_success | false |
| recovery_consecutive_rounds_after_r89 | 1 |
| fresh12_round2_banked | false |
| fresh12_closure_declared | false |

## Taxonomy

- allowed_phase_labels: app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged
- observed_phase_labels_in_taxonomy: `[]`
- unexpected_phase_labels: `[]`
- new_structural_divergence: false

## Redaction

- Only the neutral key `fresh12` is committed in this round summary.
- Raw tag/server/uuid/public_key/short_id/path/header/server_name/password material remains only in local `/tmp` inputs.
- Empty subset-schema violations are committed because they carry no secret-bearing values.
