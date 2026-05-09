# R90 - fresh13 isolated rotation-bank round

Authorization: REALITY/VLESS live only, outbound fresh13, 3 planned runs, target example.com:80. No auto-extension, no retry repair, no in-round rotation.

## Outcome

- Classification: **A.fresh13_round2_banked**.
- fresh13: 3/3 `run_all_ok`.
- `run_health_counts={run_all_ok: 3, run_divergence: 0, run_same_failure: 0, run_unknown: 0}`.
- `matrix_status_counts={0: 3}`.
- R90 is counted as fresh13 recovery success round 2.
- fresh13 recovery_consecutive_rounds is **2** via R73 + R90.
- fresh13 round 2 banked: **true**.
- fresh13 closure declared: **false**.
- original cohort C closure declared: **false**.
- BHV 52/56 unchanged; not dual-kernel parity completion.
- No observed phase labels; no NEW phase label; no NEW structural divergence.

## Pre-gate

- HEAD at gate: `0e69cccdd8ae300c0626f007498833984db757f7`
- origin/main at gate: `0e69cccdd8ae300c0626f007498833984db757f7`
- main synced with origin/main: true
- intake_counts: `covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0`
- dry-run: `selected_count=1, runs_per_outbound=3, planned_total_runs=3, target=example.com:80`
- `subset_schema_gate_passed=true`, `subset_schema_gate.violations=[]`

## Live Scope

- executed_runs: 3 / 3
- outbounds: fresh13
- runs_per_outbound: 3
- target: example.com:80
- excluded outbounds executed: no
- excluded protocols executed: no
- sampler/dataplane, source fork, workflow automation, and golden spec: untouched

## Per-run Facts

| outbound | run | status | matrix_status | labels | run_health |
| --- | ---: | --- | ---: | --- | --- |
| fresh13 | 1 | completed | 0 | all_ok | run_all_ok |
| fresh13 | 2 | completed | 0 | all_ok | run_all_ok |
| fresh13 | 3 | completed | 0 | all_ok | run_all_ok |

## fresh13 Bank Status

| field | value |
| --- | --- |
| scope | isolated rotation bank round |
| prior state | R73 round-1-only all_ok |
| R90 state | all_ok |
| round_counted_for_recovery_success | true |
| recovery_consecutive_rounds_after_r90 | 2 |
| fresh13_round2_banked | true |
| fresh13_closure_declared | false |

## Taxonomy

- allowed_phase_labels: app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged
- observed_phase_labels_in_taxonomy: `[]`
- unexpected_phase_labels: `[]`
- new_structural_divergence: false

## Redaction

- Only the neutral key `fresh13` is committed in this round summary.
- Raw tag/server/uuid/public_key/short_id/path/header/server_name/password material remains only in local `/tmp` inputs.
- Empty subset-schema violations are committed because they carry no secret-bearing values.
