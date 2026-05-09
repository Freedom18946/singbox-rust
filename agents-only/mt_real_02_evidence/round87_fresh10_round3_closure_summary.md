# R87 - fresh10 round-3 closure attempt

Authorization: explicit user authorization for REALITY/VLESS only, outbound fresh10, x3 = 3 runs, target example.com:80. No fresh01/fresh15/fresh09/fresh04/other fresh nodes; no Hys2/WS/plain-VLESS; no auto-extension; no failed-run retry; no in-round rotation.

## Outcome (lead)

- Classification: **A.per_rep_recovery_closure**.
- fresh10: 3/3 `run_all_ok`; recovery_consecutive_rounds=3 via R73 + R86 + R87; **per-rep recovery closure achieved**.
- Rotated active set fresh01/fresh15/fresh10 all hold per-rep recovery closure (fresh01/fresh15 closed at R86, fresh10 closed at R87).
- **Original cohort C closure NOT claimed**: fresh09 (original cohort C member) remains broken from R85 (3/3 same_failure timeout, recovery_consecutive_rounds=0) and was not re-run.
- **fresh09 NOT recovered**.
- BHV 52/56 unchanged. Not parity completion. Not dual-kernel parity completion.

## Pre-gate

- HEAD at gate: `ee229a27`; main synced with origin/main: true
- Intake counts: covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0
- Dry-run: selected_count=1, runs_per_outbound=3, planned_total_runs=3, target=example.com:80
- **subset_schema_gate_passed=true**, `subset_schema_gate.violations==[]` (R81 gate cleared)
- BHV: 52/56 unchanged

## Live scope

- executed_runs: 3 / 3 (all status=`completed`; all matrix_status=0)
- outbounds: fresh10
- runs_per_outbound: 3
- target: example.com:80
- fresh01 / fresh15 / fresh09 / fresh04 / other fresh / Hys2 / WS / plain-VLESS executed: no
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` / golden_spec: untouched

## Run-health accounting

- run_all_ok: 3
- run_divergence: 0
- run_same_failure: 0
- run_unknown: 0
- divergence_phase_label_count: 0
- divergence_phase_label_breakdown: `{}`
- label_counts: `{"all_ok": 3}`
- class_counts: `{"ok": 27}`

## Per-run facts

| outbound | run | status | matrix_status | labels | run_health |
| --- | ---: | --- | ---: | --- | --- |
| fresh10 | 1 | completed | 0 | all_ok | run_all_ok |
| fresh10 | 2 | completed | 0 | all_ok | run_all_ok |
| fresh10 | 3 | completed | 0 | all_ok | run_all_ok |

## fresh10 round-3 closure status

| field | value |
| --- | --- |
| scope | per-rep only (fresh10) |
| consecutive_rounds_required | 3 |
| fresh10 chain | R73 + R86 + R87 |
| fresh10 recovery_consecutive_rounds | 3 |
| fresh10 per_rep_recovery_closure_achieved | true |
| original_cohort_c_closure_achieved | **false** |
| fresh09 recovered | **false** |

`original_cohort_c_closure_achieved=false`: original cohort C identity is fresh01+fresh09+fresh15. fresh09 broke at R85 with 3/3 same_failure(timeout) and was not re-run; it remains broken. fresh10 is a rotated replacement, not a substitute for fresh09 in the original-cohort identity.

## Rotated active set status (post-R87)

| rep | role | per_rep_recovery_closure | closure round | chain |
| --- | --- | --- | --- | --- |
| fresh01 | clean_existing_rep | true | R86 | R73 + R85 + R86 |
| fresh15 | clean_existing_rep | true | R86 | R73 + R85 + R86 |
| fresh10 | replacement_rep | true | R87 | R73 + R86 + R87 |

## fresh09 status (unchanged from R85)

| field | value |
| --- | --- |
| latest_round | 85 |
| latest_state | same_failure |
| latest_same_failure_class | timeout |
| recovery_consecutive_rounds | 0 |
| recovered | false |

## Recovery transitions (fresh10)

| round | state | labels | consecutive |
| --- | --- | --- | ---: |
| R73 | all_ok | all_ok×5 | 1 |
| R86 | all_ok | all_ok×3 | 2 |
| R87 | all_ok | all_ok×3 | 3 |

## Taxonomy

- allowed_phase_labels: app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged
- observed_phase_labels_in_taxonomy: `[]`
- unexpected_phase_labels: `[]`
- new_structural_divergence: false

## Classification narrative

**A.per_rep_recovery_closure.** R87 ran the authorized round-3 closure attempt for fresh10 only (3 runs at example.com:80). All 3 runs completed with matrix_status=0 and label all_ok, no phase labels, no NEW structural divergence. fresh10 now has three consecutive all_ok recovery rounds (R73, R86, R87) and therefore reaches per-rep recovery closure. Together with fresh01/fresh15 closed at R86, the rotated active set fresh01/fresh15/fresh10 holds per-rep recovery closure end-to-end. Original cohort C closure is NOT claimed because fresh09 still broke at R85 (and was not re-run).

## Next handling

- Do not auto-extend R87.
- Do not write whole / original cohort C closure.
- Do not write fresh09 recovered.
- Next natural authorized round (requires a new explicit user authorization), if desired, can either:
  - draw from R73 round-1-only recovery pool (fresh08 / fresh11 / fresh12 / fresh13 / fresh14) for additional rotated coverage, or
  - re-evaluate fresh09 independently to decide whether the R85 timeout was steady-state or noise.

## Range confirmation

- live runs in R87: 3 (fresh10 only)
- live node contact: 1 rep
- fresh01 / fresh15 / fresh09 / fresh04 / fresh02/03/05/06/07/08/11/12/13/14 / Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` / golden_spec modifications: 0 / 0 / 0 / 0 / 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust/live supporting evidence only under DEV-REALITY-01 ARCH-LIMIT

## Redaction

- Only the neutral key `fresh10` is committed.
- Raw tag / server / uuid / public_key / short_id / path / header / server_name / password material remains only in local /tmp inputs and is not committed.
- subset_schema_gate.violations is committed only because it is the empty array; structural redaction is preserved.
