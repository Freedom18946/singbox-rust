# R86 - cohort C rotation-bank round

Authorization: explicit user authorization for REALITY/VLESS only, outbounds fresh01/fresh15/fresh10, x3 each = 9 runs, target example.com:80. No fresh09, no fresh04, no fresh08/fresh11/fresh12/fresh13/fresh14, no Hysteria2, no WS/plain-VLESS, no auto-extension, no failed-run retry, no in-round rotation.

## Outcome (lead)

- Classification: **A.rotation_bank_clean**.
- fresh01: 3/3 `run_all_ok`; recovery_consecutive_rounds=3; **per-rep recovery closure achieved**.
- fresh15: 3/3 `run_all_ok`; recovery_consecutive_rounds=3; **per-rep recovery closure achieved**.
- fresh10: 3/3 `run_all_ok`; recovery_consecutive_rounds=2; round 2 banked only, **not closure**.
- Whole cohort C closure is **not** claimed. fresh09 broke at R85 and fresh10 has only R73 + R86.
- BHV 52/56 unchanged. Not parity completion.

## Pre-gate

- HEAD at gate: 370e26ed; main synced with origin/main: true
- Intake counts: covered_existing=3, fresh_ready=0, duplicate=0, not_ready=0
- Dry-run: selected_count=3, runs_per_outbound=3, planned_total_runs=9, target=example.com:80
- **subset_schema_gate_passed=true**, `subset_schema_gate.violations==[]` (R81 gate cleared)
- BHV: 52/56 unchanged

## Live scope

- executed_runs: 9 / 9 (all status=`completed`; all matrix_status=0)
- outbounds: fresh01, fresh15, fresh10
- runs_per_outbound: 3
- target: example.com:80
- fresh09 / fresh04 / other fresh / Hys2 / WS / plain-VLESS executed: no
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*`: untouched

## Run-health accounting

- run_all_ok: 9
- run_divergence: 0
- run_same_failure: 0
- run_unknown: 0
- divergence_phase_label_count: 0
- divergence_phase_label_breakdown: `{}`
- label_counts: `{"all_ok": 9}`
- class_counts: `{"ok": 81}`

## Per-run facts

| outbound | run | status | labels | run_health |
| --- | ---: | --- | --- | --- |
| fresh01 | 1 | completed | all_ok | run_all_ok |
| fresh01 | 2 | completed | all_ok | run_all_ok |
| fresh01 | 3 | completed | all_ok | run_all_ok |
| fresh15 | 1 | completed | all_ok | run_all_ok |
| fresh15 | 2 | completed | all_ok | run_all_ok |
| fresh15 | 3 | completed | all_ok | run_all_ok |
| fresh10 | 1 | completed | all_ok | run_all_ok |
| fresh10 | 2 | completed | all_ok | run_all_ok |
| fresh10 | 3 | completed | all_ok | run_all_ok |

## Rotation Bank Status

| rep | role | latest_state | recovery_consecutive_rounds | per_rep_recovery_closure_achieved |
| --- | --- | --- | ---: | --- |
| fresh01 | clean_existing_rep_round3_closure_attempt | all_ok | 3 | true |
| fresh15 | clean_existing_rep_round3_closure_attempt | all_ok | 3 | true |
| fresh10 | replacement_rep_round2_bank | all_ok | 2 | false |

`whole_cohort_c_closure_achieved=false`: fresh01/fresh15 close only at per-rep scope; fresh10 is a replacement rep with round 2 banked.

## Recovery Transitions

| rep | round | state | labels | same_failure_class | recovery_consecutive_rounds_after_round |
| --- | --- | --- | --- | --- | ---: |
| fresh01 | R73 | all_ok | all_okx5 | n/a | 1 |
| fresh01 | R85 | all_ok | all_okx3 | n/a | 2 |
| fresh01 | R86 | all_ok | all_okx3 | n/a | 3 |
| fresh15 | R73 | all_ok | all_okx5 | n/a | 1 |
| fresh15 | R85 | all_ok | all_okx3 | n/a | 2 |
| fresh15 | R86 | all_ok | all_okx3 | n/a | 3 |
| fresh10 | R73 | all_ok | all_okx5 | n/a | 1 |
| fresh10 | R86 | all_ok | all_okx3 | n/a | 2 |

## Taxonomy

- allowed_phase_labels: app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged
- observed_phase_labels_in_taxonomy: `[]`
- unexpected_phase_labels: `[]`
- new_structural_divergence: false

## Classification narrative

**A.rotation_bank_clean.** All authorized R86 reps produced 3/3 `run_all_ok`. fresh01 and fresh15 now have three consecutive recovery rounds (R73, R85, R86), so they achieve per-rep recovery closure. fresh10 was introduced as the replacement for fresh09 and only has R73 + R86 in its recovery chain; it banks round 2 and remains one clean authorized round short of closure.

## Next handling

- Do not auto-extend R86.
- fresh10 is the natural next closure candidate: one future authorized round with 3/3 `run_all_ok` would bring it to consecutive=3.
- fresh01/fresh15 require no immediate recovery work after per-rep closure unless future monitoring is explicitly desired.
- Do not call this whole cohort C closure while fresh09 remains broken and fresh10 is only at round 2.

## Range confirmation

- live runs in R86: 9 (fresh01/fresh15/fresh10 only)
- live node contact: 3 reps
- fresh09 / fresh04 / fresh08/fresh11/fresh12/fresh13/fresh14 / Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` modifications: 0 / 0 / 0 / 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust/live supporting evidence only under DEV-REALITY-01 ARCH-LIMIT

## Redaction

- Only neutral keys `fresh01`, `fresh15`, and `fresh10` are committed.
- Raw tag / server / uuid / public_key / short_id / path / header / server_name / password material remains only in local /tmp inputs and is not committed.
- subset_schema_gate.violations is committed only because it is the empty array; structural redaction is preserved.
