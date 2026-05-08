# R85 - cohort C recovery-watch round 2 of 3

Authorization: explicit user authorization for cohort C reps fresh01/fresh09/fresh15 only, REALITY/VLESS only, x3 each = 9 runs, target example.com:80. No fresh04, no other fresh nodes, no Hysteria2, no WS/plain-VLESS, no auto-extension beyond 3 runs/rep, no failed-run retry, no rotation in this round.

## Outcome (lead)

- Classification: **B.partial_per_rep**.
- fresh01: 3/3 `run_all_ok`; recovery_consecutive_rounds=2 (R73 + R85).
- fresh09: 3/3 `run_same_failure(timeout)`; recovery_consecutive_rounds reset to 0.
- fresh15: 3/3 `run_all_ok`; recovery_consecutive_rounds=2 (R73 + R85).
- R85 is **round 2 of 3**, not recovery closure. No closure claim is made.
- BHV 52/56 unchanged. Not parity completion.

## Pre-gate

- HEAD at gate: 2e0433ca; main synced with origin/main: true
- Intake counts: covered_existing=3, fresh_ready=0, duplicate=0, not_ready=0
- Dry-run: selected_count=3, runs_per_outbound=3, planned_total_runs=9, target=example.com:80
- **subset_schema_gate_passed=true**, `subset_schema_gate.violations==[]` (R81 gate cleared)
- BHV: 52/56 unchanged

## Live scope

- executed_runs: 9 / 9 (all status=`completed`; all matrix_status=0)
- outbounds: fresh01, fresh09, fresh15
- runs_per_outbound: 3
- target: example.com:80
- fresh04 / other fresh / Hys2 / WS / plain-VLESS executed: no
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*`: untouched

## Run-health accounting

- run_all_ok: 6
- run_divergence: 0
- run_same_failure: 3
- run_unknown: 0
- divergence_phase_label_count: 0
- divergence_phase_label_breakdown: `{}`
- label_counts: `{"all_ok": 6, "probe_io_all_timeout": 3, "reality_all_timeout": 3}`
- class_counts: `{"ok": 54, "timeout": 27}`

## Per-run facts

| outbound | run | status | labels | run_health |
| --- | ---: | --- | --- | --- |
| fresh01 | 1 | completed | all_ok | run_all_ok |
| fresh01 | 2 | completed | all_ok | run_all_ok |
| fresh01 | 3 | completed | all_ok | run_all_ok |
| fresh09 | 1 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| fresh09 | 2 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| fresh09 | 3 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| fresh15 | 1 | completed | all_ok | run_all_ok |
| fresh15 | 2 | completed | all_ok | run_all_ok |
| fresh15 | 3 | completed | all_ok | run_all_ok |

## Cohort C Recovery Status

| rep | latest_state | recovery_consecutive_rounds | round_2_banked | same_failure_class |
| --- | --- | ---: | --- | --- |
| fresh01 | all_ok | 2 | true | n/a |
| fresh09 | same_failure | 0 | false | timeout |
| fresh15 | all_ok | 2 | true | n/a |

`all_reps_clean_at_r85=false`; `rotation_recommended=true` because fresh09 failed round 2 with a uniform timeout same-failure. Rotation is not executed in R85.

## R73 -> R85 Transition

| rep | round | state | labels | same_failure_class | recovery_consecutive_rounds_after_round |
| --- | --- | --- | --- | --- | ---: |
| fresh01 | R73 | all_ok | all_okx5 | n/a | 1 |
| fresh01 | R85 | all_ok | all_okx3 | n/a | 2 |
| fresh09 | R73 | all_ok | all_okx5 | n/a | 1 |
| fresh09 | R85 | same_failure | probe_io_all_timeoutx3, reality_all_timeoutx3 | timeout | 0 |
| fresh15 | R73 | all_ok | all_okx5 | n/a | 1 |
| fresh15 | R85 | all_ok | all_okx3 | n/a | 2 |

## Taxonomy

- allowed_phase_labels: app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged
- observed_phase_labels_in_taxonomy: `[]`
- unexpected_phase_labels: `[]`
- new_structural_divergence: false

## Classification narrative

**B.partial_per_rep.** fresh01 and fresh15 banked recovery-watch round 2 with 3/3 `run_all_ok`; fresh09 did not. Its three R85 runs all returned `probe_io_all_timeout` + `reality_all_timeout`, so its recovery consecutive all_ok count resets to 0. There is no taxonomy divergence and no matrix-level tooling regression.

## Next handling

- Do not auto-extend R85.
- fresh01 and fresh15 remain eligible for a future round-3 closure attempt.
- fresh09 should go to a next-round rotation decision: either replace it from the R73 round-1-only recovery pool, or explicitly re-authorize fresh09 if the goal is to test whether the timeout was transient.
- Do not write cohort C recovery closure until a rep reaches 3 consecutive all_ok rounds.

## Range confirmation

- live runs in R85: 9 (fresh01/fresh09/fresh15 only)
- live node contact: 3 reps
- fresh04 / fresh02/03/05/06/07/08/10/11/12/13/14 / Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` modifications: 0 / 0 / 0 / 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust/live supporting evidence only under DEV-REALITY-01 ARCH-LIMIT

## Redaction

- Only neutral keys `fresh01`, `fresh09`, and `fresh15` are committed.
- Raw tag / server / uuid / public_key / short_id / path / header / server_name / password material remains only in local /tmp inputs and is not committed.
- subset_schema_gate.violations is committed only because it is the empty array; structural redaction is preserved.
