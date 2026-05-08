# R84 - fresh04 cohort-A-style divergence-carrier re-evaluation (5-run depth)

Authorization: explicit user authorization for fresh04 only, REALITY/VLESS only, x5 = 5 runs, target example.com:80. No fresh05, no cohort C, no other fresh nodes, no Hysteria2, no WS/plain-VLESS, no auto-extension beyond 5 runs.

## Outcome (lead)

- Classification: **A.same_failure_only** (5/5 run_same_failure, class==timeout)
- **R83 phase divergence (`app_minimal_diverged`) did NOT reproduce in 5 runs.** Cohort-A-style hypothesis (fresh04 carries stable phase divergence) is FALSIFIED at the 5-run depth.
- `closure_status.evaluated=false`. R84 is a cohort-A-style re-evaluation round, not a closure attempt. The broken closure chain at R83 is permanent and is NOT patched by R84.
- BHV 52/56 unchanged. Not parity completion.

## Pre-gate

- HEAD at gate: ae54c501; main synced with origin/main: true
- Intake counts: covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0
- Dry-run: selected_count=1, runs_per_outbound=5, planned_total_runs=5, target=example.com:80
- **subset_schema_gate_passed=true**, `subset_schema_gate.violations==[]` (R81 gate cleared)
- BHV: 52/56 unchanged

## Live scope

- executed_runs: 5 / 5 (all status=`completed`)
- outbound: fresh04
- runs_per_outbound: 5
- target: example.com:80
- fresh05 / cohort C / other fresh / Hys2 / WS / plain-VLESS executed: no
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*`: untouched

## Run-health accounting

- run_all_ok: 0
- run_divergence: **0** (no `app_minimal_diverged`, no four-element-taxonomy phase label observed)
- run_same_failure: **5**
- run_unknown: 0
- divergence_phase_label_count: 0
- divergence_phase_label_breakdown: `{}`
- label_counts: `{probe_io_all_timeout: 5, reality_all_timeout: 5}`
- class_counts: `{timeout: 45}` (9 classes × 5 runs)

## Per-run facts

| run | status | labels | run_health |
| ---: | --- | --- | --- |
| 1 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| 2 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| 3 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| 4 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| 5 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |

## Cohort-A-style assessment

| field | value |
| --- | --- |
| verdict | **A.same_failure_only** |
| stable_phase_divergence_observed | false |
| r83_app_minimal_diverged_reproduced | false |

R84's purpose was to determine whether R83's `app_minimal_diverged` event was a stable phase divergence carrier behavior (cohort A signature) or a single transient event. The 5-run depth produced 0 divergence runs and 5 uniform-failure (timeout) runs, falsifying the stable-carrier hypothesis. R83 is best read as a single transient divergence event, not a structural carrier signature.

## fresh04 R73 -> R78 -> R80 -> R82 -> R83 -> R84

| round | run_health | labels / phase labels | state | same_failure_class |
| --- | --- | --- | --- | --- |
| R73 | sf=5 | probe_io_all_other×5, reality_all_other×5 | same_failure | other |
| R78 | sf=3 | probe_io_all_timeout×3, reality_all_timeout×3 | same_failure | timeout |
| R80 | unk=3 | (matrix_error: no labels) | matrix_error | n/a |
| R82 | sf=3 | probe_io_all_timeout×3, reality_all_timeout×3 | same_failure | timeout |
| R83 | div=1, sf=2 | app_minimal_diverged×1, probe_io_all_timeout×3, reality_all_timeout×3 | mixed | n/a (mixed) |
| **R84** | **sf=5** | **probe_io_all_timeout×5, reality_all_timeout×5** | **same_failure** | **timeout** |

`class_history`: `[other, timeout, null, timeout, null, timeout]`

## Closure verdict

R84 is **NOT** a closure attempt round.

| closure_status field | value |
| --- | --- |
| evaluated | **false** |
| reason | fresh04 reclassified to cohort-A-style at R83; closure semantics apply only to cohort-B single-outbound + single-class consecutive 3-round longer-repeat |
| scope | fresh04 cohort-A-style re-evaluation |
| broken_chain_can_restart_only_in_new_round | true |
| broken_chain_round | 83 |
| this_round_extends_broken_chain | **false** |

The R78+R82 timeout-class chain that R83 broke **cannot** be patched together with R84. R84 = round 1 of a fresh sequence (if a future closure attempt is desired). Two more authorized rounds beyond R84 with 5/5 run_same_failure(timeout) would be needed to form a 3-round consecutive longer-repeat. R78 and R82 are NOT counted toward this fresh sequence.

## Classification narrative

**A.same_failure_only with class=timeout.** All 5 fresh04 matrix runs returned status=completed with identical labels `probe_io_all_timeout` + `reality_all_timeout` (run_same_failure, class=timeout). Class breakdown is uniformly timeout (45 = 9 classes × 5 runs). divergence_phase_label_count=0; the R83 `app_minimal_diverged` event did NOT reproduce. fresh04's R83 phase divergence is best read as a single transient event, not a stable phase divergence carrier behavior.

## Next handling (no auto-extension)

- Do NOT auto-extend R84.
- fresh04's class behavior over 6 rounds: `other(R73) → timeout(R78) → matrix_error(R80) → timeout(R82) → mixed(R83) → timeout(R84)`. fresh04 is back to looking like a stable timeout-class same_failure candidate, but with one transient mixed round (R83) on the record.
- A future round could start a NEW closure-counting sequence for fresh04 timeout-class (R84 round 1 of fresh sequence + two more authorized rounds), but this is OUT of scope for R84 itself.
- **cohort C round-2** (fresh01 / fresh09 / fresh15 ×3) and the **6 R73 unselected recovery nodes** (fresh08 / 10 / 11 / 12 / 13 / 14) remain the natural independent next-step candidates.

## Range confirmation

- live runs in R84: 5 (fresh04 only)
- live node contact: 1 (fresh04)
- fresh05 / cohort C / other fresh / Hys2 / WS / plain-VLESS live: 0 / 0 / 0 / 0 / 0 / 0
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` modifications: 0 / 0 / 0 / 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust/live evidence only
- Closure scope: fresh04 cohort-A-style re-evaluation; closure NOT evaluated this round

## Redaction

- Only neutral key `fresh04` is committed.
- Raw tag / server / uuid / public_key / short_id / path / header / server_name / password material remains only in local /tmp inputs and is not committed.
- subset_schema_gate.violations is committed only because it is the empty array; structural redaction (violations carry only path/field/reason) is preserved.
