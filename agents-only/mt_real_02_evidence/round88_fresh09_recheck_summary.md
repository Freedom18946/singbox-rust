# R88 - fresh09 single-node recheck

Authorization: explicit user authorization for REALITY/VLESS only, outbound fresh09, x5 = 5 runs, target example.com:80. No fresh01/fresh15/fresh10/fresh04/other fresh nodes; no Hys2/WS/plain-VLESS; no auto-extension; no failed-run retry; no in-round rotation. Not a closure attempt by design.

## Outcome (lead)

- Classification: **A.fresh09_timeout_steady_state**.
- fresh09: 5/5 `run_same_failure` (probe_io_all_timeout + reality_all_timeout, classes={timeout: 9} per run); R85 timeout reproduced.
- fresh09 recovery_consecutive_rounds=0 (chain reset at R85; no all_ok run in R88; cannot patch a broken chain).
- **fresh09 per-rep recovery closure NOT achieved**.
- **Original cohort C closure NOT claimed**: fresh09 (the original cohort C member) remains broken; rotated active set fresh01/fresh15/fresh10 per-rep closures (R86/R86/R87) are rotated-replacement closures, not substitutes for fresh09's original-cohort identity.
- **fresh09 NOT recovered**.
- BHV 52/56 unchanged. Not parity completion. Not dual-kernel parity completion.
- No NEW phase labels; no NEW structural divergence; no matrix_error.

## Pre-gate

- HEAD at gate: `c56fd368`; main synced with origin/main: true
- Intake counts: covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0
- Dry-run: selected_count=1, runs_per_outbound=5, planned_total_runs=5, target=example.com:80
- **subset_schema_gate_passed=true**, `subset_schema_gate.violations==[]` (R81 gate cleared)
- BHV: 52/56 unchanged

## Live scope

- executed_runs: 5 / 5 (all status=`completed`; all matrix_status=0)
- outbounds: fresh09
- runs_per_outbound: 5
- target: example.com:80
- fresh01 / fresh15 / fresh10 / fresh04 / other fresh / Hys2 / WS / plain-VLESS executed: no
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` / golden_spec: untouched

## Run-health accounting

- run_all_ok: 0
- run_divergence: 0
- run_same_failure: 5
- run_unknown: 0
- divergence_phase_label_count: 0
- divergence_phase_label_breakdown: `{}`
- label_counts: `{"probe_io_all_timeout": 5, "reality_all_timeout": 5}`
- class_counts: `{"timeout": 45}`

## Per-run facts

| outbound | run | status | matrix_status | labels | run_health |
| --- | ---: | --- | ---: | --- | --- |
| fresh09 | 1 | completed | 0 | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| fresh09 | 2 | completed | 0 | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| fresh09 | 3 | completed | 0 | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| fresh09 | 4 | completed | 0 | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| fresh09 | 5 | completed | 0 | probe_io_all_timeout, reality_all_timeout | run_same_failure |

## fresh09 recheck status

| field | value |
| --- | --- |
| scope | single-node recheck (fresh09) |
| is_closure_attempt | **false** (chain reset at R85) |
| fresh09 R85 state | same_failure (timeout) |
| fresh09 R88 state | same_failure (timeout) |
| R85 timeout reproduced | **true** |
| recovery_consecutive_rounds | 0 |
| per_rep_recovery_closure_achieved | **false** |
| fresh09 recovered | **false** |
| original_cohort_c_closure_achieved | **false** |

`is_closure_attempt=false`: fresh09's recovery chain was reset to 0 at R85 (3/3 same_failure timeout). A broken closure chain cannot be patched; restart needs a fresh consecutive sequence beginning with at least one all_ok round. R88 is therefore a recheck, not a closure attempt; even a hypothetical 5/5 all_ok would only have been a fresh new-chain round 1.

`original_cohort_c_closure_achieved=false`: original cohort C identity is fresh01+fresh09+fresh15. fresh09 reproduces R85 same_failure(timeout) 5/5 at R88 and remains broken. The rotated active set fresh01/fresh15/fresh10 holds per-rep closure (R86/R86/R87) but that is a rotated-replacement closure, not a substitute for fresh09's original-cohort identity.

## Rotated active set status (post-R88, unchanged from R87)

| rep | role | per_rep_recovery_closure | closure round | chain |
| --- | --- | --- | --- | --- |
| fresh01 | clean_existing_rep | true | R86 | R73 + R85 + R86 |
| fresh15 | clean_existing_rep | true | R86 | R73 + R85 + R86 |
| fresh10 | replacement_rep | true | R87 | R73 + R86 + R87 |

## fresh09 transition history

| round | state | labels | consecutive |
| --- | --- | --- | ---: |
| R73 | all_ok | all_ok×5 | 1 |
| R85 | same_failure (timeout) | probe_io_all_timeout×3, reality_all_timeout×3 | 0 |
| R88 | same_failure (timeout) | probe_io_all_timeout×5, reality_all_timeout×5 | 0 |

## Taxonomy

- allowed_phase_labels: app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged
- observed_phase_labels_in_taxonomy: `[]`
- unexpected_phase_labels: `[]`
- new_structural_divergence: false

## Classification narrative

**A.fresh09_timeout_steady_state.** R88 ran the authorized single-node recheck for fresh09 only (5 runs at example.com:80). All 5 runs completed with matrix_status=0 and uniform same_failure labels (probe_io_all_timeout + reality_all_timeout, classes={timeout:9} per run). No divergence phase labels, no NEW structural divergence, no matrix_error. fresh09 reproduces the R85 same_failure(timeout) 5/5, so the R85 result is steady-state, not transient noise. R88 is NOT a closure attempt by design: fresh09's recovery chain was reset to 0 at R85, and a broken closure chain cannot be patched. recovery_consecutive_rounds remains 0. Per-rep recovery closure is NOT achieved; fresh09 is NOT recovered; original cohort C closure is NOT claimed.

## Next handling

- Do not auto-extend R88.
- Do not retry failed runs to patch the result.
- Do not write fresh09 recovered.
- Do not write whole / original cohort C closure.
- fresh09 is now confirmed as steady-state same_failure(timeout) at R85 + R88.
- Next natural authorized round, if desired, can either:
  - accept fresh09 as steady-state broken and continue rotated-active-set coverage (fresh01/fresh15/fresh10), possibly drawing from R73 round-1-only recovery pool (fresh08/fresh11/fresh12/fresh13/fresh14) for additional rotated reps; or
  - attempt another fresh09 recheck only if there is a specific hypothesis about why R85+R88 timeouts could be transient (e.g. upstream node maintenance window).

## Range confirmation

- live runs in R88: 5 (fresh09 only)
- live node contact: 1 rep
- fresh01 / fresh15 / fresh10 / fresh04 / fresh02/03/05/06/07/08/11/12/13/14 / Hys2 / WS / plain-VLESS live: 0
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` / golden_spec modifications: 0 / 0 / 0 / 0 / 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust/live supporting evidence only under DEV-REALITY-01 ARCH-LIMIT

## Redaction

- Only the neutral key `fresh09` is committed.
- Raw tag / server / uuid / public_key / short_id / path / header / server_name / password material remains only in local /tmp inputs and is not committed.
- subset_schema_gate.violations is committed only because it is the empty array; structural redaction is preserved.
