# R83 - fresh04 timeout-class round 3 of 3 longer-repeat (cohort-B closure attempt; closure NOT achieved)

Authorization: explicit user authorization for fresh04 only, REALITY/VLESS only, x3 = 3 runs, target example.com:80. No fresh05, no cohort C, no other fresh nodes, no Hysteria2, no WS/plain-VLESS, no auto-extension beyond 3 runs.

## Outcome (lead)

- Classification: **B** — mixed: 1 known-taxonomy divergence (`app_minimal_diverged`) + 2 same-failure (timeout).
- **`cohort_b_single_outbound_closure_achieved=false`**. Closure scope: fresh04 single-outbound + timeout class.
- timeout-class consecutive rounds: 2 (R78, R82). Chain broken at R83.
- BHV 52/56 unchanged. Not parity completion. No new structural divergence.

## Pre-gate

- HEAD at gate: 8b0ab0c2; main synced with origin/main: true
- Intake counts: covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0
- Dry-run: selected_count=1, runs_per_outbound=3, planned_total_runs=3, target=example.com:80
- **subset_schema_gate_passed=true**, `subset_schema_gate.violations==[]` (R81 gate cleared)
- BHV: 52/56 unchanged

## Subset cleansing (R81 two-branch contract)

- (a) `__`-prefixed fields stripped at any depth: `__id_in_gui` removed (same recipe as R82).
- (b) outbound-level fields are all in the REALITY/VLESS allow-list.
- Cleansed subset: `/tmp/r83_fresh04_subset_clean.json` (kept local, not committed).

## Live scope

- executed_runs: 3 / 3 (all status=`completed`)
- outbound: fresh04
- runs_per_outbound: 3
- target: example.com:80
- fresh05 / cohort C / other fresh / Hys2 / WS / plain-VLESS executed: no
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*`: untouched

## Run-health accounting

- run_all_ok: 0
- run_divergence: **1** (run 1: `app_minimal_diverged`)
- run_same_failure: **2** (runs 2 and 3: timeout class)
- run_unknown: 0
- divergence_phase_label_count: 1
- divergence_phase_label_breakdown: `{app_minimal_diverged: 1}`
- label_counts: `{app_minimal_diverged: 1, probe_io_all_timeout: 3, reality_all_timeout: 3}`
- class_counts: `{connection_reset: 1, timeout: 26}`

## Per-run facts

| run | status | labels | run_health |
| ---: | --- | --- | --- |
| 1 | completed | app_minimal_diverged, probe_io_all_timeout, reality_all_timeout | run_divergence |
| 2 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| 3 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |

### Run 1 divergence root

`minimal.vless_dial=connection_reset` while every other class (app.pre.direct_reality, app.pre.direct_vless_dial, app.post.direct_reality, app.post.direct_vless_dial, app.bridge, minimal.direct_reality, minimal.transport_reality, minimal.vless_probe_io) is `timeout`. The asymmetry between app and minimal probes at the vless_dial layer produced the `app_minimal_diverged` taxonomy label. Runs 2 and 3 did not reproduce this asymmetry.

## fresh04 R73 -> R78 -> R80 -> R82 -> R83

| round | run_health | labels / phase labels | state | same_failure_class |
| --- | --- | --- | --- | --- |
| R73 | ok=0, div=0, same_failure=5 | probe_io_all_other=5, reality_all_other=5 | same_failure | other |
| R78 | ok=0, div=0, same_failure=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure | timeout |
| R80 | ok=0, div=0, same_failure=0, unknown=3 | (matrix_error: no labels) | matrix_error | n/a |
| R82 | ok=0, div=0, same_failure=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure | timeout |
| R83 | ok=0, **div=1**, same_failure=2 | app_minimal_diverged=1, probe_io_all_timeout=3, reality_all_timeout=3 | **mixed** | n/a (mixed) |

`class_history`: `[other, timeout, null, timeout, null]` (trailing null is R83 mixed; no single same_failure_class)

## Closure verdict

- timeout-class consecutive rounds: **2** (R78 round 1 + R82 round 2)
- timeout-class consecutive round ids: `[78, 82]`
- Chain broken at: **R83**
- Reason: R83 produced 1 run_divergence (`app_minimal_diverged`) + 2 run_same_failure (timeout); not 3/3 same_failure(timeout) → the longer-repeat chain stops at round 2 and does not extend to round 3.
- **`cohort_b_single_outbound_closure_achieved=false`**
- Scope: fresh04 single-outbound + timeout class. This finding does NOT extend to cohort B as a whole and does NOT affect the 6 historical stable same-failure outbounds (HK/JP/UK/US-A-BGP) that are already closed.

## Classification narrative

**B — mixed: 1 known-taxonomy divergence + 2 same-failure (timeout); cohort-B single-outbound closure NOT achieved for fresh04.**

Run 1 carried the known-taxonomy divergence label `app_minimal_diverged` (asymmetry between app and minimal probes at the vless_dial layer; `minimal.vless_dial=connection_reset` while every other class is timeout). Runs 2 and 3 produced the uniform-failure pair `probe_io_all_timeout` + `reality_all_timeout` (run_same_failure with class=timeout). The mix of 1 run_divergence + 2 run_same_failure puts R83 in the B branch per prompt v2: cohort-B single-outbound closure for fresh04 is NOT achieved because the consecutive timeout-class chain breaks here at round 2 (R78 round 1, R82 round 2, R83 mixed). fresh04 transitions from a stable cohort-B same_failure candidate into a cohort-A-style re-evaluation candidate.

## Next handling (no auto-extension)

- Do NOT auto-extend R83. The R76 plan structure expects a separate authorized round for any further fresh04 work.
- fresh04 should be treated going forward as a **divergence-carrier candidate** (R76 cohort A semantics), not a same_failure carrier. A future round could re-probe fresh04 to determine whether the `app_minimal_diverged` behavior is reproducible or noise.
- cohort C round-2 (fresh01/09/15 ×3) and the 6 R73 unselected recovery nodes are independent lines and remain unaffected.

## Range confirmation

- live runs in R83: 3 (fresh04 only)
- live node contact: 1 (fresh04)
- fresh05 / cohort C / other fresh / Hys2 / WS / plain-VLESS live: 0 / 0 / 0 / 0 / 0 / 0
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` modifications: 0 / 0 / 0 / 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust/live evidence only
- Closure scope strictly fresh04 single-outbound + timeout class; not extended to cohort B group or any other outbound

## Redaction

- Only neutral key `fresh04` is committed.
- Raw tag / server / uuid / public_key / short_id / path / header / server_name / password material remains only in local /tmp inputs and is not committed.
- subset_schema_gate.violations is committed only because it is the empty array; structural redaction (violations carry only path/field/reason) is preserved.
