# R82 - fresh04 same-failure live recheck with cleansed subset (redacted)

Authorization: explicit user authorization for fresh04 only, REALITY/VLESS only, x3 = 3 runs, target example.com:80. No fresh05, no cohort C, no other fresh nodes, no Hysteria2, no WS/plain-VLESS, no auto-extension beyond 3 runs.

## Pre-gate

- HEAD at gate: d6fd23a2; main synced with origin/main: true
- Intake counts: covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0
- Dry-run: selected_count=1, runs_per_outbound=3, planned_total_runs=3, target=example.com:80
- **subset_schema_gate_passed=true**, `subset_schema_gate.violations==[]` (R81 gate cleared)
- BHV: 52/56 unchanged

## Subset cleansing (R81 two-branch contract)

- (a) `__`-prefixed fields stripped at any depth: `__id_in_gui` (R80's exact failure path) removed.
- (b) outbound-level fields are all in the REALITY/VLESS allow-list (`crates/sb-config/src/outbound/raw.rs::RawVlessConfig` + `crates/sb-config/src/compat.rs` aliases).
- Cleansed subset: `/tmp/r82_fresh04_subset_clean.json` (kept local, not committed).

## Live scope

- executed_runs: 3 / 3 (all status=`completed`)
- outbound: fresh04
- runs_per_outbound: 3
- target: example.com:80
- fresh05 / cohort C / other fresh / Hys2 / WS / plain-VLESS executed: no
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*`: untouched

## Run-health accounting

- run_all_ok: 0
- run_divergence: 0
- run_same_failure: 3
- run_unknown: 0
- divergence_phase_label_count: 0
- distinct_divergence_phase_label_count: 0
- divergence_phase_label_breakdown: {}
- label_counts: `{probe_io_all_timeout: 3, reality_all_timeout: 3}`
- class_counts: `{timeout: 27}` (9 classes x 3 runs)

## Per-run facts

| run | status | labels | run_health |
| ---: | --- | --- | --- |
| 1 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| 2 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |
| 3 | completed | probe_io_all_timeout, reality_all_timeout | run_same_failure |

## Phase probe supporting evidence

| run | direct_reality | transport_reality | vless_dial | vless_probe_io |
| ---: | --- | --- | --- | --- |
| 1 | timeout | timeout | timeout | timeout |
| 2 | timeout | timeout | timeout | timeout |
| 3 | timeout | timeout | timeout | timeout |

3/3 runs at timeout class for the network-level phase probe — consistent with the matrix-level same-failure(timeout) label. Phase data is supporting only; the matrix-level result is authoritative.

## fresh04 R73 -> R78 -> R80 -> R82

| round | run_health | labels / phase labels | state | same_failure_class |
| --- | --- | --- | --- | --- |
| R73 | ok=0, div=0, same_failure=5 | probe_io_all_other=5, reality_all_other=5 | same_failure | other |
| R78 | ok=0, div=0, same_failure=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure | timeout |
| R80 | ok=0, div=0, same_failure=0, unknown=3 | (matrix_error: no labels) | matrix_error / run_unknown | n/a |
| R82 | ok=0, div=0, same_failure=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure | timeout |

`class_history`: `[other, timeout, null, timeout]`

### Closure-counting refinement (per R82 prompt v2)

- R73 was same-failure **other-class**, NOT a timeout-class round.
- R78 was same-failure **timeout-class round 1** (NOT a longer-repeat continuation of R73, because the class flipped).
- R80 returned matrix_error and is **excluded from closure counting** (not a valid round).
- R82 is **timeout-class round 2 of 3**.
- Cohort-B single-outbound closure for fresh04 still requires one more longer-repeat round (proposed R83). R82 is **NOT** cohort-B 单 outbound 闭环 completion; do not write it as such.

### Assessment

R82 formally re-confirms fresh04 same-failure at the matrix level for the timeout class. fresh04 latest_health: latest_unknown -> latest_same_failure(timeout). The `__id_in_gui` schema-mismatch path that R80 hit is closed at dry-run by R81, and R82 demonstrated the closure operationally.

## Classification

- Final: **A.1** — 3/3 same-failure with class==timeout; matrix-level recheck successful; timeout-class round 2 of 3 longer-repeat for fresh04.
- Primary branch: **A** (3/3 same-failure)
- Sub-branch: **A.1** (class==timeout, distinct from A.2/A.3 per prompt v2)
- Next handling (no auto-extension): optional R83 timeout-class round 3 with cleansed subset would close the cohort-B single-outbound narrative for fresh04; requires explicit re-authorization.
- New structural divergence: false
- Unexpected phase labels: none (all 4-element taxonomy: app_pre_post_diverged / app_minimal_diverged / minimal_transport_diverged / bridge_io_diverged were not produced; observed labels are uniform-failure labels probe_io_all_timeout and reality_all_timeout)
- This is Rust/live evidence; it is **not** dual-kernel parity completion. BHV remains 52/56 unchanged.
- This is **not** sampler/dataplane regression. Do not auto-extend the run cap.

## Range confirmation

- live runs in R82: 3 (fresh04 only)
- live node contact: 1 (fresh04)
- fresh05 / cohort C / other fresh / Hys2 / WS / plain-VLESS live: 0 / 0 / 0 / 0 / 0 / 0
- sampler / dataplane / `go_fork_source/*` / `.github/workflows/*` modifications: 0 / 0 / 0 / 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust/live evidence only

## Redaction

- Only neutral key `fresh04` is committed.
- Raw tag / server / uuid / public_key / short_id / path / header / server_name / password material remains only in local /tmp inputs and is not committed.
- subset_schema_gate.violations is committed only because it is the empty array; the gate's structural redaction guarantee (violations carry only path/field/reason) was preserved.
