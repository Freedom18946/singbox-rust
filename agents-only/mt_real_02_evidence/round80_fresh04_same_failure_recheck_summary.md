# R80 - Fresh04 same-failure bounded live recheck (redacted)

Authorization: explicit user authorization for fresh04 only. REALITY/VLESS only. No fresh05, no cohort C, no other fresh nodes, no Hysteria2, no WS/plain-VLESS, no auto-extension beyond 3 runs.

## Pre-gate

- HEAD at gate: ef26f1cf; main synced with origin/main: true
- intake counts: covered_existing=1, fresh_ready=0, duplicate=0, not_ready=0
- dry-run: selected_count=1, runs_per_outbound=3, planned_total_runs=3, target=example.com:80
- BHV: 52/56 unchanged
- Pre-gate gap: counts (intake + dry-run) matched, but dry-run does not load the subset config in the rust app process; the schema mismatch only surfaced at live matrix execution

## Live scope

- executed_runs: 3 / 3 (all status=`matrix_error`)
- outbound: fresh04
- runs_per_outbound: 3
- target: example.com:80
- fresh05 executed: no
- cohort C / other fresh nodes executed: no / no
- Hysteria2 / WS / plain-VLESS live: no / no / no
- sampler/dataplane, go_fork_source/*, .github/workflows/*: untouched

## Run-health accounting

- run_all_ok: 0
- run_divergence: 0
- run_same_failure: 0
- run_unknown: 3 (matrix_error → no labels → run_unknown)
- divergence_phase_label_count: 0
- distinct_divergence_phase_label_count: 0
- divergence_phase_label_breakdown: {}

## Tooling blocker

- Blocker: rust app config validation failed; matrix script returned exit 1 on all 3 runs.
- Root cause: fresh04 subset retained an `__id_in_gui` field inherited from `/tmp/mt_mixed_fresh_subset_reality_neutral.json`; rust app config schema rejects the field with `unknown field at /outbounds/0/__id_in_gui`.
- Fix recommendation: subset extraction must strip GUI-only fields (e.g. `__id_in_gui`) before live probe; pre-gate dry-run does not catch this because it does not load the config in the rust app process.

## Phase probe supporting evidence

The matrix script's phase probe ran for all 3 attempts and produced consistent timeout-class results across direct_reality, transport_reality, vless_dial, and vless_probe_io. This is supporting evidence that fresh04 network reachability still times out, qualitatively consistent with R78 same-failure(timeout). It is **not** authoritative for the same-failure recheck because the matrix-level app probe and compare did not run; per-run `run_health` stays `run_unknown`.

| run | direct_reality | transport_reality | vless_dial | vless_probe_io |
| ---: | --- | --- | --- | --- |
| 1 | timeout | timeout | timeout | timeout |
| 2 | timeout | timeout | timeout | timeout |
| 3 | timeout | timeout | timeout | timeout |

## fresh04 R73 -> R78 -> R80

| round | run_health | labels / phase labels | state |
| --- | --- | --- | --- |
| R73 | ok=0, div=0, same_failure=5 | probe_io_all_other=5, reality_all_other=5 | same_failure (other) |
| R78 | ok=0, div=0, same_failure=3 | probe_io_all_timeout=3, reality_all_timeout=3 | same_failure (timeout) |
| R80 | ok=0, div=0, same_failure=0, unknown=3 | (matrix_error: no labels) | matrix_error / run_unknown |

Assessment: R80 cannot formally re-confirm fresh04 same-failure status at the matrix level. Phase probe shows 3/3 timeout class, qualitatively consistent with R78 same-failure(timeout) at the network level. The matrix-level run_health for fresh04 stays `run_unknown`.

## Per-run facts

| run | status | labels | run_health |
| ---: | --- | --- | --- |
| 1 | matrix_error | (none) | run_unknown |
| 2 | matrix_error | (none) | run_unknown |
| 3 | matrix_error | (none) | run_unknown |

## Classification

- Final: **C** — tooling/config blocker; fresh04 same-failure recheck not formally re-confirmed at matrix level.
- New structural divergence: false
- Unexpected phase labels: none
- This is Rust/live supporting evidence only; it is not dual-kernel parity completion. BHV remains 52/56.
- This is not sampler/dataplane regression. Do not auto-extend the run cap; if fresh04 same-failure recheck is needed, re-authorize a separate bounded round with a cleaned subset.

## Redaction

- Only neutral key fresh04 is committed.
- Raw tag/server/uuid/public_key/short_id/path/header/server_name/password material remains only in local /tmp inputs and is not committed.
- The `app.stderr` excerpt in `tooling_blocker` is paraphrased to remove the absolute /tmp path; only the schema-mismatch error class is preserved.
