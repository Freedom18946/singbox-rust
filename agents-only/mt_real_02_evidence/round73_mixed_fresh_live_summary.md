# R73 — MT-MIXED-FRESH-01 fresh REALITY/VLESS bounded live (redacted)

Authorization: explicit user authorization for REALITY/VLESS only. No Hysteria2 or WS/plain VLESS live. Outbound names redacted to neutral keys fresh01..fresh15; original tags / server material live only in /tmp.

R74 (2026-05-08) split divergence_run_count from divergence_phase_label_count. R75 (2026-05-08) materialized per-run `run_health` directly into `runs[]` so future readers no longer have to rederive it from labels; emitter is `scripts/tools/round_summary_run_health.py` (`materialize_run_health`).

## Plan identity

- target: example.com:80
- runs_per_outbound: 5
- selected_count: 15
- planned_total_runs: 75
- executed_runs: 75

## Run-level accounting

- run_all_ok: 46
- run_divergence: 2
- run_same_failure: 27
- divergence_phase_label_count (occurrences): 5
- distinct_divergence_phase_label_count: 4
- divergence_phase_label_breakdown: {"app_minimal_diverged": 2, "app_pre_post_diverged": 1, "bridge_io_diverged": 1, "minimal_transport_diverged": 1}
- has_divergence: True

divergence_run_count counts runs (a run is a divergence run iff it carries any of the four phase labels app_pre_post_diverged, app_minimal_diverged, minimal_transport_diverged, bridge_io_diverged); divergence_phase_label_count counts phase-label occurrences across those divergence runs (a single run can carry multiple phase labels). label_counts above is per-occurrence, matching divergence_phase_label_breakdown.

## Label counts (per-occurrence)

- all_ok: 46
- app_minimal_diverged: 2
- app_pre_post_diverged: 1
- bridge_io_diverged: 1
- minimal_transport_diverged: 1
- probe_io_all_connection_reset: 5
- probe_io_all_other: 19
- probe_io_all_timeout: 4
- reality_all_connection_reset: 5
- reality_all_other: 18
- reality_all_timeout: 4

## probe_io vs reality alignment

| kind | probe_io_all_* | reality_all_* | delta |
| --- | ---: | ---: | ---: |
| connection_reset | 5 | 5 | +0 |
| timeout | 4 | 4 | +0 |
| other | 19 | 18 | +1 |

Delta is always within ±1; the single difference (other) is fresh02 whose 1 divergence run carries probe_io_all_other AND app_pre_post_diverged + app_minimal_diverged (no reality_all_other on that same run). No new structural divergence beyond the four MT-REAL-02 phase labels enumerated in `scripts/tools/reality_vless_evidence_rollup.py` lines 24-29.

## Per-outbound buckets (run-level)

| outbound | runs | run_all_ok | run_divergence | run_same_failure | divergence_phase_labels (occurrences) | uniform_failure |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| fresh01 | 5 | 5 | 0 | 0 | 0 | - |
| fresh02 | 5 | 0 | 1 | 4 | 2 | probe_io_all_other, probe_io_all_timeout, reality_all_timeout |
| fresh03 | 5 | 0 | 0 | 5 | 0 | probe_io_all_other, reality_all_other |
| fresh04 | 5 | 0 | 0 | 5 | 0 | probe_io_all_other, reality_all_other |
| fresh05 | 5 | 0 | 0 | 5 | 0 | probe_io_all_other, reality_all_other |
| fresh06 | 5 | 1 | 1 | 3 | 3 | probe_io_all_other, reality_all_other |
| fresh07 | 5 | 0 | 0 | 5 | 0 | probe_io_all_connection_reset, reality_all_connection_reset |
| fresh08 | 5 | 5 | 0 | 0 | 0 | - |
| fresh09 | 5 | 5 | 0 | 0 | 0 | - |
| fresh10 | 5 | 5 | 0 | 0 | 0 | - |
| fresh11 | 5 | 5 | 0 | 0 | 0 | - |
| fresh12 | 5 | 5 | 0 | 0 | 0 | - |
| fresh13 | 5 | 5 | 0 | 0 | 0 | - |
| fresh14 | 5 | 5 | 0 | 0 | 0 | - |
| fresh15 | 5 | 5 | 0 | 0 | 0 | - |

Totals: runs=75, run_all_ok=46, run_divergence=2, run_same_failure=27, divergence_phase_labels=5.

## fresh02 / fresh06 per-run facts (run_health materialized)

### fresh02 (5 runs)

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_same_failure | probe_io_all_timeout, reality_all_timeout |
| 2 | run_same_failure | probe_io_all_timeout, reality_all_timeout |
| 3 | run_same_failure | probe_io_all_timeout, reality_all_timeout |
| 4 | run_same_failure | probe_io_all_timeout, reality_all_timeout |
| 5 | run_divergence | app_minimal_diverged, app_pre_post_diverged, probe_io_all_other |

fresh02: 4 same-failure runs (probe_io_all_timeout + reality_all_timeout) + 1 divergence run carrying app_minimal_diverged + app_pre_post_diverged + probe_io_all_other in the same run. Phase labels in divergence runs: 2.

### fresh06 (5 runs)

| run | run_health | labels |
| ---: | --- | --- |
| 1 | run_same_failure | probe_io_all_other, reality_all_other |
| 2 | run_same_failure | probe_io_all_other, reality_all_other |
| 3 | run_same_failure | probe_io_all_other, reality_all_other |
| 4 | run_divergence | app_minimal_diverged, bridge_io_diverged, minimal_transport_diverged |
| 5 | run_all_ok | all_ok |

fresh06: 3 same-failure runs (probe_io_all_other + reality_all_other) + 1 divergence run carrying app_minimal_diverged + bridge_io_diverged + minimal_transport_diverged in the same run + 1 all_ok run. Phase labels in divergence runs: 3 — first MT-REAL-02 sample where one run carries all three of those phase labels at once.

## Classification

- **A — actionable; no new structural divergence** (run-level: run_divergence=2, both within the existing four phase labels; the labels themselves are MT-REAL-02 internal evidence-pipeline categories defined at `reality_vless_evidence_rollup.DIVERGENCE_PHASE_LABEL_ORDER` and emitted by `reality_probe_compare.build_report` lines 74-141)
  - 9 fresh outbounds reached 5/5 run_all_ok end-to-end (fresh01, fresh08, fresh09, fresh10, fresh11, fresh12, fresh13, fresh14, fresh15)
  - fresh06: 1 divergence run (3 phase labels: app_minimal_diverged + bridge_io_diverged + minimal_transport_diverged) + 3 same-failure runs (probe_io_all_other + reality_all_other) + 1 all_ok run — first MT-REAL-02 single-run all-three-phase carrier; still inside existing taxonomy
  - fresh02: 1 divergence run (2 phase labels: app_pre_post_diverged + app_minimal_diverged; same run also tagged probe_io_all_other) + 4 same-failure runs (timeout) — node-health limited
  - fresh03/04/05/07: 5/5 run_same_failure each (uniform other or connection_reset) with zero divergence runs — node-health limited, NOT a sampler regression (per "Still-Valid Constraints" in active_context)
  - probe_io and reality run-level fates are aligned within ±1, so no transport-vs-app divergence beyond the four already-enumerated phase labels

## R75 attribution audit

S2/S3/S4 mapping (golden_spec):

- The four MT-REAL-02 phase labels (`app_pre_post_diverged`, `app_minimal_diverged`, `minimal_transport_diverged`, `bridge_io_diverged`) are NOT registered in golden_spec S2 (diff dimensions) or S3 (BHV registry); they are MT-REAL-02 internal evidence-pipeline categories defined at `scripts/tools/reality_vless_evidence_rollup.py:24-29` and emitted by `scripts/tools/reality_probe_compare.py:74-141`.
- Containing S4 entry: **`DEV-REALITY-01` (ARCH-LIMIT)**. The Rust REALITY live-dataplane line is accepted as architecturally limited (Rust `rustls` lacks a `uTLS`-equivalent browser TLS mimic) until Rust gains a `uTLS`-equivalent library.
- fresh02 phase labels (app_pre_post + app_minimal) → covered by `DEV-REALITY-01`. **No new S4 entry needed.**
- fresh06 phase labels (app_minimal + bridge_io + minimal_transport) → covered by `DEV-REALITY-01`. **No new S4 entry needed.**
- R73 fresh data is supporting evidence under `DEV-REALITY-01`, not a new dual-kernel divergence. BHV 52/56 unchanged.

## Authorization scope confirmation

- REALITY/VLESS live: 75 executed runs (15 candidates × 5)
- Hysteria2 live: 0 (not authorized; no socket opened to any hys2 candidate)
- WS/plain VLESS live: 0 (not authorized; no socket opened to any plain-VLESS candidate)
- Sampler/dataplane: untouched in this round; untouched by R74 audit; untouched by R75 materialization
- go_fork_source/* and .github/workflows/*: untouched
- BHV: 52/56 unchanged (this round did not touch dual-kernel parity)
