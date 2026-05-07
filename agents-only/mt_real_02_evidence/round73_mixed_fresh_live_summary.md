# R73 — MT-MIXED-FRESH-01 fresh REALITY/VLESS bounded live (redacted)

Authorization: explicit user authorization for REALITY/VLESS only. No Hysteria2 or WS/plain VLESS live. Outbound names redacted to neutral keys fresh01..fresh15; original tags / server material live only in /tmp.

## Plan identity

- target: example.com:80
- runs_per_outbound: 5
- selected_count: 15
- planned_total_runs: 75
- executed_runs: 75

## Live counts

- status_counts: {"completed": 75}
- all_ok_runs: 46
- non_all_ok_runs: 29
- has_divergence: True

## Label counts

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

Delta is always within ±1; the single difference (other) is fresh02 mixing one probe_io_all_other with one app_pre_post_diverged on the same run. No new structural divergence beyond the four phase labels enumerated in MT-REAL-02 golden spec / S4.

## Per-outbound buckets

| outbound | runs | all_ok | divergence_runs | uniform_failure |
| --- | ---: | ---: | ---: | --- |
| fresh01 | 5 | 5 | 0 | - |
| fresh02 | 5 | 0 | 2 | probe_io_all_other, probe_io_all_timeout, reality_all_timeout |
| fresh03 | 5 | 0 | 0 | probe_io_all_other, reality_all_other |
| fresh04 | 5 | 0 | 0 | probe_io_all_other, reality_all_other |
| fresh05 | 5 | 0 | 0 | probe_io_all_other, reality_all_other |
| fresh06 | 5 | 1 | 3 | probe_io_all_other, reality_all_other |
| fresh07 | 5 | 0 | 0 | probe_io_all_connection_reset, reality_all_connection_reset |
| fresh08 | 5 | 5 | 0 | - |
| fresh09 | 5 | 5 | 0 | - |
| fresh10 | 5 | 5 | 0 | - |
| fresh11 | 5 | 5 | 0 | - |
| fresh12 | 5 | 5 | 0 | - |
| fresh13 | 5 | 5 | 0 | - |
| fresh14 | 5 | 5 | 0 | - |
| fresh15 | 5 | 5 | 0 | - |

## Classification

- **A (actionable, no new divergence)**
  - 9 fresh outbounds reached 5/5 all_ok end-to-end (fresh01, fresh08, fresh09, fresh10, fresh11, fresh12, fresh13, fresh14, fresh15)
  - 1 fresh outbound (fresh06) produced 1/5 all_ok plus mixed phase divergence within existing taxonomy (app_minimal_diverged, bridge_io_diverged, minimal_transport_diverged) → first non-trivial all-three-phase divergence sample
  - 1 fresh outbound (fresh02) produced 1 divergence sample (app_pre_post + app_minimal) plus 4 timeouts — node-health-limited; the 1 sample fits MT-REAL-02 golden spec phase taxonomy, no new class
  - 4 fresh outbounds (fresh03/04/05/07) produced 5/5 same-failure (uniform connection_reset / other) with zero divergence — node-health limited, NOT a sampler regression (per "Still-Valid Constraints" in active_context)
  - probe_io and reality phase fates are aligned within ±1, so no transport-vs-app divergence beyond the four already-enumerated phase labels

## Authorization scope confirmation

- REALITY/VLESS live: 75 executed runs (15 candidates × 5)
- Hysteria2 live: 0 (not authorized; no socket opened to any hys2 candidate)
- WS/plain VLESS live: 0 (not authorized; no socket opened to any plain-VLESS candidate)
- Sampler/dataplane: untouched in this round
- go_fork_source/* and .github/workflows/*: untouched
- BHV: 52/56 unchanged (this round did not touch dual-kernel parity)
