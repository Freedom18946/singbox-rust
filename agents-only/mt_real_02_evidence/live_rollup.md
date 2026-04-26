# MT-REAL-02 REALITY Live Evidence Rollup

- rounds: 7
- executed runs: 26
- all_ok runs: 19
- non-all_ok runs: 7
- has divergence: true
- latest non-all_ok outbounds: 6

## Rounds

| Round | Runs | all_ok | Labels | Classes | Divergence |
| --- | ---: | ---: | --- | --- | --- |
| 41 | 4 | 4 | all_ok=4 | ok=36 | false |
| 42 | 3 | 2 | all_ok=2, reality_all_timeout=1 | ok=18, timeout=9 | false |
| 44 | 5 | 4 | all_ok=4, reality_all_connection_reset=1 | connection_reset=9, ok=36 | false |
| 47 | 5 | 2 | all_ok=2, app_minimal_diverged=1, minimal_transport_diverged=1, reality_all_reality_dial_eof=1, reality_all_timeout=1 | ok=26, reality_dial_eof=10, timeout=9 | true |
| 48 | 3 | 3 | all_ok=3 | ok=27 | false |
| 50 | 5 | 3 | all_ok=3, probe_io_all_connection_reset=1, probe_io_all_post_dial_eof=1, reality_all_connection_reset=1 | connection_reset=9, ok=34, post_dial_eof=2 | false |
| 52 | 1 | 1 | all_ok=1 | ok=9 | false |

## Aggregates

- labels: {"all_ok": 19, "app_minimal_diverged": 1, "minimal_transport_diverged": 1, "probe_io_all_connection_reset": 1, "probe_io_all_post_dial_eof": 1, "reality_all_connection_reset": 2, "reality_all_reality_dial_eof": 1, "reality_all_timeout": 2}
- classes: {"connection_reset": 18, "ok": 186, "post_dial_eof": 2, "reality_dial_eof": 10, "timeout": 18}
