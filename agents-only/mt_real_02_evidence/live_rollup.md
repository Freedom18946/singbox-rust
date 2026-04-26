# MT-REAL-02 REALITY Live Evidence Rollup

- rounds: 5
- executed runs: 20
- all_ok runs: 15
- non-all_ok runs: 5
- has divergence: true

## Rounds

| Round | Runs | all_ok | Labels | Classes | Divergence |
| --- | ---: | ---: | --- | --- | --- |
| 41 | 4 | 4 | all_ok=4 | ok=36 | false |
| 42 | 3 | 2 | all_ok=2, reality_all_timeout=1 | ok=18, timeout=9 | false |
| 44 | 5 | 4 | all_ok=4, reality_all_connection_reset=1 | connection_reset=9, ok=36 | false |
| 47 | 5 | 2 | all_ok=2, app_minimal_diverged=1, minimal_transport_diverged=1, reality_all_reality_dial_eof=1, reality_all_timeout=1 | ok=26, reality_dial_eof=10, timeout=9 | true |
| 48 | 3 | 3 | all_ok=3 | ok=27 | false |

## Aggregates

- labels: {"all_ok": 15, "app_minimal_diverged": 1, "minimal_transport_diverged": 1, "reality_all_connection_reset": 1, "reality_all_reality_dial_eof": 1, "reality_all_timeout": 2}
- classes: {"connection_reset": 9, "ok": 143, "reality_dial_eof": 10, "timeout": 18}
