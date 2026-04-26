# MT-REAL-02 REALITY Live Evidence Rollup

- rounds: 3
- executed runs: 12
- all_ok runs: 10
- non-all_ok runs: 2
- has divergence: false

## Rounds

| Round | Runs | all_ok | Labels | Classes | Divergence |
| --- | ---: | ---: | --- | --- | --- |
| 41 | 4 | 4 | all_ok=4 | ok=36 | false |
| 42 | 3 | 2 | all_ok=2, reality_all_timeout=1 | ok=18, timeout=9 | false |
| 44 | 5 | 4 | all_ok=4, reality_all_connection_reset=1 | connection_reset=9, ok=36 | false |

## Aggregates

- labels: {"all_ok": 10, "reality_all_connection_reset": 1, "reality_all_timeout": 1}
- classes: {"connection_reset": 9, "ok": 90, "timeout": 9}
