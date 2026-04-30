# MT-REAL-02 REALITY Live Evidence Rollup

- rounds: 11
- executed runs: 62
- all_ok runs: 21
- non-all_ok runs: 41
- has divergence: true
- latest non-all_ok outbounds: 5
- latest divergence outbounds: 1
- latest stable divergence outbounds: 0
- latest mixed run-health outbounds: 1
- latest stable same-failure outbounds: 4
- recovered outbounds: 2

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
| 54 | 12 | 0 | app_pre_post_diverged=1, probe_io_all_connection_reset=4, probe_io_all_post_dial_eof=2, probe_io_all_reality_dial_eof=2, probe_io_all_timeout=4, reality_all_connection_reset=4, reality_all_reality_dial_eof=2, reality_all_timeout=3 | connection_reset=36, ok=15, post_dial_eof=4, reality_dial_eof=18, timeout=35 | true |
| 56 | 12 | 2 | all_ok=2, app_minimal_diverged=1, app_pre_post_diverged=1, bridge_io_diverged=1, probe_io_all_connection_reset=4, probe_io_all_reality_dial_eof=2, probe_io_all_timeout=3, reality_all_connection_reset=4, reality_all_reality_dial_eof=2, reality_all_timeout=3 | connection_reset=38, ok=18, reality_dial_eof=18, timeout=34 | true |
| 57 | 4 | 0 | app_minimal_diverged=2, app_pre_post_diverged=1, minimal_transport_diverged=2, probe_io_all_timeout=4, reality_all_timeout=1 | connection_reset=2, reality_dial_eof=1, timeout=33 | true |
| 58 | 8 | 0 | probe_io_all_connection_reset=4, probe_io_all_reality_dial_eof=2, probe_io_all_timeout=2, reality_all_connection_reset=4, reality_all_reality_dial_eof=2, reality_all_timeout=2 | connection_reset=36, reality_dial_eof=18, timeout=18 | false |

## Aggregates

- labels: {"all_ok": 21, "app_minimal_diverged": 4, "app_pre_post_diverged": 3, "bridge_io_diverged": 1, "minimal_transport_diverged": 3, "probe_io_all_connection_reset": 13, "probe_io_all_post_dial_eof": 3, "probe_io_all_reality_dial_eof": 6, "probe_io_all_timeout": 13, "reality_all_connection_reset": 14, "reality_all_reality_dial_eof": 7, "reality_all_timeout": 11}
- classes: {"connection_reset": 130, "ok": 219, "post_dial_eof": 6, "reality_dial_eof": 65, "timeout": 138}
- latest health: {"latest_all_ok": 16, "latest_divergence": 1, "latest_same_failure": 4}
- latest run health: {"run_all_ok": 15, "run_divergence": 3, "run_same_failure": 9}

## Latest divergence phase composition

- app_pre_post_diverged: 1 (HK-A-BGP-2.0)
- app_minimal_diverged: 2 (HK-A-BGP-2.0)
- minimal_transport_diverged: 2 (HK-A-BGP-2.0)
- bridge_io_diverged: 0 (-)
