# MT-REAL-02 REALITY Live Evidence Rollup

- rounds: 20
- executed runs: 198
- all_ok runs: 80
- non-all_ok runs: 118
- has divergence: true
- latest non-all_ok outbounds: 10
- latest divergence outbounds: 0
- latest stable divergence outbounds: 0
- latest mixed run-health outbounds: 0
- latest stable same-failure outbounds: 10
- recovered outbounds: 5

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
| 59-B | 12 | 0 | app_minimal_diverged=2, app_pre_post_diverged=4, bridge_io_diverged=1, minimal_transport_diverged=1, probe_io_all_timeout=11, reality_all_timeout=10 | connection_reset=3, ok=1, reality_dial_eof=2, timeout=102 | true |
| 60 | 16 | 0 | probe_io_all_connection_reset=8, probe_io_all_reality_dial_eof=4, probe_io_all_timeout=4, reality_all_connection_reset=8, reality_all_reality_dial_eof=4, reality_all_timeout=4 | connection_reset=72, reality_dial_eof=36, timeout=36 | false |
| 61 | 4 | 0 | probe_io_all_connection_reset=4, reality_all_connection_reset=4 | connection_reset=36 | false |
| 61 | 3 | 1 | all_ok=1, probe_io_all_connection_reset=2, reality_all_connection_reset=2 | connection_reset=18, ok=9 | false |
| 61 | 8 | 2 | all_ok=2, probe_io_all_connection_reset=4, probe_io_all_reality_dial_eof=2, reality_all_connection_reset=4, reality_all_reality_dial_eof=2 | connection_reset=36, ok=18, reality_dial_eof=18 | false |
| 62 | 4 | 0 | probe_io_all_connection_reset=4, reality_all_connection_reset=4 | connection_reset=36 | false |
| 63 | 4 | 0 | probe_io_all_connection_reset=4, reality_all_connection_reset=4 | connection_reset=36 | false |
| 73 | 75 | 46 | all_ok=46, app_minimal_diverged=2, app_pre_post_diverged=1, bridge_io_diverged=1, minimal_transport_diverged=1, probe_io_all_connection_reset=5, probe_io_all_other=19, probe_io_all_timeout=4, reality_all_connection_reset=5, reality_all_other=18, reality_all_timeout=4 | connection_reset=47, ok=417, other=172, timeout=39 | true |
| 77 | 10 | 10 | all_ok=10 | ok=90 | false |

## Aggregates

- labels: {"all_ok": 80, "app_minimal_diverged": 8, "app_pre_post_diverged": 8, "bridge_io_diverged": 3, "minimal_transport_diverged": 5, "probe_io_all_connection_reset": 44, "probe_io_all_other": 19, "probe_io_all_post_dial_eof": 3, "probe_io_all_reality_dial_eof": 12, "probe_io_all_timeout": 32, "reality_all_connection_reset": 45, "reality_all_other": 18, "reality_all_reality_dial_eof": 13, "reality_all_timeout": 29}
- classes: {"connection_reset": 414, "ok": 754, "other": 172, "post_dial_eof": 6, "reality_dial_eof": 121, "timeout": 315}
- latest health: {"latest_all_ok": 26, "latest_same_failure": 10}
- latest run health: {"run_all_ok": 72, "run_same_failure": 32}

## Latest divergence phase composition

_(no latest divergence)_

## Latest phase dominance

- dominant outbounds (>=0.75): (none)
- no-dominance outbounds (<0.50): (none)
- mid-band outbounds (0.50-0.75): (none)

## Latest bi-modal outbounds

- bi-modal (divergence_ratio in 0.25-0.75 with >=6 runs): (none)

## Phase-shifting outbounds

- phase shifting (dominant phase changed across last 3 rounds): (none)
