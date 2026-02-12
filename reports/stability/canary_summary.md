# Canary Summary

- Generated: 2026-02-12T17:12:04Z
- API URL: http://127.0.0.1:1
- PID File: (not provided)
- Duration Hours (requested): 0
- Sample Interval Seconds: 1

## Metrics

- Samples: 1
- Health 200 Count: 0
- First RSS (KB): null
- Last RSS (KB): null
- Max RSS (KB): null

## Artifacts

- JSONL: `reports/stability/canary_7day.jsonl`

## Notes

- This report is framework output. For L17 short-run evidence, run with:
  - `--duration-hours 24 --sample-interval-sec 3600`
- A result is considered healthy when health remains 200 and RSS/FD show no monotonic leak trend.
