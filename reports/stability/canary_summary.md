# Canary Summary

- Generated: 2026-02-14T11:30:05Z
- Profile: `fast`
- API URL: `http://127.0.0.1:19090`
- Status: `ENV_LIMITED`
- Reason: `canary_api_unreachable` (health endpoint unavailable during this run)
- Related status: `reports/stability/l17_capstone_status.json`

## Fast-Run Target

- Duration Hours (requested): `1`
- Sample Interval Seconds (requested): `300`

## Artifacts

- JSONL target path: `reports/stability/canary_7day.jsonl`
- Summary path: `reports/stability/canary_summary.md`

## Re-run Command

```bash
scripts/canary_7day.sh \
  --duration-hours 1 \
  --sample-interval-sec 300 \
  --api-url http://127.0.0.1:19090 \
  --out-jsonl reports/stability/canary_7day.jsonl \
  --out-summary reports/stability/canary_summary.md
```
