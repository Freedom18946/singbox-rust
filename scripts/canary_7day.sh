#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  canary_7day.sh \
    --duration-hours <hours> \
    --sample-interval-sec <seconds> \
    --api-url <url> \
    --pid-file <path> \
    --out-jsonl <path> \
    --out-summary <path>

Defaults:
  --duration-hours 168
  --sample-interval-sec 3600
EOF
}

DURATION_HOURS=168
SAMPLE_INTERVAL_SEC=3600
API_URL=""
PID_FILE=""
OUT_JSONL="reports/stability/canary_7day.jsonl"
OUT_SUMMARY="reports/stability/canary_summary.md"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration-hours) DURATION_HOURS="$2"; shift 2 ;;
    --sample-interval-sec) SAMPLE_INTERVAL_SEC="$2"; shift 2 ;;
    --api-url) API_URL="$2"; shift 2 ;;
    --pid-file) PID_FILE="$2"; shift 2 ;;
    --out-jsonl) OUT_JSONL="$2"; shift 2 ;;
    --out-summary) OUT_SUMMARY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$API_URL" ]]; then
  echo "--api-url is required" >&2
  usage
  exit 2
fi

mkdir -p "$(dirname "$OUT_JSONL")"
mkdir -p "$(dirname "$OUT_SUMMARY")"
: > "$OUT_JSONL"

read_pid() {
  if [[ -n "$PID_FILE" && -f "$PID_FILE" ]]; then
    tr -d '[:space:]' < "$PID_FILE"
  else
    echo ""
  fi
}

get_health_code() {
  curl -sS -o /dev/null -w '%{http_code}' "$API_URL/services/health" || echo 000
}

get_conn_count() {
  local payload
  payload="$(curl -sS "$API_URL/connections" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    echo "null"
    return
  fi
  if command -v jq >/dev/null 2>&1; then
    echo "$payload" | jq -r 'if .connections then (.connections | length) elif .total then .total else "null" end' 2>/dev/null || echo "null"
  else
    echo "null"
  fi
}

get_rss_kb() {
  local pid="$1"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "null"
    return
  fi
  ps -o rss= -p "$pid" 2>/dev/null | awk '{print $1+0}' || echo "null"
}

get_fd_count() {
  local pid="$1"
  if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "null"
    return
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -p "$pid" 2>/dev/null | wc -l | awk '{print $1+0}'
  else
    echo "null"
  fi
}

start_epoch="$(date +%s)"
end_epoch="$((start_epoch + DURATION_HOURS * 3600))"
sample=0

while :; do
  now_epoch="$(date +%s)"
  now_iso="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  pid="$(read_pid)"
  health_code="$(get_health_code)"
  conn_count="$(get_conn_count)"
  rss_kb="$(get_rss_kb "$pid")"
  fd_count="$(get_fd_count "$pid")"

  printf '{"ts":"%s","sample":%d,"pid":%s,"health_code":%s,"rss_kb":%s,"fd_count":%s,"connections":%s}\n' \
    "$now_iso" \
    "$sample" \
    "${pid:-null}" \
    "$health_code" \
    "$rss_kb" \
    "$fd_count" \
    "$conn_count" >> "$OUT_JSONL"

  sample=$((sample + 1))

  if [[ "$DURATION_HOURS" -eq 0 ]] || [[ "$now_epoch" -ge "$end_epoch" ]]; then
    break
  fi

  sleep "$SAMPLE_INTERVAL_SEC"
done

sample_count="$(wc -l < "$OUT_JSONL" | awk '{print $1+0}')"
health_ok_count="$(grep -c '"health_code":200' "$OUT_JSONL" || true)"
first_rss="$(awk -F'"rss_kb":' 'NR==1{split($2,a,","); print a[1]}' "$OUT_JSONL")"
last_rss="$(awk -F'"rss_kb":' 'END{split($2,a,","); print a[1]}' "$OUT_JSONL")"
max_rss="$(awk -F'"rss_kb":' '{split($2,a,","); if (a[1] != "null" && a[1] > max) max=a[1]} END{if (max=="") print "null"; else print max}' "$OUT_JSONL")"

cat > "$OUT_SUMMARY" <<EOF
# Canary Summary

- Generated: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
- API URL: $API_URL
- PID File: ${PID_FILE:-"(not provided)"}
- Duration Hours (requested): $DURATION_HOURS
- Sample Interval Seconds: $SAMPLE_INTERVAL_SEC

## Metrics

- Samples: $sample_count
- Health 200 Count: $health_ok_count
- First RSS (KB): $first_rss
- Last RSS (KB): $last_rss
- Max RSS (KB): $max_rss

## Artifacts

- JSONL: \`$OUT_JSONL\`

## Notes

- This report is framework output. For L17 short-run evidence, run with:
  - \`--duration-hours 24 --sample-interval-sec 3600\`
- A result is considered healthy when health remains 200 and RSS/FD show no monotonic leak trend.
EOF

echo "jsonl generated: $OUT_JSONL"
echo "summary generated: $OUT_SUMMARY"
