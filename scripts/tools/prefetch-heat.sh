#!/usr/bin/env bash
set -euo pipefail

# Hot URL heater to visualize prefetch pipeline.
# Usage:
#   SB_ADMIN_URL=http://127.0.0.1:8088 \
#   ./scripts/prefetch-heat.sh "http://example.com/subs" --duration 20 --concurrency 8

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <URL> [--duration N] [--concurrency M]" >&2
  exit 1
fi

TARGET="$1"; shift
DUR=20
CONC=8
while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) DUR="$2"; shift 2;;
    --concurrency) CONC="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

echo "Heating $TARGET for $DUR s with $CONC workers"

work() {
  for ((i=0;i<${DUR};i++)); do
    curl -fsS "$TARGET" >/dev/null 2>&1 || true
  done
}

for ((w=0; w<${CONC}; w++)); do
  work &
done

ADMIN="${SB_ADMIN_URL:-http://127.0.0.1:8088}"
for ((t=0; t<${DUR}; t++)); do
  sleep 1
  M=$(curl -fsS "$ADMIN/__metrics" || true)
  Q=$(grep -E "^sb_prefetch_queue_depth" <<<"$M" | awk '{print $2}' || echo "0")
  J_DONE=$(grep -E "^sb_prefetch_jobs_total\{event=\"done\"" <<<"$M" | awk '{print $2}' || echo "0")
  J_RETRY=$(grep -E "^sb_prefetch_jobs_total\{event=\"retry\"" <<<"$M" | awk '{print $2}' || echo "0")
  J_FAIL=$(grep -E "^sb_prefetch_jobs_total\{event=\"fail\"" <<<"$M" | awk '{print $2}' || echo "0")
  HIT=$(grep -E "^cache_hit_total" <<<"$M" | awk '{print $2}' || echo "0")
  echo "t=$t q=$Q jobs_done=$J_DONE retry=$J_RETRY fail=$J_FAIL cache_hit=$HIT"
done

wait
echo "heat done."