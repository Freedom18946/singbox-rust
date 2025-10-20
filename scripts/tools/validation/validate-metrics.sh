#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REQ=(
  "sb_build_info"
  "udp_upstream_map_size"
  "udp_evict_total"
  "udp_ttl_seconds"
  "udp_upstream_fail_total"
  "route_explain_total"
  "__PROM_HTTP_FAIL__"
)

curl -sS "http://127.0.0.1:19090/metrics" > /tmp/metrics.txt || {
  echo "curl metrics failed"
  exit 1
}

miss=0
for n in "${REQ[@]}"; do
  if ! grep -q "$n" /tmp/metrics.txt; then
    echo "MISSING METRIC: $n"
    miss=1
  fi
done
exit $miss