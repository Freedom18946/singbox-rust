#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
METRICS_ADDR="${1:-127.0.0.1:19090}"
TMP_METRICS="$(mktemp)"
cleanup() {
  rm -f "${TMP_METRICS}"
}
trap cleanup EXIT
REQ=(
  "sb_build_info"
  "udp_upstream_map_size"
  "udp_evict_total"
  "udp_ttl_seconds"
  "udp_upstream_fail_total"
  "route_explain_total"
  "__PROM_HTTP_FAIL__"
)

curl -sS "http://${METRICS_ADDR}/metrics" > "${TMP_METRICS}" || {
  echo "curl metrics failed"
  exit 1
}

miss=0
for n in "${REQ[@]}"; do
  if ! grep -q "$n" "${TMP_METRICS}"; then
    echo "MISSING METRIC: $n"
    miss=1
  fi
done
exit $miss
