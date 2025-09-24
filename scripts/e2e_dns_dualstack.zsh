#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: dns dualstack a/aaaa + cache"
export SB_DNS_MODE=${SB_DNS_MODE:-udp}
export SB_DNS_QTYPE=${SB_DNS_QTYPE:-auto}
export SB_DNS_CACHE_ENABLE=1
export SB_DNS_CACHE_CAP=256
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}
host=${HOST:-example.com}

echo "[STEP] first query (may be miss) - auto mode"
cargo run -q --example dns_query --features "dns_udp,dns_cache" -- ${host} 80 >/dev/null
echo "[STEP] second query (expect pos/coalesced hit)"
cargo run -q --example dns_query --features "dns_udp,dns_cache" -- ${host} 80 >/dev/null

echo "[STEP] A-only query"
export SB_DNS_QTYPE=a
cargo run -q --example dns_query --features "dns_udp,dns_cache" -- ${host} 80 >/dev/null

echo "[STEP] AAAA-only query"
export SB_DNS_QTYPE=aaaa
cargo run -q --example dns_query --features "dns_udp,dns_cache" -- ${host} 80 >/dev/null

echo "[SCRAPE] /metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" | grep -E 'dns_query_total\{.*qtype=.*\}|dns_cache_hit_total' && \
  echo "[OK] qtype metrics visible" || echo "[WARN] metrics not visible"
set -e
echo "[DONE]"