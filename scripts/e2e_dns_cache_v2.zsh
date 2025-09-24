#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: dns cache v2"
export SB_DNS_MODE=${SB_DNS_MODE:-udp}
export SB_DNS_CACHE_ENABLE=1
export SB_DNS_CACHE_CAP=${SB_DNS_CACHE_CAP:-128}
export SB_DNS_CACHE_NEG_TTL_MS=${SB_DNS_CACHE_NEG_TTL_MS:-2000}
export SB_DNS_CACHE_TTL_SEC=${SB_DNS_CACHE_TTL_SEC:-5}
export SB_DNS_CACHE_STALE_MS=${SB_DNS_CACHE_STALE_MS:-1500}
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

host=${HOST:-example.com}
echo "[STEP] first query (miss)"
cargo run -q --example dns_cache_show --features "dns_cache,dns_udp" -- ${host} >/dev/null
echo "[STEP] second query (pos hit/coalesced)"
cargo run -q --example dns_cache_show --features "dns_cache,dns_udp" -- ${host} >/dev/null

echo "[STEP] negative cache (expect empty; not error)"
BAD="nonexistent.zzzinvalid."
cargo run -q --example dns_query --features "dns_udp" -- ${BAD} 80 || true
cargo run -q --example dns_query --features "dns_cache,dns_udp" -- ${BAD} 80 || true

echo "[SCRAPE] /metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" | grep -E 'dns_cache_(hit|size|evict)_|dns_query_total' && \
  echo "[OK] dns cache metrics visible" || echo "[WARN] metrics not visible"
set -e
echo "[DONE]"