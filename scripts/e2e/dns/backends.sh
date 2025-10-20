#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: DNS backends (system/udp/dot/doh/auto)"
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

run_mode () {
  local mode=$1
  echo "[RUN] mode=$mode"
  SB_DNS_MODE=$mode cargo run -q --example dns_query --features "dns_udp,dns_dot,dns_doh,tls_rustls" -- example.com 80 || true
}

run_mode system
run_mode udp
run_mode dot
run_mode doh
run_mode auto

echo "[SCRAPE] /metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" | grep -E 'dns_query_total|dns_rtt_seconds' && \
  echo "[OK] dns metrics present" || echo "[WARN] metrics not visible"
set -e
echo "[DONE]"