#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: socks5 udp roundtrip (dns)"
export SB_SOCKS_UDP_ENABLE=1
export SB_SOCKS_UDP_LISTEN=${SB_SOCKS_UDP_LISTEN:-127.0.0.1:11080}
export SB_SOCKS_UDP_NAT_TTL_MS=${SB_SOCKS_UDP_NAT_TTL_MS:-30000}
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

echo "[RUN] probe"
cargo run -q --example socks5_udp_probe -- ${SB_SOCKS_UDP_LISTEN} 1.1.1.1:53 example.com

echo "[SCRAPE] /metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" | grep -E 'udp_pkts_|udp_bytes_|udp_nat_size|udp_nat_evicted_total' && \
  echo "[OK] udp metrics present" || echo "[WARN] metrics exporter not enabled / not visible"
set -e
echo "[DONE]"