#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: outbound dial metrics (direct)"

export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

cnt=${CNT:-5}
host=${HOST:-example.com}
port=${PORT:-80}

echo "[RUN] $cnt direct connects to $host:$port"
for i in $(seq 1 $cnt); do
  echo "  [$i/$cnt] Connecting..."
  cargo run -q --example tcp_connect --features metrics -- $host $port || true
done

echo "[SCRAPE] /metrics from $SB_METRICS_ADDR"
if command -v curl >/dev/null 2>&1; then
  curl -s "http://$SB_METRICS_ADDR/metrics" | \
    grep -E 'outbound_connect_seconds|outbound_connect_total|outbound_error_total' && \
    echo "[OK] dial metrics present" || \
    (echo "[WARN] metrics not found; ensure app exporter enabled and feature=metrics"; exit 1)
else
  echo "[WARN] curl not available, skipping metrics check"
fi

echo "[INFO] e2e dial metrics test completed"