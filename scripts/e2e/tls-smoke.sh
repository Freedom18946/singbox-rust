#!/usr/bin/env zsh
set -euo pipefail

echo "[INFO] e2e: tls smoke (rustls 0.23)"

export RUST_LOG=${RUST_LOG:-warn}
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

# 默认校验；如需跳过：SB_TLS_NO_VERIFY=1
host=${HOST:-example.com}
port=${PORT:-443}

echo "[TEST] TLS handshake: ${host}:${port}"
echo "[ENV] SB_TLS_NO_VERIFY=${SB_TLS_NO_VERIFY:-0}"

cargo run -q -p sb-core --example tls_handshake --features tls_rustls -- ${host} ${port}

echo "[SCRAPE] /metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" | grep -E 'outbound_connect_seconds|outbound_error_total|tls_handshake' >/dev/null && \
  echo "[OK] tls metrics present" || echo "[WARN] metrics exporter not enabled / no metrics"
set -e

echo "[PASS] TLS smoke test completed"