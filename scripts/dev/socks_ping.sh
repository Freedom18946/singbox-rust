#!/usr/bin/env bash
set -euo pipefail

# Simple SOCKS5 traffic generator for local testing
# - Assumes a SOCKS5 inbound listening on 127.0.0.1:1081
# - Uses curl to make HTTP requests via the proxy

PROXY_HOST="127.0.0.1"
PROXY_PORT="1081"
TARGET_URL="http://example.com/"
COUNT=${COUNT:-5}

echo "Generating ${COUNT} HTTP requests via SOCKS5 ${PROXY_HOST}:${PROXY_PORT} → ${TARGET_URL}" >&2
for i in $(seq 1 "$COUNT"); do
  echo "[$i] curl --socks5-hostname ${PROXY_HOST}:${PROXY_PORT} ${TARGET_URL}" >&2
  curl -sS --max-time 3 \
    --socks5-hostname "${PROXY_HOST}:${PROXY_PORT}" \
    "${TARGET_URL}" >/dev/null || true
  sleep 0.5
done

echo "Done. Check metrics: inbound_active_connections{protocol=\"socks\"}." >&2

