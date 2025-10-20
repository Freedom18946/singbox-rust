#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: router JSON bridge"

export SB_ROUTER_RULES_FROM_JSON=1
export SB_ROUTER_JSON_FILE=${SB_ROUTER_JSON_FILE:-examples/router.json}
export SB_ROUTER_DEFAULT_PROXY=${SB_ROUTER_DEFAULT_PROXY:-direct}
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

HTTP=${HTTP:-127.0.0.1:18081}
echo "[RUN] curl -x http://$HTTP http://www.example.com/ (suffix=.example.com => proxy or direct per DEFAULT PROXY)"
set +e
curl -sv -x http://$HTTP http://www.example.com/ -o /dev/null 2>&1 | tail -n5
set -e

echo "[SCRAPE] /metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" | grep -E 'router_(match|decide|route)_total|router_json_bridge_errors_total' && \
  echo "[OK] router metrics present" || echo "[WARN] metrics not visible"
set -e
echo "[DONE]"