#!/usr/bin/env zsh
set -euo pipefail

echo "[INFO] e2e: socks5 udp via upstream proxy"

UP=${UP:-127.0.0.1:29080}
DNS=${DNS:-1.1.1.1:53}
LISTEN=${SB_SOCKS_UDP_LISTEN:-127.0.0.1:11080}

# Start mock upstream (SOCKS5 with UDP associate)
echo "[RUN] mock upstream socks5 server at $UP -> $DNS"
cargo run -q --example mock_socks5_upstream -- ${UP} ${DNS} &
UP_PID=$!
trap 'kill $UP_PID $APP_PID 2>/dev/null || true' EXIT
sleep 0.5

# Configure proxy registry and router
export SB_SOCKS_UDP_ENABLE=1
export SB_SOCKS_UDP_LISTEN=${LISTEN}
export SB_SOCKS_UDP_PROXY_FALLBACK_DIRECT=0
export SB_SOCKS_UDP_PROXY_TIMEOUT_MS=${SB_SOCKS_UDP_PROXY_TIMEOUT_MS:-800}
export SB_SOCKS_UDP_UP_TTL_MS=${SB_SOCKS_UDP_UP_TTL_MS:-30000}
export SB_PROXY_POOL_JSON='[
  {
    "name": "poolA",
    "policy": "weighted_rr",
    "endpoints": [
      {
        "kind": "socks5",
        "addr": "'${UP}'",
        "weight": 1,
        "max_fail": 3,
        "open_ms": 3000,
        "half_open_ms": 1000
      }
    ]
  }
]'
export SB_ROUTER_RULES_ENABLE=1
export SB_ROUTER_RULES_TEXT='default = proxy:poolA'
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}

# Launch main service (no HTTP inbound needed but keep default CLI alive)
echo "[RUN] launching singbox-rust"
cargo run -q -p app --bin singbox-rust -- --no-banner --http 127.0.0.1:18081 >/tmp/sb-udp-proxy.log 2>&1 &
APP_PID=$!
sleep 1.5

echo "[PROBE] dns query through socks5 udp (should hit upstream)"
cargo run -q --example socks5_udp_probe -- ${LISTEN} ${DNS} example.com

echo "[INFO] scraping udp upstream metrics (optional)"
set +e
curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'udp_upstream_' && echo "[OK] udp upstream metrics present" || echo "[WARN] metrics exporter unavailable"
set -e

echo "[CLEANUP] shutting down"
kill $APP_PID 2>/dev/null || true
kill $UP_PID 2>/dev/null || true
sleep 0.2

echo "[DONE]"
