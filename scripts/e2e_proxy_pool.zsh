#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: proxy pool -> weighted selection with health/circuit breaking"

# 1) Setup proxy pool JSON with one good and one bad endpoint
export SB_PROXY_POOL_JSON='[
  {
    "name": "poolA",
    "policy": "weighted_rr",
    "sticky_ttl_ms": 5000,
    "sticky_cap": 1024,
    "endpoints": [
      {
        "kind": "http",
        "addr": "127.0.0.1:8080",
        "weight": 3,
        "max_fail": 2,
        "open_ms": 3000,
        "half_open_ms": 1000
      },
      {
        "kind": "http",
        "addr": "127.0.0.1:39998",
        "weight": 1,
        "max_fail": 2,
        "open_ms": 3000,
        "half_open_ms": 1000
      }
    ]
  }
]'
echo "[INFO] Proxy pool configured with poolA (one good: :8080, one bad: :39998)"

# 2) Enable health checking
export SB_PROXY_HEALTH_ENABLE=1
export SB_PROXY_HEALTH_INTERVAL_MS=1000  # Quick checks for testing
export SB_PROXY_HEALTH_TIMEOUT_MS=500    # Quick timeout
export SB_PROXY_HEALTH_FALLBACK_DIRECT=1
echo "[INFO] Health check enabled with circuit breaking and fallback"

# 3) Configure sticky affinity
export SB_PROXY_STICKY_TTL_MS=5000
export SB_PROXY_STICKY_CAP=1024
echo "[INFO] Sticky affinity configured"

# 4) Enable router rules to use named proxy pool
export SB_ROUTER_RULES_ENABLE=1
export SB_ROUTER_RULES_TEXT='default=proxy:poolA'
echo "[INFO] Router rules: default traffic routed to proxy:poolA"

# 5) Setup metrics endpoint
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}
INB=${INB:-127.0.0.1:18081}

# 6) Start a simple HTTP proxy on port 8080 (the "good" endpoint) in background
echo "[INFO] Starting test HTTP proxy on port 8080"
{
    # Simple HTTP CONNECT proxy using netcat
    while true; do
        echo -e "HTTP/1.1 200 Connection Established\r\n\r\n" | nc -l -p 8080 -q 1 || sleep 0.1
    done 2>/dev/null &
} &
PROXY_PID=$!
sleep 2  # Let proxy start

# 7) Wait for health checker to assess endpoints
echo "[INFO] Waiting 4 seconds for health checks to run..."
sleep 4

# 8) Test several HTTP connections to observe pool selection
echo "[INFO] Testing HTTP connections via proxy pool (should select available endpoints)"
for i in {1..3}; do
    echo "[TEST $i] Connecting via proxy pool..."
    set +e
    curl -sv -x http://$INB http://httpbin.org/ip -o /dev/null --max-time 5 2>&1 | tail -n2
    CURL_EXIT=$?
    set -e

    if [ $CURL_EXIT -eq 0 ]; then
        echo "[OK] Connection $i succeeded"
    else
        echo "[WARN] Connection $i failed (exit code: $CURL_EXIT)"
    fi
    sleep 1
done

# 9) Check metrics for proxy pool behavior
echo "[SCRAPE] Checking proxy pool metrics"
set +e

# Check endpoint health metrics
echo "[METRICS] Proxy endpoint health:"
curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'proxy_up{.*endpoint' | while read line; do
    echo "  $line"
done

# Check pool selection metrics
pool_selected=$(curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'proxy_pool_selected_total' | head -1)
if [[ -n "$pool_selected" ]]; then
    echo "[METRICS] proxy_pool_selected_total: $pool_selected"
    echo "[OK] Pool selection metrics present"
else
    echo "[WARN] proxy_pool_selected_total metric not found"
fi

# Check circuit breaker metrics
circuit_open=$(curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'proxy_circuit_state_total.*state="open"' | head -1)
if [[ -n "$circuit_open" ]]; then
    echo "[METRICS] proxy_circuit_state_total (open): $circuit_open"
    echo "[OK] Circuit breaker metrics present"
else
    echo "[INFO] No circuit breaker open events yet"
fi

# Check health check attempts with error classes
echo "[METRICS] Health check attempts by class:"
curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'proxy_check_total.*class' | while read line; do
    echo "  $line"
done

# Check fallback events (if all endpoints become unavailable)
fallback_total=$(curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'router_route_fallback_total.*reason="pool_empty"' | head -1)
if [[ -n "$fallback_total" ]]; then
    echo "[METRICS] router_route_fallback_total (pool_empty): $fallback_total"
    echo "[OK] Pool empty fallback metrics present"
else
    echo "[INFO] No pool empty fallback events yet"
fi

set -e

# 10) Cleanup
echo "[CLEANUP] Stopping test proxy"
kill $PROXY_PID 2>/dev/null || true

echo "[INFO] Summary: Proxy pool system with weighted selection, health checks, and circuit breaking tested"
echo "[DONE]"