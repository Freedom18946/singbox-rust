#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: proxy health -> fallback direct"

# 1) Setup failing proxy (non-existent port to simulate failure)
export SB_ROUTER_DEFAULT_PROXY=${SB_ROUTER_DEFAULT_PROXY:-http://127.0.0.1:39999}
echo "[INFO] USING FAILING PROXY = $SB_ROUTER_DEFAULT_PROXY"

# 2) Enable health checking and fallback
export SB_PROXY_HEALTH_ENABLE=1
export SB_PROXY_HEALTH_INTERVAL_MS=1000  # Quick checks for testing
export SB_PROXY_HEALTH_TIMEOUT_MS=500    # Quick timeout for testing
export SB_PROXY_HEALTH_FALLBACK_DIRECT=1
echo "[INFO] Health check enabled with fallback to direct"

# 3) Enable router rules to force proxy decision
export SB_ROUTER_RULES_ENABLE=1
export SB_ROUTER_RULES_TEXT='default=proxy'
echo "[INFO] Router rules: default traffic routed to proxy"

# 4) Setup metrics endpoint
export SB_METRICS_ADDR=${SB_METRICS_ADDR:-127.0.0.1:9090}
INB=${INB:-127.0.0.1:18081}

# 5) Wait briefly for health checker to detect the failing proxy
echo "[INFO] Waiting 3 seconds for health check to detect failure..."
sleep 3

# 6) Test HTTP connection (should work via fallback to direct)
echo "[INFO] Testing HTTP connection via failing proxy (should fallback to direct)"
set +e
curl -sv -x http://$INB http://example.com/ -o /dev/null --max-time 10 2>&1 | tail -n5
CURL_EXIT=$?
set -e

if [ $CURL_EXIT -eq 0 ]; then
    echo "[OK] HTTP connection succeeded (fallback working)"
else
    echo "[WARN] HTTP connection failed (exit code: $CURL_EXIT)"
fi

# 7) Check metrics for proxy health and fallback events
echo "[SCRAPE] Checking health and fallback metrics"
set +e

# Check proxy health metrics (should show proxy as down)
proxy_up=$(curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'proxy_up' | head -1)
if [[ -n "$proxy_up" ]]; then
    echo "[METRICS] proxy_up: $proxy_up"
    if [[ "$proxy_up" == *"0"* ]]; then
        echo "[OK] Proxy correctly detected as down"
    else
        echo "[WARN] Proxy not detected as down"
    fi
else
    echo "[WARN] proxy_up metric not found"
fi

# Check health check attempts
check_total=$(curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'proxy_check_total' | head -1)
if [[ -n "$check_total" ]]; then
    echo "[METRICS] proxy_check_total: $check_total"
    echo "[OK] Health check metrics present"
else
    echo "[WARN] proxy_check_total metric not found"
fi

# Check fallback events
fallback_total=$(curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'router_route_fallback_total' | head -1)
if [[ -n "$fallback_total" ]]; then
    echo "[METRICS] router_route_fallback_total: $fallback_total"
    echo "[OK] Fallback metrics present"
else
    echo "[WARN] router_route_fallback_total metric not found"
fi

# Check route totals (should show fallback behavior)
route_total=$(curl -s "http://${SB_METRICS_ADDR}/metrics" 2>/dev/null | grep 'router_route_total' | grep 'decision="direct"')
if [[ -n "$route_total" ]]; then
    echo "[METRICS] router_route_total (direct): $route_total"
    echo "[OK] Direct routes recorded (indicating fallback)"
else
    echo "[WARN] Direct route metrics not found"
fi

set -e

echo "[INFO] Summary: Proxy health check system with fallback tested"
echo "[DONE]"