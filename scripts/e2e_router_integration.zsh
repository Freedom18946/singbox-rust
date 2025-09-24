#!/usr/bin/env zsh
set -euo pipefail
echo "[INFO] e2e: router integration (reject + nat capacity)"

# Test environment variables
export SB_ROUTER_RULES_ENABLE=1
export SB_ROUTER_RULES_TEXT='keyword:tracker = reject
default = direct'
export SB_UDP_NAT_MAX=2

# HTTP inbound address (user needs to start singbox-rust externally)
HTTP=${HTTP:-127.0.0.1:18081}
SOCKS=${SOCKS:-127.0.0.1:11080}

echo "[STEP] Testing HTTP CONNECT to tracker domain (expect 403)"
set +e
# Test HTTP reject - should get 403
response=$(curl -sv --connect-timeout 5 -x http://$HTTP http://cdn.tracker.net/ -o /dev/null 2>&1)
code=$(echo "$response" | awk '/< HTTP\/1.1/{print $3}' | tail -n1)
set -e

if [[ "$code" == "403" ]]; then
    echo "[OK] HTTP reject: got 403 as expected"
else
    echo "[FAIL] HTTP reject: expected 403, got '$code'"
    echo "Response: $response"
    exit 1
fi

echo "[STEP] Testing HTTP CONNECT to allowed domain (expect 200)"
set +e
response=$(curl -sv --connect-timeout 5 -x http://$HTTP http://example.com/ -o /dev/null 2>&1)
code=$(echo "$response" | awk '/< HTTP\/1.1/{print $3}' | tail -n1)
set -e

if [[ "$code" == "200" ]]; then
    echo "[OK] HTTP allow: got 200 as expected"
else
    echo "[WARN] HTTP allow: expected 200, got '$code' (may be expected if example.com is not reachable)"
fi

echo "[STEP] Testing SOCKS5 TCP to tracker domain (expect connection refused)"
set +e
# Test SOCKS5 TCP reject - should fail to connect
timeout 5 nc -X 5 -x $SOCKS cdn.tracker.net 80 < /dev/null > /dev/null 2>&1
result=$?
set -e

if [[ $result -ne 0 ]]; then
    echo "[OK] SOCKS5 TCP reject: connection failed as expected"
else
    echo "[FAIL] SOCKS5 TCP reject: connection should have failed"
    exit 1
fi

echo "[INFO] Testing UDP NAT capacity limits requires SOCKS5 UDP service"
echo "[HINT] Start the service with SB_SOCKS_UDP_ENABLE=1 and check /metrics for udp_nat_reject_total"
echo "[HINT] Send multiple UDP flows to exceed SB_UDP_NAT_MAX=2 and observe rejections"

echo "[INFO] Router integration tests completed"
echo "[NEXT] Check metrics at /metrics for:"
echo "  - router_decide_total{decision=\"reject\"} > 0"
echo "  - udp_nat_reject_total{reason=\"capacity\"} (if UDP NAT capacity exceeded)"