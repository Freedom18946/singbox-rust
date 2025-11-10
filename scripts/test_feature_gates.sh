#!/bin/bash
# Feature gate combination test script
# Tests various combinations of DNS and adapter features

# Note: Don't use 'set -e' so we can continue testing after failures

echo "=== Testing Feature Gate Combinations ==="

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
PASSED=0
FAILED=0
TOTAL=0

test_build() {
    local name="$1"
    shift
    local features="$@"

    TOTAL=$((TOTAL + 1))
    echo ""
    echo -e "${YELLOW}[$TOTAL] Testing: $name${NC}"
    echo "Features: $features"

    if cargo build --package sb-core --features "$features" --no-default-features --quiet 2>&1 | grep -q "error\[E"; then
        echo -e "${RED}✗ FAILED${NC}"
        FAILED=$((FAILED + 1))
        return 1
    else
        echo -e "${GREEN}✓ PASSED${NC}"
        PASSED=$((PASSED + 1))
        return 0
    fi
}

# Basic DNS feature combinations
echo ""
echo "=== DNS Feature Combinations ==="

test_build "DNS UDP only" "dns_udp"
test_build "DNS DoH only" "dns_doh dns_udp"
test_build "DNS DoT only" "dns_dot"
test_build "DNS DoQ only" "dns_doq dns_udp"
test_build "DNS DoH3 only" "dns_doh3 dns_udp"

# All DNS features together
test_build "All DNS features" "dns_udp dns_doh dns_dot dns_doq dns_doh3"

# DNS with default features
test_build "DNS with defaults" "dns_udp dns_doh dns_dot dns_doq dns_doh3 tls_rustls"

# Adapter feature combinations
echo ""
echo "=== Adapter Feature Combinations ==="

test_build "HTTP adapter" "adapter-http"
test_build "SOCKS adapter" "adapter-socks"
test_build "Shadowsocks adapter" "adapter-shadowsocks"
test_build "VMess adapter" "adapter-vmess"
test_build "VLESS adapter" "adapter-vless"
test_build "Trojan adapter" "adapter-trojan"

# Combined adapter features
test_build "HTTP + SOCKS" "adapter-http adapter-socks"
test_build "All basic adapters" "adapter-http adapter-socks adapter-shadowsocks adapter-vmess adapter-vless adapter-trojan"

# QUIC-based adapters
echo ""
echo "=== QUIC-based Adapter Combinations ==="

test_build "TUIC outbound" "out_tuic out_quic tls_rustls"
test_build "Hysteria2 outbound" "out_hysteria2 out_quic tls_rustls"

# DNS + Adapters combinations
echo ""
echo "=== DNS + Adapters Combinations ==="

test_build "DNS DoH3 + HTTP adapter" "dns_doh3 dns_udp adapter-http"
test_build "All DNS + All adapters" "dns_udp dns_doh dns_dot dns_doq dns_doh3 adapter-http adapter-socks adapter-shadowsocks"

# Print summary
echo ""
echo "========================================="
echo -e "${GREEN}PASSED: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}FAILED: $FAILED${NC}"
fi
echo "TOTAL:  $TOTAL"
echo "========================================="

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
else
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
fi
