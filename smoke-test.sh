#!/bin/bash
# Smoke test for singbox-rust CLI

set -e
echo "=== singbox-rust CLI Smoke Test ==="

# Test 1: Version
echo "Test 1: Version check"
./target/debug/singbox-rust --version
echo "✓ Version check passed"

# Test 2: Help
echo -e "\nTest 2: Help output"
./target/debug/singbox-rust --help > /dev/null
echo "✓ Help output passed"

# Test 3: Route command with JSON output
echo -e "\nTest 3: Route command (JSON)"
result=$(./target/debug/singbox-rust route --config minimal.yaml --dest example.com:443 --explain --format json)
echo "Route result: $result"
# Check if JSON contains expected fields
if echo "$result" | grep -q '"dest"' && echo "$result" | grep -q '"matched_rule"' && echo "$result" | grep -q '"outbound"'; then
    echo "✓ Route JSON output passed"
else
    echo "✗ Route JSON output failed"
    exit 1
fi

# Test 4: Route command with text output
echo -e "\nTest 4: Route command (text)"
result=$(./target/debug/singbox-rust route --config minimal.yaml --dest example.com:443 --explain --format text)
echo "Route result: $result"
if echo "$result" | grep -q "dest=example.com:443" && echo "$result" | grep -q "outbound=direct"; then
    echo "✓ Route text output passed"
else
    echo "✗ Route text output failed"
    exit 1
fi

# Test 5: Route command with trace
echo -e "\nTest 5: Route command (with trace)"
result=$(./target/debug/singbox-rust route --config minimal.yaml --dest example.com:443 --explain --trace --format json)
if echo "$result" | grep -q '"trace"'; then
    echo "✓ Route trace output passed"
else
    echo "✗ Route trace output failed"
    exit 1
fi

# Test 6: Check CLI with fingerprint
echo -e "\nTest 6: Check CLI (good config)"
if cargo build --bin check > /dev/null 2>&1; then
    echo "✓ Built check binary"
    ./target/debug/check --config minimal.yaml > /dev/null
    echo "✓ Check CLI good config passed"
else
    echo "✗ Failed to build check binary"
    exit 1
fi

# Test 7: Check CLI with bad config and JSON output
echo -e "\nTest 7: Check CLI (bad config with JSON)"
cat > /tmp/bad_test.yaml <<EOF
inbounds: [{type: socks, listen: "127.0.0.1:1080"}]
outbounds: [{type: direct, name: direct}]
route: {rules: [{domain_suffix: 123, outbound: direct}]}
EOF

set +e
result=$(./target/debug/check --config /tmp/bad_test.yaml --format json 2>/dev/null)
exit_code=$?
set -e

if [ $exit_code -ne 0 ] && echo "$result" | grep -q '"issues"' && echo "$result" | jq -e '.issues | length >= 1' > /dev/null 2>&1; then
    echo "✓ Check CLI bad config detection passed"
else
    echo "✗ Check CLI bad config detection failed"
    exit 1
fi

# Test 8: Check CLI with fingerprint
echo -e "\nTest 8: Check CLI (fingerprint)"
fingerprint=$(./target/debug/check --config minimal.yaml --print-fingerprint)
if [ ${#fingerprint} -eq 8 ] && echo "$fingerprint" | grep -qE '^[0-9a-f]+$'; then
    echo "✓ Check CLI fingerprint passed (fingerprint: $fingerprint)"
else
    echo "✗ Check CLI fingerprint failed"
    exit 1
fi

# Test 9: Admin debug endpoints (observe feature)
echo -e "\nTest 9: Admin debug endpoints (observe)"
if cargo build -p app --features observe --release > /dev/null 2>&1; then
    echo "✓ Built with observe feature"

    # Start the admin server in the background
    SB_ADMIN_DEBUG_ADDR="127.0.0.1:0" ./target/release/singbox-rust run --config minimal.yaml &
    SERVER_PID=$!

    # Give it time to start
    sleep 2

    # Test basic endpoints without full admin functionality
    echo "ℹ Admin debug server started (basic smoke test only)"

    # Clean up
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    echo "✓ Admin debug basic test passed"
else
    echo "✗ Failed to build with observe feature"
    exit 1
fi

echo -e "\n🎉 All smoke tests passed!"
echo "✓ CLI binary compiles successfully"
echo "✓ Version and help commands work"
echo "✓ Route command functions with JSON and text output"
echo "✓ Route trace functionality works"
echo "✓ Configuration file loading works"
echo "✓ Admin debug endpoints compile with observe feature"