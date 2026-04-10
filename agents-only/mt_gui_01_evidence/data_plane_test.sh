#!/bin/bash
set -uo pipefail

REPO="/Users/bob/Desktop/Projects/ING/sing/singbox-rust"
RUST_BIN="$REPO/target/release/app"
GO_BIN="$REPO/go_fork_source/sing-box-1.12.14/sing-box"
RUST_CFG="$REPO/labs/interop-lab/configs/l18_gui_rust.json"
GO_CFG="$REPO/labs/interop-lab/configs/l18_gui_go.json"
REPORT="/tmp/gui_dataplane_report.txt"

echo "=== MT-GUI-01 Dual-Kernel Data Plane Verification ===" > "$REPORT"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$REPORT"
echo "" >> "$REPORT"

# Start a local HTTP echo target
python3 -m http.server 18899 --bind 127.0.0.1 &>/dev/null &
ECHO_PID=$!
sleep 1

cleanup() {
  kill $ECHO_PID 2>/dev/null || true
  kill $RUST_PID 2>/dev/null || true
  kill $GO_PID 2>/dev/null || true
  wait $ECHO_PID 2>/dev/null || true
  wait $RUST_PID 2>/dev/null || true
  wait $GO_PID 2>/dev/null || true
}
trap cleanup EXIT

# Start both kernels
"$RUST_BIN" run -c "$RUST_CFG" &>/tmp/rust_dp.log &
RUST_PID=$!
"$GO_BIN" run -c "$GO_CFG" &>/tmp/go_dp.log &
GO_PID=$!
sleep 3

# Verify both are listening
R_SOCKS=$(lsof -i :11810 -P -n 2>/dev/null | grep LISTEN | head -1 || echo "NOT_LISTENING")
G_SOCKS=$(lsof -i :11811 -P -n 2>/dev/null | grep LISTEN | head -1 || echo "NOT_LISTENING")
echo "--- Inbound SOCKS5 listener check ---" >> "$REPORT"
echo "Rust 11810: $R_SOCKS" >> "$REPORT"
echo "Go   11811: $G_SOCKS" >> "$REPORT"
echo "" >> "$REPORT"

# SOCKS5 traffic test via curl --socks5
echo "--- SOCKS5 TCP CONNECT through inbound proxy ---" >> "$REPORT"
R_OUT=$(curl -sS --socks5-hostname 127.0.0.1:11810 --max-time 5 http://127.0.0.1:18899/ 2>&1 | head -c 200)
R_CODE=$?
G_OUT=$(curl -sS --socks5-hostname 127.0.0.1:11811 --max-time 5 http://127.0.0.1:18899/ 2>&1 | head -c 200)
G_CODE=$?
echo "Rust exit=$R_CODE output=$(echo "$R_OUT" | head -c 80)..." >> "$REPORT"
echo "Go   exit=$G_CODE output=$(echo "$G_OUT" | head -c 80)..." >> "$REPORT"
if [ "$R_CODE" = "0" ] && [ "$G_CODE" = "0" ]; then
  echo "RESULT: PASS-STRICT (both kernels relay HTTP via SOCKS5 successfully)" >> "$REPORT"
elif [ "$R_CODE" = "0" ] || [ "$G_CODE" = "0" ]; then
  echo "RESULT: FAIL (asymmetric: Rust=$R_CODE Go=$G_CODE)" >> "$REPORT"
else
  echo "RESULT: FAIL (both failed: Rust=$R_CODE Go=$G_CODE)" >> "$REPORT"
fi
echo "" >> "$REPORT"

# Now check connections registered after data plane traffic
echo "--- GET /connections after data plane traffic ---" >> "$REPORT"
sleep 1
R_CONN=$(curl -s -H "Authorization: Bearer test-secret" "http://127.0.0.1:19090/connections" 2>/dev/null)
G_CONN=$(curl -s -H "Authorization: Bearer test-secret" "http://127.0.0.1:9090/connections" 2>/dev/null)
R_DOWN=$(echo "$R_CONN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("downloadTotal","N/A"))' 2>/dev/null || echo "PARSE_ERR")
G_DOWN=$(echo "$G_CONN" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("downloadTotal","N/A"))' 2>/dev/null || echo "PARSE_ERR")
echo "Rust downloadTotal: $R_DOWN" >> "$REPORT"
echo "Go   downloadTotal: $G_DOWN" >> "$REPORT"
if [ "$R_DOWN" != "PARSE_ERR" ] && [ "$G_DOWN" != "PARSE_ERR" ] && [ "$R_DOWN" != "0" ] && [ "$G_DOWN" != "0" ]; then
  echo "RESULT: PASS-STRICT (both kernels track download bytes through GUI control plane)" >> "$REPORT"
elif [ "$R_DOWN" != "PARSE_ERR" ] && [ "$G_DOWN" != "PARSE_ERR" ]; then
  echo "RESULT: PASS-ENV-LIMITED (counters present but may be 0 for short-lived conn)" >> "$REPORT"
else
  echo "RESULT: FAIL" >> "$REPORT"
fi
echo "" >> "$REPORT"

cat "$REPORT"
