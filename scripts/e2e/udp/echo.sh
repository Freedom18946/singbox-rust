#!/usr/bin/env zsh
set -euo pipefail

# 前置：确保你的 singbox-rust 已启动 SOCKS inbound（含 UDP 监听）
# 并设置环境变量：SB_SOCKS_UDP_ENABLE=1

ECHO_BIN="./target/debug/examples/udp_echo"
SOCKS_HOST="${SOCKS_HOST:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-11080}" # 你的 SOCKS 入站端口
ECHO_ADDR="${ECHO_ADDR:-127.0.0.1:19090}"

if [ ! -x "$ECHO_BIN" ]; then
  echo "[INFO] building echo example ..."
  cargo build -q --example udp_echo
fi

echo "[STEP] start local udp echo: $ECHO_ADDR"
$ECHO_BIN "$ECHO_ADDR" & echo_pid=$!
trap "kill $echo_pid || true" EXIT
sleep 0.2

echo "[STEP] send packet through SOCKS UDP (using socat if available)"
if command -v socat >/dev/null 2>&1; then
  # 通过 socks5 UDP 发送一帧数据
  # 注意：socat 的 socks5-udp 支持因版本而异，这里仅做演示
  printf "hello-udp" | socat -T1 -v - "socks5:$SOCKS_HOST:$ECHO_ADDR,socksport=$SOCKS_PORT,udp,interval=1"
else
  echo "[WARN] socat not found; please use your own UDP client to verify"
fi

echo "[OK] done"
