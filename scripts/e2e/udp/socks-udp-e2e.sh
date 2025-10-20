#!/usr/bin/env zsh
set -euo pipefail

# 只跑 sb-adapters 的 SOCKS5 UDP e2e 集成测试
echo "[RUN] sb-adapters socks_udp_e2e"
cargo test -q -p sb-adapters --test socks_udp_e2e -- --nocapture
echo "[OK] socks_udp_e2e passed"