#!/usr/bin/env bash
set -euo pipefail
# ASSERT:
# METRIC key=udp_upstream_pkts_in_total label='.*' min=1 gate=1

run() {
  local socks="${SOCKS:-127.0.0.1:11080}"
  # Use workspace example (declared under singbox-rust)
  if timeout 8 cargo run -q -p singbox-rust --example socks5_udp_probe -- "${socks}" "1.1.1.1:53" "example.com" >/dev/null 2>&1 ; then
    echo '{"name":"socks5_udp_direct","ok":1,"msg":"probe ok"}'
  else
    echo '{"name":"socks5_udp_direct","ok":0,"msg":"probe failed"}'
  fi
}

run
