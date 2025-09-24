#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_UP_CONF=1 时执行；否则跳过
# ASSERT:
# METRIC key=proxy_select_total label='pool="up#1"' min=1 gate=1
# ASSERT:
# METRIC key=udp_upstream_pkts_in_total label='.*' min=1 gate=1
run() {
  if [[ "${SB_E2E_UP_CONF:-0}" != "1" ]]; then
    echo '{"name":"socks5_udp_upstream_conf","ok":1,"msg":"skipped"}'; return 0
  fi
  local socks="${SOCKS:-127.0.0.1:11080}"
  # 触发一次 UDP 查询，经主实例路由到上游池 up#1
  if cargo run -q --example socks5_udp_probe --manifest-path "${ROOT}/crates/sb-core/Cargo.toml" -- "${socks}" "1.1.1.1:53" "example.com" >/dev/null 2>&1 ; then
    echo '{"name":"socks5_udp_upstream_conf","ok":1,"msg":"probe via configured upstream ok"}'
  else
    echo '{"name":"socks5_udp_upstream_conf","ok":0,"msg":"probe via configured upstream failed"}'
  fi
}
run