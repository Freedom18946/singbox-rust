#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_UDP_LONGRUN=1 时执行；否则跳过
# ASSERT:
# METRIC key=udp_upstream_pkts_in_total  label='.*' min=10 gate=1
# METRIC key=udp_upstream_bytes_in_total label='.*' min=300 gate=1

run() {
  if [[ "${SB_E2E_UDP_LONGRUN:-0}" != "1" ]]; then
    echo '{"name":"udp_upstream_longrun","ok":1,"msg":"skipped"}'
    return 0
  fi

  local socks="${SOCKS:-127.0.0.1:11080}"
  local dur="${UDP_LONGRUN_SEC:-30}"
  local t_end=$(( $(date +%s) + dur ))
  local ok=1 c=0 failed=0

  echo "[DEBUG] Starting UDP longrun test for ${dur}s"

  while [[ $(date +%s) -lt $t_end ]]; do
    if cargo run -q --example socks5_udp_probe --manifest-path "${ROOT}/crates/sb-core/Cargo.toml" -- "${socks}" "1.1.1.1:53" "example.com" >/dev/null 2>&1; then
      c=$((c+1))
    else
      failed=$((failed+1))
      # Allow some failures but not too many
      if [[ $failed -gt 5 ]]; then
        ok=0
        break
      fi
    fi
    sleep 0.05
  done

  if [[ "$ok" == "1" ]]; then
    echo "{\"name\":\"udp_upstream_longrun\",\"ok\":1,\"msg\":\"sent=${c} failed=${failed}\"}"
  else
    echo "{\"name\":\"udp_upstream_longrun\",\"ok\":0,\"msg\":\"too many failures: sent=${c} failed=${failed}\"}"
  fi
}

run