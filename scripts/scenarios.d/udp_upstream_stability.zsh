#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_UDP_STABILITY=1 时执行；否则跳过
# ASSERT:
# METRIC key=udp_upstream_pkts_in_total  label='.*' min=50 gate=1
# METRIC key=udp_upstream_bytes_in_total label='.*' min=1000 gate=1
# VALUE  key=udp_upstream_map_size      label='.*' op='<=' value=512 gate=1

run() {
  if [[ "${SB_E2E_UDP_STABILITY:-0}" != "1" ]]; then
    echo '{"name":"udp_upstream_stability","ok":1,"msg":"skipped"}'
    return 0
  fi

  # Enable upstream receive task for more realistic session usage
  export SB_SOCKS_UDP_UP_RECV_TASK=1

  local socks="${SOCKS:-127.0.0.1:11080}"
  local dur="${UDP_STAB_SEC:-60}"
  local max_map_size="${UDP_MAP_MAX:-512}"
  local t_end=$(( $(date +%s) + dur ))
  local sent=0 failed=0 ok=1

  echo "[DEBUG] Starting UDP stability test for ${dur}s with map_size <= ${max_map_size}"

  while [[ $(date +%s) -lt $t_end ]]; do
    if cargo run -q --example socks5_udp_probe --manifest-path "${ROOT}/crates/sb-core/Cargo.toml" -- "${socks}" "1.1.1.1:53" "example.com" >/dev/null 2>&1; then
      sent=$((sent+1))
    else
      failed=$((failed+1))
      # Allow some failures but not too many for long-running scenario
      if [[ $failed -gt 10 ]]; then
        ok=0
        break
      fi
    fi
    sleep 0.03
  done

  if [[ "$ok" == "1" ]]; then
    echo "{\"name\":\"udp_upstream_stability\",\"ok\":1,\"msg\":\"sent=${sent} failed=${failed}\"}"
  else
    echo "{\"name\":\"udp_upstream_stability\",\"ok\":0,\"msg\":\"too many failures: sent=${sent} failed=${failed}\"}"
  fi
}

run