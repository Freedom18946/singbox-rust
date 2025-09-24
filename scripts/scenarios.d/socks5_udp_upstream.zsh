#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_UDP_UPSTREAM=1 时执行；否则跳过
# ASSERT:
# METRIC key=udp_upstream_pkts_in_total label='.*' min=1 gate=1

run() {
  if [[ "${SB_E2E_UDP_UPSTREAM:-0}" != "1" ]]; then
    echo '{"name":"socks5_udp_upstream","ok":1,"msg":"skipped"}'
    return 0
  fi

  local root="${ROOT}"
  local target="${root}/target/e2e"
  local up_cfg="${target}/runtime_up.yaml"
  local up_log="${target}/upstream.log"
  local up_pid=""

  # 上游端口（与主实例不冲突）
  local up_socks="${UP_SOCKS:-127.0.0.1:21080}"
  local up_http="${UP_HTTP:-127.0.0.1:28081}"

  # 生成上游最小配置：仅 socks 入站 + direct 出站
  cat > "${up_cfg}" <<YAML
inbounds:
  - type: socks
    listen: ${up_socks}

outbounds:
  - name: direct
    type: direct
YAML

  # 启动上游实例（必要时带 metrics 可另配，不强制）
  echo "[DEBUG] Starting upstream instance on ${up_socks}"
  RUST_LOG=${RUST_LOG:-warn} "${root}/target/debug/singbox-rust" --config "${up_cfg}" > "${up_log}" 2>&1 &
  up_pid=$!

  # 等上游 socks 口就绪
  local up_host="${up_socks%%:*}"
  local up_port="${up_socks##*:}"
  local ready=0

  for i in {1..50}; do
    if (echo > /dev/tcp/"${up_host}"/"${up_port}") >/dev/null 2>&1; then
      ready=1; break
    fi
    if command -v nc >/dev/null 2>&1; then
      if nc -z -w 1 "${up_host}" "${up_port}" >/dev/null 2>&1; then
        ready=1; break
      fi
    fi
    sleep 0.2
  done

  if [[ "${ready}" != "1" ]]; then
    echo '{"name":"socks5_udp_upstream","ok":0,"msg":"upstream not ready"}'
    [[ -n "${up_pid}" ]] && kill "${up_pid}" >/dev/null 2>&1 || true
    return 0
  fi

  # 通过主实例的 socks（127.0.0.1:11080）出站到"上游 socks"，对 1.1.1.1:53 发 UDP 查询
  # Note: This is a simplified test - in a real setup, the main instance would need
  # to be configured to route through the upstream socks proxy
  local socks_main="${SOCKS:-127.0.0.1:11080}"
  local ok=0

  # Try the probe through main instance (this will test if UDP upstream metrics get incremented)
  for i in 1 2 3; do
    if timeout 5 cargo run -q --example socks5_udp_probe --manifest-path "${root}/crates/sb-core/Cargo.toml" -- "${socks_main}" "1.1.1.1:53" "example.com" >/dev/null 2>&1; then
      ok=1; break
    fi
    sleep 0.5
  done

  # 清理上游实例
  if [[ -n "${up_pid}" ]]; then
    kill "${up_pid}" >/dev/null 2>&1 || true
    wait "${up_pid}" >/dev/null 2>&1 || true
  fi

  if [[ "$ok" == "1" ]]; then
    echo '{"name":"socks5_udp_upstream","ok":1,"msg":"probe via main instance ok"}'
  else
    echo '{"name":"socks5_udp_upstream","ok":0,"msg":"probe via main instance failed"}'
  fi
}

run