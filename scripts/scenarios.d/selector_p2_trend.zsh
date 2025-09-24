#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_P2_TREND=1 时执行；否则跳过
# 断言（示例池名 up，端点 up#1=快、up#2=慢）:
# METRIC  key=proxy_select_total label='pool="up",endpoint="up#1"' min=1 gate=1
# METRIC  key=proxy_select_total label='pool="up",endpoint="up#2"' min=1 gate=1
# COMPARE key=proxy_select_total left='pool="up",endpoint="up#1"' right='pool="up",endpoint="up#2"' op='>' gap=10 gate=1

run() {
  if [[ "${SB_E2E_P2_TREND:-0}" != "1" ]]; then
    echo '{"name":"selector_p2_trend","ok":1,"msg":"skipped"}'
    return 0
  fi

  local root="${ROOT}"
  local target="${root}/target/e2e"
  local fast="127.0.0.1:31080"
  local slow="127.0.0.1:31081"
  local PID_FAST="" PID_SLOW=""

  # 启动快/慢 SOCKS5 桩
  (cargo run -q --example socks5_stub --manifest-path "${root}/crates/sb-core/Cargo.toml" -- --listen "${fast}" --delay-ms 1 >/dev/null 2>&1) &
  PID_FAST=$!
  (cargo run -q --example socks5_stub --manifest-path "${root}/crates/sb-core/Cargo.toml" -- --listen "${slow}" --delay-ms 160 >/dev/null 2>&1) &
  PID_SLOW=$!

  # Wait for stubs to be ready
  local fast_ready=0 slow_ready=0
  for i in {1..30}; do
    [[ "$fast_ready" == "0" ]] && (echo > /dev/tcp/127.0.0.1/31080) >/dev/null 2>&1 && fast_ready=1
    [[ "$slow_ready" == "0" ]] && (echo > /dev/tcp/127.0.0.1/31081) >/dev/null 2>&1 && slow_ready=1
    [[ "$fast_ready" == "1" && "$slow_ready" == "1" ]] && break
    sleep 0.1
  done

  if [[ "$fast_ready" != "1" || "$slow_ready" != "1" ]]; then
    echo '{"name":"selector_p2_trend","ok":0,"msg":"stubs not ready"}'
    [[ -n "${PID_FAST}" ]] && kill "${PID_FAST}" >/dev/null 2>&1 || true
    [[ -n "${PID_SLOW}" ]] && kill "${PID_SLOW}" >/dev/null 2>&1 || true
    return 0
  fi

  # 修改主实例运行配置：两上游端点 up#1/up#2，UDP 走 proxy:up（命名池）
  local runtime_orig="${target}/runtime.yaml"
  local runtime_backup="${target}/runtime.yaml.backup"
  cp "${runtime_orig}" "${runtime_backup}"

  # Inject two upstream endpoints and route UDP traffic through the "up" pool
  awk '
    BEGIN{in_out=0; in_route=0}
    {print}
    /outbounds:/{in_out=1}
    in_out==1 && /default_outbound:/ {
      print "  - name: up#1"
      print "    type: socks"
      print "    server: \"127.0.0.1\""
      print "    port: 31080"
      print "  - name: up#2"
      print "    type: socks"
      print "    server: \"127.0.0.1\""
      print "    port: 31081"
      in_out=0
    }
    /route:/{in_route=1}
    in_route==1 && /rules:/ {
      print "    - name: udp->up"
      print "      when: { proto: [\"udp\"] }"
      print "      to: \"proxy:up\""
      in_route=0
    }
  ' "${runtime_backup}" > "${runtime_orig}"

  # 开 P2：RTT 偏置 + 半开
  export SB_SELECT_RTT_BIAS=1 SB_SELECT_RTT_ALPHA=0.6 SB_SELECT_HALF_OPEN=1

  # 触发若干 UDP 查询，驱动选择器学习
  local socks="${SOCKS:-127.0.0.1:11080}"
  local n=${P2_TREND_PROBES:-40}
  local probe_ok=0

  for i in $(seq 1 "$n"); do
    if cargo run -q --example socks5_udp_probe --manifest-path "${root}/crates/sb-core/Cargo.toml" -- "${socks}" "1.1.1.1:53" "example.com" >/dev/null 2>&1; then
      probe_ok=$((probe_ok + 1))
    fi
    sleep 0.02
  done

  # 恢复配置
  mv "${runtime_backup}" "${runtime_orig}"

  # 清理
  [[ -n "${PID_FAST}" ]] && kill "${PID_FAST}" >/dev/null 2>&1 || true
  [[ -n "${PID_SLOW}" ]] && kill "${PID_SLOW}" >/dev/null 2>&1 || true

  # 场景自身的基本 ok（只是执行成功，不包含断言）
  if [[ "$probe_ok" -gt 0 ]]; then
    echo "{\"name\":\"selector_p2_trend\",\"ok\":1,\"msg\":\"probes sent: ${probe_ok}/${n}\"}"
  else
    echo "{\"name\":\"selector_p2_trend\",\"ok\":0,\"msg\":\"no successful probes\"}"
  fi
}

run