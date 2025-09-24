#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_P2_RECOVERY=1 时执行；否则跳过
# ASSERT:
# METRIC  key=proxy_select_total label='pool="up2",endpoint="up2#1"' min=1 gate=1
# METRIC  key=proxy_select_total label='pool="up2",endpoint="up2#2"' min=1 gate=1
# COMPARE key=proxy_select_total left='pool="up2",endpoint="up2#2"' right='pool="up2",endpoint="up2#1"' op='>' gap=10 gate=1

run() {
  if [[ "${SB_E2E_P2_RECOVERY:-0}" != "1" ]]; then
    echo '{"name":"selector_p2_recovery","ok":1,"msg":"skipped"}'
    return 0
  fi

  local root="${ROOT}"
  local target="${root}/target/e2e"
  local slow="127.0.0.1:32080"  # up2#1 slow
  local fast="127.0.0.1:32081"  # up2#2 fast
  local PID_SLOW="" PID_FAST=""

  # 启动慢/快 SOCKS5 桩 (inverted from trend scenario)
  (cargo run -q --example socks5_stub --manifest-path "${root}/crates/sb-core/Cargo.toml" -- --listen "${slow}" --delay-ms 160 >/dev/null 2>&1) &
  PID_SLOW=$!
  (cargo run -q --example socks5_stub --manifest-path "${root}/crates/sb-core/Cargo.toml" -- --listen "${fast}" --delay-ms 1 >/dev/null 2>&1) &
  PID_FAST=$!

  # Wait for stubs to be ready
  local slow_ready=0 fast_ready=0
  for i in {1..30}; do
    [[ "$slow_ready" == "0" ]] && (echo > /dev/tcp/127.0.0.1/32080) >/dev/null 2>&1 && slow_ready=1
    [[ "$fast_ready" == "0" ]] && (echo > /dev/tcp/127.0.0.1/32081) >/dev/null 2>&1 && fast_ready=1
    [[ "$slow_ready" == "1" && "$fast_ready" == "1" ]] && break
    sleep 0.1
  done

  if [[ "$slow_ready" != "1" || "$fast_ready" != "1" ]]; then
    echo '{"name":"selector_p2_recovery","ok":0,"msg":"stubs not ready"}'
    [[ -n "${PID_SLOW}" ]] && kill "${PID_SLOW}" >/dev/null 2>&1 || true
    [[ -n "${PID_FAST}" ]] && kill "${PID_FAST}" >/dev/null 2>&1 || true
    return 0
  fi

  # 修改主实例运行配置：独立池 up2 (避免与 up 池历史累加干扰)
  local runtime_orig="${target}/runtime.yaml"
  local runtime_backup="${target}/runtime.yaml.backup"
  cp "${runtime_orig}" "${runtime_backup}"

  # Inject up2 pool with inverted fast/slow and route UDP through up2
  awk '
    BEGIN{o=0; r=0}
    {print}
    /outbounds:/ && o==0 {
      print "  - name: up2#1"
      print "    type: socks"
      print "    server: \"127.0.0.1\""
      print "    port: 32080"
      print "  - name: up2#2"
      print "    type: socks"
      print "    server: \"127.0.0.1\""
      print "    port: 32081"
      o=1
    }
    /rules:/ && r==0 {
      print "    - name: udp->up2"
      print "      when: { proto: [\"udp\"] }"
      print "      to: \"proxy:up2\""
      r=1
    }
  ' "${runtime_backup}" > "${runtime_orig}"

  # 开 P2：RTT 偏置 + 半开，与 trend 相同参数
  export SB_SELECT_RTT_BIAS=1 SB_SELECT_RTT_ALPHA=0.6 SB_SELECT_HALF_OPEN=1

  # 触发若干 UDP 查询，驱动选择器学习（期望收敛到 up2#2 快端）
  local socks="${SOCKS:-127.0.0.1:11080}"
  local n=${P2_RECOVERY_PROBES:-40}
  local gap=${P2_RECOVERY_GAP:-10}
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
  [[ -n "${PID_SLOW}" ]] && kill "${PID_SLOW}" >/dev/null 2>&1 || true
  [[ -n "${PID_FAST}" ]] && kill "${PID_FAST}" >/dev/null 2>&1 || true

  # 场景自身的基本 ok（只是执行成功，不包含断言）
  if [[ "$probe_ok" -gt 0 ]]; then
    echo "{\"name\":\"selector_p2_recovery\",\"ok\":1,\"msg\":\"probes sent: ${probe_ok}/${n}, gap=${gap}\"}"
  else
    echo "{\"name\":\"selector_p2_recovery\",\"ok\":0,\"msg\":\"no successful probes\"}"
  fi
}

run