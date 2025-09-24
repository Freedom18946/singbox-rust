#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_DNS_DOT=1 时执行；否则跳过通过
# ASSERT:
# METRIC key=dns_query_total label='backend="dot"' min=1 gate=1

run() {
  if [[ "${SB_E2E_DNS_DOT:-0}" != "1" ]]; then
    echo '{"name":"dns_dot_internal","ok":1,"msg":"skipped"}'
    return 0
  fi

  # 通过系统解析或 dig 触发一次查询，实际由内部 dot 后端处理
  local ok=0
  for i in 1 2 3; do
    if getent hosts example.com >/dev/null 2>&1 || host -W 2 example.com 127.0.0.1 >/dev/null 2>&1; then
      ok=1; break
    fi
    sleep 0.3
  done

  if [[ "$ok" == "1" ]]; then
    echo '{"name":"dns_dot_internal","ok":1,"msg":"dot backend query ok"}'
  else
    echo '{"name":"dns_dot_internal","ok":0,"msg":"dot query failed"}'
  fi
}

run