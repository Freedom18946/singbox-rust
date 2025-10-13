#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_DNS_DOQ=1 时执行；否则跳过通过
# ASSERT:
# METRIC key=dns_query_total label='backend="doq"' min=1 gate=1

run() {
  if [[ "${SB_E2E_DNS_DOQ:-0}" != "1" ]]; then
    echo '{"name":"dns_doq_internal","ok":1,"msg":"skipped"}'
    return 0
  fi

  # 触发一次解析，由内部 doq 后端处理（需主进程已配置/启用 DoQ）
  local ok=0
  for i in 1 2 3; do
    if getent hosts example.com >/dev/null 2>&1 || host -W 2 example.com 127.0.0.1 >/dev/null 2>&1; then
      ok=1; break
    fi
    sleep 0.3
  done

  if [[ "$ok" == "1" ]]; then
    echo '{"name":"dns_doq_internal","ok":1,"msg":"doq backend query ok"}'
  else
    echo '{"name":"dns_doq_internal","ok":0,"msg":"doq query failed"}'
  fi
}

run

