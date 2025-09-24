#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_DNS_DOH=1 时执行；否则跳过通过
# ASSERT:
# METRIC key=dns_query_total label='backend="doh"' min=1 gate=1

run() {
  if [[ "${SB_E2E_DNS_DOH:-0}" != "1" ]]; then
    echo '{"name":"dns_doh_internal","ok":1,"msg":"skipped"}'
    return 0
  fi

  # 触发一次解析，由内部 doh 后端处理
  local ok=0
  for i in 1 2 3; do
    if getent hosts example.com >/dev/null 2>&1 || host -W 2 example.com 127.0.0.1 >/dev/null 2>&1; then
      ok=1; break
    fi
    sleep 0.3
  done

  if [[ "$ok" == "1" ]]; then
    echo '{"name":"dns_doh_internal","ok":1,"msg":"doh backend query ok"}'
  else
    echo '{"name":"dns_doh_internal","ok":0,"msg":"doh query failed"}'
  fi
}

run