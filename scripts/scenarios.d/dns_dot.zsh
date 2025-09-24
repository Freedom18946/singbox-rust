#!/usr/bin/env bash
set -euo pipefail
# 需要 SB_TEST_DOT=1 才运行；否则跳过但不失败
# ASSERT:
# METRIC key=dns_query_total label='backend="dot"' min=0 gate=0

run() {
  if [[ "${SB_TEST_DOT:-0}" != "1" ]]; then
    echo '{"name":"dns_dot","ok":1,"msg":"skipped"}'
    return 0
  fi
  if timeout 3s openssl s_client -connect 1.1.1.1:853 -brief >/dev/null 2>&1; then
    echo '{"name":"dns_dot","ok":1,"msg":"tls ok"}'
  else
    echo '{"name":"dns_dot","ok":0,"msg":"tls failed"}'
  fi
}

run
