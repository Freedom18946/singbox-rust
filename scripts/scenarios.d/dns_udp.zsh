#!/usr/bin/env bash
set -euo pipefail
# ASSERT:
# METRIC key=dns_query_total label='backend="system"|backend="udp"|.*' min=0 gate=0

run() {
  if getent hosts example.com >/dev/null 2>&1 || host -W 2 example.com 1.1.1.1 >/dev/null 2>&1 ; then
    echo '{"name":"dns_udp","ok":1,"msg":"dns ok"}'
  else
    echo '{"name":"dns_udp","ok":0,"msg":"dns failed"}'
  fi
}

run
