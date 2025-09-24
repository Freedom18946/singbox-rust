#!/usr/bin/env bash
set -euo pipefail
# 需要 SB_TEST_DOH=1 才运行；否则跳过但不失败
# ASSERT:
# METRIC key=dns_query_total label='backend="doh"' min=0 gate=0

run() {
  if [[ "${SB_TEST_DOH:-0}" != "1" ]]; then
    echo '{"name":"dns_doh","ok":1,"msg":"skipped"}'
    return 0
  fi
  if curl -s -m 3 -H 'accept: application/dns-json' 'https://cloudflare-dns.com/dns-query?name=example.com&type=A' | grep -q '"Status":0'; then
    echo '{"name":"dns_doh","ok":1,"msg":"doh ok"}'
  else
    echo '{"name":"dns_doh","ok":0,"msg":"doh failed"}'
  fi
}

run
