#!/usr/bin/env bash
set -euo pipefail
# ASSERT:
# METRIC key=proxy_select_total label='.*' min=1 gate=1

run() {
  local socks="${SOCKS:-127.0.0.1:11080}"
  # 客户端重试，避免短暂未就绪导致偶发失败
  local ok=0
  for i in 1 2 3; do
    if curl -sS --socks5-hostname "${socks}" http://example.com/ -I -m 3 >/dev/null; then ok=1; break; fi
    sleep 0.3
  done
  if [[ "$ok" == "1" ]]; then
    echo '{"name":"socks5_tcp_connect","ok":1,"msg":"connect ok"}'
  else
    echo '{"name":"socks5_tcp_connect","ok":0,"msg":"connect failed"}'
  fi
}

run
