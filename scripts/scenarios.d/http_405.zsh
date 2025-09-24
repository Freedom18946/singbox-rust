#!/usr/bin/env bash
set -euo pipefail
# ASSERT:
# METRIC key=http_respond_total label='code="405"' min=1 gate=1

run() {
  local http="${HTTP:-127.0.0.1:18081}"
  local code="" ok=0
  # 客户端重试，避免短暂未就绪导致偶发失败
  for i in 1 2 3; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X GET "http://${http}/" 2>/dev/null || echo "000")
    [[ "${code}" == "405" ]] && { ok=1; break; }
    sleep 0.3
  done
  if [[ "$ok" == "1" ]]; then
    echo '{"name":"http_405","ok":1,"msg":"405 as expected (with retry)"}'
  else
    echo "{\"name\":\"http_405\",\"ok\":0,\"msg\":\"code=${code}\"}"
  fi
}

run
