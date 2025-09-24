#!/usr/bin/env bash
set -euo pipefail
# 断言：good 配置应 0 退出
run() {
  local root="${ROOT}"; local target="${root}/target/e2e"
  mkdir -p "${target}"
  cat > "${target}/check_good.yaml" <<YAML
inbounds:
  - type: http
    listen: "127.0.0.1"
    port: 18081
outbounds:
  - type: direct
route:
  rules:
    - name: all->direct
      to: "direct"
dns:
  mode: system
YAML
  if "${BIN}" check -c "${target}/check_good.yaml" >/dev/null 2>&1; then
    echo '{"name":"check_good","ok":1,"msg":"good config ok"}'
  else
    echo '{"name":"check_good","ok":0,"msg":"good config should pass"}'
  fi
}
run