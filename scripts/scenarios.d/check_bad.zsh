#!/usr/bin/env bash
set -euo pipefail
# 断言：bad 配置应非 0；给出最小失败定位
run() {
  local root="${ROOT}"; local target="${root}/target/e2e"
  mkdir -p "${target}"
  cat > "${target}/check_bad.yaml" <<YAML
inbounds:
  - type: socks
    listen: "127.0.0.1"
    port: 70000   # invalid
outbounds:
  - type: socks
    server: "127.0.0.1"
    port: 1080
route:
  rules:
    - when: { proto: "tcp" }  # should be array
      to: "proxy:up#1"
dns:
  mode: bad
YAML
  if "${BIN}" check -c "${target}/check_bad.yaml" >/dev/null 2>&1; then
    echo '{"name":"check_bad","ok":0,"msg":"bad config unexpectedly passed"}'
  else
    echo '{"name":"check_bad","ok":1,"msg":"bad config rejected"}'
  fi
}
run