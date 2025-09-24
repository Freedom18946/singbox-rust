#!/usr/bin/env bash
set -euo pipefail
# 注入未知字段触发 --deny-unknown；默认跳过，SB_E2E_CHECK_UNKNOWN=1 开启
run() {
  if [[ "${SB_E2E_CHECK_UNKNOWN:-0}" != "1" ]]; then
    echo '{"name":"check_unknown","ok":1,"msg":"skipped"}'; return 0
  fi
  local root="${ROOT}"; local target="${root}/target/e2e"
  mkdir -p "${target}"
  cat > "${target}/bad_unknown.yaml" <<YAML
inbounds: [ { type: http, listen: "127.0.0.1", port: 18081, WHAT: "??" } ]
outbounds: [ { type: direct, name: "direct" } ]
route: { rules: [ { to: "direct" } ] }
YAML
  if "${BIN}" check -c "${target}/bad_unknown.yaml" --schema --deny-unknown >/dev/null 2>&1; then
    echo '{"name":"check_unknown","ok":0,"msg":"deny-unknown should fail"}'
  else
    echo '{"name":"check_unknown","ok":1,"msg":"unknown field denied as expected"}'
  fi
}
run