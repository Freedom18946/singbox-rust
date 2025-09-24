#!/usr/bin/env bash
set -euo pipefail
# 规则引用文件缺失
run() {
  if [[ "${SB_E2E_CHECK_REF_MISS:-0}" != "1" ]]; then
    echo '{"name":"check_ref_missing","ok":1,"msg":"skipped"}'; return 0
  fi
  local root="${ROOT}"; local target="${root}/target/e2e"
  mkdir -p "${target}"
  cat > "${target}/bad_ref.yaml" <<YAML
inbounds: [ { type: http, listen: "127.0.0.1", port: 18081 } ]
outbounds: [ { type: direct, name: "direct" } ]
route: { rules: [ { to: "direct" } ] }
rules_text: "rules/nonexist.txt"
YAML
  if "${BIN}" check -c "${target}/bad_ref.yaml" --check-refs --rules-dir "${target}" >/dev/null 2>&1; then
    echo '{"name":"check_ref_missing","ok":0,"msg":"missing ref should fail"}'
  else
    echo '{"name":"check_ref_missing","ok":1,"msg":"ref missing detected"}'
  fi
}
run