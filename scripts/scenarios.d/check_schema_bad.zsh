#!/usr/bin/env bash
set -euo pipefail
# 仅当 SB_E2E_CHECK_SCHEMA_BAD=1 时执行；否则跳过
run() {
  if [[ "${SB_E2E_CHECK_SCHEMA_BAD:-0}" != "1" ]]; then
    echo '{"name":"check_schema_bad","ok":1,"msg":"skipped"}'; return 0
  fi
  local root="${ROOT}"; local target="${root}/target/e2e"
  mkdir -p "${target}"
  cat > "${target}/bad_schema.yaml" <<YAML
inbounds: { type: socks }    # 非数组，Schema 应报错
outbounds: [ { type: direct } ]
YAML
  if "${BIN}" check -c "${target}/bad_schema.yaml" --format json --schema >/dev/null 2>&1; then
    echo '{"name":"check_schema_bad","ok":0,"msg":"schema should fail"}'
  else
    echo '{"name":"check_schema_bad","ok":1,"msg":"schema failed as expected"}'
  fi
}
run