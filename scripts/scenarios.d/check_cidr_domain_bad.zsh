#!/usr/bin/env bash
# scripts/scenarios.d/check_cidr_domain_bad.zsh
set -euo pipefail
run() {
  if [[ "${SB_E2E_CHECK_CIDR_BAD:-0}" != "1" ]]; then
    echo '{"name":"check_cidr_domain_bad","ok":1,"msg":"skipped"}'; return 0
  fi
  local target="${ROOT}/target/e2e"; mkdir -p "$target"
  cat > "${target}/bad_cidr_domain.yaml" <<Y
inbounds: [{ type: http, listen: "127.0.0.1", port: 18081 }]
outbounds: [{ type: direct, name: "direct" }]
route:
  rules:
    - when: { cidr: ["10.0.0.0"], domain: ["-bad-.example.com"] }  # 错误 CIDR/域名
      to: "direct"
Y
  if "${BIN}" check -c "${target}/bad_cidr_domain.yaml" --format json | jq -e '.issues[] | select(.code=="BadCIDR" or .code=="BadDomain")' >/dev/null; then
    echo '{"name":"check_cidr_domain_bad","ok":1,"msg":"bad cidr/domain detected"}'
  else
    echo '{"name":"check_cidr_domain_bad","ok":0,"msg":"cidr/domain should be flagged"}'
  fi
}
run