#!/usr/bin/env bash
set -euo pipefail
# prom_safe: wrapper around prom.sh; if prom.sh missing or args empty, no-op (exit 0)
# Usage: prom_safe <function> [args...]
prom_safe() {
  local fn="${1:-}"; shift || true
  # only call if function name and at least one arg present (prom.sh usually requires)
  if [[ -z "${fn:-}" || $# -eq 0 ]]; then
    return 0
  fi
  # locate prom.sh
  local here="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)"
  local prom="${here}/prom.sh"
  if [[ -x "${prom}" || -f "${prom}" ]]; then
    # shellcheck disable=SC1090
    source "${prom}"
    if declare -F -- "${fn}" >/dev/null 2>&1; then
      "${fn}" "$@"
      return 0
    fi
  fi
  # POSIX fallback: minimal curl/awk scrape by prefix when fn=prom_dump_by_prefix
  if [[ "${fn}" == "prom_dump_by_prefix" ]]; then
    local addr="${1:-127.0.0.1:9090}"; local prefix="${2:-proxy_select_params}"
    curl -fsS "http://${addr}/metrics" 2>/dev/null | awk -v p="$prefix" 'index($0,p)==1 {print}' || true
    return 0
  fi
  return 0
}

export -f prom_safe