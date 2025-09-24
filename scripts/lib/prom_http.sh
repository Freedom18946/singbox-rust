#!/usr/bin/env bash
set -euo pipefail
PROM_HTTP="${SB_PROM_HTTP:-}"
[[ -z "$PROM_HTTP" ]] && { echo "__PROM_HTTP_DISABLED__"; exit 0; }

maybe_failpoint_prom_pull() {
  local cfg="${SB_FAILPOINTS:-}"
  [[ -z "$cfg" ]] && return
  local decision
  decision=$(python - "$cfg" <<'PY'
import random, sys
cfg = sys.argv[1]
site = "prom::pull"
for entry in cfg.split(';'):
    if not entry or '=' not in entry:
        continue
    key, val = entry.split('=', 1)
    if key != site:
        continue
    rate = 1.0
    action = 'panic'
    delay = 0
    for part in val.split(','):
        if part.startswith('rate:'):
            try:
                rate = float(part.split(':', 1)[1])
            except ValueError:
                rate = 1.0
        elif part.lower() == 'none':
            action = 'none'
        elif part.lower().startswith('panic'):
            action = 'panic'
        elif part.startswith('delay:') and part.endswith('ms'):
            try:
                delay = int(part[6:-2])
                action = 'delay'
            except ValueError:
                pass
    if random.random() <= rate:
        if action == 'panic':
            print('panic')
        elif action == 'delay':
            print(f'delay:{delay}')
        else:
            print('none')
    else:
        print('skip')
    break
else:
    print('skip')
PY
  )
  case "$decision" in
    panic)
      echo "failpoint hit: prom::pull" >&2
      exit 1
      ;;
    delay:*)
      local ms="${decision#delay:}"
      python - "$ms" <<'PY'
import sys, time
ms = float(sys.argv[1])
time.sleep(ms / 1000.0)
PY
      ;;
    none|skip)
      ;;
  esac
}

qurl() {
  local q="$1"
  python - "$q" <<'PY'
import sys, urllib.parse
print(urllib.parse.urlencode({'query': sys.argv[1]}))
PY
}

prom_http_query() { # $1=expr
  local expr="$1"
  local timeout_ms="${SB_PROM_TIMEOUT_MS:-2000}"
  local timeout_sec
  timeout_sec=$(awk -v t="$timeout_ms" 'BEGIN{print t/1000}')

  if ! command -v curl >/dev/null 2>&1; then
    echo "__PROM_HTTP_FAIL__:nocurl"
    return 0
  fi

  maybe_failpoint_prom_pull

  local qs; qs=$(qurl "$expr")
  local out rc

  set +e
  out=$(curl -m "$timeout_sec" -fsS "${PROM_HTTP}/api/v1/query?${qs}" 2>&1)
  rc=$?
  set -e

  case $rc in
    0)
      if echo "$out" | jq -e '.status == "success"' >/dev/null 2>&1; then
        echo "$out"
      else
        echo "__PROM_HTTP_FAIL__:json"
      fi
      ;;
    28)
      echo "__PROM_HTTP_FAIL__:timeout"
      ;;
    22)
      echo "__PROM_HTTP_FAIL__:http4xx"
      ;;
    6|7)
      echo "__PROM_HTTP_FAIL__:connect"
      ;;
    *)
      echo "__PROM_HTTP_FAIL__:curl"
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <prometheus_query>"
    exit 1
  fi
  prom_http_query "$1"
fi
