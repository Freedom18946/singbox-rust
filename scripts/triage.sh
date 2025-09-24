#!/usr/bin/env bash
set -euo pipefail

# scripts/triage.sh - quick triage helpers for sb-rust CLI/admin

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> workspace members"
grep -n "members" -A 20 ${ROOT_DIR}/Cargo.toml || true

echo "==> env"
env | grep -E 'SB_|PROM_|RUST' || true

echo "==> grep text/plain errors"
grep -RIn --line-number --color=always 'text/plain' "${ROOT_DIR}" || true

echo "==> scan json error responders"
grep -RIn --line-number --color=always 'respond_json_error' "${ROOT_DIR}" || true

echo "==> build minimal CLI only (no sb-core)"
( cd "${ROOT_DIR}/app" && cargo build --bin check --quiet )

echo "==> run version"
( cd "${ROOT_DIR}/app" && cargo run --quiet --bin version )

echo "==> structured report (json)"
( cd "${ROOT_DIR}/app" && cargo run --quiet --bin report -- --with-health ) | jq .

echo "==> /__health smoke (if admin is running)"
if [[ -f /tmp/admin.port ]]; then
  PORT=$(cat /tmp/admin.port)
  curl -s -H "Accept: application/json" "http://127.0.0.1:${PORT}/__health" | jq .
else
  echo "no /tmp/admin.port file, skip"
fi

echo "==> redirect chain test helper (external -> private)"
cat > /tmp/redirect.html <<'EOF'
<meta http-equiv="refresh" content="0;url=http://127.0.0.1/">
EOF
python3 -m http.server 19081 -d /tmp >/dev/null 2>&1 &
PID=$!
trap "kill ${PID}" EXIT
curl -s "http://127.0.0.1:19081/redirect.html" || true

echo "==> find dangling '...' placeholders which cause hard errors"
grep -RIn --line-number --color=always -E '(^|[^a-zA-Z0-9_])\.\.\.($|[^a-zA-Z0-9_])' "${ROOT_DIR}" || true

echo "==> list bins and required-features"
grep -n '^\[\[bin\]\]' -A 3 ${ROOT_DIR}/app/Cargo.toml || true

echo "==> minimal cargo tree (app/check)"
( cd "${ROOT_DIR}/app" && cargo tree -e features -i app:0.1.0 || true )

echo "==> done"