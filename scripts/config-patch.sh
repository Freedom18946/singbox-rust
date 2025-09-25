#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   SB_ADMIN_URL=http://127.0.0.1:8088 \
#   SB_ADMIN_HMAC_SECRET=supersecret123 \
#   ./scripts/config-patch.sh patch.json [--dry-run]
#
# Exit codes:
#   0  success
#   1  missing args
#   2  request failed

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <patch.json> [--dry-run]" >&2
  exit 1
fi

PATCH_FILE="$1"
DRYRUN="${2:-}"
URL="${SB_ADMIN_URL:-http://127.0.0.1:8088}"
SECRET="${SB_ADMIN_HMAC_SECRET:-}"
ROLE="${SB_ADMIN_ROLE:-admin}"
PATHNAME="/__config"

if [[ ! -f "$PATCH_FILE" ]]; then
  echo "patch file not found: $PATCH_FILE" >&2
  exit 1
fi

BODY="$(cat "$PATCH_FILE")"
TS="$(date +%s)"

# HMAC message MUST match server convention: ts + path (no colon)
MSG="${TS}${PATHNAME}"
SIG="$(printf "%s" "$MSG" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')"
AUTH="SB-HMAC ${ROLE}:${TS}:${SIG}"

HDRS=(-H "Authorization: ${AUTH}" -H "X-Role: admin" -H "Content-Type: application/json")
if [[ "$DRYRUN" == "--dry-run" ]]; then
  HDRS+=(-H "X-Config-Dryrun: 1")
fi

HTTP_CODE=$(curl -sS -o /tmp/sb_cfg_resp.json -w "%{http_code}" \
  -X PUT "${URL}${PATHNAME}" "${HDRS[@]}" --data-binary "$BODY" || echo "000")

cat /tmp/sb_cfg_resp.json | jq .
echo "http_code: $HTTP_CODE"

if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
  CHANGED=$(jq -r '.changed // empty' /tmp/sb_cfg_resp.json 2>/dev/null || echo "")
  VERSION=$(jq -r '.version // empty' /tmp/sb_cfg_resp.json 2>/dev/null || echo "")
  if [[ "$DRYRUN" == "--dry-run" ]]; then
    echo "dry-run: changed=${CHANGED:-?} version=${VERSION:-?}"
  else
    echo "applied: changed=${CHANGED:-?} version=${VERSION:-?}"
  fi
  exit 0
else
  echo "apply failed" >&2
  exit 2
fi