#!/usr/bin/env bash
set -euo pipefail

ADDR=${ADDR:-"127.0.0.1:19090"}
TOKEN=${TOKEN:-""}

hdrs=()
if [ -n "$TOKEN" ]; then hdrs+=("-H" "X-Admin-Token: $TOKEN"); fi

echo "GET /healthz" >&2
curl -sS "http://$ADDR/healthz" "${hdrs[@]}" | jq . || true

echo -e "\nGET /inbounds" >&2
curl -sS "http://$ADDR/inbounds" "${hdrs[@]}" | jq . || true

echo -e "\nGET /cb-states" >&2
curl -sS "http://$ADDR/cb-states" "${hdrs[@]}" | jq . || true

