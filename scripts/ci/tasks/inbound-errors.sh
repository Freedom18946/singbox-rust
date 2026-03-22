#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/../../.. && pwd)"
cd "$ROOT"

echo "[ci] inbound-errors: build minimal runtime" >&2
FEATS="${FEATS:-acceptance,adapters}"
cargo build -q -p app --features "${FEATS}" --bin run

PROM_LISTEN="${PROM_LISTEN:-127.0.0.1:19090}"
SB_SOCKS_UDP_LISTEN="${SB_SOCKS_UDP_LISTEN:-127.0.0.1:11090}"
export PROM_LISTEN SB_SOCKS_UDP_LISTEN

echo "[ci] run udp-errors e2e (prom=${PROM_LISTEN} udp=${SB_SOCKS_UDP_LISTEN})" >&2
if FEATS="${FEATS}" zsh scripts/e2e/socks5/udp-errors.sh >&2; then
  echo "{\"task\":\"inbound_errors\",\"ok\":true,\"prom\":\"${PROM_LISTEN}\",\"listen\":\"${SB_SOCKS_UDP_LISTEN}\"}"
else
  reason="udp-error-e2e-failed"
  if [[ -f /tmp/sb-udp-errors.log ]]; then
    if grep -q "beginning graceful shutdown" /tmp/sb-udp-errors.log; then
      reason="runtime-exited-before-metrics"
    elif grep -q "no inbound builder available" /tmp/sb-udp-errors.log; then
      reason="missing-inbound-builder"
    fi
  fi
  echo "{\"task\":\"inbound_errors\",\"ok\":false,\"prom\":\"${PROM_LISTEN}\",\"listen\":\"${SB_SOCKS_UDP_LISTEN}\",\"reason\":\"${reason}\"}"
fi
