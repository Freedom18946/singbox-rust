#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"/..
cd "$ROOT"

echo "[ci] inbound-errors: build minimal runtime"
cargo build -q -p app --bin run

PROM_LISTEN="${PROM_LISTEN:-127.0.0.1:19090}"
SB_SOCKS_UDP_LISTEN="${SB_SOCKS_UDP_LISTEN:-127.0.0.1:11090}"
export PROM_LISTEN SB_SOCKS_UDP_LISTEN

echo "[ci] run udp-errors e2e (prom=${PROM_LISTEN} udp=${SB_SOCKS_UDP_LISTEN})"
scripts/e2e/socks5/udp-errors.sh

echo "{\"task\":\"inbound_errors\",\"ok\":true,\"prom\":\"${PROM_LISTEN}\",\"listen\":\"${SB_SOCKS_UDP_LISTEN}\"}"
