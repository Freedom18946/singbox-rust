#!/usr/bin/env sh
set -eu

CFG=${CFG:-/data/config.yaml}
METRICS_ADDR=${SB_METRICS_ADDR:-0.0.0.0:18088}

export SB_METRICS_ADDR="$METRICS_ADDR"
exec /usr/local/bin/singbox-rust --config "$CFG"

