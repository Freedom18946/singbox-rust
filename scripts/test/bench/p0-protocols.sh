#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE'
Usage: ./scripts/test/bench/p0-protocols.sh [--baseline|--all|--help]

  --baseline   Run the baseline P0 benchmark set (default)
  --all        Run extended P0 benchmarks
USAGE
}

mode="--baseline"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --baseline|--all)
      mode="$1"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
fi

exec "$SCRIPT_DIR/run-p0.sh" "$mode"
