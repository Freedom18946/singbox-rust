#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(cd "$ROOT" && pwd)

RUST_BIN="${PROJECT_ROOT}/target/debug/singbox-rust"
if [[ ! -x "$RUST_BIN" ]]; then
  RUST_BIN="${PROJECT_ROOT}/target/debug/app"
fi

GO_BIN="${GO_SINGBOX_BIN:-}"
CFG="${PROJECT_ROOT}/minimal.yaml"

if [[ ! -x "$RUST_BIN" ]]; then
  echo "SKIP: Rust binary not found; run 'cargo build' first" >&2
  exit 77
fi

if [[ -z "$GO_BIN" || ! -x "$GO_BIN" ]]; then
  echo "SKIP: GO_SINGBOX_BIN not set or not executable; skipping Go compare" >&2
  exit 77
fi

dest_tcp="example.com:443"
dest_udp="example.com:53"

subset() {
  python3 - "$@" <<'PY'
import sys, json
try:
  v=json.load(sys.stdin)
  o={k:v.get(k) for k in ["dest","matched_rule","chain","outbound"]}
  print(json.dumps(o, separators=(",",":")))
except Exception:
  sys.exit(1)
PY
}

rust_json_tcp=$($RUST_BIN route --config "$CFG" --dest "$dest_tcp" --explain --format json 2>/dev/null || true)
go_json_tcp=$($GO_BIN route --config "$CFG" --dest "$dest_tcp" --explain --format json 2>/dev/null || true)

rust_json_udp=$($RUST_BIN route --config "$CFG" --dest "$dest_udp" --udp --explain --format json 2>/dev/null || true)
go_json_udp=$($GO_BIN route --config "$CFG" --dest "$dest_udp" --explain --format json 2>/dev/null || true)

R_TCP=$(printf '%s' "$rust_json_tcp" | subset || true)
G_TCP=$(printf '%s' "$go_json_tcp"   | subset || true)
R_UDP=$(printf '%s' "$rust_json_udp" | subset || true)
G_UDP=$(printf '%s' "$go_json_udp"   | subset || true)

fail=0
if [[ -n "$R_TCP" && -n "$G_TCP" ]]; then
  if [[ "$R_TCP" != "$G_TCP" ]]; then
    echo "mismatch TCP: rust=$R_TCP go=$G_TCP" >&2
    fail=1
  fi
fi
if [[ -n "$R_UDP" && -n "$G_UDP" ]]; then
  if [[ "$R_UDP" != "$G_UDP" ]]; then
    echo "mismatch UDP: rust=$R_UDP go=$G_UDP" >&2
    fail=1
  fi
fi

exit $fail

