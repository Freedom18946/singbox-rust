#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="${ROOT}/.e2e"
mkdir -p "$OUT" "$ROOT/target"

echo "[e2e] Preparing… (GO_SINGBOX_BIN=${GO_SINGBOX_BIN:-})"
export RUST_BACKTRACE=1
cargo build -q --bins

# 1) Run cargo tests tagged as e2e (non-blocking)
set +e
cargo test -q --tests e2e -- --nocapture
E2E_STATUS=$?
set -e

# 2) Optional golden compare via CLI (subset) to produce a stable summary
COMPAT="skipped"
if [[ -n "${GO_SINGBOX_BIN:-}" && -x "${GO_SINGBOX_BIN}" ]]; then
  RBIN="${ROOT}/target/debug/singbox-rust"
  if [[ ! -x "$RBIN" ]]; then RBIN="${ROOT}/target/debug/app"; fi
  if [[ -x "$RBIN" ]]; then
    CFG="${ROOT}/minimal.yaml"
    GO_JSON=$("${GO_SINGBOX_BIN}" route --config "$CFG" --dest example.com:443 --explain --format json 2>/dev/null || true)
    RS_JSON=$("${RBIN}" route --config "$CFG" --dest example.com:443 --explain --format json 2>/dev/null || true)
    # Extract subset
    subset() { printf '%s' "$1" | python3 - "$@" <<'PY' 2>/dev/null || true
import sys, json
try:
  v=json.load(sys.stdin)
  o={k:v.get(k) for k in ["dest","matched_rule","chain","outbound"]}
  print(json.dumps(o, separators=(",",":")))
except Exception:
  pass
PY
    }
    G=$(subset "$GO_JSON")
    R=$(subset "$RS_JSON")
    if [[ -n "$G" && -n "$R" && "$G" == "$R" ]]; then
      COMPAT="ok"
      printf '%s' "$R" > "$OUT/compat_subset.json"
    else
      COMPAT="mismatch"
      printf '%s' "$R" > "$OUT/compat_subset_rust.json"
      printf '%s' "$G" > "$OUT/compat_subset_go.json"
    fi
  fi
fi

# 3) Bench JSON histogram presence (dev-only feature may be missing)
BENCH="skipped"
if "${ROOT}/target/debug/${BIN:-singbox-rust}" bench io --url http://example.com --requests 0 --concurrency 1 --json --hist-buckets 1,5,10 >"$OUT/bench.json" 2>/dev/null; then
  if grep -q '"histogram"' "$OUT/bench.json"; then BENCH="ok"; else BENCH="bad_json"; fi
fi

# 4) Write summary
TS=$(date -u +%FT%TZ)
cat >"$OUT/summary.json" <<JSON
{
  "ts": "$TS",
  "tests_status": $E2E_STATUS,
  "go_present": $( [[ -n "${GO_SINGBOX_BIN:-}" ]] && echo true || echo false ),
  "compat": "$COMPAT",
  "bench_json": "$BENCH"
}
JSON

echo "[e2e] summary: $OUT/summary.json"
