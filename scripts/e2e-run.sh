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

# 4) Run acceptance test suite A1-A5
echo "[e2e] Running acceptance tests..."
ACCEPTANCE_RESULTS=()
ACCEPTANCE_OVERALL="pass"

# A1: Go vs Rust route --explain compatibility
echo "[e2e] A1: Go vs Rust compatibility"
if bash "${ROOT}/scripts/A1_explain_replay.sh" >/dev/null 2>&1; then
  A1_STATUS="pass"
else
  case $? in
    77) A1_STATUS="skip" ;;
    *) A1_STATUS="fail"; ACCEPTANCE_OVERALL="partial" ;;
  esac
fi
ACCEPTANCE_RESULTS+=("A1:$A1_STATUS")

# A2: Schema v2 validation
echo "[e2e] A2: Schema v2 validation"
if bash "${ROOT}/scripts/A2_schema_v2_acceptance.sh" >/dev/null 2>&1; then
  A2_STATUS="pass"
else
  case $? in
    77) A2_STATUS="skip" ;;
    *) A2_STATUS="fail"; ACCEPTANCE_OVERALL="partial" ;;
  esac
fi
ACCEPTANCE_RESULTS+=("A2:$A2_STATUS")

# A3: UDP stress and metrics
echo "[e2e] A3: UDP stress testing"
if bash "${ROOT}/scripts/A3_udp_stress_metrics.sh" >/dev/null 2>&1; then
  A3_STATUS="pass"
else
  case $? in
    77) A3_STATUS="skip" ;;
    *) A3_STATUS="fail"; ACCEPTANCE_OVERALL="partial" ;;
  esac
fi
ACCEPTANCE_RESULTS+=("A3:$A3_STATUS")

# A4: Prometheus noise reduction
echo "[e2e] A4: Prometheus noise reduction"
if bash "${ROOT}/scripts/A4_prom_noise_regression.sh" >/dev/null 2>&1; then
  A4_STATUS="pass"
else
  case $? in
    77) A4_STATUS="skip" ;;
    *) A4_STATUS="fail"; ACCEPTANCE_OVERALL="partial" ;;
  esac
fi
ACCEPTANCE_RESULTS+=("A4:$A4_STATUS")

# A5: RC package verification
echo "[e2e] A5: RC package verification"
if bash "${ROOT}/scripts/A5_rc_package_verification.sh" >/dev/null 2>&1; then
  A5_STATUS="pass"
else
  case $? in
    77) A5_STATUS="skip" ;;
    *) A5_STATUS="fail"; ACCEPTANCE_OVERALL="partial" ;;
  esac
fi
ACCEPTANCE_RESULTS+=("A5:$A5_STATUS")

echo "[e2e] Acceptance tests completed: ${ACCEPTANCE_RESULTS[*]}"

# 5) Write summary
TS=$(date -u +%FT%TZ)
cat >"$OUT/summary.json" <<JSON
{
  "ts": "$TS",
  "tests_status": $E2E_STATUS,
  "go_present": $( [[ -n "${GO_SINGBOX_BIN:-}" ]] && echo true || echo false ),
  "compat": "$COMPAT",
  "bench_json": "$BENCH",
  "acceptance": {
    "overall": "$ACCEPTANCE_OVERALL",
    "results": [$(IFS=','; printf '"%s"' "${ACCEPTANCE_RESULTS[*]}" | sed 's/","/","/g')]
  }
}
JSON

echo "[e2e] summary: $OUT/summary.json"
