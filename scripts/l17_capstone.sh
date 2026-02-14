#!/usr/bin/env bash
set -u -o pipefail

usage() {
  cat <<'EOF'
Usage:
  l17_capstone.sh [--profile fast|full] [--api-url URL] [--pid-file PATH] [--status-file PATH]

Profiles:
  fast (default): long-tests 20x/5x + canary 1h/300s
  full: long-tests 100x/10x + canary 168h/3600s
EOF
}

PROFILE="fast"
API_URL="${L17_CANARY_API_URL:-http://127.0.0.1:19090}"
PID_FILE="${L17_CANARY_PID_FILE:-}"
STATUS_FILE="reports/stability/l17_capstone_status.json"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --api-url)
      API_URL="$2"
      shift 2
      ;;
    --pid-file)
      PID_FILE="$2"
      shift 2
      ;;
    --status-file)
      STATUS_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

case "$PROFILE" in
  fast)
    HOT_ITER=20
    SIGNAL_ITER=5
    CANARY_HOURS=1
    CANARY_INTERVAL=300
    ;;
  full)
    HOT_ITER=100
    SIGNAL_ITER=10
    CANARY_HOURS=168
    CANARY_INTERVAL=3600
    ;;
  *)
    echo "--profile must be fast or full" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$STATUS_FILE")"
mkdir -p reports/stability

BOUNDARIES_STATUS="SKIP"
PARITY_STATUS="SKIP"
WORKSPACE_TEST_STATUS="SKIP"
FMT_STATUS="SKIP"
CLIPPY_STATUS="SKIP"
HOT_RELOAD_STATUS="SKIP"
SIGNAL_STATUS="SKIP"
CANARY_STATUS="SKIP"
DOCKER_STATUS="SKIP"
GUI_STATUS="SKIP"

HAS_FAIL=0
declare -a ENV_LIMITED_REASONS=()

run_gate() {
  local key="$1"
  shift
  echo "==> [$key] $*"
  if "$@"; then
    printf -v "${key}_STATUS" "%s" "PASS"
  else
    printf -v "${key}_STATUS" "%s" "FAIL"
    HAS_FAIL=1
  fi
}

run_gate "BOUNDARIES" bash agents-only/06-scripts/check-boundaries.sh
run_gate "PARITY" cargo check -p app --features parity
run_gate "WORKSPACE_TEST" cargo test --workspace
run_gate "FMT" cargo fmt --all -- --check
run_gate "CLIPPY" cargo clippy --workspace --all-features --all-targets -- -D warnings
run_gate "HOT_RELOAD" env SINGBOX_HOT_RELOAD_ITERATIONS="${HOT_ITER}" cargo test -p app --test hot_reload_stability --features long_tests -- --nocapture
run_gate "SIGNAL" env SINGBOX_SIGNAL_ITERATIONS="${SIGNAL_ITER}" cargo test -p app --test signal_reliability --features long_tests -- --nocapture

if docker version >/dev/null 2>&1; then
  DOCKER_STATUS="PASS"
else
  DOCKER_STATUS="ENV_LIMITED"
  ENV_LIMITED_REASONS+=("docker_daemon_unavailable")
fi

if [[ "${L17_GUI_SMOKE_AUTO:-0}" == "1" ]]; then
  GUI_ROOT="${L17_GUI_ROOT:-/Users/bob/Desktop/Projects/ING/sing/singbox-rust/GUI_fork_source/GUI.for.SingBox-1.19.0}"
  KERNEL_BIN="${L17_GUI_KERNEL_BIN:-/Users/bob/Desktop/Projects/ING/sing/singbox-rust/target/release/run}"
  GUI_CONFIG="${L17_GUI_CONFIG:-/Users/bob/Desktop/Projects/ING/sing/singbox-rust/configs/example.json}"
  if [[ -d "$GUI_ROOT" && -x "$KERNEL_BIN" && -f "$GUI_CONFIG" ]]; then
    if scripts/gui_smoke_test.sh \
      --gui-root "$GUI_ROOT" \
      --kernel-bin "$KERNEL_BIN" \
      --config "$GUI_CONFIG" \
      --api-url "$API_URL" \
      --report /Users/bob/Desktop/Projects/ING/sing/singbox-rust/reports/gui_integration_test.md \
      --artifacts-dir /Users/bob/Desktop/Projects/ING/sing/singbox-rust/reports/gui-smoke-artifacts; then
      GUI_STATUS="PASS"
    else
      GUI_STATUS="FAIL"
      HAS_FAIL=1
    fi
  else
    GUI_STATUS="ENV_LIMITED"
    ENV_LIMITED_REASONS+=("gui_prerequisites_missing")
  fi
else
  GUI_STATUS="ENV_LIMITED"
  ENV_LIMITED_REASONS+=("gui_smoke_manual_step")
fi

health_code="$(curl -sS -o /dev/null -w '%{http_code}' "${API_URL}/services/health" || echo 000)"
if [[ "$health_code" == "200" ]]; then
  CANARY_CMD=(
    scripts/canary_7day.sh
    --duration-hours "${CANARY_HOURS}"
    --sample-interval-sec "${CANARY_INTERVAL}"
    --api-url "${API_URL}"
    --out-jsonl "reports/stability/canary_7day.jsonl"
    --out-summary "reports/stability/canary_summary.md"
  )
  if [[ -n "$PID_FILE" ]]; then
    CANARY_CMD+=(--pid-file "$PID_FILE")
  fi
  if "${CANARY_CMD[@]}"; then
    CANARY_STATUS="PASS"
  else
    CANARY_STATUS="FAIL"
    HAS_FAIL=1
  fi
else
  CANARY_STATUS="ENV_LIMITED"
  ENV_LIMITED_REASONS+=("canary_api_unreachable")
fi

OVERALL="PASS"
if [[ "$HAS_FAIL" -ne 0 ]]; then
  OVERALL="FAIL"
elif [[ "${#ENV_LIMITED_REASONS[@]}" -gt 0 ]]; then
  OVERALL="PASS_ENV_LIMITED"
fi

env_limited_json=""
if [[ "${#ENV_LIMITED_REASONS[@]}" -gt 0 ]]; then
  for reason in "${ENV_LIMITED_REASONS[@]}"; do
    if [[ -n "$env_limited_json" ]]; then
      env_limited_json+=", "
    fi
    env_limited_json+="\"${reason}\""
  done
fi

cat > "$STATUS_FILE" <<EOF
{
  "generated_at": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "profile": "${PROFILE}",
  "overall": "${OVERALL}",
  "api_url": "${API_URL}",
  "fast_profile": {
    "hot_reload_iterations": ${HOT_ITER},
    "signal_iterations": ${SIGNAL_ITER},
    "canary_duration_hours": ${CANARY_HOURS},
    "canary_sample_interval_sec": ${CANARY_INTERVAL}
  },
  "gates": {
    "boundaries": "${BOUNDARIES_STATUS}",
    "parity_check": "${PARITY_STATUS}",
    "workspace_test": "${WORKSPACE_TEST_STATUS}",
    "fmt_check": "${FMT_STATUS}",
    "clippy": "${CLIPPY_STATUS}",
    "hot_reload_long_test": "${HOT_RELOAD_STATUS}",
    "signal_long_test": "${SIGNAL_STATUS}",
    "canary": "${CANARY_STATUS}",
    "docker": "${DOCKER_STATUS}",
    "gui_smoke": "${GUI_STATUS}"
  },
  "env_limited_reasons": [${env_limited_json}]
}
EOF

echo "L17 capstone status: ${OVERALL}"
echo "status file: ${STATUS_FILE}"
if [[ "$OVERALL" == "FAIL" ]]; then
  exit 1
fi
