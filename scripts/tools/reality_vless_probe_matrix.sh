#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG=""
OUTBOUND=""
TARGET="example.com:80"
OUTPUT_DIR="${SB_REALITY_PROBE_OUTPUT_DIR:-}"
APP_FEATURES="${SB_REALITY_APP_PROBE_FEATURES:-sb-core,sb-adapters,sb-transport,adapter-vless,tls_reality}"
PHASE_FEATURES="${SB_REALITY_PHASE_PROBE_FEATURES:-adapter-vless,tls_reality}"
TIMEOUT_SECS="${SB_REALITY_APP_PROBE_TIMEOUT_SECS:-10}"
PHASE_TIMEOUT_MS="${SB_REALITY_PHASE_TIMEOUT_MS:-10000}"
PROBE_IO_TIMEOUT_MS="${SB_VLESS_PROBE_IO_TIMEOUT_MS:-10000}"

usage() {
  cat <<'EOF'
usage: reality_vless_probe_matrix.sh --config PATH --outbound TAG [options]

Options:
  --target HOST:PORT            Probe target (default: example.com:80)
  --output-dir DIR             Output directory (default: temp dir)
  --timeout SECONDS            app probe timeout (default: 10)
  --phase-timeout-ms MS        minimal phase timeout (default: 10000)
  --probe-io-timeout-ms MS     minimal probe I/O timeout (default: 10000)

Outputs:
  app.json / app.stderr
  phase.json / phase.stderr
  compare.json
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="${2:-}"
      shift 2
      ;;
    --outbound)
      OUTBOUND="${2:-}"
      shift 2
      ;;
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECS="${2:-}"
      shift 2
      ;;
    --phase-timeout-ms)
      PHASE_TIMEOUT_MS="${2:-}"
      shift 2
      ;;
    --probe-io-timeout-ms)
      PROBE_IO_TIMEOUT_MS="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${CONFIG}" || -z "${OUTBOUND}" ]]; then
  usage >&2
  exit 2
fi

if [[ -z "${OUTPUT_DIR}" ]]; then
  OUTPUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/reality-vless-probe-matrix.XXXXXX")"
fi
mkdir -p "${OUTPUT_DIR}"

APP_JSON="${OUTPUT_DIR}/app.json"
APP_STDERR="${OUTPUT_DIR}/app.stderr"
PHASE_JSON="${OUTPUT_DIR}/phase.json"
PHASE_STDERR="${OUTPUT_DIR}/phase.stderr"
COMPARE_JSON="${OUTPUT_DIR}/compare.json"
RUN_JSON="${OUTPUT_DIR}/run.json"

set +e
cargo run -q -p app --bin probe-outbound \
  --features "${APP_FEATURES}" \
  -- \
  --config "${CONFIG}" \
  --outbound "${OUTBOUND}" \
  --target "${TARGET}" \
  --timeout "${TIMEOUT_SECS}" \
  --json >"${APP_JSON}" 2>"${APP_STDERR}"
APP_STATUS=$?
set -e

eval "$(
  python3 "${ROOT}/scripts/tools/reality_vless_env_from_config.py" \
    --config "${CONFIG}" \
    --outbound "${OUTBOUND}" \
    --target "${TARGET}" \
    --phase-timeout-ms "${PHASE_TIMEOUT_MS}" \
    --probe-io-timeout-ms "${PROBE_IO_TIMEOUT_MS}" \
    --format env
)"

set +e
cargo run -q -p sb-adapters \
  --example vless_reality_phase_probe \
  --features "${PHASE_FEATURES}" >"${PHASE_JSON}" 2>"${PHASE_STDERR}"
PHASE_STATUS=$?
set -e

python3 "${ROOT}/scripts/tools/reality_probe_compare.py" \
  --app-json "${APP_JSON}" \
  --phase-json "${PHASE_JSON}" >"${COMPARE_JSON}"

MATRIX_CONFIG="${CONFIG}" \
MATRIX_OUTBOUND="${OUTBOUND}" \
MATRIX_TARGET="${TARGET}" \
MATRIX_APP_STATUS="${APP_STATUS}" \
MATRIX_PHASE_STATUS="${PHASE_STATUS}" \
MATRIX_APP_JSON="${APP_JSON}" \
MATRIX_PHASE_JSON="${PHASE_JSON}" \
MATRIX_COMPARE_JSON="${COMPARE_JSON}" \
python3 - <<'PY' >"${RUN_JSON}"
import json
import os

print(json.dumps({
    "config": os.environ["MATRIX_CONFIG"],
    "outbound": os.environ["MATRIX_OUTBOUND"],
    "target": os.environ["MATRIX_TARGET"],
    "app_status": int(os.environ["MATRIX_APP_STATUS"]),
    "phase_status": int(os.environ["MATRIX_PHASE_STATUS"]),
    "app_json": os.environ["MATRIX_APP_JSON"],
    "phase_json": os.environ["MATRIX_PHASE_JSON"],
    "compare_json": os.environ["MATRIX_COMPARE_JSON"],
}, indent=2))
PY

cat <<EOF
output_dir=${OUTPUT_DIR}
app_status=${APP_STATUS}
phase_status=${PHASE_STATUS}
run_json=${RUN_JSON}
app_json=${APP_JSON}
phase_json=${PHASE_JSON}
compare_json=${COMPARE_JSON}
EOF
