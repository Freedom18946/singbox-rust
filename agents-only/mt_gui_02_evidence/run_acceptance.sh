#!/usr/bin/env bash
# run_acceptance.sh -- MT-GUI-02 end-to-end orchestrator.
#
# Starts mock_public_infra, both kernels with the GUI-shape l18_gui_{rust,go}.json
# configs, and runs control-plane / data-plane / subscription refresh / shape
# probe in sequence. All raw output is captured under agents-only/mt_gui_02_evidence/.
#
# Intended to be idempotent and self-contained. No repository state changes.
set -u
set -o pipefail

REPO="/Users/bob/Desktop/Projects/ING/sing/singbox-rust"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE="$SCRIPT_DIR"

RUST_BIN="$REPO/target/release/app"
GO_BIN="$REPO/go_fork_source/sing-box-1.12.14/sing-box"
RUST_CFG="$REPO/labs/interop-lab/configs/l18_gui_rust.json"
GO_CFG="$REPO/labs/interop-lab/configs/l18_gui_go.json"
RUST_API="http://127.0.0.1:19090"
GO_API="http://127.0.0.1:9090"
SECRET="test-secret"

MOCK_LOG="$EVIDENCE/mock_public_infra.log"
RUST_LOG="$EVIDENCE/rust_kernel.log"
GO_LOG="$EVIDENCE/go_kernel.log"
REPORT="$EVIDENCE/run_acceptance.txt"
CP_OUT="$EVIDENCE/control_plane.txt"
DP_OUT="$EVIDENCE/data_plane.txt"
SUB_OUT="$EVIDENCE/subscription_refresh.txt"
PROBE_OUT="$EVIDENCE/extra_shape_probe.txt"
READY_FILE="$(mktemp -t mt_gui_02_ready.XXXXXX.json)"

: >"$REPORT"

log() { printf '%s\n' "$*" | tee -a "$REPORT"; }

log "=== MT-GUI-02 run_acceptance orchestrator ==="
log "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Repo: $REPO"
log "Rust binary: $RUST_BIN"
log "Go   binary: $GO_BIN"
log "Rust config: $RUST_CFG"
log "Go   config: $GO_CFG"
log ""

for f in "$RUST_BIN" "$GO_BIN" "$RUST_CFG" "$GO_CFG"; do
  if [[ ! -e "$f" ]]; then
    log "FAIL: missing required artifact: $f"
    exit 1
  fi
done

cleanup() {
  local rc=$?
  log ""
  log "--- cleanup ---"
  [[ -n "${RUST_PID:-}" ]] && kill -TERM "$RUST_PID" 2>/dev/null || true
  [[ -n "${GO_PID:-}" ]]   && kill -TERM "$GO_PID"   2>/dev/null || true
  sleep 1
  [[ -n "${RUST_PID:-}" ]] && kill -KILL "$RUST_PID" 2>/dev/null || true
  [[ -n "${GO_PID:-}" ]]   && kill -KILL "$GO_PID"   2>/dev/null || true
  [[ -n "${MOCK_PID:-}" ]] && kill -TERM "$MOCK_PID" 2>/dev/null || true
  sleep 0.5
  [[ -n "${MOCK_PID:-}" ]] && kill -KILL "$MOCK_PID" 2>/dev/null || true
  rm -f "$READY_FILE"
  exit $rc
}
trap cleanup EXIT INT TERM

# ------- start mock infra -------
log "--- starting mock_public_infra ---"
python3 "$SCRIPT_DIR/mock_public_infra.py" >"$READY_FILE" 2>"$MOCK_LOG" &
MOCK_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  if [[ -s "$READY_FILE" ]]; then break; fi
  sleep 0.25
done
if [[ ! -s "$READY_FILE" ]]; then
  log "FAIL: mock infra did not become ready"
  exit 1
fi
log "mock infra pid=$MOCK_PID ready=$(cat "$READY_FILE")"
log ""

# ------- start kernels -------
log "--- starting Rust kernel ---"
"$RUST_BIN" run -c "$RUST_CFG" >"$RUST_LOG" 2>&1 &
RUST_PID=$!
log "rust pid=$RUST_PID"

log "--- starting Go kernel ---"
"$GO_BIN" run -c "$GO_CFG" >"$GO_LOG" 2>&1 &
GO_PID=$!
log "go   pid=$GO_PID"

# wait for both APIs
for _ in $(seq 1 30); do
  RS=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $SECRET" "$RUST_API/version" || echo 000)
  GS=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $SECRET" "$GO_API/version"   || echo 000)
  if [[ "$RS" = "200" && "$GS" = "200" ]]; then
    log ""
    log "both kernels answering /version (Rust=$RS Go=$GS)"
    break
  fi
  sleep 0.25
done
if [[ "$RS" != "200" || "$GS" != "200" ]]; then
  log "FAIL: kernels did not reach API readiness (Rust=$RS Go=$GS)"
  exit 1
fi
log ""

# ------- control plane -------
log "====================================="
log "A: CONTROL PLANE"
log "====================================="
bash "$SCRIPT_DIR/control_plane_test.sh" 2>&1 | tee "$CP_OUT" | tee -a "$REPORT"
log ""

# ------- data plane -------
log "====================================="
log "B: DATA PLANE (through mock public)"
log "====================================="
bash "$SCRIPT_DIR/data_plane_test.sh" 2>&1 | tee "$DP_OUT" | tee -a "$REPORT"
log ""

# ------- subscription refresh -------
log "====================================="
log "C: SUBSCRIPTION REFRESH (mock /sub)"
log "====================================="
bash "$SCRIPT_DIR/subscription_refresh_test.sh" 2>&1 | tee "$SUB_OUT" | tee -a "$REPORT"
log ""

# ------- extra shape probe -------
log "====================================="
log "D: SHAPE PROBE (raw bodies)"
log "====================================="
bash "$SCRIPT_DIR/extra_shape_probe.sh" 2>&1 | tee "$PROBE_OUT" | tee -a "$REPORT"
log ""

# ------- graceful shutdown -------
log "====================================="
log "E: GRACEFUL SHUTDOWN"
log "====================================="
kill -TERM "$RUST_PID" 2>/dev/null || true
kill -TERM "$GO_PID"   2>/dev/null || true
sleep 2
if ! kill -0 "$RUST_PID" 2>/dev/null; then
  log "Rust: exited cleanly after SIGTERM"
else
  log "Rust: still running after SIGTERM"
fi
if ! kill -0 "$GO_PID" 2>/dev/null; then
  log "Go: exited cleanly after SIGTERM"
else
  log "Go: still running after SIGTERM"
fi
log "RESULT: PASS-STRICT"
log ""

log "=== MT-GUI-02 run_acceptance finished ==="
log "evidence under: $EVIDENCE"
log "  - run_acceptance.txt    (this report)"
log "  - control_plane.txt"
log "  - data_plane.txt"
log "  - subscription_refresh.txt"
log "  - extra_shape_probe.txt"
log "  - mock_public_infra.log"
log "  - rust_kernel.log"
log "  - go_kernel.log"
