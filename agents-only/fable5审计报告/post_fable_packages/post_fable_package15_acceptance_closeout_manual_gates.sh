#!/usr/bin/env bash
# post_fable_package15 — acceptance closeout/manual-gate index.
#
# This script aggregates the remaining post-FABLE acceptance gates without
# upgrading package03/package07 to DONE. Artifacts are written under WORK only.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PKG_DIR="$REPO/agents-only/fable5审计报告/post_fable_packages"
WORK="${WORK:-/tmp/pf15_acceptance_closeout}"
KERNEL="${KERNEL:-$REPO/target/debug/app}"
UID_NOW="$(id -u)"
RESULT="$WORK/result.json"
SUMMARY="$WORK/summary.txt"
GATES_JSONL="$WORK/gates.jsonl"

PASS_COUNT=0
FAIL_COUNT=0
BLOCKED_COUNT=0

mkdir -p "$WORK"
: > "$SUMMARY"
: > "$GATES_JSONL"

log() {
  printf '[pf15] %s\n' "$*" | tee -a "$SUMMARY"
}

record_gate() {
  local name="$1"
  local status="$2"
  local code="$3"
  local log_path="$4"
  local message="$5"

  case "$status" in
    PASS|SKIPPED_ROOT_EXISTING|NOT_RUN_ROOT) PASS_COUNT=$((PASS_COUNT + 1)) ;;
    BLOCKED_PRIVILEGE|BLOCKED_NORMAL_REQUIRES_NON_ROOT|MANUAL_REQUIRED) BLOCKED_COUNT=$((BLOCKED_COUNT + 1)) ;;
    *) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
  esac

  GATE_NAME="$name" \
  GATE_STATUS="$status" \
  GATE_CODE="$code" \
  GATE_LOG="$log_path" \
  GATE_MESSAGE="$message" \
  python3 - <<'PY' >> "$GATES_JSONL"
import json
import os

print(json.dumps({
    "name": os.environ["GATE_NAME"],
    "status": os.environ["GATE_STATUS"],
    "exit_code": int(os.environ["GATE_CODE"]),
    "log": os.environ["GATE_LOG"],
    "message": os.environ["GATE_MESSAGE"],
}, sort_keys=True))
PY

  log "$name: $status ($message)"
}

run_capture() {
  local name="$1"
  local log_file="$2"
  shift 2

  log "running $name"
  "$@" > "$log_file" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    record_gate "$name" "PASS" "$rc" "$log_file" "command completed"
  else
    record_gate "$name" "FAIL" "$rc" "$log_file" "command failed"
  fi
  return "$rc"
}

run_build_gui_runtime() {
  local log_file="$WORK/build_gui_runtime.log"

  log "running build_gui_runtime"
  (cd "$REPO" && cargo build -p app --bin app --features gui_runtime) > "$log_file" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    record_gate "build_gui_runtime" "PASS" "$rc" "$log_file" "GUI runtime binary built"
  else
    record_gate "build_gui_runtime" "FAIL" "$rc" "$log_file" "GUI runtime build failed"
  fi
}

run_package07() {
  local gate_work="$WORK/package07_gui_runtime"
  local log_file="$WORK/package07_probe_harness.log"
  mkdir -p "$gate_work"

  log "running package07 process-contract harness"
  WORK="$gate_work" KERNEL="$KERNEL" bash "$PKG_DIR/post_fable_package07_probe_harness.sh" > "$log_file" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    record_gate "package07_process_contract" "PASS" "$rc" "$log_file" "GUI process-contract harness passed"
  else
    record_gate "package07_process_contract" "FAIL" "$rc" "$log_file" "GUI process-contract harness failed"
  fi
}

copy_pf03b_result() {
  local src="$1/result.json"
  local dest="$2"
  if [ -f "$src" ]; then
    cp "$src" "$dest"
  fi
}

run_pf03b_normal() {
  local gate_work="$WORK/package03b_normal"
  local log_file="$WORK/package03b_normal.log"
  mkdir -p "$gate_work"

  if [ "$UID_NOW" = "0" ]; then
    record_gate "package03b_normal" "NOT_RUN_ROOT" 0 "" "normal-user permission proof requires non-root; skipped under uid 0"
    return 0
  fi

  log "running package03b normal-user TUN proof"
  PF03B_SKIP_BUILD=1 WORK="$gate_work" KERNEL="$KERNEL" PF03B_MODE=normal \
    bash "$PKG_DIR/post_fable_package03b_tun_smoke_harness.sh" > "$log_file" 2>&1
  local rc=$?
  copy_pf03b_result "$gate_work" "$WORK/package03b_normal_result.json"
  if [ "$rc" -eq 0 ]; then
    record_gate "package03b_normal" "PASS" "$rc" "$log_file" "normal-user TUN proof failed before startup as expected"
  else
    record_gate "package03b_normal" "FAIL" "$rc" "$log_file" "normal-user TUN proof did not match expected boxed behavior"
  fi
}

run_pf03b_privileged() {
  local gate_work="$WORK/package03b_privileged"
  local log_file="$WORK/package03b_privileged.log"
  mkdir -p "$gate_work"

  log "running package03b privileged TUN dataplane proof"
  PF03B_SKIP_BUILD=1 WORK="$gate_work" KERNEL="$KERNEL" PF03B_MODE=privileged \
    bash "$PKG_DIR/post_fable_package03b_tun_smoke_harness.sh" > "$log_file" 2>&1
  local rc=$?
  copy_pf03b_result "$gate_work" "$WORK/package03b_privileged_result.json"

  if [ "$rc" -eq 0 ]; then
    record_gate "package03b_privileged" "PASS" "$rc" "$log_file" "privileged TUN dataplane proof passed"
  elif [ "$rc" -eq 3 ] && [ "$UID_NOW" != "0" ]; then
    record_gate "package03b_privileged" "BLOCKED_PRIVILEGE" "$rc" "$log_file" "root/admin privilege required; rerun with sudo -E"
  elif [ "$rc" -eq 3 ]; then
    record_gate "package03b_privileged" "BLOCKED_PRIVILEGE" "$rc" "$log_file" "privileged harness reported blocked even though uid is 0"
  else
    record_gate "package03b_privileged" "FAIL" "$rc" "$log_file" "privileged TUN dataplane proof failed"
  fi
}

write_result() {
  local status="$1"
  local exit_code="$2"
  local message="$3"

  PF15_STATUS="$status" \
  PF15_EXIT_CODE="$exit_code" \
  PF15_MESSAGE="$message" \
  PF15_REPO="$REPO" \
  PF15_WORK="$WORK" \
  PF15_KERNEL="$KERNEL" \
  PF15_UID="$UID_NOW" \
  PF15_PASS="$PASS_COUNT" \
  PF15_FAIL="$FAIL_COUNT" \
  PF15_BLOCKED="$BLOCKED_COUNT" \
  PF15_GATES_JSONL="$GATES_JSONL" \
  python3 - <<'PY' > "$RESULT"
import json
import os

gates = []
with open(os.environ["PF15_GATES_JSONL"], "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if line:
            gates.append(json.loads(line))

data = {
    "status": os.environ["PF15_STATUS"],
    "exit_code": int(os.environ["PF15_EXIT_CODE"]),
    "message": os.environ["PF15_MESSAGE"],
    "repo": os.environ["PF15_REPO"],
    "work": os.environ["PF15_WORK"],
    "kernel": os.environ["PF15_KERNEL"],
    "uid": int(os.environ["PF15_UID"]),
    "interactive_wails": {
        "status": "MANUAL_REQUIRED",
        "reason": "desktop-window Start/Stop/toggle flow is not agent-drivable",
    },
    "counts": {
        "pass": int(os.environ["PF15_PASS"]),
        "fail": int(os.environ["PF15_FAIL"]),
        "blocked": int(os.environ["PF15_BLOCKED"]),
    },
    "gates": gates,
}
print(json.dumps(data, indent=2, sort_keys=True))
PY
}

finish() {
  local status
  local code
  local message

  record_gate "wails_interactive_e2e" "MANUAL_REQUIRED" 0 "" "real Wails desktop-window flow must be driven by a human/operator"

  if [ "$FAIL_COUNT" -gt 0 ]; then
    status="FAIL"
    code=1
    message="one or more automatic closeout gates failed"
  elif [ "$BLOCKED_COUNT" -gt 0 ]; then
    status="PASS_WITH_MANUAL_BLOCKERS"
    code=0
    message="automatic gates passed; remaining acceptance requires root/Wails manual evidence"
  else
    status="PASS"
    code=0
    message="all automatic gates passed and no manual blocker was reported"
  fi

  write_result "$status" "$code" "$message"
  log "final status: $status"
  log "result: $RESULT"
  exit "$code"
}

log "repo=$REPO"
log "work=$WORK"
log "kernel=$KERNEL"
log "uid=$UID_NOW"

run_build_gui_runtime
run_capture "app_version" "$WORK/app_version.log" "$KERNEL" version
run_package07
run_pf03b_normal
run_pf03b_privileged
finish
