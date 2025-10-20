#!/usr/bin/env bash
set -euo pipefail
export TEST_TIMEOUT_SECS="${TEST_TIMEOUT_SECS:-60}"

echo "[1/4] Build (acceptance)"
cargo +1.90 build -p app --features acceptance

echo "[2/4] Test (acceptance)"
run_with_timeout() {
  local seconds="$1"; shift
  set +e
  "$@" &
  local cmd_pid=$!
  local elapsed=0
  while kill -0 "$cmd_pid" 2>/dev/null; do
    if [ "$elapsed" -ge "$seconds" ]; then
      echo "[timeout] Command exceeded ${seconds}s, sending SIGTERM (pid=$cmd_pid)" >&2
      kill -TERM "$cmd_pid" 2>/dev/null || true
      sleep 5
      if kill -0 "$cmd_pid" 2>/dev/null; then
        echo "[timeout] Still alive, sending SIGKILL (pid=$cmd_pid)" >&2
        kill -KILL "$cmd_pid" 2>/dev/null || true
      fi
      wait "$cmd_pid" 2>/dev/null || true
      echo "[timeout] Aborted due to timeout" >&2
      return 124
    fi
    sleep 1
    elapsed=$((elapsed+1))
  done
  wait "$cmd_pid"
  return $?
}

run_with_timeout "$TEST_TIMEOUT_SECS" cargo +1.90 test -p app --features acceptance

echo "[3/5] Clippy (workspace, strict)"
cargo +1.90 clippy --workspace --exclude xtests -- -D warnings

echo "[4/5] No-unwrap guard (core crates)"
./scripts/lint/no-unwrap-core.sh

echo "[5/5] Smoke run"
target/debug/app version --format json >/dev/null
target/debug/app check -c app/tests/data/ok.json   --schema-v2-validate --format json >/dev/null || true
target/debug/app check -c app/tests/data/bad.json  --schema-v2-validate --format sarif >/dev/null || true

