#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/l18/build_go_oracle.sh [--go-source-dir PATH] [--output-root PATH] [--run-id ID] [--ldflags STR] [--build-tags TAGS]

Defaults:
  go source: go_fork_source/sing-box-1.12.14
  output root: reports/l18/oracle/go
  run-id: UTC timestamp + random suffix
  build-tags: with_clash_api
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

GO_SOURCE_DIR="${L18_GO_SOURCE_DIR:-${ROOT_DIR}/go_fork_source/sing-box-1.12.14}"
OUTPUT_ROOT="${L18_GO_ORACLE_OUTPUT_ROOT:-${ROOT_DIR}/reports/l18/oracle/go}"
RUN_ID="${L18_RUN_ID:-}"
LDFLAGS="${L18_GO_ORACLE_LDFLAGS:--s -w}"
BUILD_TAGS="${L18_GO_ORACLE_BUILD_TAGS:-with_clash_api}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --go-source-dir)
      GO_SOURCE_DIR="$2"
      shift 2
      ;;
    --output-root)
      OUTPUT_ROOT="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    --ldflags)
      LDFLAGS="$2"
      shift 2
      ;;
    --build-tags)
      BUILD_TAGS="$2"
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

if ! command -v go >/dev/null 2>&1; then
  echo "go command not found" >&2
  exit 1
fi

if [[ ! -d "$GO_SOURCE_DIR" ]]; then
  echo "go source dir not found: $GO_SOURCE_DIR" >&2
  exit 1
fi

if [[ -z "$RUN_ID" ]]; then
  RAND_SUFFIX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
  RUN_ID="$(date -u +'%Y%m%dT%H%M%SZ')-${RAND_SUFFIX}"
fi

OUT_DIR="${OUTPUT_ROOT}/${RUN_ID}"
OUT_BIN="${OUT_DIR}/sing-box"
MANIFEST_PATH="${OUT_DIR}/oracle_manifest.json"
BUILD_LOG="${OUT_DIR}/build.log"

mkdir -p "$OUT_DIR"

build_cmd=(go build -trimpath -ldflags "$LDFLAGS")
if [[ -n "$BUILD_TAGS" ]]; then
  build_cmd+=( -tags "$BUILD_TAGS" )
fi
build_cmd+=( -o "$OUT_BIN" ./cmd/sing-box )

{
  echo "[L18 oracle] source=${GO_SOURCE_DIR}"
  echo "[L18 oracle] out=${OUT_BIN}"
  echo "[L18 oracle] run_id=${RUN_ID}"
  echo "[L18 oracle] cmd=${build_cmd[*]}"
} | tee "$BUILD_LOG"

(
  cd "$GO_SOURCE_DIR"
  "${build_cmd[@]}"
) >> "$BUILD_LOG" 2>&1

if [[ ! -x "$OUT_BIN" ]]; then
  echo "go oracle build failed: missing binary ${OUT_BIN}" >&2
  exit 1
fi

SHA256="$(shasum -a 256 "$OUT_BIN" | awk '{print $1}')"
VERSION_LINE="$($OUT_BIN version 2>&1 | head -n1 | tr -d '\r')"
GO_VERSION="$(go version 2>/dev/null || echo unknown)"
GO_SOURCE_COMMIT="$(git -C "$GO_SOURCE_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"

export MANIFEST_PATH RUN_ID OUT_BIN GO_SOURCE_DIR LDFLAGS BUILD_TAGS SHA256 VERSION_LINE GO_VERSION GO_SOURCE_COMMIT BUILD_LOG
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

manifest = {
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "run_id": os.environ["RUN_ID"],
    "oracle": {
        "binary": os.path.abspath(os.environ["OUT_BIN"]),
        "sha256": os.environ["SHA256"],
        "version": os.environ["VERSION_LINE"],
    },
    "source": {
        "path": os.path.abspath(os.environ["GO_SOURCE_DIR"]),
        "git_commit": os.environ["GO_SOURCE_COMMIT"],
    },
    "build": {
        "go_version": os.environ["GO_VERSION"],
        "ldflags": os.environ["LDFLAGS"],
        "build_tags": os.environ["BUILD_TAGS"],
        "log": os.path.abspath(os.environ["BUILD_LOG"]),
    },
}

manifest_path = os.environ["MANIFEST_PATH"]
os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
with open(manifest_path, "w", encoding="utf-8") as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)

print(f"oracle manifest written: {manifest_path}")
PY

echo "[L18 oracle] PASS"
echo "run_id=${RUN_ID}"
echo "binary=${OUT_BIN}"
echo "manifest=${MANIFEST_PATH}"
