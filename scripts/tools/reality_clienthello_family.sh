#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

RUNS="${SB_REALITY_FAMILY_RUNS:-12}"
GO_DIR="${TMP_DIR}/go"
RUST_DIR="${TMP_DIR}/rust"
mkdir -p "${GO_DIR}" "${RUST_DIR}"

for i in $(seq 1 "${RUNS}"); do
  bash "${ROOT}/scripts/tools/reality_go_utls_dump.sh" > "${GO_DIR}/run$(printf '%02d' "${i}").hex"
  (
    cd "${ROOT}"
    cargo run -q -p sb-tls --example reality_clienthello_dump > "${RUST_DIR}/run$(printf '%02d' "${i}").hex"
  )
done

python3 "${ROOT}/scripts/tools/reality_clienthello_family.py" \
  --go-hex-dir "${GO_DIR}" \
  --rust-hex-dir "${RUST_DIR}"
