#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

GO_HEX="${TMP_DIR}/go.hex"
RUST_HEX="${TMP_DIR}/rust.hex"

bash "${ROOT}/scripts/tools/reality_go_utls_dump.sh" > "${GO_HEX}"
(
  cd "${ROOT}"
  cargo run -q -p sb-tls --example reality_clienthello_dump > "${RUST_HEX}"
)

python3 "${ROOT}/scripts/tools/reality_clienthello_diff.py" \
  --go-hex-file "${GO_HEX}" \
  --rust-hex-file "${RUST_HEX}"
